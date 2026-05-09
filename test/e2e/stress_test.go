package e2e_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const (
	defaultStressConcurrency    = 8
	defaultStressDuration       = 90 * time.Second
	defaultStressRequestTimeout = 10 * time.Second
)

var _ = Describe("gateway stress", Label("stress"), func() {
	It("drives mixed local-test traffic through the gateway authz path", func(ctx SpecContext) {
		profile := loadStressProfile()
		client := stressHTTPClient(profile.RequestTimeout)
		cases := stressCases(ctx)
		deadline := time.Now().Add(profile.Duration)
		results := &stressResults{}
		var sequence uint64
		var wg sync.WaitGroup

		for worker := 0; worker < profile.Concurrency; worker++ {
			worker := worker
			wg.Add(1)
			go func() {
				defer wg.Done()
				for time.Now().Before(deadline) {
					index := atomic.AddUint64(&sequence, 1) - 1
					runStressCase(ctx, client, cases.pick(index, worker), results)
				}
			}()
		}
		wg.Wait()

		summary := results.summary()
		AddReportEntry("stress summary", fmt.Sprintf("total=%d success=%d expected_denial=%d expected_failure=%d transport_errors=%d unexpected_failures=%d unexpected_rate=%.2f%% p95_latency=%s",
			summary.Total, summary.Success, summary.ExpectedDenial, summary.ExpectedFailure, summary.TransportErrors, summary.UnexpectedFailures, summary.UnexpectedRate*100, summary.P95Latency,
		), ReportEntryVisibilityAlways)

		Expect(summary.Total).To(BeNumerically(">", 0))
		Expect(summary.TransportErrors).To(BeNumerically("<=", maxInt(1, summary.Total/100)))
		Expect(summary.UnexpectedRate).To(BeNumerically("<=", 0.01))
	})
})

type stressProfile struct {
	Concurrency    int
	Duration       time.Duration
	RequestTimeout time.Duration
}

func loadStressProfile() stressProfile {
	return stressProfile{
		Concurrency:    envInt("E2E_STRESS_CONCURRENCY", defaultStressConcurrency),
		Duration:       envDuration("E2E_STRESS_DURATION", defaultStressDuration),
		RequestTimeout: envDuration("E2E_STRESS_REQUEST_TIMEOUT", defaultStressRequestTimeout),
	}
}

type stressCase struct {
	Name         string
	Method       string
	Path         string
	Bearer       string
	ExpectStatus int
	Kind         stressResultKind
}

type stressCaseSet struct {
	Success         []stressCase
	UnmatchedAllow  []stressCase
	ExpectedDenial  []stressCase
	ExpectedFailure []stressCase
}

func (s stressCaseSet) pick(index uint64, worker int) stressCase {
	bucket := int(index % 100)
	switch {
	case bucket < 55:
		return s.Success[(int(index)+worker)%len(s.Success)]
	case bucket < 75:
		return s.UnmatchedAllow[(int(index)+worker)%len(s.UnmatchedAllow)]
	case bucket < 90:
		return s.ExpectedDenial[(int(index)+worker)%len(s.ExpectedDenial)]
	default:
		return s.ExpectedFailure[(int(index)+worker)%len(s.ExpectedFailure)]
	}
}

func stressCases(ctx context.Context) stressCaseSet {
	if env.issuer == keycloakIssuer {
		subjectToken := fetchKeycloakSubjectToken(ctx)
		return stressCaseSet{
			Success: []stressCase{{
				Name: "keycloak exchange", Method: http.MethodGet, Path: "/anything/keycloak-audience", Bearer: subjectToken, ExpectStatus: http.StatusOK, Kind: stressResultSuccess,
			}},
			UnmatchedAllow: []stressCase{{
				Name: "unmatched allow", Method: http.MethodGet, Path: "/anything/no-policy-match", Bearer: "stress-original", ExpectStatus: http.StatusOK, Kind: stressResultSuccess,
			}},
			ExpectedDenial: []stressCase{{
				Name: "missing bearer", Method: http.MethodGet, Path: "/anything/keycloak-audience", ExpectStatus: http.StatusUnauthorized, Kind: stressResultDenial,
			}},
			ExpectedFailure: []stressCase{{
				Name: "invalid audience", Method: http.MethodGet, Path: "/anything/keycloak-invalid-audience", Bearer: subjectToken, ExpectStatus: http.StatusBadRequest, Kind: stressResultFailure,
			}},
		}
	}
	return stressCaseSet{
		Success: []stressCase{
			{Name: "yellow exchange", Method: http.MethodGet, Path: "/anything/yellow", Bearer: "stress-yellow", ExpectStatus: http.StatusOK, Kind: stressResultSuccess},
			{Name: "red exchange", Method: http.MethodGet, Path: "/anything/red", Bearer: "stress-red", ExpectStatus: http.StatusOK, Kind: stressResultSuccess},
			{Name: "blue exchange", Method: http.MethodGet, Path: "/anything/blue", Bearer: "stress-blue", ExpectStatus: http.StatusOK, Kind: stressResultSuccess},
		},
		UnmatchedAllow: []stressCase{{
			Name: "unmatched allow", Method: http.MethodGet, Path: "/anything/no-policy-match", Bearer: "stress-original", ExpectStatus: http.StatusOK, Kind: stressResultSuccess,
		}},
		ExpectedDenial: []stressCase{
			{Name: "missing bearer", Method: http.MethodGet, Path: "/anything/yellow", ExpectStatus: http.StatusUnauthorized, Kind: stressResultDenial},
			{Name: "explicit deny", Method: http.MethodGet, Path: "/anything/denied", Bearer: "stress-denied", ExpectStatus: http.StatusForbidden, Kind: stressResultDenial},
		},
		ExpectedFailure: []stressCase{{
			Name: "invalid grant", Method: http.MethodGet, Path: "/anything/error-invalid-grant", Bearer: "stress-invalid", ExpectStatus: http.StatusBadRequest, Kind: stressResultFailure,
		}},
	}
}

type stressResultKind string

const (
	stressResultSuccess stressResultKind = "success"
	stressResultDenial  stressResultKind = "denial"
	stressResultFailure stressResultKind = "failure"
)

type stressResults struct {
	mu                 sync.Mutex
	latencies          []time.Duration
	total              int
	success            int
	expectedDenial     int
	expectedFailure    int
	transportErrors    int
	unexpectedFailures int
}

type stressSummary struct {
	Total              int
	Success            int
	ExpectedDenial     int
	ExpectedFailure    int
	TransportErrors    int
	UnexpectedFailures int
	UnexpectedRate     float64
	P95Latency         time.Duration
}

func runStressCase(ctx context.Context, client *http.Client, tc stressCase, results *stressResults) {
	started := time.Now()
	status, err := stressRequest(ctx, client, tc)
	results.record(tc, status, err, time.Since(started))
}

func (r *stressResults) record(tc stressCase, status int, err error, latency time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.total++
	r.latencies = append(r.latencies, latency)
	if err != nil {
		r.transportErrors++
		r.unexpectedFailures++
		return
	}
	if status != tc.ExpectStatus {
		r.unexpectedFailures++
		return
	}
	switch tc.Kind {
	case stressResultSuccess:
		r.success++
	case stressResultDenial:
		r.expectedDenial++
	case stressResultFailure:
		r.expectedFailure++
	}
}

func (r *stressResults) summary() stressSummary {
	r.mu.Lock()
	defer r.mu.Unlock()
	latencies := append([]time.Duration(nil), r.latencies...)
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	var p95 time.Duration
	if len(latencies) > 0 {
		index := int(float64(len(latencies)-1) * 0.95)
		p95 = latencies[index]
	}
	unexpectedRate := 0.0
	if r.total > 0 {
		unexpectedRate = float64(r.unexpectedFailures) / float64(r.total)
	}
	return stressSummary{
		Total:              r.total,
		Success:            r.success,
		ExpectedDenial:     r.expectedDenial,
		ExpectedFailure:    r.expectedFailure,
		TransportErrors:    r.transportErrors,
		UnexpectedFailures: r.unexpectedFailures,
		UnexpectedRate:     unexpectedRate,
		P95Latency:         p95,
	}
}

func stressRequest(ctx context.Context, client *http.Client, tc stressCase) (int, error) {
	req, err := http.NewRequestWithContext(ctx, tc.Method, env.baseURL+tc.Path, nil)
	if err != nil {
		return 0, err
	}
	if env.host != "" {
		req.Host = env.host
	}
	if tc.Bearer != "" {
		req.Header.Set("Authorization", "Bearer "+tc.Bearer)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}

func stressHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: env.insecureTLS},
	}}
}

func envInt(name string, fallback int) int {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

func envDuration(name string, fallback time.Duration) time.Duration {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func (tc stressCase) String() string {
	return fmt.Sprintf("%s %s %s", tc.Name, tc.Method, tc.Path)
}
