package exchange_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"

	"github.com/michaelw/ext-authz-token-exchange/internal/config"
	"github.com/michaelw/ext-authz-token-exchange/internal/exchange"
	"github.com/michaelw/ext-authz-token-exchange/internal/policy"
)

func TestExchange(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Exchange Suite")
}

var _ = Describe("Client", func() {
	var cfg config.RuntimeConfig

	BeforeEach(func() {
		cfg = config.RuntimeConfig{
			ClientID:                "client",
			ClientSecret:            "secret",
			TokenEndpointAuthMethod: config.AuthMethodClientSecretBasic,
			GrantType:               config.DefaultGrantType,
			SubjectTokenType:        config.DefaultSubjectTokenType,
			LabelSelector:           config.DefaultConfigMapLabelSelector,
			AllowHTTPTokenEndpoint:  true,
			RequireIssuedTokenType:  true,
			ExpectedIssuedTokenType: config.DefaultIssuedTokenType,
			IssuerProfiles: map[string]config.IssuerProfile{
				"primary": {
					Name:          "primary",
					TokenEndpoint: "http://issuer.example/token",
					ClientID:      "client",
					ClientSecret:  "secret",
				},
			},
		}
	})

	It("posts RFC8693 form data with Basic client authentication", func() {
		var form url.Values
		var authUser, authPass string
		tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authUser, authPass, _ = r.BasicAuth()
			Expect(r.Header.Get("Content-Type")).To(HavePrefix("application/x-www-form-urlencoded"))
			Expect(r.ParseForm()).To(Succeed())
			form = r.PostForm
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"access_token":      "exchanged",
				"token_type":        "Bearer",
				"issued_token_type": config.DefaultIssuedTokenType,
			})
		}))
		defer tokenEndpoint.Close()

		setPrimaryEndpoint(&cfg, tokenEndpoint.URL)

		result, oauthErr := exchange.NewClient(cfg, tokenEndpoint.Client()).Exchange(context.Background(), policy.Entry{
			IssuerRef: "primary",
			Scope:     "read write",
			Resources: []string{"https://orders.example.com/api/"},
			Audiences: []string{"orders-api", "orders-backend"},
		}, "subject")

		Expect(oauthErr).To(BeNil())
		Expect(result.AccessToken).To(Equal("exchanged"))
		Expect(authUser).To(Equal("client"))
		Expect(authPass).To(Equal("secret"))
		Expect(form.Get("grant_type")).To(Equal(config.DefaultGrantType))
		Expect(form.Get("subject_token")).To(Equal("subject"))
		Expect(form["resource"]).To(Equal([]string{"https://orders.example.com/api/"}))
		Expect(form["audience"]).To(Equal([]string{"orders-api", "orders-backend"}))
		Expect(form).NotTo(HaveKey("client_secret"))
	})

	It("supports client_secret_post as explicit compatibility mode", func() {
		cfg.TokenEndpointAuthMethod = config.AuthMethodClientSecretPost
		tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			Expect(r.ParseForm()).To(Succeed())
			Expect(r.PostForm.Get("client_id")).To(Equal("client"))
			Expect(r.PostForm.Get("client_secret")).To(Equal("secret"))
			Expect(r.Header.Get("Authorization")).To(BeEmpty())
			_ = json.NewEncoder(w).Encode(map[string]string{
				"access_token":      "exchanged",
				"token_type":        "bearer",
				"issued_token_type": config.DefaultIssuedTokenType,
			})
		}))
		defer tokenEndpoint.Close()

		setPrimaryEndpoint(&cfg, tokenEndpoint.URL)

		_, oauthErr := exchange.NewClient(cfg, tokenEndpoint.Client()).Exchange(context.Background(), policy.Entry{
			IssuerRef: "primary",
			Scope:     "read",
		}, "subject")

		Expect(oauthErr).To(BeNil())
	})

	It("rejects successful responses without bearer token semantics", func() {
		tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]string{
				"access_token":      "exchanged",
				"token_type":        "N_A",
				"issued_token_type": config.DefaultIssuedTokenType,
			})
		}))
		defer tokenEndpoint.Close()

		setPrimaryEndpoint(&cfg, tokenEndpoint.URL)

		_, oauthErr := exchange.NewClient(cfg, tokenEndpoint.Client()).Exchange(context.Background(), policy.Entry{
			IssuerRef: "primary",
			Scope:     "read",
		}, "subject")

		Expect(oauthErr).NotTo(BeNil())
		Expect(oauthErr.StatusCode).To(Equal(http.StatusInternalServerError))
		Expect(oauthErr.ErrorDescription).To(Equal("internal server error (TXE-3003)"))
	})

	It("preserves recognized OAuth error codes while sanitizing bodies by default", func() {
		tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="issuer"`)
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_target","error_description":"too much detail"}`))
		}))
		defer tokenEndpoint.Close()

		setPrimaryEndpoint(&cfg, tokenEndpoint.URL)

		_, oauthErr := exchange.NewClient(cfg, tokenEndpoint.Client()).Exchange(context.Background(), policy.Entry{
			IssuerRef: "primary",
			Scope:     "read",
		}, "subject")

		Expect(oauthErr).NotTo(BeNil())
		Expect(oauthErr.StatusCode).To(Equal(http.StatusBadRequest))
		Expect(oauthErr.Error).To(Equal("invalid_target"))
		Expect(oauthErr.Body).To(BeEmpty())
		Expect(oauthErr.ErrorDescription).To(Equal("request failed (TXE-2001)"))
		Expect(oauthErr.WWWAuthenticate).To(Equal([]string{`Bearer realm="issuer"`}))
	})

	It("uses stable diagnostic codes for non-OAuth token endpoint errors", func() {
		cases := []struct {
			status          int
			wantStatus      int
			wantError       string
			wantDescription string
		}{
			{status: http.StatusBadRequest, wantStatus: http.StatusBadRequest, wantError: "invalid_request", wantDescription: "request failed (TXE-2002)"},
			{status: http.StatusUnauthorized, wantStatus: http.StatusUnauthorized, wantError: "invalid_client", wantDescription: "request failed (TXE-2003)"},
			{status: http.StatusForbidden, wantStatus: http.StatusInternalServerError, wantError: "server_error", wantDescription: "internal server error (TXE-2004)"},
			{status: http.StatusBadGateway, wantStatus: http.StatusInternalServerError, wantError: "server_error", wantDescription: "internal server error (TXE-2005)"},
		}
		for _, tc := range cases {
			tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(`not-oauth-json`))
			}))
			setPrimaryEndpoint(&cfg, tokenEndpoint.URL)

			_, oauthErr := exchange.NewClient(cfg, tokenEndpoint.Client()).Exchange(context.Background(), policy.Entry{
				IssuerRef: "primary",
				Scope:     "read",
			}, "subject")
			tokenEndpoint.Close()

			Expect(oauthErr).NotTo(BeNil())
			Expect(oauthErr.StatusCode).To(Equal(tc.wantStatus))
			Expect(oauthErr.Error).To(Equal(tc.wantError))
			Expect(oauthErr.ErrorDescription).To(Equal(tc.wantDescription))
		}
	})

	It("uses stable diagnostic codes for invalid token success responses", func() {
		cases := []struct {
			body            string
			wantDescription string
		}{
			{body: `{"access_token":`, wantDescription: "internal server error (TXE-3001)"},
			{body: `{"token_type":"Bearer","issued_token_type":"` + config.DefaultIssuedTokenType + `"}`, wantDescription: "internal server error (TXE-3002)"},
			{body: `{"access_token":"exchanged","token_type":"N_A","issued_token_type":"` + config.DefaultIssuedTokenType + `"}`, wantDescription: "internal server error (TXE-3003)"},
			{body: `{"access_token":"exchanged","token_type":"Bearer","issued_token_type":"urn:ietf:params:oauth:token-type:refresh_token"}`, wantDescription: "internal server error (TXE-3004)"},
		}
		for _, tc := range cases {
			tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.body))
			}))
			setPrimaryEndpoint(&cfg, tokenEndpoint.URL)

			_, oauthErr := exchange.NewClient(cfg, tokenEndpoint.Client()).Exchange(context.Background(), policy.Entry{
				IssuerRef: "primary",
				Scope:     "read",
			}, "subject")
			tokenEndpoint.Close()

			Expect(oauthErr).NotTo(BeNil())
			Expect(oauthErr.StatusCode).To(Equal(http.StatusInternalServerError))
			Expect(oauthErr.Error).To(Equal("invalid_request"))
			Expect(oauthErr.ErrorDescription).To(Equal(tc.wantDescription))
		}
	})

	It("uses stable diagnostic codes for operational failures", func() {
		setPrimaryEndpoint(&cfg, "ftp://issuer.example/token")
		_, oauthErr := exchange.NewClient(cfg, nil).Exchange(context.Background(), policy.Entry{
			IssuerRef: "primary",
			Scope:     "read",
		}, "subject")
		Expect(oauthErr).NotTo(BeNil())
		Expect(oauthErr.Message).To(Equal("invalid token endpoint (TXE-1001)"))
		Expect(oauthErr.Message).NotTo(ContainSubstring("ftp://issuer.example/token"))

		setPrimaryEndpoint(&cfg, "http://issuer.example/token")
		_, oauthErr = exchange.NewClient(cfg, clientWithRoundTripper(roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, context.Canceled
		}))).Exchange(context.Background(), policy.Entry{
			IssuerRef: "primary",
			Scope:     "read",
		}, "subject")
		Expect(oauthErr).NotTo(BeNil())
		Expect(oauthErr.Message).To(Equal("token exchange request failed (TXE-1003)"))

		_, oauthErr = exchange.NewClient(cfg, clientWithRoundTripper(roundTripFunc(func(*http.Request) (*http.Response, error) {
			return responseWithReadError(http.StatusOK), nil
		}))).Exchange(context.Background(), policy.Entry{
			IssuerRef: "primary",
			Scope:     "read",
		}, "subject")
		Expect(oauthErr).NotTo(BeNil())
		Expect(oauthErr.Message).To(Equal("failed to read token exchange response (TXE-1004)"))
	})

	It("passes through OAuth error bodies only when enabled", func() {
		cfg.ErrorPassthrough = true
		tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_request"}`))
		}))
		defer tokenEndpoint.Close()

		setPrimaryEndpoint(&cfg, tokenEndpoint.URL+"/oauth/token?tenant=secret")

		_, oauthErr := exchange.NewClient(cfg, tokenEndpoint.Client()).Exchange(context.Background(), policy.Entry{
			IssuerRef: "primary",
			Scope:     "read",
		}, "subject")

		Expect(oauthErr).NotTo(BeNil())
		Expect(strings.TrimSpace(oauthErr.Body)).To(Equal(`{"error":"invalid_request"}`))
	})

	It("propagates trace context to the token endpoint request", func() {
		var traceparent string
		tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			traceparent = r.Header.Get("traceparent")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"access_token":      "exchanged",
				"token_type":        "Bearer",
				"issued_token_type": config.DefaultIssuedTokenType,
			})
		}))
		defer tokenEndpoint.Close()

		setPrimaryEndpoint(&cfg, tokenEndpoint.URL)

		traceID, err := trace.TraceIDFromHex("4bf92f3577b34da6a3ce929d0e0e4736")
		Expect(err).NotTo(HaveOccurred())
		spanID, err := trace.SpanIDFromHex("00f067aa0ba902b7")
		Expect(err).NotTo(HaveOccurred())
		spanContext := trace.NewSpanContext(trace.SpanContextConfig{
			TraceID:    traceID,
			SpanID:     spanID,
			TraceFlags: trace.FlagsSampled,
		})
		ctx := trace.ContextWithSpanContext(context.Background(), spanContext)

		_, oauthErr := exchange.NewClient(cfg, nil).Exchange(ctx, policy.Entry{
			IssuerRef: "primary",
			Scope:     "read",
		}, "subject")

		Expect(oauthErr).To(BeNil())
		Expect(traceparent).To(MatchRegexp(`^00-4bf92f3577b34da6a3ce929d0e0e4736-[0-9a-f]{16}-01$`))
	})

	It("records a token endpoint HTTP client span under an extracted remote parent", func() {
		recorder := tracetest.NewSpanRecorder()
		provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
		previousProvider := otel.GetTracerProvider()
		otel.SetTracerProvider(provider)
		defer otel.SetTracerProvider(previousProvider)

		tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]string{
				"access_token":      "exchanged",
				"token_type":        "Bearer",
				"issued_token_type": config.DefaultIssuedTokenType,
			})
		}))
		defer tokenEndpoint.Close()

		setPrimaryEndpoint(&cfg, tokenEndpoint.URL)

		traceID, err := trace.TraceIDFromHex("4bf92f3577b34da6a3ce929d0e0e4736")
		Expect(err).NotTo(HaveOccurred())
		spanID, err := trace.SpanIDFromHex("00f067aa0ba902b7")
		Expect(err).NotTo(HaveOccurred())
		remoteParent := trace.NewSpanContext(trace.SpanContextConfig{
			TraceID:    traceID,
			SpanID:     spanID,
			TraceFlags: trace.FlagsSampled,
			Remote:     true,
		})

		_, oauthErr := exchange.NewClient(cfg, nil).Exchange(trace.ContextWithSpanContext(context.Background(), remoteParent), policy.Entry{
			IssuerRef: "primary",
			Scope:     "read",
		}, "subject")

		Expect(oauthErr).To(BeNil())
		spans := recorder.Ended()
		Expect(spans).To(HaveLen(1))
		Expect(spans[0].Name()).To(Equal("HTTP POST"))
		Expect(spans[0].SpanContext().TraceID().String()).To(Equal("4bf92f3577b34da6a3ce929d0e0e4736"))
		Expect(spans[0].Parent().SpanID().String()).To(Equal("00f067aa0ba902b7"))
	})

	It("builds an HTTP client and base transport with configured bounded timeouts", func() {
		cfg.TokenEndpointRequestTimeout = 7 * time.Second
		cfg.TokenEndpointDialTimeout = 2 * time.Second
		cfg.TokenEndpointTLSHandshakeTimeout = 3 * time.Second
		cfg.TokenEndpointResponseHeaderTimeout = 4 * time.Second
		cfg.TokenEndpointIdleConnTimeout = 5 * time.Second
		cfg.TokenEndpointMaxIdleConns = 11
		cfg.TokenEndpointMaxIdleConnsPerHost = 6

		client := exchange.NewHTTPClient(cfg)

		Expect(client.Timeout).To(Equal(7 * time.Second))
		Expect(client.Transport).NotTo(BeNil())

		transport := exchange.NewHTTPTransport(cfg)
		Expect(transport.TLSHandshakeTimeout).To(Equal(3 * time.Second))
		Expect(transport.ResponseHeaderTimeout).To(Equal(4 * time.Second))
		Expect(transport.IdleConnTimeout).To(Equal(5 * time.Second))
		Expect(transport.MaxIdleConns).To(Equal(11))
		Expect(transport.MaxIdleConnsPerHost).To(Equal(6))
		Expect(transport.TLSClientConfig.MinVersion).NotTo(BeZero())
	})

	It("times out slow token endpoint responses within the configured request timeout", func() {
		cfg.TokenEndpointRequestTimeout = 20 * time.Millisecond
		cfg.TokenEndpointResponseHeaderTimeout = time.Second
		tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(200 * time.Millisecond)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"access_token":      "late",
				"token_type":        "Bearer",
				"issued_token_type": config.DefaultIssuedTokenType,
			})
		}))
		defer tokenEndpoint.Close()

		setPrimaryEndpoint(&cfg, tokenEndpoint.URL)

		_, oauthErr := exchange.NewClient(cfg, nil).Exchange(context.Background(), policy.Entry{
			IssuerRef: "primary",
			Scope:     "read",
		}, "subject")

		Expect(oauthErr).NotTo(BeNil())
		Expect(oauthErr.Message).To(Equal("token exchange request failed (TXE-1003)"))
		Expect(metricWithLabels("ext_authz_token_exchange_timeouts_total", map[string]string{
			"endpoint_host": "127.0.0.1",
		})).To(BeNumerically(">=", 1))
	})

	It("honors an Envoy-equivalent request context deadline before the token endpoint answers", func() {
		tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(200 * time.Millisecond)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"access_token":      "late",
				"token_type":        "Bearer",
				"issued_token_type": config.DefaultIssuedTokenType,
			})
		}))
		defer tokenEndpoint.Close()

		setPrimaryEndpoint(&cfg, tokenEndpoint.URL)

		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		_, oauthErr := exchange.NewClient(cfg, tokenEndpoint.Client()).Exchange(ctx, policy.Entry{
			IssuerRef: "primary",
			Scope:     "read",
		}, "subject")

		Expect(oauthErr).NotTo(BeNil())
		Expect(oauthErr.Message).To(Equal("token exchange request failed (TXE-1003)"))
		Expect(metricWithLabels("ext_authz_token_exchange_timeouts_total", map[string]string{
			"endpoint_host": "127.0.0.1",
		})).To(BeNumerically(">=", 1))
	})

	It("cancels the outbound token endpoint request when the ext-authz context is canceled", func() {
		ctx, cancel := context.WithCancel(context.Background())
		roundTripperStarted := make(chan struct{})
		requestCanceled := make(chan struct{})
		done := make(chan *exchange.OAuthError, 1)
		client := clientWithRoundTripper(roundTripFunc(func(req *http.Request) (*http.Response, error) {
			close(roundTripperStarted)
			<-req.Context().Done()
			close(requestCanceled)
			return nil, req.Context().Err()
		}))
		go func() {
			_, oauthErr := exchange.NewClient(cfg, client).Exchange(ctx, policy.Entry{
				IssuerRef: "primary",
				Scope:     "read",
			}, "subject")
			done <- oauthErr
		}()

		Eventually(roundTripperStarted).Should(BeClosed())
		cancel()

		Eventually(requestCanceled).Should(BeClosed())
		Eventually(done).Should(Receive(Not(BeNil())))
		Expect(metricWithLabels("ext_authz_token_exchange_context_cancellations_total", map[string]string{
			"endpoint_host": "issuer.example",
		})).To(BeNumerically(">=", 1))
	})

	It("records safe token endpoint metrics without token secrets or full URLs", func() {
		tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte(`issuer detail mentioning nothing sensitive`))
		}))
		defer tokenEndpoint.Close()

		setPrimaryEndpoint(&cfg, tokenEndpoint.URL)

		_, oauthErr := exchange.NewClient(cfg, tokenEndpoint.Client()).Exchange(context.Background(), policy.Entry{
			IssuerRef: "primary",
			Scope:     "read",
		}, "subject-token-secret")

		Expect(oauthErr).NotTo(BeNil())
		Expect(metricWithLabels("ext_authz_token_exchange_requests_total", map[string]string{
			"endpoint_host":     "127.0.0.1",
			"result":            "failure",
			"error_kind":        "http_status",
			"http_status_class": "5xx",
		})).To(BeNumerically(">=", 1))
		Expect(metricLabelValues("ext_authz_token_exchange_requests_total")).NotTo(ContainElement(ContainSubstring("subject-token-secret")))
		Expect(metricLabelValues("ext_authz_token_exchange_requests_total")).NotTo(ContainElement(ContainSubstring("/oauth/token")))
		Expect(metricLabelValues("ext_authz_token_exchange_requests_total")).NotTo(ContainElement(ContainSubstring("tenant=secret")))
	})

	It("tracks token endpoint requests in flight", func() {
		roundTripperStarted := make(chan struct{})
		releaseRoundTripper := make(chan struct{})
		client := clientWithRoundTripper(roundTripFunc(func(req *http.Request) (*http.Response, error) {
			close(roundTripperStarted)
			<-releaseRoundTripper
			return responseWithBody(http.StatusOK, `{"access_token":"exchanged","token_type":"Bearer","issued_token_type":"`+config.DefaultIssuedTokenType+`"}`), nil
		}))
		done := make(chan *exchange.OAuthError, 1)

		go func() {
			_, oauthErr := exchange.NewClient(cfg, client).Exchange(context.Background(), policy.Entry{
				IssuerRef: "primary",
				Scope:     "read",
			}, "subject")
			done <- oauthErr
		}()

		Eventually(roundTripperStarted).Should(BeClosed())
		Expect(metricWithLabels("ext_authz_token_exchange_in_flight", map[string]string{
			"endpoint_host": "issuer.example",
		})).To(BeNumerically(">=", 1))

		close(releaseRoundTripper)
		Eventually(done).Should(Receive(BeNil()))
		Eventually(func() float64 {
			return metricWithLabels("ext_authz_token_exchange_in_flight", map[string]string{
				"endpoint_host": "issuer.example",
			})
		}).Should(Equal(float64(0)))
	})
})

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func clientWithRoundTripper(rt http.RoundTripper) *http.Client {
	return &http.Client{Transport: rt}
}

func responseWithReadError(status int) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       readErrorBody{},
		Header:     http.Header{},
	}
}

func responseWithBody(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     http.Header{},
	}
}

func setPrimaryEndpoint(cfg *config.RuntimeConfig, endpoint string) {
	profile := cfg.IssuerProfiles["primary"]
	profile.TokenEndpoint = endpoint
	cfg.IssuerProfiles["primary"] = profile
}

type readErrorBody struct{}

func (readErrorBody) Read([]byte) (int, error) {
	return 0, io.ErrUnexpectedEOF
}

func (readErrorBody) Close() error {
	return nil
}

func metricWithLabels(name string, labels map[string]string) float64 {
	for _, family := range metricFamilies(name) {
		for _, metric := range family.GetMetric() {
			if metricHasLabels(metric, labels) {
				if metric.GetCounter() != nil {
					return metric.GetCounter().GetValue()
				}
				if metric.GetHistogram() != nil {
					return float64(metric.GetHistogram().GetSampleCount())
				}
				if metric.GetGauge() != nil {
					return metric.GetGauge().GetValue()
				}
			}
		}
	}
	return 0
}

func metricLabelValues(name string) []string {
	var values []string
	for _, family := range metricFamilies(name) {
		for _, metric := range family.GetMetric() {
			for _, label := range metric.GetLabel() {
				values = append(values, label.GetValue())
			}
		}
	}
	return values
}

func metricFamilies(name string) []*dto.MetricFamily {
	families, err := prometheus.DefaultGatherer.Gather()
	Expect(err).NotTo(HaveOccurred())
	var matches []*dto.MetricFamily
	for _, family := range families {
		if family.GetName() == name {
			matches = append(matches, family)
		}
	}
	return matches
}

func metricHasLabels(metric *dto.Metric, labels map[string]string) bool {
	actual := map[string]string{}
	for _, label := range metric.GetLabel() {
		actual[label.GetName()] = label.GetValue()
	}
	for name, value := range labels {
		if actual[name] != value {
			return false
		}
	}
	return true
}
