package e2e_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
)

var _ = Describe("InferencePool route", Label("inferencepool"), func() {
	BeforeEach(func() {
		if os.Getenv("E2E_INFERENCEPOOL_ENABLED") != "true" {
			Skip("enable the inferencepool-test DevSpace profile")
		}
	})

	It("preserves denial and exchange on an ordinary route on the same gateway", func(ctx SpecContext) {
		bearer := "ordinary-route-" + randomHexSuffix()
		Eventually(func(g Gomega) {
			resp, body := requestOrdinary(ctx, "/anything/red", bearer)
			g.Expect(resp.StatusCode).To(Equal(http.StatusOK), string(body))
			assertExchangedJWT(g, headerFromHTTPBin(body, "Authorization"), exchangedJWTWant{
				Scenario: "red",
				Subject:  bearer,
				Scope:    "red",
				Resource: []string{env.httpbinResourceBase + "/anything/red"},
				Audience: []string{"httpbin-red"},
			})
		}, 45*time.Second, time.Second).Should(Succeed())

		resp, body := requestOrdinary(ctx, "/anything/denied", bearer)
		Expect(resp.StatusCode).To(Equal(http.StatusForbidden), string(body))
		var parsed map[string]string
		Expect(json.Unmarshal(body, &parsed)).To(Succeed())
		Expect(parsed).To(HaveKeyWithValue("error", "policy_denied"))
	})

	It("keeps token-exchange denial active on a pool route", func(ctx SpecContext) {
		caseID := "deny-" + randomHexSuffix()
		call := func() (*http.Response, []byte) {
			return requestInference(ctx, caseID, "incoming-token")
		}

		Eventually(func(g Gomega) {
			resp, body := call()
			g.Expect(resp.StatusCode).To(Equal(http.StatusOK), string(body))
		}, 90*time.Second, time.Second).Should(Succeed(), "the pool must serve a valid request before testing policy")

		name := "inference-pool-deny-" + randomHexSuffix()
		config := fmt.Sprintf(`version: v1
entries:
  - match:
      host: %s
      pathPrefix: /v1/chat/completions
      methods: ["POST"]
    action: deny
`, env.host)
		upsertConfigMap(ctx, env.teamNamespace("red"), name, config)
		DeferCleanup(func() {
			deleteConfigMapIgnoreNotFound(context.Background(), env.teamNamespace("red"), name)
		})

		Eventually(func(g Gomega) {
			resp, body := call()
			g.Expect(resp.StatusCode).To(Equal(http.StatusForbidden), string(body))
			var parsed map[string]string
			g.Expect(json.Unmarshal(body, &parsed)).To(Succeed())
			g.Expect(parsed).To(HaveKeyWithValue("error", "policy_denied"))
		}, 45*time.Second, time.Second).Should(Succeed())

		deniedCase := "deny-confirmed-" + randomHexSuffix()
		resp, body := requestInference(ctx, deniedCase, "incoming-token")
		Expect(resp.StatusCode).To(Equal(http.StatusForbidden), string(body))
		Expect(inferenceObservation(ctx, deniedCase).Count).To(Equal(0))
	})

	It("requires a bearer token on a matched exchange route", func(ctx SpecContext) {
		name := "inference-pool-exchange-" + randomHexSuffix()
		upsertConfigMap(ctx, env.teamNamespace("red"), name, exchangePolicy())
		DeferCleanup(func() {
			deleteConfigMapIgnoreNotFound(context.Background(), env.teamNamespace("red"), name)
		})

		Eventually(func(g Gomega) {
			resp, body := requestInference(ctx, "missing-"+name, "")
			g.Expect(resp.StatusCode).To(Equal(http.StatusUnauthorized), string(body))
			g.Expect(resp.Header.Get("WWW-Authenticate")).To(ContainSubstring("Bearer"))
		}, 45*time.Second, time.Second).Should(Succeed())
		missingCase := "missing-confirmed-" + randomHexSuffix()
		resp, body := requestInference(ctx, missingCase, "")
		Expect(resp.StatusCode).To(Equal(http.StatusUnauthorized), string(body))
		Expect(inferenceObservation(ctx, missingCase).Count).To(Equal(0))
	})

	It("exchanges a bearer token on a pool route", func(ctx SpecContext) {
		name := "inference-pool-allowed-" + randomHexSuffix()
		upsertConfigMap(ctx, env.teamNamespace("red"), name, exchangePolicy())
		DeferCleanup(func() {
			deleteConfigMapIgnoreNotFound(context.Background(), env.teamNamespace("red"), name)
		})
		beforeIssuer := tokenEndpointLogs(ctx)
		beforeService := pluginLogs(ctx)
		bearer := "pool-allowed-" + randomHexSuffix()
		caseID := name

		Eventually(func(g Gomega) {
			resp, body := requestInference(ctx, caseID, bearer)
			g.Expect(resp.StatusCode).To(Equal(http.StatusOK), string(body))
			g.Expect(strings.TrimPrefix(tokenEndpointLogs(ctx), beforeIssuer)).To(ContainSubstring("scenario=red"))
			logs := strings.TrimPrefix(pluginLogs(ctx), beforeService)
			if env.expectInsecureLogs {
				g.Expect(hasTokenDebugEvent(logs, bearer)).To(BeTrue())
			} else {
				g.Expect(logs).To(ContainSubstring("allow_exchange"))
				g.Expect(logs).NotTo(ContainSubstring(bearer))
			}
		}, 45*time.Second, time.Second).Should(Succeed())
		allowedCase := "allowed-confirmed-" + randomHexSuffix()
		resp, body := requestInference(ctx, allowedCase, bearer)
		Expect(resp.StatusCode).To(Equal(http.StatusOK), string(body))
		observed := inferenceObservation(ctx, allowedCase)
		Expect(observed.Count).To(Equal(1))
		Expect(observed.Path).To(Equal("/v1/chat/completions"))
		Expect(observed.Authorization).NotTo(Equal("Bearer " + bearer))
		assertExchangedJWT(NewWithT(GinkgoT()), observed.Authorization, exchangedJWTWant{
			Scenario: "red",
			Subject:  bearer,
			Scope:    "red",
			Resource: []string{"https://" + env.host + "/v1/chat/completions"},
			Audience: []string{"httpbin-red"},
		})
	})

	It("fails closed for an invalid matched policy", func(ctx SpecContext) {
		name := "inference-pool-invalid-" + randomHexSuffix()
		config := fmt.Sprintf(`version: v1
entries:
  - match:
      host: %s
      pathPrefix: /v1/chat/completions
      methods: ["POST"]
    action: exchange
`, env.host)
		upsertConfigMap(ctx, env.teamNamespace("red"), name, config)
		DeferCleanup(func() {
			deleteConfigMapIgnoreNotFound(context.Background(), env.teamNamespace("red"), name)
		})
		Eventually(func(g Gomega) {
			resp, body := requestInference(ctx, name, "incoming-token")
			g.Expect(resp.StatusCode).To(Equal(http.StatusInternalServerError), string(body))
		}, 45*time.Second, time.Second).Should(Succeed())
		invalidCase := "invalid-confirmed-" + randomHexSuffix()
		resp, body := requestInference(ctx, invalidCase, "incoming-token")
		Expect(resp.StatusCode).To(Equal(http.StatusInternalServerError), string(body))
		Expect(inferenceObservation(ctx, invalidCase).Count).To(Equal(0))
	})

	It("denies an unmatched pool route when default deny is enabled", func(ctx SpecContext) {
		original, present := pluginEnv(ctx, "TOKEN_EXCHANGE_DEFAULT_DENY_UNMATCHED")
		setPluginEnv(ctx, "TOKEN_EXCHANGE_DEFAULT_DENY_UNMATCHED", "true")
		DeferCleanup(func(ctx SpecContext) {
			restorePluginEnv(ctx, "TOKEN_EXCHANGE_DEFAULT_DENY_UNMATCHED", original, present)
		})
		Eventually(func(g Gomega) {
			resp, body := requestInference(ctx, "unmatched-"+randomHexSuffix(), "incoming-token")
			g.Expect(resp.StatusCode).To(Equal(http.StatusForbidden), string(body))
			var parsed map[string]string
			g.Expect(json.Unmarshal(body, &parsed)).To(Succeed())
			g.Expect(parsed).To(HaveKeyWithValue("error", "policy_denied"))
		}, 45*time.Second, time.Second).Should(Succeed())
		unmatchedCase := "unmatched-confirmed-" + randomHexSuffix()
		resp, body := requestInference(ctx, unmatchedCase, "incoming-token")
		Expect(resp.StatusCode).To(Equal(http.StatusForbidden), string(body))
		Expect(inferenceObservation(ctx, unmatchedCase).Count).To(Equal(0))
	})

	It("keeps denial active when the endpoint picker is unavailable", func(ctx SpecContext) {
		name := "picker-down-deny-" + randomHexSuffix()
		config := fmt.Sprintf(`version: v1
entries:
  - match:
      host: %s
      pathPrefix: /v1/chat/completions
      methods: ["POST"]
    action: deny
`, env.host)
		upsertConfigMap(ctx, env.teamNamespace("red"), name, config)
		DeferCleanup(func() {
			deleteConfigMapIgnoreNotFound(context.Background(), env.teamNamespace("red"), name)
		})
		Eventually(func(g Gomega) {
			resp, body := requestInference(ctx, name, "incoming-token")
			g.Expect(resp.StatusCode).To(Equal(http.StatusForbidden), string(body))
		}, 45*time.Second, time.Second).Should(Succeed())

		setInferencePickerReplicas(ctx, 0)
		DeferCleanup(func(ctx SpecContext) {
			setInferencePickerReplicas(ctx, 1)
		})
		Eventually(func(g Gomega) {
			resp, body := requestInference(ctx, "picker-down-probe-"+randomHexSuffix(), "incoming-token")
			g.Expect(resp.StatusCode).To(Equal(http.StatusForbidden), string(body))
		}, 45*time.Second, time.Second).Should(Succeed())
		caseID := "picker-down-confirmed-" + randomHexSuffix()
		resp, body := requestInference(ctx, caseID, "incoming-token")
		Expect(resp.StatusCode).To(Equal(http.StatusForbidden), string(body))
		Expect(inferenceObservation(ctx, caseID).Count).To(Equal(0))
	})

	It("exchanges tokens for either backend in a weighted rule", func(ctx SpecContext) {
		for _, prefix := range []string{"weighted-ordinary", "weighted-pool"} {
			host := inferenceTestHost(prefix)
			name := prefix + "-policy-" + randomHexSuffix()
			upsertConfigMap(ctx, env.teamNamespace("red"), name, exchangePolicyForHost(host))
			DeferCleanup(func() {
				deleteConfigMapIgnoreNotFound(context.Background(), env.teamNamespace("red"), name)
			})
			bearer := prefix + "-token-" + randomHexSuffix()
			before := tokenEndpointLogs(ctx)
			Eventually(func(g Gomega) {
				resp, body := requestInferenceAtHost(ctx, host, name, bearer)
				g.Expect(resp.StatusCode).To(Equal(http.StatusOK), string(body))
				g.Expect(strings.TrimPrefix(tokenEndpointLogs(ctx), before)).To(ContainSubstring("scenario=red"))
			}, 45*time.Second, time.Second).Should(Succeed())
			caseID := prefix + "-confirmed-" + randomHexSuffix()
			resp, body := requestInferenceAtHost(ctx, host, caseID, bearer)
			Expect(resp.StatusCode).To(Equal(http.StatusOK), string(body))
			observed := inferenceObservation(ctx, caseID)
			Expect(observed.Count).To(Equal(1))
			assertExchangedJWT(NewWithT(GinkgoT()), observed.Authorization, exchangedJWTWant{
				Scenario: "red",
				Subject:  bearer,
				Scope:    "red",
				Resource: []string{"https://" + host + "/v1/chat/completions"},
				Audience: []string{"httpbin-red"},
			})
		}
	})

	It("keeps denial active with a normal backend and a pool in one weighted rule", func(ctx SpecContext) {
		assertWeightedDeny(ctx, inferenceTestHost("weighted-mixed"))
	})

	It("keeps denial active for either picker in two-pool weighted rules", func(ctx SpecContext) {
		for _, prefix := range []string{"two-pools-a", "two-pools-b", "two-pools-mixed"} {
			assertWeightedDeny(ctx, inferenceTestHost(prefix))
		}
	})
})

func assertWeightedDeny(ctx SpecContext, host string) {
	baseline := "weighted-baseline-" + randomHexSuffix()
	Eventually(func(g Gomega) {
		resp, body := requestInferenceAtHost(ctx, host, baseline, "incoming-token")
		g.Expect(resp.StatusCode).To(Equal(http.StatusOK), string(body))
	}, 60*time.Second, time.Second).Should(Succeed())
	name := "weighted-deny-" + randomHexSuffix()
	config := fmt.Sprintf(`version: v1
entries:
  - match:
      host: %s
      pathPrefix: /v1/chat/completions
      methods: ["POST"]
    action: deny
`, host)
	upsertConfigMap(ctx, env.teamNamespace("red"), name, config)
	DeferCleanup(func() {
		deleteConfigMapIgnoreNotFound(context.Background(), env.teamNamespace("red"), name)
	})
	Eventually(func(g Gomega) {
		resp, body := requestInferenceAtHost(ctx, host, name, "incoming-token")
		g.Expect(resp.StatusCode).To(Equal(http.StatusForbidden), string(body))
	}, 45*time.Second, time.Second).Should(Succeed())
	for range 12 {
		caseID := "weighted-denied-" + randomHexSuffix()
		resp, body := requestInferenceAtHost(ctx, host, caseID, "incoming-token")
		Expect(resp.StatusCode).To(Equal(http.StatusForbidden), string(body))
		Expect(inferenceObservation(ctx, caseID).Count).To(Equal(0))
	}
}

func inferenceTestHost(prefix string) string {
	return prefix + "." + strings.TrimPrefix(env.host, "inference.")
}

func setInferencePickerReplicas(ctx context.Context, replicas int32) {
	Expect(retry.RetryOnConflict(retry.DefaultRetry, func() error {
		deployment, err := env.kube.AppsV1().Deployments(env.demoNamespace).Get(ctx, "e2e-inferencepool-epp", metav1.GetOptions{})
		if err != nil {
			return err
		}
		deployment.Spec.Replicas = &replicas
		_, err = env.kube.AppsV1().Deployments(env.demoNamespace).Update(ctx, deployment, metav1.UpdateOptions{})
		return err
	})).To(Succeed())
	Eventually(func(g Gomega) {
		deployment, err := env.kube.AppsV1().Deployments(env.demoNamespace).Get(ctx, "e2e-inferencepool-epp", metav1.GetOptions{})
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(deployment.Status.ReadyReplicas).To(Equal(replicas))
	}, 90*time.Second, time.Second).Should(Succeed())
}

type inferenceRequestObservation struct {
	Count         int    `json:"count"`
	Authorization string `json:"authorization"`
	Path          string `json:"path"`
}

func inferenceObservation(ctx context.Context, caseID string) inferenceRequestObservation {
	pods, err := env.kube.CoreV1().Pods(env.demoNamespace).List(ctx, metav1.ListOptions{LabelSelector: "app=inference-test-backend"})
	Expect(err).NotTo(HaveOccurred())
	Expect(pods.Items).To(HaveLen(1))
	data, err := env.kube.CoreV1().Pods(env.demoNamespace).ProxyGet("http", pods.Items[0].Name, "8000", "observations", map[string]string{"case": caseID}).DoRaw(ctx)
	Expect(err).NotTo(HaveOccurred())
	var observed inferenceRequestObservation
	Expect(json.Unmarshal(data, &observed)).To(Succeed())
	return observed
}

func exchangePolicy() string {
	return exchangePolicyForHost(env.host)
}

func exchangePolicyForHost(host string) string {
	return fmt.Sprintf(`version: v1
entries:
  - match:
      host: %s
      pathPrefix: /v1/chat/completions
      methods: ["POST"]
    action: exchange
    exchange:
      issuerRef: fake-issuer
      scope: red
      resources:
        - https://%s/v1/chat/completions
      audiences:
        - httpbin-red
`, host, host)
}

func requestInference(ctx context.Context, caseID, bearer string) (*http.Response, []byte) {
	return requestInferenceAtHost(ctx, env.host, caseID, bearer)
}

func requestInferenceAtHost(ctx context.Context, host, caseID, bearer string) (*http.Response, []byte) {
	base, err := url.Parse(env.baseURL)
	Expect(err).NotTo(HaveOccurred())
	base.Host = net.JoinHostPort(host, base.Port())
	base.Path = "/v1/chat/completions"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base.String(), strings.NewReader(`{"model":"Qwen/Qwen3-32B","messages":[{"role":"user","content":"hello"}],"max_tokens":1}`))
	Expect(err).NotTo(HaveOccurred())
	req.Host = host
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Test-Case", caseID)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := httpClient().Do(req)
	Expect(err).NotTo(HaveOccurred())
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	Expect(err).NotTo(HaveOccurred())
	return resp, body
}

func requestOrdinary(ctx context.Context, path, bearer string) (*http.Response, []byte) {
	base, err := url.Parse(env.baseURL)
	Expect(err).NotTo(HaveOccurred())
	host := "httpbin." + strings.TrimPrefix(env.host, "inference.")
	base.Host = net.JoinHostPort(host, base.Port())
	base.Path = path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base.String(), nil)
	Expect(err).NotTo(HaveOccurred())
	req.Host = host
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := httpClient().Do(req)
	Expect(err).NotTo(HaveOccurred())
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	Expect(err).NotTo(HaveOccurred())
	return resp, body
}
