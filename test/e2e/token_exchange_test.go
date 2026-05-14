package e2e_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("multi-namespace token exchange", Ordered, func() {
	It("merges per-team ConfigMaps and exchanges tokens for each color namespace", func(ctx SpecContext) {
		for _, color := range []string{"yellow", "red", "blue"} {
			color := color
			Eventually(func(g Gomega) {
				resp, body := request(ctx, http.MethodGet, "/anything/"+color, "incoming-"+color, nil)
				g.Expect(resp.StatusCode).To(Equal(http.StatusOK), string(body))
				assertExchangedJWT(g, headerFromHTTPBin(body, "Authorization"), exchangedJWTWant{
					Scenario: color,
					Subject:  "incoming-" + color,
					Scope:    color,
					Resource: []string{env.httpbinResourceBase + "/anything/" + color},
					Audience: []string{"httpbin-" + color},
				})
			}, 45*time.Second, time.Second).Should(Succeed())
		}
	})

	It("adds and deletes one team policy without disabling unrelated teams", func(ctx SpecContext) {
		policy := createEphemeralPolicy(ctx, env.teamNamespace("red"), "red-v2", "red-v2")

		Eventually(func(g Gomega) {
			resp, body := request(ctx, http.MethodGet, policy.Path, "incoming-red", nil)
			g.Expect(resp.StatusCode).To(Equal(http.StatusOK), string(body))
			assertExchangedJWT(g, headerFromHTTPBin(body, "Authorization"), exchangedJWTWant{
				Scenario: "red",
				Subject:  "incoming-red",
				Scope:    "red-v2",
				Resource: []string{env.httpbinResourceBase + policy.Path},
				Audience: []string{"httpbin-red"},
			})
		}, 45*time.Second, time.Second).Should(Succeed())

		deleteConfigMapIgnoreNotFound(ctx, env.teamNamespace("red"), policy.Name)

		Eventually(func(g Gomega) {
			resp, body := request(ctx, http.MethodGet, policy.Path, "original-red", nil)
			g.Expect(resp.StatusCode).To(Equal(http.StatusOK), string(body))
			g.Expect(headerFromHTTPBin(body, "Authorization")).To(Equal("Bearer original-red"))
		}, 45*time.Second, time.Second).Should(Succeed())

		resp, body := request(ctx, http.MethodGet, "/anything/yellow", "incoming-yellow", nil)
		Expect(resp.StatusCode).To(Equal(http.StatusOK), string(body))
		assertExchangedJWT(NewWithT(GinkgoT()), headerFromHTTPBin(body, "Authorization"), exchangedJWTWant{
			Scenario: "yellow",
			Subject:  "incoming-yellow",
			Scope:    "yellow",
			Resource: []string{env.httpbinResourceBase + "/anything/yellow"},
			Audience: []string{"httpbin-yellow"},
		})
	})

	It("returns a bearer challenge when a matched request has no bearer token", func(ctx SpecContext) {
		resp, body := request(ctx, http.MethodGet, "/anything/yellow", "", nil)
		Expect(resp.StatusCode).To(Equal(http.StatusUnauthorized), string(body))
		Expect(resp.Header.Values("WWW-Authenticate")).NotTo(BeEmpty())
		Expect(resp.Header.Get("WWW-Authenticate")).To(ContainSubstring(`Bearer realm="ext-authz-token-exchange-e2e"`))

		var parsed map[string]string
		Expect(json.Unmarshal(body, &parsed)).To(Succeed())
		Expect(parsed).To(HaveKeyWithValue("error", "bearer_token_required"))
	})

	It("lets true CORS preflight requests pass through to httpbin", func(ctx SpecContext) {
		resp, body := request(ctx, http.MethodOptions, "/anything/yellow", "", map[string]string{
			"Origin":                         "https://client.example.test",
			"Access-Control-Request-Method":  "GET",
			"Access-Control-Request-Headers": "Authorization",
		})
		Expect(resp.StatusCode).To(Equal(http.StatusOK), string(body))
		Expect(resp.Header.Get("Access-Control-Allow-Origin")).To(Equal("https://client.example.test"))
		Expect(resp.Header.Get("Access-Control-Allow-Methods")).To(ContainSubstring("OPTIONS"))
		Expect(resp.Header.Get("Access-Control-Allow-Headers")).To(Equal("Authorization"))
	})

	It("returns a bearer challenge for OPTIONS requests without bearer or CORS preflight headers", func(ctx SpecContext) {
		resp, body := request(ctx, http.MethodOptions, "/anything/yellow", "", nil)
		Expect(resp.StatusCode).To(Equal(http.StatusUnauthorized), string(body))
		Expect(resp.Header.Values("WWW-Authenticate")).NotTo(BeEmpty())
		Expect(resp.Header.Get("WWW-Authenticate")).To(ContainSubstring(`Bearer realm="ext-authz-token-exchange-e2e"`))

		var parsed map[string]string
		Expect(json.Unmarshal(body, &parsed)).To(Succeed())
		Expect(parsed).To(HaveKeyWithValue("error", "bearer_token_required"))
	})

	It("exchanges bearer tokens on OPTIONS requests that are not CORS preflight", func(ctx SpecContext) {
		before := tokenEndpointLogs(ctx)
		pluginBefore := pluginLogs(ctx)
		resp, body := request(ctx, http.MethodOptions, "/anything/yellow", "options-token", nil)
		Expect(resp.StatusCode).To(Equal(http.StatusOK), string(body))

		Eventually(func(g Gomega) {
			after := strings.TrimPrefix(tokenEndpointLogs(ctx), before)
			g.Expect(after).To(ContainSubstring(`scenario=yellow`))
			g.Expect(after).NotTo(ContainSubstring(`subject_token=`))
			g.Expect(after).NotTo(ContainSubstring(`options-token`))
		}, 30*time.Second, time.Second).Should(Succeed())

		Eventually(func(g Gomega) {
			after := strings.TrimPrefix(pluginLogs(ctx), pluginBefore)
			g.Expect(after).To(ContainSubstring(`INSECURE_LOG_TOKENS`))
			g.Expect(after).To(ContainSubstring(`subject_token=options-token`))
			assertExchangedJWT(g, "Bearer "+exchangedTokenFromLogs(after), exchangedJWTWant{
				Scenario: "yellow",
				Subject:  "options-token",
				Scope:    "yellow",
				Resource: []string{env.httpbinResourceBase + "/anything/yellow"},
				Audience: []string{"httpbin-yellow"},
			})
		}, 30*time.Second, time.Second).Should(Succeed())
	})

	It("allows unmatched requests through unchanged", func(ctx SpecContext) {
		resp, body := request(ctx, http.MethodGet, "/anything/no-policy-match", "original-token", nil)
		Expect(resp.StatusCode).To(Equal(http.StatusOK), string(body))
		Expect(headerFromHTTPBin(body, "Authorization")).To(Equal("Bearer original-token"))
	})

	It("denies unmatched requests when default deny is enabled", func(ctx SpecContext) {
		setPluginEnv(ctx, "TOKEN_EXCHANGE_DEFAULT_DENY_UNMATCHED", "true")
		DeferCleanup(func(ctx SpecContext) {
			setPluginEnv(ctx, "TOKEN_EXCHANGE_DEFAULT_DENY_UNMATCHED", "false")
		})

		Eventually(func(g Gomega) {
			resp, body := request(ctx, http.MethodGet, "/anything/no-policy-match", "original-token", nil)
			g.Expect(resp.StatusCode).To(Equal(http.StatusForbidden), string(body))

			var parsed map[string]string
			g.Expect(json.Unmarshal(body, &parsed)).To(Succeed())
			g.Expect(parsed).To(HaveKeyWithValue("error", "policy_denied"))
		}, 45*time.Second, time.Second).Should(Succeed())

		resp, body := request(ctx, http.MethodOptions, "/anything/no-policy-match", "", map[string]string{
			"Origin":                        "https://client.example.test",
			"Access-Control-Request-Method": "GET",
		})
		Expect(resp.StatusCode).To(Equal(http.StatusForbidden), string(body))
	})

	It("denies explicitly denied routes without default deny", func(ctx SpecContext) {
		for _, tc := range []struct {
			method string
			bearer string
		}{
			{method: http.MethodGet, bearer: "denied-token"},
			{method: http.MethodOptions},
		} {
			resp, body := request(ctx, tc.method, "/anything/denied", tc.bearer, nil)
			Expect(resp.StatusCode).To(Equal(http.StatusForbidden), string(body))

			var parsed map[string]string
			Expect(json.Unmarshal(body, &parsed)).To(Succeed())
			Expect(parsed).To(HaveKeyWithValue("error", "policy_denied"))
		}
	})

	It("ignores policies from namespaces that do not match the namespace selector", func(ctx SpecContext) {
		namespace := createUnlabeledTeamNamespace(ctx, "black")
		policy := createEphemeralPolicy(ctx, namespace, "black-unselected", "black")

		Consistently(func(g Gomega) {
			resp, body := request(ctx, http.MethodGet, policy.Path, "original-black", nil)
			g.Expect(resp.StatusCode).To(Equal(http.StatusOK), string(body))
			g.Expect(headerFromHTTPBin(body, "Authorization")).To(Equal("Bearer original-black"))
		}, 5*time.Second, time.Second).Should(Succeed())
	})

	It("fails closed for cross-namespace ties", func(ctx SpecContext) {
		policy := newEphemeralPolicy("yellow-conflict")
		createPolicy(ctx, env.teamNamespace("yellow"), policy.Name, "yellow-conflict", policy.Path)
		createPolicy(ctx, env.teamNamespace("blue"), policy.Name, "yellow-conflict", policy.Path)
		DeferCleanup(func() {
			deleteConfigMapIgnoreNotFound(context.Background(), env.teamNamespace("yellow"), policy.Name)
			deleteConfigMapIgnoreNotFound(context.Background(), env.teamNamespace("blue"), policy.Name)
		})

		Eventually(func(g Gomega) {
			resp, body := request(ctx, http.MethodGet, policy.Path, "incoming-yellow", nil)
			g.Expect(resp.StatusCode).To(Equal(http.StatusInternalServerError), string(body))
		}, 45*time.Second, time.Second).Should(Succeed())
	})

	It("fails closed only for the affected invalid policy region", func(ctx SpecContext) {
		policy := newEphemeralPolicy("invalid-region")
		config := fmt.Sprintf(`version: v1
entries:
  - match:
      host: %s
      pathPrefix: %s
      methods: ["GET"]
    action: exchange
`, env.host, policy.Path)
		upsertConfigMap(ctx, env.teamNamespace("red"), policy.Name, config)
		DeferCleanup(func() {
			deleteConfigMapIgnoreNotFound(context.Background(), env.teamNamespace("red"), policy.Name)
		})

		Eventually(func(g Gomega) {
			resp, body := request(ctx, http.MethodGet, policy.Path, "token", nil)
			g.Expect(resp.StatusCode).To(Equal(http.StatusInternalServerError), string(body))
		}, 45*time.Second, time.Second).Should(Succeed())

		resp, body := request(ctx, http.MethodGet, "/anything/blue", "incoming-blue", nil)
		Expect(resp.StatusCode).To(Equal(http.StatusOK), string(body))
		assertExchangedJWT(NewWithT(GinkgoT()), headerFromHTTPBin(body, "Authorization"), exchangedJWTWant{
			Scenario: "blue",
			Subject:  "incoming-blue",
			Scope:    "blue",
			Resource: []string{env.httpbinResourceBase + "/anything/blue"},
			Audience: []string{"httpbin-blue"},
		})
	})

	It("maps token endpoint OAuth and protocol failures to downstream responses", func(ctx SpecContext) {
		cases := []struct {
			path       string
			statusCode int
			errorCode  string
			wantWWW    bool
		}{
			{path: "/anything/error-invalid-target", statusCode: http.StatusBadRequest, errorCode: "invalid_target"},
			{path: "/anything/error-invalid-grant", statusCode: http.StatusBadRequest, errorCode: "invalid_grant"},
			{path: "/anything/error-expired-subject-token", statusCode: http.StatusBadRequest, errorCode: "invalid_grant"},
			{path: "/anything/error-unauthorized", statusCode: http.StatusUnauthorized, errorCode: "invalid_client", wantWWW: true},
			{path: "/anything/error-forbidden", statusCode: http.StatusInternalServerError, errorCode: "invalid_target"},
			{path: "/anything/error-malformed", statusCode: http.StatusInternalServerError, errorCode: "invalid_request"},
		}
		for _, tc := range cases {
			resp, body := request(ctx, http.MethodGet, tc.path, "incoming-error", nil)
			Expect(resp.StatusCode).To(Equal(tc.statusCode), string(body))
			if tc.wantWWW {
				Expect(resp.Header.Values("WWW-Authenticate")).NotTo(BeEmpty())
			}
			var parsed map[string]string
			Expect(json.Unmarshal(body, &parsed)).To(Succeed(), string(body))
			Expect(parsed).To(HaveKeyWithValue("error", tc.errorCode))
		}
	})
})

type exchangedJWTWant struct {
	Scenario string
	Subject  string
	Scope    string
	Resource []string
	Audience []string
}

func assertExchangedJWT(g Gomega, auth string, want exchangedJWTWant) {
	g.Expect(auth).To(HavePrefix("Bearer "))
	header, payload, err := decodeUnsignedJWT(strings.TrimPrefix(auth, "Bearer "))
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(header).To(HaveKeyWithValue("alg", "none"))
	g.Expect(header).To(HaveKeyWithValue("typ", "JWT"))
	g.Expect(payload).To(HaveKeyWithValue("iss", "fake-token-endpoint"))
	g.Expect(payload).To(HaveKeyWithValue("scenario", want.Scenario))
	g.Expect(payload).To(HaveKeyWithValue("sub", want.Subject))
	g.Expect(payload).To(HaveKeyWithValue("scope", want.Scope))
	g.Expect(payload).To(HaveKeyWithValue("subject_token_type", "urn:ietf:params:oauth:token-type:access_token"))
	g.Expect(payload).To(HaveKeyWithValue("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange"))
	g.Expect(payload).To(HaveKeyWithValue("client_id", defaultOAuthClientID))
	g.Expect(stringArrayClaim(payload, "resource")).To(Equal(want.Resource))
	g.Expect(stringArrayClaim(payload, "aud")).To(Equal(want.Audience))
	g.Expect(payload).NotTo(HaveKey("client_secret"))
}

func decodeUnsignedJWT(token string) (map[string]any, map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[2] != "" {
		return nil, nil, fmt.Errorf("token is not an unsigned JWT")
	}
	var header map[string]any
	if err := decodeBase64URLJSON(parts[0], &header); err != nil {
		return nil, nil, err
	}
	var payload map[string]any
	if err := decodeBase64URLJSON(parts[1], &payload); err != nil {
		return nil, nil, err
	}
	return header, payload, nil
}

func decodeBase64URLJSON(part string, out any) error {
	decoded, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		return err
	}
	return json.Unmarshal(decoded, out)
}

func stringArrayClaim(payload map[string]any, key string) []string {
	raw, _ := payload[key].([]any)
	values := make([]string, 0, len(raw))
	for _, item := range raw {
		if value, ok := item.(string); ok {
			values = append(values, value)
		}
	}
	return values
}

func exchangedTokenFromLogs(logs string) string {
	const marker = "exchanged_token="
	index := strings.LastIndex(logs, marker)
	Expect(index).NotTo(Equal(-1), logs)
	fields := strings.Fields(logs[index+len(marker):])
	Expect(fields).NotTo(BeEmpty(), logs)
	return fields[0]
}
