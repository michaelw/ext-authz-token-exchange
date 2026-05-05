package e2e_test

import (
	"context"
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
				g.Expect(headerFromHTTPBin(body, "Authorization")).To(Equal("Bearer exchanged-" + color + "-incoming-" + color))
			}, 45*time.Second, time.Second).Should(Succeed())
		}
	})

	It("adds and deletes one team policy without disabling unrelated teams", func(ctx SpecContext) {
		policy := createEphemeralPolicy(ctx, env.teamNamespace("red"), "red-v2", "red-v2", "/token/red")

		Eventually(func(g Gomega) {
			resp, body := request(ctx, http.MethodGet, policy.Path, "incoming-red", nil)
			g.Expect(resp.StatusCode).To(Equal(http.StatusOK), string(body))
			g.Expect(headerFromHTTPBin(body, "Authorization")).To(Equal("Bearer exchanged-red-incoming-red"))
		}, 45*time.Second, time.Second).Should(Succeed())

		deleteConfigMapIgnoreNotFound(ctx, env.teamNamespace("red"), policy.Name)

		Eventually(func(g Gomega) {
			resp, body := request(ctx, http.MethodGet, policy.Path, "original-red", nil)
			g.Expect(resp.StatusCode).To(Equal(http.StatusOK), string(body))
			g.Expect(headerFromHTTPBin(body, "Authorization")).To(Equal("Bearer original-red"))
		}, 45*time.Second, time.Second).Should(Succeed())

		resp, body := request(ctx, http.MethodGet, "/anything/yellow", "incoming-yellow", nil)
		Expect(resp.StatusCode).To(Equal(http.StatusOK), string(body))
		Expect(headerFromHTTPBin(body, "Authorization")).To(Equal("Bearer exchanged-yellow-incoming-yellow"))
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
		resp, body := request(ctx, http.MethodOptions, "/anything/yellow", "options-token", nil)
		Expect(resp.StatusCode).To(Equal(http.StatusOK), string(body))

		Eventually(func(g Gomega) {
			after := strings.TrimPrefix(tokenEndpointLogs(ctx), before)
			g.Expect(after).To(ContainSubstring(`scenario=yellow`))
			g.Expect(after).To(ContainSubstring(`subject_token="options-token"`))
		}, 30*time.Second, time.Second).Should(Succeed())
	})

	It("allows unmatched requests through unchanged", func(ctx SpecContext) {
		resp, body := request(ctx, http.MethodGet, "/anything/no-policy-match", "original-token", nil)
		Expect(resp.StatusCode).To(Equal(http.StatusOK), string(body))
		Expect(headerFromHTTPBin(body, "Authorization")).To(Equal("Bearer original-token"))
	})

	It("ignores policies from namespaces that do not match the namespace selector", func(ctx SpecContext) {
		namespace := createUnlabeledTeamNamespace(ctx, "black")
		policy := createEphemeralPolicy(ctx, namespace, "black-unselected", "black", "/token/black")

		Consistently(func(g Gomega) {
			resp, body := request(ctx, http.MethodGet, policy.Path, "original-black", nil)
			g.Expect(resp.StatusCode).To(Equal(http.StatusOK), string(body))
			g.Expect(headerFromHTTPBin(body, "Authorization")).To(Equal("Bearer original-black"))
		}, 5*time.Second, time.Second).Should(Succeed())
	})

	It("fails closed for cross-namespace ties", func(ctx SpecContext) {
		policy := newEphemeralPolicy("yellow-conflict")
		createPolicy(ctx, env.teamNamespace("yellow"), policy.Name, "yellow-conflict", policy.Path, "/token/yellow")
		createPolicy(ctx, env.teamNamespace("blue"), policy.Name, "yellow-conflict", policy.Path, "/token/blue")
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
  - host: %s
    pathPrefix: %s
    methods: ["GET"]
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
		Expect(headerFromHTTPBin(body, "Authorization")).To(Equal("Bearer exchanged-blue-incoming-blue"))
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
