package exchange_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

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

		result, oauthErr := exchange.NewClient(cfg, tokenEndpoint.Client()).Exchange(context.Background(), policy.Entry{
			TokenEndpoint: tokenEndpoint.URL,
			Scope:         "read write",
			Resources:     []string{"https://orders.example.com/api/"},
			Audiences:     []string{"orders-api", "orders-backend"},
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

		_, oauthErr := exchange.NewClient(cfg, tokenEndpoint.Client()).Exchange(context.Background(), policy.Entry{
			TokenEndpoint: tokenEndpoint.URL,
			Scope:         "read",
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

		_, oauthErr := exchange.NewClient(cfg, tokenEndpoint.Client()).Exchange(context.Background(), policy.Entry{
			TokenEndpoint: tokenEndpoint.URL,
			Scope:         "read",
		}, "subject")

		Expect(oauthErr).NotTo(BeNil())
		Expect(oauthErr.StatusCode).To(Equal(http.StatusInternalServerError))
		Expect(oauthErr.ErrorDescription).To(Equal("internal server error"))
	})

	It("preserves recognized OAuth error codes while sanitizing bodies by default", func() {
		tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="issuer"`)
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_target","error_description":"too much detail"}`))
		}))
		defer tokenEndpoint.Close()

		_, oauthErr := exchange.NewClient(cfg, tokenEndpoint.Client()).Exchange(context.Background(), policy.Entry{
			TokenEndpoint: tokenEndpoint.URL,
			Scope:         "read",
		}, "subject")

		Expect(oauthErr).NotTo(BeNil())
		Expect(oauthErr.StatusCode).To(Equal(http.StatusBadRequest))
		Expect(oauthErr.Error).To(Equal("invalid_target"))
		Expect(oauthErr.Body).To(BeEmpty())
		Expect(oauthErr.ErrorDescription).To(HavePrefix("request failed ("))
		Expect(oauthErr.WWWAuthenticate).To(Equal([]string{`Bearer realm="issuer"`}))
	})

	It("passes through OAuth error bodies only when enabled", func() {
		cfg.ErrorPassthrough = true
		tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_request"}`))
		}))
		defer tokenEndpoint.Close()

		_, oauthErr := exchange.NewClient(cfg, tokenEndpoint.Client()).Exchange(context.Background(), policy.Entry{
			TokenEndpoint: tokenEndpoint.URL,
			Scope:         "read",
		}, "subject")

		Expect(oauthErr).NotTo(BeNil())
		Expect(strings.TrimSpace(oauthErr.Body)).To(Equal(`{"error":"invalid_request"}`))
	})

	It("builds an HTTP client with configured bounded timeouts", func() {
		cfg.TokenEndpointRequestTimeout = 7 * time.Second
		cfg.TokenEndpointDialTimeout = 2 * time.Second
		cfg.TokenEndpointTLSHandshakeTimeout = 3 * time.Second
		cfg.TokenEndpointResponseHeaderTimeout = 4 * time.Second
		cfg.TokenEndpointIdleConnTimeout = 5 * time.Second
		cfg.TokenEndpointMaxIdleConns = 11
		cfg.TokenEndpointMaxIdleConnsPerHost = 6

		client := exchange.NewHTTPClient(cfg)

		Expect(client.Timeout).To(Equal(7 * time.Second))
		transport, ok := client.Transport.(*http.Transport)
		Expect(ok).To(BeTrue())
		Expect(transport.TLSHandshakeTimeout).To(Equal(3 * time.Second))
		Expect(transport.ResponseHeaderTimeout).To(Equal(4 * time.Second))
		Expect(transport.IdleConnTimeout).To(Equal(5 * time.Second))
		Expect(transport.MaxIdleConns).To(Equal(11))
		Expect(transport.MaxIdleConnsPerHost).To(Equal(6))
		Expect(transport.TLSClientConfig.MinVersion).NotTo(BeZero())
	})
})
