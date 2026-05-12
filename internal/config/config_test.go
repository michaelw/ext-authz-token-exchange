package config_test

import (
	"context"
	"os"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/michaelw/ext-authz-token-exchange/internal/config"
)

func TestConfig(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Config Suite")
}

var _ = Describe("RuntimeConfig", func() {
	It("validates issuer profiles and defaults", func() {
		cfg := config.RuntimeConfig{
			TokenEndpointAuthMethod:            config.AuthMethodClientSecretBasic,
			GrantType:                          config.DefaultGrantType,
			SubjectTokenType:                   config.DefaultSubjectTokenType,
			LabelSelector:                      config.DefaultConfigMapLabelSelector,
			NamespaceSelector:                  config.DefaultConfigMapNamespaceSelector,
			RequireIssuedTokenType:             true,
			ExpectedIssuedTokenType:            config.DefaultIssuedTokenType,
			MetricsEnabled:                     true,
			MetricsPort:                        "3002",
			MetricsPath:                        "/metrics",
			TokenEndpointRequestTimeout:        time.Second,
			TokenEndpointDialTimeout:           time.Second,
			TokenEndpointTLSHandshakeTimeout:   time.Second,
			TokenEndpointResponseHeaderTimeout: time.Second,
			TokenEndpointIdleConnTimeout:       time.Second,
			AllowHTTPTokenEndpoint:             true,
			IssuerProfiles: map[string]config.IssuerProfile{
				"primary": {
					Name:          "primary",
					TokenEndpoint: "http://issuer.example/token",
					ClientID:      "client",
					ClientSecret:  "secret",
				},
			},
		}

		Expect(cfg.Validate()).To(Succeed())
	})

	It("rejects HTTP token endpoints unless explicitly enabled", func() {
		cfg := config.RuntimeConfig{
			TokenEndpointAuthMethod:            config.AuthMethodClientSecretBasic,
			GrantType:                          config.DefaultGrantType,
			SubjectTokenType:                   config.DefaultSubjectTokenType,
			LabelSelector:                      config.DefaultConfigMapLabelSelector,
			NamespaceSelector:                  config.DefaultConfigMapNamespaceSelector,
			RequireIssuedTokenType:             true,
			ExpectedIssuedTokenType:            config.DefaultIssuedTokenType,
			TokenEndpointRequestTimeout:        time.Second,
			TokenEndpointDialTimeout:           time.Second,
			TokenEndpointTLSHandshakeTimeout:   time.Second,
			TokenEndpointResponseHeaderTimeout: time.Second,
			TokenEndpointIdleConnTimeout:       time.Second,
			IssuerProfiles: map[string]config.IssuerProfile{
				"primary": {
					Name:          "primary",
					TokenEndpoint: "http://issuer.example/token",
					ClientID:      "client",
					ClientSecret:  "secret",
				},
			},
		}

		Expect(cfg.Validate()).To(MatchError(ContainSubstring("must use https")))
		cfg.AllowHTTPTokenEndpoint = true
		Expect(cfg.Validate()).To(Succeed())
	})

	It("loads issuer profiles from the configured file", func() {
		file, err := os.CreateTemp("", "issuer-profiles-*.yaml")
		Expect(err).NotTo(HaveOccurred())
		defer os.Remove(file.Name())
		_, err = file.WriteString(`
issuers:
  - name: primary
    tokenEndpoint: http://issuer.example/token
    bearerRealm: issuer
    tokenEndpointAuthMethod: client_secret_post
    clientID: client
    clientSecret: secret
`)
		Expect(err).NotTo(HaveOccurred())
		Expect(file.Close()).To(Succeed())

		setenv("TOKEN_EXCHANGE_ISSUER_PROFILES_FILE", file.Name())
		setenv("TOKEN_EXCHANGE_ALLOW_HTTP_TOKEN_ENDPOINT", "true")

		cfg, err := config.LoadFromEnv()

		Expect(err).NotTo(HaveOccurred())
		profile, ok := cfg.IssuerProfile("primary")
		Expect(ok).To(BeTrue())
		Expect(profile.TokenEndpoint).To(Equal("http://issuer.example/token"))
		Expect(profile.BearerRealm).To(Equal("issuer"))
		Expect(profile.TokenEndpointAuthMethod).To(Equal(config.AuthMethodClientSecretPost))
	})

	It("resolves issuer profile credential Secret refs", func() {
		cfg := config.RuntimeConfig{
			TokenEndpointAuthMethod:            config.AuthMethodClientSecretBasic,
			GrantType:                          config.DefaultGrantType,
			SubjectTokenType:                   config.DefaultSubjectTokenType,
			LabelSelector:                      config.DefaultConfigMapLabelSelector,
			NamespaceSelector:                  config.DefaultConfigMapNamespaceSelector,
			AllowHTTPTokenEndpoint:             true,
			RequireIssuedTokenType:             true,
			ExpectedIssuedTokenType:            config.DefaultIssuedTokenType,
			TokenEndpointRequestTimeout:        time.Second,
			TokenEndpointDialTimeout:           time.Second,
			TokenEndpointTLSHandshakeTimeout:   time.Second,
			TokenEndpointResponseHeaderTimeout: time.Second,
			TokenEndpointIdleConnTimeout:       time.Second,
			IssuerProfiles: map[string]config.IssuerProfile{
				"fake-issuer": {
					Name:                  "fake-issuer",
					TokenEndpoint:         "http://issuer.example/token",
					ClientIDSecretRef:     &config.SecretKeyRef{Name: "issuer-oauth", Key: "client_id"},
					ClientSecretSecretRef: &config.SecretKeyRef{Name: "issuer-oauth", Key: "client_secret"},
				},
			},
		}
		client := fake.NewSimpleClientset(&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "issuer-oauth", Namespace: "ext-authz-token-exchange"},
			Data: map[string][]byte{
				"client_id":     []byte("client"),
				"client_secret": []byte("secret"),
			},
		})

		resolved, err := config.ResolveIssuerProfileSecrets(context.Background(), client, "ext-authz-token-exchange", cfg)

		Expect(err).NotTo(HaveOccurred())
		Expect(resolved.NeedsIssuerSecretResolution()).To(BeTrue())
		profile, ok := resolved.IssuerProfile("fake-issuer")
		Expect(ok).To(BeTrue())
		Expect(profile.ClientID).To(Equal("client"))
		Expect(profile.ClientSecret).To(Equal("secret"))
	})

	It("fails issuer profile Secret resolution when a referenced key is missing", func() {
		cfg := config.RuntimeConfig{
			TokenEndpointAuthMethod:            config.AuthMethodClientSecretBasic,
			GrantType:                          config.DefaultGrantType,
			SubjectTokenType:                   config.DefaultSubjectTokenType,
			LabelSelector:                      config.DefaultConfigMapLabelSelector,
			NamespaceSelector:                  config.DefaultConfigMapNamespaceSelector,
			AllowHTTPTokenEndpoint:             true,
			RequireIssuedTokenType:             true,
			ExpectedIssuedTokenType:            config.DefaultIssuedTokenType,
			TokenEndpointRequestTimeout:        time.Second,
			TokenEndpointDialTimeout:           time.Second,
			TokenEndpointTLSHandshakeTimeout:   time.Second,
			TokenEndpointResponseHeaderTimeout: time.Second,
			TokenEndpointIdleConnTimeout:       time.Second,
			IssuerProfiles: map[string]config.IssuerProfile{
				"fake-issuer": {
					Name:                  "fake-issuer",
					TokenEndpoint:         "http://issuer.example/token",
					ClientIDSecretRef:     &config.SecretKeyRef{Name: "issuer-oauth", Key: "client_id"},
					ClientSecretSecretRef: &config.SecretKeyRef{Name: "issuer-oauth", Key: "client_secret"},
				},
			},
		}
		client := fake.NewSimpleClientset(&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "issuer-oauth", Namespace: "ext-authz-token-exchange"},
			Data:       map[string][]byte{"client_id": []byte("client")},
		})

		_, err := config.ResolveIssuerProfileSecrets(context.Background(), client, "ext-authz-token-exchange", cfg)

		Expect(err).To(MatchError(ContainSubstring(`missing key "client_secret"`)))
	})

	It("loads the default namespace selector from the environment", func() {
		setenv("OAUTH_CLIENT_ID", "client")
		setenv("OAUTH_CLIENT_SECRET", "secret")
		unsetenv("GRPC_LOG_HEALTH_CHECKS")
		unsetenv("TOKEN_EXCHANGE_INSECURE_LOG_TOKENS")
		unsetenv("TOKEN_EXCHANGE_DEFAULT_DENY_UNMATCHED")

		cfg, err := config.LoadFromEnv()

		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.NamespaceSelector).To(Equal(config.DefaultConfigMapNamespaceSelector))
		Expect(cfg.LogHealthChecks).To(BeTrue())
		Expect(cfg.InsecureLogTokens).To(BeFalse())
		Expect(cfg.DefaultDenyUnmatched).To(BeFalse())
		Expect(cfg.MetricsEnabled).To(BeFalse())
		Expect(cfg.MetricsPort).To(Equal("3002"))
		Expect(cfg.MetricsPath).To(Equal("/metrics"))
		Expect(cfg.TokenEndpointRequestTimeout).To(Equal(750 * time.Millisecond))
		Expect(cfg.TokenEndpointResponseHeaderTimeout).To(Equal(500 * time.Millisecond))
	})

	It("loads default deny for unmatched requests only when explicitly enabled", func() {
		setenv("OAUTH_CLIENT_ID", "client")
		setenv("OAUTH_CLIENT_SECRET", "secret")
		setenv("TOKEN_EXCHANGE_DEFAULT_DENY_UNMATCHED", "true")

		cfg, err := config.LoadFromEnv()

		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.DefaultDenyUnmatched).To(BeTrue())
	})

	It("loads insecure token logging only when explicitly enabled", func() {
		setenv("OAUTH_CLIENT_ID", "client")
		setenv("OAUTH_CLIENT_SECRET", "secret")
		setenv("TOKEN_EXCHANGE_INSECURE_LOG_TOKENS", "true")

		cfg, err := config.LoadFromEnv()

		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.InsecureLogTokens).To(BeTrue())
	})

	It("loads health check logging as default-on unless explicitly disabled", func() {
		setenv("OAUTH_CLIENT_ID", "client")
		setenv("OAUTH_CLIENT_SECRET", "secret")
		setenv("GRPC_LOG_HEALTH_CHECKS", "false")

		cfg, err := config.LoadFromEnv()

		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.LogHealthChecks).To(BeFalse())
	})

	It("allows overriding the namespace selector", func() {
		setenv("OAUTH_CLIENT_ID", "client")
		setenv("OAUTH_CLIENT_SECRET", "secret")
		setenv("CONFIGMAP_NAMESPACE_SELECTOR", "platform.example.com/token-exchange=true")

		cfg, err := config.LoadFromEnv()

		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.NamespaceSelector).To(Equal("platform.example.com/token-exchange=true"))
	})

	It("rejects invalid namespace selectors", func() {
		cfg := config.RuntimeConfig{
			ClientID:                           "client",
			ClientSecret:                       "secret",
			TokenEndpointAuthMethod:            config.AuthMethodClientSecretBasic,
			GrantType:                          config.DefaultGrantType,
			SubjectTokenType:                   config.DefaultSubjectTokenType,
			LabelSelector:                      config.DefaultConfigMapLabelSelector,
			NamespaceSelector:                  "not in valid selector form",
			RequireIssuedTokenType:             true,
			ExpectedIssuedTokenType:            config.DefaultIssuedTokenType,
			TokenEndpointRequestTimeout:        time.Second,
			TokenEndpointDialTimeout:           time.Second,
			TokenEndpointTLSHandshakeTimeout:   time.Second,
			TokenEndpointResponseHeaderTimeout: time.Second,
			TokenEndpointIdleConnTimeout:       time.Second,
		}

		Expect(cfg.Validate()).To(MatchError(ContainSubstring("CONFIGMAP_NAMESPACE_SELECTOR is invalid")))
	})

	It("validates metrics listener settings when metrics are enabled", func() {
		cfg := config.RuntimeConfig{
			ClientID:                           "client",
			ClientSecret:                       "secret",
			TokenEndpointAuthMethod:            config.AuthMethodClientSecretBasic,
			GrantType:                          config.DefaultGrantType,
			SubjectTokenType:                   config.DefaultSubjectTokenType,
			LabelSelector:                      config.DefaultConfigMapLabelSelector,
			NamespaceSelector:                  config.DefaultConfigMapNamespaceSelector,
			RequireIssuedTokenType:             true,
			ExpectedIssuedTokenType:            config.DefaultIssuedTokenType,
			MetricsEnabled:                     true,
			MetricsPort:                        "3002",
			MetricsPath:                        "metrics",
			TokenEndpointRequestTimeout:        time.Second,
			TokenEndpointDialTimeout:           time.Second,
			TokenEndpointTLSHandshakeTimeout:   time.Second,
			TokenEndpointResponseHeaderTimeout: time.Second,
			TokenEndpointIdleConnTimeout:       time.Second,
		}

		Expect(cfg.Validate()).To(MatchError(ContainSubstring("METRICS_PATH must start with /")))
		cfg.MetricsPath = "/metrics"
		Expect(cfg.Validate()).To(Succeed())
		cfg.MetricsEnabled = false
		cfg.MetricsPath = ""
		cfg.MetricsPort = ""
		Expect(cfg.Validate()).To(Succeed())
	})
})

func setenv(name, value string) {
	original, hadOriginal := os.LookupEnv(name)
	Expect(os.Setenv(name, value)).To(Succeed())
	DeferCleanup(func() {
		if hadOriginal {
			Expect(os.Setenv(name, original)).To(Succeed())
			return
		}
		Expect(os.Unsetenv(name)).To(Succeed())
	})
}

func unsetenv(name string) {
	original, hadOriginal := os.LookupEnv(name)
	Expect(os.Unsetenv(name)).To(Succeed())
	DeferCleanup(func() {
		if hadOriginal {
			Expect(os.Setenv(name, original)).To(Succeed())
		}
	})
}
