package config_test

import (
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/michaelw/ext-authz-token-exchange/internal/config"
)

func TestConfig(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Config Suite")
}

var _ = Describe("RuntimeConfig", func() {
	It("validates required secrets and defaults", func() {
		cfg := config.RuntimeConfig{
			ClientID:                           "client",
			ClientSecret:                       "secret",
			TokenEndpointAuthMethod:            config.AuthMethodClientSecretBasic,
			GrantType:                          config.DefaultGrantType,
			SubjectTokenType:                   config.DefaultSubjectTokenType,
			LabelSelector:                      config.DefaultConfigMapLabelSelector,
			RequireIssuedTokenType:             true,
			ExpectedIssuedTokenType:            config.DefaultIssuedTokenType,
			TokenEndpointRequestTimeout:        time.Second,
			TokenEndpointDialTimeout:           time.Second,
			TokenEndpointTLSHandshakeTimeout:   time.Second,
			TokenEndpointResponseHeaderTimeout: time.Second,
			TokenEndpointIdleConnTimeout:       time.Second,
		}

		Expect(cfg.Validate()).To(Succeed())
	})

	It("rejects HTTP token endpoints unless explicitly enabled", func() {
		cfg := config.RuntimeConfig{
			ClientID:                           "client",
			ClientSecret:                       "secret",
			TokenEndpointAuthMethod:            config.AuthMethodClientSecretBasic,
			GrantType:                          config.DefaultGrantType,
			SubjectTokenType:                   config.DefaultSubjectTokenType,
			LabelSelector:                      config.DefaultConfigMapLabelSelector,
			DefaultTokenEndpoint:               "http://issuer.example/token",
			RequireIssuedTokenType:             true,
			ExpectedIssuedTokenType:            config.DefaultIssuedTokenType,
			TokenEndpointRequestTimeout:        time.Second,
			TokenEndpointDialTimeout:           time.Second,
			TokenEndpointTLSHandshakeTimeout:   time.Second,
			TokenEndpointResponseHeaderTimeout: time.Second,
			TokenEndpointIdleConnTimeout:       time.Second,
		}

		Expect(cfg.Validate()).To(MatchError(ContainSubstring("must use https")))
		cfg.AllowHTTPTokenEndpoint = true
		Expect(cfg.Validate()).To(Succeed())
	})

	It("enforces token endpoint allowlists", func() {
		cfg := config.RuntimeConfig{
			AllowHTTPTokenEndpoint: true,
			TokenEndpointAllowlist: []string{"issuer.example"},
		}

		Expect(cfg.ValidateTokenEndpoint("http://issuer.example/token")).To(Succeed())
		Expect(cfg.ValidateTokenEndpoint("http://other.example/token")).To(MatchError(ContainSubstring("not in TOKEN_ENDPOINT_ALLOWLIST")))
	})
})
