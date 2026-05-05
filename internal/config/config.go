// Package config loads and validates runtime settings for the token exchange
// authorization service.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/labels"
)

const (
	// DefaultConfigMapLabelSelector selects app-owned policy ConfigMaps.
	DefaultConfigMapLabelSelector = "ext-authz-token-exchange.magneticflux.net/enabled=true"
	// DefaultConfigMapNamespaceSelector selects namespaces that may own policy ConfigMaps.
	DefaultConfigMapNamespaceSelector = "ext-authz-token-exchange.magneticflux.net/policy=enabled"
	// DefaultGrantType is the RFC8693 token exchange grant type.
	DefaultGrantType = "urn:ietf:params:oauth:grant-type:token-exchange"
	// DefaultSubjectTokenType is the RFC8693 OAuth access-token token type.
	DefaultSubjectTokenType = "urn:ietf:params:oauth:token-type:access_token"
	// DefaultIssuedTokenType is the RFC8693 OAuth access-token issued token type.
	DefaultIssuedTokenType = "urn:ietf:params:oauth:token-type:access_token"

	// AuthMethodClientSecretBasic authenticates with HTTP Basic.
	AuthMethodClientSecretBasic = "client_secret_basic"
	// AuthMethodClientSecretPost authenticates with body parameters.
	AuthMethodClientSecretPost = "client_secret_post"
)

// RuntimeConfig contains process-wide token exchange settings.
type RuntimeConfig struct {
	ClientID                           string
	ClientSecret                       string
	TokenEndpointAuthMethod            string
	DefaultTokenEndpoint               string
	GrantType                          string
	SubjectTokenType                   string
	LabelSelector                      string
	NamespaceSelector                  string
	TokenEndpointAllowlist             []string
	AllowHTTPTokenEndpoint             bool
	ErrorPassthrough                   bool
	RequireIssuedTokenType             bool
	ExpectedIssuedTokenType            string
	BearerRealm                        string
	AllowUnauthenticatedOptions        bool
	TokenEndpointRequestTimeout        time.Duration
	TokenEndpointDialTimeout           time.Duration
	TokenEndpointTLSHandshakeTimeout   time.Duration
	TokenEndpointResponseHeaderTimeout time.Duration
	TokenEndpointIdleConnTimeout       time.Duration
	TokenEndpointMaxIdleConns          int
	TokenEndpointMaxIdleConnsPerHost   int
}

// LoadFromEnv loads RuntimeConfig from environment variables and validates
// deployment-critical values.
func LoadFromEnv() (RuntimeConfig, error) {
	cfg := RuntimeConfig{
		ClientID:                           strings.TrimSpace(os.Getenv("OAUTH_CLIENT_ID")),
		ClientSecret:                       os.Getenv("OAUTH_CLIENT_SECRET"),
		TokenEndpointAuthMethod:            envDefault("TOKEN_ENDPOINT_AUTH_METHOD", AuthMethodClientSecretBasic),
		DefaultTokenEndpoint:               strings.TrimSpace(os.Getenv("TOKEN_EXCHANGE_DEFAULT_TOKEN_ENDPOINT")),
		GrantType:                          envDefault("TOKEN_EXCHANGE_GRANT_TYPE", DefaultGrantType),
		SubjectTokenType:                   envDefault("TOKEN_EXCHANGE_SUBJECT_TOKEN_TYPE", DefaultSubjectTokenType),
		LabelSelector:                      envDefault("CONFIGMAP_LABEL_SELECTOR", DefaultConfigMapLabelSelector),
		NamespaceSelector:                  envDefault("CONFIGMAP_NAMESPACE_SELECTOR", DefaultConfigMapNamespaceSelector),
		TokenEndpointAllowlist:             splitCSV(os.Getenv("TOKEN_ENDPOINT_ALLOWLIST")),
		AllowHTTPTokenEndpoint:             envBool("TOKEN_EXCHANGE_ALLOW_HTTP_TOKEN_ENDPOINT", false),
		ErrorPassthrough:                   envBool("TOKEN_EXCHANGE_ERROR_PASSTHROUGH", false),
		RequireIssuedTokenType:             envBool("TOKEN_EXCHANGE_REQUIRE_ISSUED_TOKEN_TYPE", true),
		ExpectedIssuedTokenType:            envDefault("TOKEN_EXCHANGE_EXPECTED_ISSUED_TOKEN_TYPE", DefaultIssuedTokenType),
		BearerRealm:                        envDefault("TOKEN_EXCHANGE_BEARER_REALM", "ext-authz-token-exchange"),
		AllowUnauthenticatedOptions:        envBool("TOKEN_EXCHANGE_ALLOW_UNAUTHENTICATED_OPTIONS", false),
		TokenEndpointRequestTimeout:        envDuration("TOKEN_ENDPOINT_REQUEST_TIMEOUT", 5*time.Second),
		TokenEndpointDialTimeout:           envDuration("TOKEN_ENDPOINT_DIAL_TIMEOUT", 3*time.Second),
		TokenEndpointTLSHandshakeTimeout:   envDuration("TOKEN_ENDPOINT_TLS_HANDSHAKE_TIMEOUT", 3*time.Second),
		TokenEndpointResponseHeaderTimeout: envDuration("TOKEN_ENDPOINT_RESPONSE_HEADER_TIMEOUT", 5*time.Second),
		TokenEndpointIdleConnTimeout:       envDuration("TOKEN_ENDPOINT_IDLE_CONN_TIMEOUT", 90*time.Second),
		TokenEndpointMaxIdleConns:          envInt("TOKEN_ENDPOINT_MAX_IDLE_CONNS", 100),
		TokenEndpointMaxIdleConnsPerHost:   envInt("TOKEN_ENDPOINT_MAX_IDLE_CONNS_PER_HOST", 10),
	}
	return cfg, cfg.Validate()
}

// Validate checks for missing secrets and unsupported protocol options.
func (c RuntimeConfig) Validate() error {
	var problems []string
	if c.ClientID == "" {
		problems = append(problems, "OAUTH_CLIENT_ID is required")
	}
	if c.ClientSecret == "" {
		problems = append(problems, "OAUTH_CLIENT_SECRET is required")
	}
	switch c.TokenEndpointAuthMethod {
	case AuthMethodClientSecretBasic, AuthMethodClientSecretPost:
	default:
		problems = append(problems, fmt.Sprintf("TOKEN_ENDPOINT_AUTH_METHOD must be %q or %q", AuthMethodClientSecretBasic, AuthMethodClientSecretPost))
	}
	if c.LabelSelector == "" {
		problems = append(problems, "CONFIGMAP_LABEL_SELECTOR is required")
	}
	if c.NamespaceSelector == "" {
		problems = append(problems, "CONFIGMAP_NAMESPACE_SELECTOR is required")
	} else if _, err := labels.Parse(c.NamespaceSelector); err != nil {
		problems = append(problems, fmt.Sprintf("CONFIGMAP_NAMESPACE_SELECTOR is invalid: %v", err))
	}
	if c.DefaultTokenEndpoint != "" {
		if err := c.ValidateTokenEndpoint(c.DefaultTokenEndpoint); err != nil {
			problems = append(problems, fmt.Sprintf("TOKEN_EXCHANGE_DEFAULT_TOKEN_ENDPOINT: %v", err))
		}
	}
	if c.GrantType == "" {
		problems = append(problems, "TOKEN_EXCHANGE_GRANT_TYPE is required")
	}
	if c.SubjectTokenType == "" {
		problems = append(problems, "TOKEN_EXCHANGE_SUBJECT_TOKEN_TYPE is required")
	}
	if c.RequireIssuedTokenType && c.ExpectedIssuedTokenType == "" {
		problems = append(problems, "TOKEN_EXCHANGE_EXPECTED_ISSUED_TOKEN_TYPE is required when issued token type validation is enabled")
	}
	if c.TokenEndpointRequestTimeout <= 0 {
		problems = append(problems, "TOKEN_ENDPOINT_REQUEST_TIMEOUT must be positive")
	}
	if c.TokenEndpointDialTimeout <= 0 {
		problems = append(problems, "TOKEN_ENDPOINT_DIAL_TIMEOUT must be positive")
	}
	if c.TokenEndpointTLSHandshakeTimeout <= 0 {
		problems = append(problems, "TOKEN_ENDPOINT_TLS_HANDSHAKE_TIMEOUT must be positive")
	}
	if c.TokenEndpointResponseHeaderTimeout <= 0 {
		problems = append(problems, "TOKEN_ENDPOINT_RESPONSE_HEADER_TIMEOUT must be positive")
	}
	if c.TokenEndpointIdleConnTimeout <= 0 {
		problems = append(problems, "TOKEN_ENDPOINT_IDLE_CONN_TIMEOUT must be positive")
	}
	if c.TokenEndpointMaxIdleConns < 0 {
		problems = append(problems, "TOKEN_ENDPOINT_MAX_IDLE_CONNS must not be negative")
	}
	if c.TokenEndpointMaxIdleConnsPerHost < 0 {
		problems = append(problems, "TOKEN_ENDPOINT_MAX_IDLE_CONNS_PER_HOST must not be negative")
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

// ValidateTokenEndpoint validates endpoint syntax and deployment guardrails.
func (c RuntimeConfig) ValidateTokenEndpoint(endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil {
		return err
	}
	if u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("must be an absolute URL")
	}
	if u.Scheme != "https" && !(c.AllowHTTPTokenEndpoint && u.Scheme == "http") {
		return fmt.Errorf("must use https")
	}
	if len(c.TokenEndpointAllowlist) > 0 && !hostAllowed(u.Hostname(), c.TokenEndpointAllowlist) {
		return fmt.Errorf("host %q is not in TOKEN_ENDPOINT_ALLOWLIST", u.Hostname())
	}
	return nil
}

func envDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func envBool(name string, fallback bool) bool {
	value := strings.TrimSpace(strings.ToLower(os.Getenv(name)))
	if value == "" {
		return fallback
	}
	return value == "1" || value == "true" || value == "yes" || value == "on"
}

func envDuration(name string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0
	}
	return parsed
}

func envInt(name string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return -1
	}
	return parsed
}

func splitCSV(value string) []string {
	var out []string
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

func hostAllowed(host string, allowlist []string) bool {
	for _, allowed := range allowlist {
		if strings.EqualFold(host, allowed) {
			return true
		}
		if strings.HasPrefix(allowed, ".") && strings.HasSuffix(host, allowed) {
			return true
		}
	}
	return false
}
