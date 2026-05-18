// Package config loads and validates runtime settings for the token exchange
// authorization service.
package config

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
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
	GrantType                          string
	SubjectTokenType                   string
	LabelSelector                      string
	NamespaceSelector                  string
	AllowHTTPTokenEndpoint             bool
	ErrorPassthrough                   bool
	InsecureLogTokens                  bool
	LogHealthChecks                    bool
	RequireIssuedTokenType             bool
	ExpectedIssuedTokenType            string
	BearerRealm                        string
	AllowUnauthenticatedOptions        bool
	DefaultDenyUnmatched               bool
	MetricsEnabled                     bool
	MetricsPort                        string
	MetricsPath                        string
	TokenEndpointRequestTimeout        time.Duration
	TokenEndpointDialTimeout           time.Duration
	TokenEndpointTLSHandshakeTimeout   time.Duration
	TokenEndpointResponseHeaderTimeout time.Duration
	TokenEndpointIdleConnTimeout       time.Duration
	TokenEndpointMaxIdleConns          int
	TokenEndpointMaxIdleConnsPerHost   int
	IssuerProfiles                     map[string]IssuerProfile
}

// IssuerProfile contains operator-owned token endpoint settings selected by policy.
type IssuerProfile struct {
	Name                    string        `yaml:"name" json:"name"`
	TokenEndpoint           string        `yaml:"tokenEndpoint" json:"tokenEndpoint"`
	BearerRealm             string        `yaml:"bearerRealm" json:"bearerRealm"`
	TokenEndpointAuthMethod string        `yaml:"tokenEndpointAuthMethod" json:"tokenEndpointAuthMethod"`
	ClientID                string        `yaml:"clientID" json:"clientID"`
	ClientSecret            string        `yaml:"clientSecret" json:"clientSecret"`
	ClientIDSecretRef       *SecretKeyRef `yaml:"clientIDSecretRef" json:"clientIDSecretRef,omitempty"`
	ClientSecretSecretRef   *SecretKeyRef `yaml:"clientSecretSecretRef" json:"clientSecretSecretRef,omitempty"`
}

// SecretKeyRef identifies a Kubernetes Secret key containing issuer credentials.
type SecretKeyRef struct {
	Name      string `yaml:"name" json:"name"`
	Namespace string `yaml:"namespace,omitempty" json:"namespace,omitempty"`
	Key       string `yaml:"key" json:"key"`
}

// LoadFromEnv loads RuntimeConfig from environment variables and validates
// deployment-critical values.
func LoadFromEnv() (RuntimeConfig, error) {
	cfg := RuntimeConfig{
		ClientID:                           strings.TrimSpace(os.Getenv("OAUTH_CLIENT_ID")),
		ClientSecret:                       os.Getenv("OAUTH_CLIENT_SECRET"),
		TokenEndpointAuthMethod:            envDefault("TOKEN_ENDPOINT_AUTH_METHOD", AuthMethodClientSecretBasic),
		GrantType:                          envDefault("TOKEN_EXCHANGE_GRANT_TYPE", DefaultGrantType),
		SubjectTokenType:                   envDefault("TOKEN_EXCHANGE_SUBJECT_TOKEN_TYPE", DefaultSubjectTokenType),
		LabelSelector:                      envDefault("CONFIGMAP_LABEL_SELECTOR", DefaultConfigMapLabelSelector),
		NamespaceSelector:                  envDefault("CONFIGMAP_NAMESPACE_SELECTOR", DefaultConfigMapNamespaceSelector),
		AllowHTTPTokenEndpoint:             envBool("TOKEN_EXCHANGE_ALLOW_HTTP_TOKEN_ENDPOINT", false),
		ErrorPassthrough:                   envBool("TOKEN_EXCHANGE_ERROR_PASSTHROUGH", false),
		InsecureLogTokens:                  envBool("TOKEN_EXCHANGE_INSECURE_LOG_TOKENS", false),
		LogHealthChecks:                    envBool("GRPC_LOG_HEALTH_CHECKS", true),
		RequireIssuedTokenType:             envBool("TOKEN_EXCHANGE_REQUIRE_ISSUED_TOKEN_TYPE", true),
		ExpectedIssuedTokenType:            envDefault("TOKEN_EXCHANGE_EXPECTED_ISSUED_TOKEN_TYPE", DefaultIssuedTokenType),
		BearerRealm:                        envDefault("TOKEN_EXCHANGE_BEARER_REALM", "ext-authz-token-exchange"),
		AllowUnauthenticatedOptions:        envBool("TOKEN_EXCHANGE_ALLOW_UNAUTHENTICATED_OPTIONS", false),
		DefaultDenyUnmatched:               envBool("TOKEN_EXCHANGE_DEFAULT_DENY_UNMATCHED", false),
		MetricsEnabled:                     envBool("METRICS_ENABLED", false),
		MetricsPort:                        envDefault("METRICS_PORT", "3002"),
		MetricsPath:                        envDefault("METRICS_PATH", "/metrics"),
		TokenEndpointRequestTimeout:        envDuration("TOKEN_ENDPOINT_REQUEST_TIMEOUT", 750*time.Millisecond),
		TokenEndpointDialTimeout:           envDuration("TOKEN_ENDPOINT_DIAL_TIMEOUT", 3*time.Second),
		TokenEndpointTLSHandshakeTimeout:   envDuration("TOKEN_ENDPOINT_TLS_HANDSHAKE_TIMEOUT", 3*time.Second),
		TokenEndpointResponseHeaderTimeout: envDuration("TOKEN_ENDPOINT_RESPONSE_HEADER_TIMEOUT", 500*time.Millisecond),
		TokenEndpointIdleConnTimeout:       envDuration("TOKEN_ENDPOINT_IDLE_CONN_TIMEOUT", 90*time.Second),
		TokenEndpointMaxIdleConns:          envInt("TOKEN_ENDPOINT_MAX_IDLE_CONNS", 100),
		TokenEndpointMaxIdleConnsPerHost:   envInt("TOKEN_ENDPOINT_MAX_IDLE_CONNS_PER_HOST", 10),
	}
	if path := strings.TrimSpace(os.Getenv("TOKEN_EXCHANGE_ISSUER_PROFILES_FILE")); path != "" {
		profiles, err := LoadIssuerProfilesFile(path)
		if err != nil {
			return RuntimeConfig{}, err
		}
		cfg.IssuerProfiles = profiles
	}
	return cfg, cfg.Validate()
}

// Validate checks for missing secrets and unsupported protocol options.
func (c RuntimeConfig) Validate() error {
	var problems []string
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
	for name, profile := range c.IssuerProfiles {
		if err := c.validateIssuerProfile(name, profile); err != nil {
			problems = append(problems, err.Error())
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
	if c.MetricsEnabled {
		if c.MetricsPort == "" {
			problems = append(problems, "METRICS_PORT is required when metrics are enabled")
		}
		if c.MetricsPath == "" || !strings.HasPrefix(c.MetricsPath, "/") {
			problems = append(problems, "METRICS_PATH must start with / when metrics are enabled")
		}
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

// IssuerProfile returns the configured profile referenced by policy.
func (c RuntimeConfig) IssuerProfile(name string) (IssuerProfile, bool) {
	profile, ok := c.IssuerProfiles[strings.TrimSpace(name)]
	return profile, ok
}

// NeedsIssuerSecretResolution reports whether any issuer profile references Kubernetes Secrets.
func (c RuntimeConfig) NeedsIssuerSecretResolution() bool {
	for _, profile := range c.IssuerProfiles {
		if profile.ClientIDSecretRef != nil || profile.ClientSecretSecretRef != nil {
			return true
		}
	}
	return false
}

func (c RuntimeConfig) validateIssuerProfile(mapName string, profile IssuerProfile) error {
	name := strings.TrimSpace(profile.Name)
	if name == "" {
		name = strings.TrimSpace(mapName)
	}
	if name == "" {
		return fmt.Errorf("issuer profile name is required")
	}
	if mapName != "" && name != mapName {
		return fmt.Errorf("issuer profile %q name must match map key %q", name, mapName)
	}
	if strings.TrimSpace(profile.TokenEndpoint) == "" {
		return fmt.Errorf("issuer profile %q tokenEndpoint is required", name)
	}
	if err := c.ValidateTokenEndpoint(profile.TokenEndpoint); err != nil {
		return fmt.Errorf("issuer profile %q tokenEndpoint: %v", name, err)
	}
	authMethod := strings.TrimSpace(profile.TokenEndpointAuthMethod)
	if authMethod == "" {
		authMethod = c.TokenEndpointAuthMethod
	}
	switch authMethod {
	case AuthMethodClientSecretBasic, AuthMethodClientSecretPost:
	default:
		return fmt.Errorf("issuer profile %q tokenEndpointAuthMethod must be %q or %q", name, AuthMethodClientSecretBasic, AuthMethodClientSecretPost)
	}
	if strings.TrimSpace(profile.ClientID) == "" && profile.ClientIDSecretRef == nil {
		return fmt.Errorf("issuer profile %q clientID is required", name)
	}
	if profile.ClientIDSecretRef != nil {
		if err := validateSecretKeyRef(name, "clientIDSecretRef", *profile.ClientIDSecretRef); err != nil {
			return err
		}
	}
	if profile.ClientSecret == "" && profile.ClientSecretSecretRef == nil {
		return fmt.Errorf("issuer profile %q clientSecret is required", name)
	}
	if profile.ClientSecretSecretRef != nil {
		if err := validateSecretKeyRef(name, "clientSecretSecretRef", *profile.ClientSecretSecretRef); err != nil {
			return err
		}
	}
	return nil
}

func validateSecretKeyRef(profileName, field string, ref SecretKeyRef) error {
	if strings.TrimSpace(ref.Name) == "" {
		return fmt.Errorf("issuer profile %q %s.name is required", profileName, field)
	}
	if strings.TrimSpace(ref.Key) == "" {
		return fmt.Errorf("issuer profile %q %s.key is required", profileName, field)
	}
	return nil
}

// ResolveIssuerProfileSecrets resolves any Kubernetes Secret refs in issuer profiles.
func ResolveIssuerProfileSecrets(ctx context.Context, client kubernetes.Interface, defaultNamespace string, cfg RuntimeConfig) (RuntimeConfig, error) {
	if len(cfg.IssuerProfiles) == 0 {
		return cfg, nil
	}
	resolved := make(map[string]IssuerProfile, len(cfg.IssuerProfiles))
	secretCache := map[string]map[string][]byte{}
	for name, profile := range cfg.IssuerProfiles {
		var err error
		if profile.ClientIDSecretRef != nil {
			profile.ClientID, err = resolveSecretValue(ctx, client, defaultNamespace, secretCache, *profile.ClientIDSecretRef)
			if err != nil {
				return RuntimeConfig{}, fmt.Errorf("issuer profile %q clientIDSecretRef: %w", name, err)
			}
		}
		if profile.ClientSecretSecretRef != nil {
			profile.ClientSecret, err = resolveSecretValue(ctx, client, defaultNamespace, secretCache, *profile.ClientSecretSecretRef)
			if err != nil {
				return RuntimeConfig{}, fmt.Errorf("issuer profile %q clientSecretSecretRef: %w", name, err)
			}
		}
		resolved[name] = profile
	}
	cfg.IssuerProfiles = resolved
	if err := cfg.Validate(); err != nil {
		return RuntimeConfig{}, err
	}
	return cfg, nil
}

func resolveSecretValue(ctx context.Context, client kubernetes.Interface, defaultNamespace string, cache map[string]map[string][]byte, ref SecretKeyRef) (string, error) {
	namespace := strings.TrimSpace(ref.Namespace)
	if namespace == "" {
		namespace = strings.TrimSpace(defaultNamespace)
	}
	if namespace == "" {
		return "", fmt.Errorf("namespace is required")
	}
	name := strings.TrimSpace(ref.Name)
	key := strings.TrimSpace(ref.Key)
	cacheKey := namespace + "/" + name
	data, ok := cache[cacheKey]
	if !ok {
		secret, err := client.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return "", err
		}
		data = secret.Data
		cache[cacheKey] = data
	}
	value, ok := data[key]
	if !ok {
		return "", fmt.Errorf("Secret %s missing key %q", cacheKey, key)
	}
	if len(value) == 0 {
		return "", fmt.Errorf("Secret %s key %q is empty", cacheKey, key)
	}
	return string(value), nil
}

// LoadIssuerProfilesFile loads named issuer profiles from a YAML or JSON file.
func LoadIssuerProfilesFile(path string) (map[string]IssuerProfile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Issuers []IssuerProfile `yaml:"issuers" json:"issuers"`
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&doc); err != nil {
		return nil, err
	}
	profiles := make(map[string]IssuerProfile, len(doc.Issuers))
	for _, profile := range doc.Issuers {
		name := strings.TrimSpace(profile.Name)
		if name == "" {
			return nil, fmt.Errorf("issuer profile name is required")
		}
		if _, exists := profiles[name]; exists {
			return nil, fmt.Errorf("issuer profile %q is duplicated", name)
		}
		profile.Name = name
		profiles[name] = profile
	}
	return profiles, nil
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
