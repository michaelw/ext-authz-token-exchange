// Package demo contains shared helpers for local token-exchange demos.
package demo

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/template"
	"time"

	"sigs.k8s.io/yaml"
)

const (
	// DefaultBaseURL is the local-test Gateway API host used by demo tooling.
	DefaultBaseURL = "https://httpbin.int.kube"
	// DefaultNamespacePrefix is the namespace prefix used by the e2e Helm chart.
	DefaultNamespacePrefix = "service"
	// DefaultSystemNamespace is the central namespace for the plugin and fake issuer.
	DefaultSystemNamespace = "ext-authz-token-exchange-e2e"
	// DefaultConfigPath is the shared scenario file used by e2e demo tooling.
	DefaultConfigPath = "test/e2e/demo-scenarios.yaml"
	// DefaultRequestTimeout bounds each demo HTTP request.
	DefaultRequestTimeout = 10 * time.Second
)

// Options configures scenario rendering and HTTP execution.
type Options struct {
	BaseURL         string
	ConfigPath      string
	NamespacePrefix string
	SystemNamespace string
	InsecureTLS     bool
}

// LoadOptionsFromEnv returns demo options from environment variables.
func LoadOptionsFromEnv() Options {
	return Options{
		BaseURL:         strings.TrimRight(envDefault("DEMO_BASE_URL", DefaultBaseURL), "/"),
		ConfigPath:      envDefault("DEMO_SCENARIO_CONFIG", DefaultConfigPath),
		NamespacePrefix: envDefault("DEMO_NAMESPACE_PREFIX", DefaultNamespacePrefix),
		SystemNamespace: envDefault("DEMO_SYSTEM_NAMESPACE", DefaultSystemNamespace),
		InsecureTLS:     envBool("DEMO_INSECURE_SKIP_VERIFY", true),
	}
}

// Config contains the configured demo scenarios.
type Config struct {
	Version   string     `json:"version"`
	Scenarios []Scenario `json:"scenarios"`
}

// Scenario describes one demo request and its expected behavior.
type Scenario struct {
	Name        string      `json:"name"`
	Description string      `json:"summary"`
	Request     Request     `json:"request"`
	Policy      string      `json:"policy"`
	Exchange    string      `json:"exchange"`
	Behavior    Behavior    `json:"behavior"`
	Expect      Expectation `json:"expect"`
}

// Behavior describes the fake token endpoint action for a scenario.
type Behavior struct {
	Summary string `json:"summary"`
	Detail  string `json:"detail"`
}

// Request describes an HTTP request for a scenario.
type Request struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Bearer  string            `json:"bearer"`
	Headers map[string]string `json:"headers"`
}

// Expectation describes the observable response a scenario should produce.
type Expectation struct {
	Status          int    `json:"status"`
	Auth            string `json:"upstreamAuthorization"`
	Error           string `json:"error"`
	WWW             string `json:"wwwAuthenticateContains"`
	CORSAllowOrigin string `json:"corsOrigin"`
}

// Observed contains the HTTP behavior seen while running a scenario.
type Observed struct {
	Status      int    `json:"status"`
	Auth        string `json:"upstreamAuthorization,omitempty"`
	ErrorCode   string `json:"error,omitempty"`
	WWW         string `json:"wwwAuthenticate,omitempty"`
	CORSOrigin  string `json:"corsOrigin,omitempty"`
	ContentType string `json:"contentType,omitempty"`
	Body        string `json:"body,omitempty"`
	BodyBase64  string `json:"bodyBase64,omitempty"`
	PrettyJSON  string `json:"prettyJSON,omitempty"`
	PrettyYAML  string `json:"prettyYAML,omitempty"`
	Elapsed     string `json:"elapsed,omitempty"`
}

// Result contains a completed scenario run.
type Result struct {
	Scenario   Scenario  `json:"scenario"`
	Observed   Observed  `json:"observed"`
	RequestURL string    `json:"requestURL"`
	Curl       string    `json:"curl"`
	Passed     bool      `json:"passed"`
	Failures   []Failure `json:"failures,omitempty"`
}

// Failure describes an expectation mismatch.
type Failure struct {
	Label string `json:"label"`
	Want  string `json:"want"`
	Got   string `json:"got"`
}

type templateData struct {
	BaseURL         string
	BaseURLHost     string
	NamespacePrefix string
	SystemNamespace string
}

// LoadConfig reads, renders, parses, and validates the demo scenario config.
func LoadConfig(opts Options) (Config, error) {
	opts = opts.WithDefaults()
	data, err := os.ReadFile(opts.ConfigPath)
	if err != nil {
		return Config{}, fmt.Errorf("read scenario config %q: %w", opts.ConfigPath, err)
	}
	rendered, err := RenderConfig(data, opts)
	if err != nil {
		return Config{}, fmt.Errorf("render scenario config %q: %w", opts.ConfigPath, err)
	}
	var cfg Config
	if err := yaml.Unmarshal(rendered, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse scenario config %q: %w", opts.ConfigPath, err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// RenderConfig renders a scenario YAML file as a small Go template.
func RenderConfig(data []byte, opts Options) ([]byte, error) {
	opts = opts.WithDefaults()
	baseURLHost := ""
	if parsed, err := url.Parse(opts.BaseURL); err == nil {
		baseURLHost = parsed.Hostname()
	}
	tmpl, err := template.New("demo-scenarios").Option("missingkey=error").Parse(string(data))
	if err != nil {
		return nil, err
	}
	var rendered bytes.Buffer
	err = tmpl.Execute(&rendered, templateData{
		BaseURL:         opts.BaseURL,
		BaseURLHost:     baseURLHost,
		NamespacePrefix: opts.NamespacePrefix,
		SystemNamespace: opts.SystemNamespace,
	})
	if err != nil {
		return nil, err
	}
	return rendered.Bytes(), nil
}

// Validate checks the scenario config for required fields.
func (cfg Config) Validate() error {
	if cfg.Version != "v1" {
		return fmt.Errorf("scenario config version must be v1, got %q", cfg.Version)
	}
	if len(cfg.Scenarios) == 0 {
		return fmt.Errorf("scenario config must contain at least one scenario")
	}
	seen := map[string]struct{}{}
	for _, sc := range cfg.Scenarios {
		if strings.TrimSpace(sc.Name) == "" {
			return fmt.Errorf("scenario config contains a scenario without a name")
		}
		if _, ok := seen[sc.Name]; ok {
			return fmt.Errorf("scenario config contains duplicate scenario %q", sc.Name)
		}
		seen[sc.Name] = struct{}{}
		if strings.TrimSpace(sc.Request.Path) == "" {
			return fmt.Errorf("scenario %q must configure request.path", sc.Name)
		}
	}
	return nil
}

// Find returns a scenario by name.
func (cfg Config) Find(name string) (Scenario, bool) {
	for _, sc := range cfg.Scenarios {
		if sc.Name == name {
			return sc, true
		}
	}
	return Scenario{}, false
}

// WithDefaults fills derived defaults for a scenario.
func (sc Scenario) WithDefaults() Scenario {
	if sc.Request.Method == "" {
		sc.Request.Method = http.MethodGet
	}
	sc.Request.Method = strings.ToUpper(sc.Request.Method)
	if sc.Policy == "" {
		sc.Policy = "-"
	}
	if sc.Exchange == "" {
		sc.Exchange = "-"
	}
	if sc.Expect.Status == 0 {
		sc.Expect.Status = http.StatusOK
	}
	sc.Behavior = ExchangeBehavior(sc.Exchange, sc.Request)
	return sc
}

// ExchangeBehavior returns demo metadata for a fake token endpoint path.
func ExchangeBehavior(exchange string, req Request) Behavior {
	if exchange == "" || exchange == "-" {
		if strings.EqualFold(req.Method, http.MethodOptions) && req.Headers["Origin"] != "" && req.Headers["Access-Control-Request-Method"] != "" {
			return Behavior{
				Summary: "Preflight bypasses token exchange.",
				Detail:  "This is a true CORS preflight request, so the plugin allows it through without calling the token endpoint.",
			}
		}
		return Behavior{
			Summary: "No token endpoint call for this scenario.",
			Detail:  "The request is denied before exchange or allowed through unchanged, so the fake issuer is not called.",
		}
	}
	switch strings.TrimPrefix(exchange, "/token/") {
	case "success", "yellow", "red", "blue":
		return Behavior{
			Summary: "Returns a Bearer access token.",
			Detail:  "Returns HTTP 200 with access_token, issued_token_type=access_token, and token_type=Bearer.",
		}
	case "invalid-request":
		return Behavior{
			Summary: "Rejects malformed exchange requests.",
			Detail:  "Returns HTTP 400 with OAuth error invalid_request for token exchange requests the issuer considers malformed.",
		}
	case "invalid-target":
		return Behavior{
			Summary: "Rejects requested resource/audience target.",
			Detail:  "Returns HTTP 400 with OAuth/RFC8693 error invalid_target. This represents a resource or audience the authorization server will not issue for.",
		}
	case "invalid-grant":
		return Behavior{
			Summary: "Rejects the subject token as invalid.",
			Detail:  "Returns HTTP 400 with OAuth error invalid_grant. This represents an incoming subject token the authorization server does not accept.",
		}
	case "expired-subject-token":
		return Behavior{
			Summary: "Rejects an expired subject token.",
			Detail:  "Returns HTTP 400 with OAuth error invalid_grant for an expired but otherwise validly shaped subject token.",
		}
	case "unauthorized":
		return Behavior{
			Summary: "Rejects the token client.",
			Detail:  "Returns HTTP 401 with OAuth error invalid_client and a WWW-Authenticate challenge from the issuer.",
		}
	case "forbidden":
		return Behavior{
			Summary: "Rejects target with a forbidden response.",
			Detail:  "Returns HTTP 403 with invalid_target. The plugin treats this as token-service failure rather than request malformation.",
		}
	case "server-error":
		return Behavior{
			Summary: "Simulates token service failure.",
			Detail:  "Returns HTTP 500 with a generic OAuth-style error body.",
		}
	case "malformed":
		return Behavior{
			Summary: "Returns malformed success JSON.",
			Detail:  "Returns HTTP 200 with broken JSON, exercising the plugin's invalid token response handling.",
		}
	case "missing-access-token":
		return Behavior{
			Summary: "Omits the required access_token field.",
			Detail:  "Returns HTTP 200 with token_type and issued_token_type but no access_token.",
		}
	case "wrong-token-type":
		return Behavior{
			Summary: "Returns a non-Bearer token type.",
			Detail:  "Returns HTTP 200 with token_type=N_A, exercising the plugin's Bearer token_type validation.",
		}
	case "wrong-issued-token-type":
		return Behavior{
			Summary: "Returns the wrong issued token type.",
			Detail:  "Returns HTTP 200 with issued_token_type=refresh_token, exercising the plugin's access-token issued_token_type validation.",
		}
	case "delay":
		return Behavior{
			Summary: "Sleeps long enough to trigger timeout handling.",
			Detail:  "Delays for 10 seconds before returning success, exercising token endpoint request timeout handling.",
		}
	default:
		return Behavior{
			Summary: "Unknown fake token scenario.",
			Detail:  "The fake issuer will return HTTP 400 invalid_request for an unknown /token/ scenario.",
		}
	}
}

// WithDefaults fills derived defaults for demo options.
func (opts Options) WithDefaults() Options {
	if opts.BaseURL == "" {
		opts.BaseURL = DefaultBaseURL
	}
	opts.BaseURL = strings.TrimRight(opts.BaseURL, "/")
	if opts.ConfigPath == "" {
		opts.ConfigPath = DefaultConfigPath
	}
	if opts.NamespacePrefix == "" {
		opts.NamespacePrefix = DefaultNamespacePrefix
	}
	if opts.SystemNamespace == "" {
		opts.SystemNamespace = DefaultSystemNamespace
	}
	return opts
}

// Run executes one scenario and compares observed behavior with expectations.
func Run(parent context.Context, opts Options, sc Scenario) (Result, error) {
	opts = opts.WithDefaults()
	sc = sc.WithDefaults()
	obs, requestURL, err := Send(parent, opts, sc)
	result := Result{
		Scenario:   sc,
		Observed:   obs,
		RequestURL: requestURL,
		Curl:       Curl(opts, sc),
	}
	if err != nil {
		result.Failures = append(result.Failures, Failure{Label: "request", Want: "success", Got: err.Error()})
		return result, err
	}
	result.Failures = Compare(obs, sc.Expect)
	result.Passed = len(result.Failures) == 0
	if !result.Passed {
		return result, fmt.Errorf("%s failed for %s", sc.Name, requestURL)
	}
	return result, nil
}

// Send performs the HTTP request for a scenario and extracts observable fields.
func Send(parent context.Context, opts Options, sc Scenario) (Observed, string, error) {
	opts = opts.WithDefaults()
	sc = sc.WithDefaults()
	requestURL, err := url.JoinPath(opts.BaseURL, sc.Request.Path)
	if err != nil {
		return Observed{}, "", err
	}

	ctx, cancel := context.WithTimeout(parent, DefaultRequestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, sc.Request.Method, requestURL, nil)
	if err != nil {
		return Observed{}, "", err
	}
	if sc.Request.Bearer != "" {
		req.Header.Set("Authorization", "Bearer "+sc.Request.Bearer)
	}
	for key, value := range sc.Request.Headers {
		req.Header.Set(key, value)
	}

	start := time.Now()
	resp, err := httpClient(opts).Do(req)
	if err != nil {
		return Observed{}, requestURL, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Observed{}, requestURL, err
	}

	parsed := parseBody(body)
	prettyJSON, prettyYAML := prettyFormats(body)
	return Observed{
		Status:      resp.StatusCode,
		Auth:        parsed.authorization,
		ErrorCode:   parsed.errorCode,
		WWW:         resp.Header.Get("WWW-Authenticate"),
		CORSOrigin:  resp.Header.Get("Access-Control-Allow-Origin"),
		ContentType: resp.Header.Get("Content-Type"),
		Body:        string(body),
		BodyBase64:  base64.StdEncoding.EncodeToString(body),
		PrettyJSON:  prettyJSON,
		PrettyYAML:  prettyYAML,
		Elapsed:     time.Since(start).Round(time.Millisecond).String(),
	}, requestURL, nil
}

// Compare returns expectation mismatches for observed behavior.
func Compare(obs Observed, expect Expectation) []Failure {
	if expect.Status == 0 {
		expect.Status = http.StatusOK
	}
	var failures []Failure
	failures = appendEqual(failures, "HTTP status", fmt.Sprint(obs.Status), fmt.Sprint(expect.Status))
	if expect.Auth != "" {
		failures = appendEqual(failures, "upstream Authorization", obs.Auth, expect.Auth)
	}
	if expect.Error != "" {
		failures = appendEqual(failures, "error", obs.ErrorCode, expect.Error)
	}
	if expect.WWW != "" && !strings.Contains(obs.WWW, expect.WWW) {
		failures = append(failures, Failure{Label: "WWW-Authenticate", Want: "contains " + expect.WWW, Got: obs.WWW})
	}
	if expect.CORSAllowOrigin != "" {
		failures = appendEqual(failures, "Access-Control-Allow-Origin", obs.CORSOrigin, expect.CORSAllowOrigin)
	}
	return failures
}

// Curl returns a shell command that reproduces the scenario request.
func Curl(opts Options, sc Scenario) string {
	opts = opts.WithDefaults()
	sc = sc.WithDefaults()
	requestURL, err := url.JoinPath(opts.BaseURL, sc.Request.Path)
	if err != nil {
		requestURL = opts.BaseURL + sc.Request.Path
	}
	parts := []string{"curl", "-sk", "-X", shellQuote(sc.Request.Method)}
	if sc.Request.Bearer != "" {
		parts = append(parts, "-H", shellQuote("Authorization: Bearer "+sc.Request.Bearer))
	}
	for key, value := range sc.Request.Headers {
		parts = append(parts, "-H", shellQuote(key+": "+value))
	}
	parts = append(parts, shellQuote(requestURL))
	return strings.Join(parts, " ")
}

func httpClient(opts Options) *http.Client {
	return &http.Client{
		Timeout: DefaultRequestTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: opts.InsecureTLS},
		},
	}
}

type parsedBody struct {
	authorization string
	errorCode     string
}

func parseBody(body []byte) parsedBody {
	var out parsedBody
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return out
	}
	if errorCode, ok := raw["error"].(string); ok {
		out.errorCode = errorCode
	}
	headers, ok := raw["headers"].(map[string]any)
	if !ok {
		return out
	}
	for key, value := range headers {
		if !strings.EqualFold(key, "Authorization") {
			continue
		}
		out.authorization = firstHeaderValue(value)
		return out
	}
	return out
}

func prettyFormats(body []byte) (string, string) {
	var raw any
	if err := json.Unmarshal(body, &raw); err == nil {
		return marshalPretty(raw)
	}
	jsonBody, err := yaml.YAMLToJSON(body)
	if err != nil {
		return "", ""
	}
	if err := json.Unmarshal(jsonBody, &raw); err != nil {
		return "", ""
	}
	return marshalPretty(raw)
}

func marshalPretty(value any) (string, string) {
	prettyJSON, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return "", ""
	}
	prettyYAML, err := yaml.Marshal(value)
	if err != nil {
		return string(prettyJSON), ""
	}
	return string(prettyJSON), string(prettyYAML)
}

func firstHeaderValue(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case []any:
		if len(typed) == 0 {
			return ""
		}
		if s, ok := typed[0].(string); ok {
			return s
		}
	case []string:
		if len(typed) > 0 {
			return typed[0]
		}
	}
	return ""
}

func appendEqual(failures []Failure, label, got, want string) []Failure {
	if got == want {
		return failures
	}
	return append(failures, Failure{Label: label, Want: want, Got: got})
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}

func envDefault(name, fallback string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	return value
}

func envBool(name string, fallback bool) bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv(name)))
	if value == "" {
		return fallback
	}
	switch value {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}
