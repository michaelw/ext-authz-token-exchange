package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/template"
	"time"

	"github.com/spf13/cobra"
	"sigs.k8s.io/yaml"
)

const (
	defaultBaseURL         = "https://httpbin.int.kube"
	defaultNamespacePrefix = "service"
	defaultSystemNamespace = "ext-authz-token-exchange-e2e"
	defaultConfigPath      = "test/e2e/demo-scenarios.yaml"
	defaultRequestTimeout  = 10 * time.Second
)

type options struct {
	baseURL         string
	configPath      string
	namespacePrefix string
	systemNamespace string
	insecureTLS     bool
}

type demoConfig struct {
	Version   string     `json:"version"`
	Scenarios []scenario `json:"scenarios"`
}

type scenario struct {
	Name        string            `json:"name"`
	Description string            `json:"summary"`
	Request     requestConfig     `json:"request"`
	Policy      string            `json:"policy"`
	Exchange    string            `json:"exchange"`
	Expect      expectationConfig `json:"expect"`
}

type requestConfig struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Bearer  string            `json:"bearer"`
	Headers map[string]string `json:"headers"`
}

type expectationConfig struct {
	Status          int    `json:"status"`
	Auth            string `json:"upstreamAuthorization"`
	Error           string `json:"error"`
	WWW             string `json:"wwwAuthenticateContains"`
	CORSAllowOrigin string `json:"corsOrigin"`
}

type templateData struct {
	BaseURL         string
	BaseURLHost     string
	NamespacePrefix string
	SystemNamespace string
}

type observed struct {
	status      int
	auth        string
	errorCode   string
	www         string
	corsOrigin  string
	contentType string
}

func main() {
	if err := newCommand().Execute(); err != nil {
		os.Exit(1)
	}
}

func newCommand() *cobra.Command {
	opts := loadOptions()
	cmd := &cobra.Command{
		Use:   "demo-scenario [list|all|scenario]",
		Short: "Run read-only token exchange demo scenarios",
		Long:  "Run read-only token exchange demo scenarios against the local-test Gateway API host.",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 || args[0] == "help" {
				return cmd.Help()
			}
			return run(cmd.Context(), args[0], opts)
		},
	}
	cmd.Flags().StringVar(&opts.configPath, "config", opts.configPath, "scenario YAML file")
	cmd.Flags().StringVar(&opts.baseURL, "base-url", opts.baseURL, "demo gateway base URL")
	cmd.Flags().StringVar(&opts.namespacePrefix, "namespace-prefix", opts.namespacePrefix, "team namespace prefix")
	cmd.Flags().StringVar(&opts.systemNamespace, "system-namespace", opts.systemNamespace, "central demo namespace")
	cmd.Flags().BoolVar(&opts.insecureTLS, "insecure-skip-verify", opts.insecureTLS, "skip TLS verification for demo HTTPS requests")
	return cmd
}

func loadOptions() options {
	return options{
		baseURL:         strings.TrimRight(envDefault("DEMO_BASE_URL", defaultBaseURL), "/"),
		configPath:      envDefault("DEMO_SCENARIO_CONFIG", defaultConfigPath),
		namespacePrefix: envDefault("DEMO_NAMESPACE_PREFIX", defaultNamespacePrefix),
		systemNamespace: envDefault("DEMO_SYSTEM_NAMESPACE", defaultSystemNamespace),
		insecureTLS:     envBool("DEMO_INSECURE_SKIP_VERIFY", true),
	}
}

func run(ctx context.Context, command string, opts options) error {
	cfg, err := loadConfig(opts)
	if err != nil {
		return err
	}
	switch command {
	case "list":
		for _, sc := range cfg.Scenarios {
			fmt.Println(sc.Name)
		}
		return nil
	case "all":
		var failed int
		for _, sc := range cfg.Scenarios {
			if err := runOne(ctx, opts, sc.withDefaults()); err != nil {
				failed++
			}
		}
		if failed > 0 {
			return fmt.Errorf("Completed with %d failed scenario(s).", failed)
		}
		fmt.Println()
		fmt.Println("All scenarios passed.")
		return nil
	default:
		sc, ok := cfg.find(command)
		if !ok {
			return fmt.Errorf("error: unknown scenario %q", command)
		}
		return runOne(ctx, opts, sc.withDefaults())
	}
}

func loadConfig(opts options) (demoConfig, error) {
	data, err := os.ReadFile(opts.configPath)
	if err != nil {
		return demoConfig{}, fmt.Errorf("read scenario config %q: %w", opts.configPath, err)
	}
	rendered, err := renderConfig(data, opts)
	if err != nil {
		return demoConfig{}, fmt.Errorf("render scenario config %q: %w", opts.configPath, err)
	}
	var cfg demoConfig
	if err := yaml.Unmarshal(rendered, &cfg); err != nil {
		return demoConfig{}, fmt.Errorf("parse scenario config %q: %w", opts.configPath, err)
	}
	if err := cfg.validate(); err != nil {
		return demoConfig{}, err
	}
	return cfg, nil
}

func renderConfig(data []byte, opts options) ([]byte, error) {
	baseURLHost := ""
	if parsed, err := url.Parse(opts.baseURL); err == nil {
		baseURLHost = parsed.Hostname()
	}
	tmpl, err := template.New("demo-scenarios").Option("missingkey=error").Parse(string(data))
	if err != nil {
		return nil, err
	}
	var rendered bytes.Buffer
	err = tmpl.Execute(&rendered, templateData{
		BaseURL:         opts.baseURL,
		BaseURLHost:     baseURLHost,
		NamespacePrefix: opts.namespacePrefix,
		SystemNamespace: opts.systemNamespace,
	})
	if err != nil {
		return nil, err
	}
	return rendered.Bytes(), nil
}

func (cfg demoConfig) validate() error {
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

func (cfg demoConfig) find(name string) (scenario, bool) {
	for _, sc := range cfg.Scenarios {
		if sc.Name == name {
			return sc, true
		}
	}
	return scenario{}, false
}

func (sc scenario) withDefaults() scenario {
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
	return sc
}

func runOne(ctx context.Context, opts options, sc scenario) error {
	obs, requestURL, err := sendRequest(ctx, opts, sc)
	if err != nil {
		return err
	}
	printScenario(sc, obs)

	var failures int
	failures += expectEqual("HTTP status", fmt.Sprint(obs.status), fmt.Sprint(sc.Expect.Status))
	if sc.Expect.Auth != "" {
		failures += expectEqual("upstream Authorization", obs.auth, sc.Expect.Auth)
	}
	if sc.Expect.Error != "" {
		failures += expectEqual("error", obs.errorCode, sc.Expect.Error)
	}
	if sc.Expect.WWW != "" {
		failures += expectContains("WWW-Authenticate", obs.www, sc.Expect.WWW)
	}
	if sc.Expect.CORSAllowOrigin != "" {
		failures += expectEqual("Access-Control-Allow-Origin", obs.corsOrigin, sc.Expect.CORSAllowOrigin)
	}

	if failures > 0 {
		fmt.Println("Result:    FAIL")
		return fmt.Errorf("%s failed for %s", sc.Name, requestURL)
	}
	fmt.Println("Result:    PASS")
	return nil
}

func sendRequest(parent context.Context, opts options, sc scenario) (observed, string, error) {
	requestURL, err := url.JoinPath(opts.baseURL, sc.Request.Path)
	if err != nil {
		return observed{}, "", err
	}

	ctx, cancel := context.WithTimeout(parent, defaultRequestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, sc.Request.Method, requestURL, nil)
	if err != nil {
		return observed{}, "", err
	}
	if sc.Request.Bearer != "" {
		req.Header.Set("Authorization", "Bearer "+sc.Request.Bearer)
	}
	for key, value := range sc.Request.Headers {
		req.Header.Set(key, value)
	}

	resp, err := httpClient(opts).Do(req)
	if err != nil {
		return observed{}, requestURL, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return observed{}, requestURL, err
	}

	parsed := parseBody(body)
	return observed{
		status:      resp.StatusCode,
		auth:        parsed.authorization,
		errorCode:   parsed.errorCode,
		www:         resp.Header.Get("WWW-Authenticate"),
		corsOrigin:  resp.Header.Get("Access-Control-Allow-Origin"),
		contentType: resp.Header.Get("Content-Type"),
	}, requestURL, nil
}

func httpClient(opts options) *http.Client {
	return &http.Client{
		Timeout: defaultRequestTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: opts.insecureTLS},
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

func printScenario(sc scenario, obs observed) {
	fmt.Println()
	fmt.Printf("Scenario:  %s\n", sc.Name)
	fmt.Printf("Summary:   %s\n", sc.Description)
	fmt.Printf("Request:   %s %s\n", sc.Request.Method, sc.Request.Path)
	if sc.Request.Bearer != "" {
		fmt.Printf("Input:     Authorization: Bearer %s\n", sc.Request.Bearer)
	} else {
		fmt.Println("Input:     Authorization: <none>")
	}
	fmt.Printf("Policy:    %s\n", sc.Policy)
	fmt.Printf("Exchange:  %s\n", sc.Exchange)
	fmt.Printf("Expected:  HTTP %d\n", sc.Expect.Status)
	if sc.Expect.Auth != "" {
		fmt.Printf("Expected:  upstream Authorization: %s\n", sc.Expect.Auth)
	}
	if sc.Expect.Error != "" {
		fmt.Printf("Expected:  error=%s\n", sc.Expect.Error)
	}
	fmt.Printf("Observed:  HTTP %d\n", obs.status)
	if obs.auth != "" {
		fmt.Printf("Observed:  upstream Authorization: %s\n", obs.auth)
	}
	if obs.errorCode != "" {
		fmt.Printf("Observed:  error=%s\n", obs.errorCode)
	}
	if obs.www != "" {
		fmt.Printf("Observed:  WWW-Authenticate: %s\n", obs.www)
	}
	if obs.corsOrigin != "" {
		fmt.Printf("Observed:  Access-Control-Allow-Origin: %s\n", obs.corsOrigin)
	}
	if obs.contentType != "" {
		fmt.Printf("Observed:  Content-Type: %s\n", obs.contentType)
	}
}

func expectEqual(label, got, want string) int {
	if got == want {
		return 0
	}
	fmt.Fprintf(os.Stderr, "FAIL: %s: expected %q, got %q\n", label, want, got)
	return 1
}

func expectContains(label, got, want string) int {
	if strings.Contains(got, want) {
		return 0
	}
	fmt.Fprintf(os.Stderr, "FAIL: %s: expected value containing %q, got %q\n", label, want, got)
	return 1
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
