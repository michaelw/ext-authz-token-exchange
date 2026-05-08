package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/michaelw/ext-authz-token-exchange/internal/demo"
	"github.com/pkg/browser"
)

//go:embed static
var staticFiles embed.FS

const defaultAddr = "127.0.0.1:8088"
const keycloakConfigPath = "test/e2e/keycloak-demo-scenarios.yaml"
const defaultKeycloakBaseURL = "https://keycloak.int.kube"
const defaultKeycloakRealm = "token-exchange-e2e"
const defaultKeycloakClientID = "tx-exchanger-client"
const defaultSubjectClientID = "tx-subject-client"
const defaultSubjectClientSecret = "tx-subject-secret"
const defaultShortTTLClientID = "tx-short-ttl-subject-client"
const defaultShortTTLClientSecret = "tx-short-ttl-subject-secret"
const defaultKeycloakUser = "token-user"
const defaultKeycloakPassword = "token-user-password"

type server struct {
	opts   demo.Options
	issuer issuerSelection
}

type issuerSelection struct {
	Name           string `json:"name"`
	Label          string `json:"label"`
	Deployment     string `json:"deployment"`
	ScenarioConfig string `json:"scenarioConfig"`
	TokenEndpoint  string `json:"tokenEndpoint,omitempty"`
	Warning        string `json:"warning,omitempty"`
}

func main() {
	openBrowser := flag.Bool("open", false, "open the demo dashboard in the system browser")
	flag.Parse()

	opts := demo.LoadOptionsFromEnv()
	issuer := selectIssuer(context.Background(), opts)
	opts = issuer.apply(opts)
	addr := envDefault("DEMO_DASHBOARD_ADDR", defaultAddr)

	s := &server{opts: opts, issuer: issuer}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/healthz", s.health)
	mux.HandleFunc("GET /api/status", s.status)
	mux.HandleFunc("GET /api/scenarios", s.scenarios)
	mux.HandleFunc("POST /api/scenarios/run-all", s.runAll)
	mux.HandleFunc("POST /api/scenarios/{name}/token", s.scenarioToken)
	mux.HandleFunc("POST /api/scenarios/{name}/run", s.runOne)
	mux.HandleFunc("POST /api/token/verify", s.verifyToken)
	mux.HandleFunc("GET /api/policies/{namespace}/{name}", s.policy)
	mux.HandleFunc("GET /api/logs/{component}", s.logs)
	mux.HandleFunc("GET /favicon.ico", favicon)
	mux.Handle("/", staticHandler())

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	browserURL, err := dashboardURL(addr)
	if err != nil {
		_ = listener.Close()
		log.Fatal(err)
	}

	log.Printf("demo dashboard listening on %s", browserURL)
	log.Printf("using issuer %s, gateway %s, and scenario config %s", issuer.Name, opts.BaseURL, opts.ConfigPath)
	if issuer.Warning != "" {
		log.Printf("warning: %s", issuer.Warning)
	}
	if *openBrowser {
		if err := browser.OpenURL(browserURL); err != nil {
			log.Printf("warning: failed to open browser for %s: %v", browserURL, err)
		}
	}

	srv := &http.Server{Handler: mux}
	if err := srv.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func (s *server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *server) status(w http.ResponseWriter, r *http.Request) {
	opts := s.opts.WithDefaults()
	plugin := deploymentStatus(r.Context(), opts.PluginNamespace, opts.PluginDeployment)
	issuer := deploymentStatus(r.Context(), opts.SystemNamespace, s.issuer.Deployment)
	writeJSON(w, http.StatusOK, map[string]any{
		"plugin":         plugin,
		"issuer":         issuer,
		"issuerName":     s.issuer.Name,
		"issuerLabel":    s.issuer.Label,
		"scenarioConfig": opts.ConfigPath,
		"tokenEndpoint":  s.issuer.TokenEndpoint,
	})
}

type componentStatus struct {
	Ready     bool   `json:"ready"`
	Namespace string `json:"namespace"`
	Deploy    string `json:"deployment"`
	Available string `json:"available,omitempty"`
	Warning   string `json:"warning,omitempty"`
}

type runRequest struct {
	Bearer *string `json:"bearer"`
}

type tokenResponse struct {
	Bearer  string `json:"bearer"`
	Source  string `json:"source"`
	Warning string `json:"warning,omitempty"`
}

type verifyTokenRequest struct {
	Token string `json:"token"`
}

type verifyTokenResponse struct {
	Format    string `json:"format"`
	Algorithm string `json:"algorithm,omitempty"`
	Verified  bool   `json:"verified"`
	Status    string `json:"status"`
	Detail    string `json:"detail,omitempty"`
}

func deploymentStatus(parent context.Context, namespace, deployment string) componentStatus {
	status := componentStatus{Namespace: namespace, Deploy: deployment}
	ctx, cancel := context.WithTimeout(parent, 4*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "kubectl", "get", "deployment", "-n", namespace, deployment, "-o", "jsonpath={.status.availableReplicas}/{.spec.replicas}")
	out, err := cmd.CombinedOutput()
	if err != nil {
		status.Warning = strings.TrimSpace(string(out))
		if status.Warning == "" {
			status.Warning = err.Error()
		}
		return status
	}
	status.Available = strings.TrimSpace(string(out))
	parts := strings.Split(status.Available, "/")
	status.Ready = len(parts) == 2 && parts[0] != "" && parts[0] != "0" && parts[0] == parts[1]
	return status
}

func (s *server) scenarios(w http.ResponseWriter, _ *http.Request) {
	cfg, err := demo.LoadConfig(s.opts)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	for i := range cfg.Scenarios {
		cfg.Scenarios[i] = cfg.Scenarios[i].WithDefaults()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"baseURL":          s.opts.WithDefaults().BaseURL,
		"namespacePrefix":  s.opts.WithDefaults().NamespacePrefix,
		"systemNamespace":  s.opts.WithDefaults().SystemNamespace,
		"pluginNamespace":  s.opts.WithDefaults().PluginNamespace,
		"pluginDeployment": s.opts.WithDefaults().PluginDeployment,
		"issuer":           s.issuer,
		"scenarios":        cfg.Scenarios,
	})
}

func (s *server) runOne(w http.ResponseWriter, r *http.Request) {
	cfg, err := demo.LoadConfig(s.opts)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	sc, ok := cfg.Find(r.PathValue("name"))
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Errorf("unknown scenario %q", r.PathValue("name")))
		return
	}
	override, err := bearerOverride(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if override != nil {
		sc.Request.Bearer = normalizeBearerInput(*override)
	}
	result, _ := demo.Run(r.Context(), s.opts, sc)
	status := http.StatusOK
	if !result.Passed {
		status = http.StatusBadGateway
	}
	writeJSON(w, status, result)
}

func (s *server) scenarioToken(w http.ResponseWriter, r *http.Request) {
	cfg, err := demo.LoadConfig(s.opts)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	sc, ok := cfg.Find(r.PathValue("name"))
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Errorf("unknown scenario %q", r.PathValue("name")))
		return
	}
	resp, err := s.tokenForScenario(r.Context(), sc.WithDefaults())
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *server) verifyToken(w http.ResponseWriter, r *http.Request) {
	var req verifyTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("decode verify request: %w", err))
		return
	}
	resp := verifyDashboardToken(r.Context(), req.Token)
	writeJSON(w, http.StatusOK, resp)
}

func (s *server) tokenForScenario(ctx context.Context, sc demo.Scenario) (tokenResponse, error) {
	if s.issuer.Name == "keycloak" {
		token, err := s.keycloakTokenForScenario(ctx, sc)
		if err != nil {
			return tokenResponse{}, err
		}
		return tokenResponse{Bearer: token, Source: "keycloak"}, nil
	}
	resp := tokenResponse{Bearer: sc.Request.Bearer, Source: "scenario"}
	if sc.Request.Bearer == "" {
		resp.Warning = "scenario has no configured bearer token"
	}
	return resp, nil
}

func (s *server) keycloakTokenForScenario(ctx context.Context, sc demo.Scenario) (string, error) {
	switch sc.Name {
	case "keycloak-expired-subject-token":
		token, err := fetchKeycloakDemoSubjectToken(ctx, s.opts, keycloakSubjectCredentials{
			clientID:     envDefault("DEMO_KEYCLOAK_SHORT_TTL_CLIENT_ID", defaultShortTTLClientID),
			clientSecret: envDefault("DEMO_KEYCLOAK_SHORT_TTL_CLIENT_SECRET", defaultShortTTLClientSecret),
		})
		if err != nil {
			return "", err
		}
		time.Sleep(3 * time.Second)
		return token, nil
	case "keycloak-unsigned-subject-token":
		return unsignedKeycloakSubjectToken(), nil
	case "keycloak-truncated-signature":
		token, err := fetchKeycloakDemoSubjectToken(ctx, s.opts, defaultKeycloakSubjectCredentials())
		if err != nil {
			return "", err
		}
		return truncateSignature(token), nil
	case "keycloak-untrusted-issuer":
		return signedUntrustedSubjectToken()
	default:
		return fetchKeycloakDemoSubjectToken(ctx, s.opts, defaultKeycloakSubjectCredentials())
	}
}

func (s *server) runAll(w http.ResponseWriter, r *http.Request) {
	cfg, err := demo.LoadConfig(s.opts)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	results := make([]demo.Result, 0, len(cfg.Scenarios))
	failed := 0
	for _, sc := range cfg.Scenarios {
		ctx, cancel := context.WithTimeout(r.Context(), demo.DefaultRequestTimeout+time.Second)
		result, _ := demo.Run(ctx, s.opts, sc)
		cancel()
		if !result.Passed {
			failed++
		}
		results = append(results, result)
	}
	status := http.StatusOK
	if failed > 0 {
		status = http.StatusBadGateway
	}
	writeJSON(w, status, map[string]any{"failed": failed, "results": results})
}

func (s *server) policy(w http.ResponseWriter, r *http.Request) {
	namespace := r.PathValue("namespace")
	name := r.PathValue("name")
	if !validKubernetesName(namespace) || !validKubernetesName(name) {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid policy reference %q/%q", namespace, name))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "kubectl", "get", "configmap", "-n", namespace, name, "-o", "jsonpath={.data.config\\.yaml}")
	out, err := cmd.CombinedOutput()
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]string{
			"namespace": namespace,
			"name":      name,
			"warning":   err.Error(),
			"text":      strings.TrimSpace(string(out)),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"namespace": namespace,
		"name":      name,
		"text":      string(out),
	})
}

func (s *server) logs(w http.ResponseWriter, r *http.Request) {
	component := r.PathValue("component")
	opts := s.opts.WithDefaults()
	namespace := ""
	deployment := ""
	switch component {
	case "plugin":
		namespace = opts.PluginNamespace
		deployment = opts.PluginDeployment
	case "issuer":
		namespace = opts.SystemNamespace
		deployment = s.issuer.Deployment
	default:
		writeError(w, http.StatusNotFound, fmt.Errorf("unknown log component %q", component))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "kubectl", "logs", "-n", namespace, "deploy/"+deployment, "--tail=80")
	out, err := cmd.CombinedOutput()
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]string{
			"component": component,
			"logs":      strings.TrimSpace(string(out)),
			"warning":   err.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"component": component, "logs": string(out)})
}

func selectIssuer(ctx context.Context, opts demo.Options) issuerSelection {
	if os.Getenv("DEMO_SCENARIO_CONFIG") != "" {
		return issuerForConfig(opts.ConfigPath)
	}
	endpoint, err := deployedTokenEndpoint(ctx, opts)
	if err != nil {
		selection := fakeIssuer()
		selection.Warning = err.Error()
		return selection
	}
	switch {
	case strings.Contains(endpoint, "keycloak"):
		selection := keycloakIssuer()
		selection.TokenEndpoint = endpoint
		return selection
	case strings.Contains(endpoint, "fake-token-endpoint"):
		selection := fakeIssuer()
		selection.TokenEndpoint = endpoint
		return selection
	default:
		selection := fakeIssuer()
		selection.TokenEndpoint = endpoint
		selection.Warning = fmt.Sprintf("could not classify deployed token endpoint %q; using fake demo scenarios", endpoint)
		return selection
	}
}

func deployedTokenEndpoint(parent context.Context, opts demo.Options) (string, error) {
	opts = opts.WithDefaults()
	ctx, cancel := context.WithTimeout(parent, 4*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "kubectl", "get", "deployment", "-n", opts.PluginNamespace, opts.PluginDeployment, "-o", `jsonpath={range .spec.template.spec.containers[*].env[?(@.name=="TOKEN_EXCHANGE_DEFAULT_TOKEN_ENDPOINT")]}{.value}{end}`)
	out, err := cmd.CombinedOutput()
	if err != nil {
		detail := strings.TrimSpace(string(out))
		if detail == "" {
			detail = err.Error()
		}
		return "", fmt.Errorf("detect deployed token endpoint: %s", detail)
	}
	endpoint := strings.TrimSpace(string(out))
	if endpoint == "" {
		return "", fmt.Errorf("detect deployed token endpoint: TOKEN_EXCHANGE_DEFAULT_TOKEN_ENDPOINT is empty")
	}
	return endpoint, nil
}

func issuerForConfig(path string) issuerSelection {
	if path == keycloakConfigPath {
		return keycloakIssuer()
	}
	return fakeIssuer()
}

func fakeIssuer() issuerSelection {
	return issuerSelection{
		Name:           "fake",
		Label:          "Fake issuer",
		Deployment:     "fake-token-endpoint",
		ScenarioConfig: demo.DefaultConfigPath,
	}
}

func keycloakIssuer() issuerSelection {
	return issuerSelection{
		Name:           "keycloak",
		Label:          "Keycloak issuer",
		Deployment:     "keycloak",
		ScenarioConfig: keycloakConfigPath,
	}
}

func (s issuerSelection) apply(opts demo.Options) demo.Options {
	if os.Getenv("DEMO_SCENARIO_CONFIG") == "" {
		opts.ConfigPath = s.ScenarioConfig
	}
	return opts
}

type keycloakSubjectCredentials struct {
	clientID     string
	clientSecret string
}

func defaultKeycloakSubjectCredentials() keycloakSubjectCredentials {
	return keycloakSubjectCredentials{
		clientID:     envDefault("DEMO_KEYCLOAK_SUBJECT_CLIENT_ID", defaultSubjectClientID),
		clientSecret: envDefault("DEMO_KEYCLOAK_SUBJECT_CLIENT_SECRET", defaultSubjectClientSecret),
	}
}

func fetchKeycloakDemoSubjectToken(parent context.Context, opts demo.Options, credentials keycloakSubjectCredentials) (string, error) {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()

	baseURL := strings.TrimRight(envDefault("DEMO_KEYCLOAK_BASE_URL", defaultKeycloakBaseURL), "/")
	realm := envDefault("DEMO_KEYCLOAK_REALM", defaultKeycloakRealm)
	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("client_id", credentials.clientID)
	form.Set("client_secret", credentials.clientSecret)
	form.Set("username", envDefault("DEMO_KEYCLOAK_USER", defaultKeycloakUser))
	form.Set("password", envDefault("DEMO_KEYCLOAK_PASSWORD", defaultKeycloakPassword))
	form.Set("scope", "profile")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/realms/"+realm+"/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("fetch Keycloak demo subject token: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	transport := http.DefaultTransport.(*http.Transport).Clone()
	if opts.WithDefaults().InsecureTLS {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // local demo uses self-signed int.kube certs.
	}
	client := &http.Client{Transport: transport}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch Keycloak demo subject token: %w", err)
	}
	defer resp.Body.Close()

	var parsed struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return "", fmt.Errorf("fetch Keycloak demo subject token: decode response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		detail := parsed.Error
		if parsed.Description != "" {
			detail += ": " + parsed.Description
		}
		if detail == "" {
			detail = resp.Status
		}
		return "", fmt.Errorf("fetch Keycloak demo subject token: %s", detail)
	}
	if parsed.TokenType != "Bearer" || parsed.AccessToken == "" {
		return "", fmt.Errorf("fetch Keycloak demo subject token: response did not contain a bearer access token")
	}
	return parsed.AccessToken, nil
}

func unsignedKeycloakSubjectToken() string {
	header := map[string]any{"alg": "none", "typ": "JWT"}
	payload := map[string]any{
		"iss": envDefault("DEMO_KEYCLOAK_BASE_URL", defaultKeycloakBaseURL) + "/realms/" + envDefault("DEMO_KEYCLOAK_REALM", defaultKeycloakRealm),
		"sub": "unsigned-demo-subject",
		"aud": envDefault("DEMO_KEYCLOAK_CLIENT_ID", defaultKeycloakClientID),
		"azp": defaultSubjectClientID,
		"exp": time.Now().Add(5 * time.Minute).Unix(),
		"iat": time.Now().Add(-time.Minute).Unix(),
	}
	return encodeBase64URLJSON(header) + "." + encodeBase64URLJSON(payload) + "."
}

func truncateSignature(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return token
	}
	return parts[0] + "." + parts[1] + "."
}

func signedUntrustedSubjectToken() (string, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", err
	}
	header := map[string]any{"alg": "RS256", "typ": "JWT", "kid": "untrusted-demo-key"}
	payload := map[string]any{
		"iss": "https://untrusted-issuer.example.test/realms/token-exchange-e2e",
		"sub": "untrusted-demo-subject",
		"aud": envDefault("DEMO_KEYCLOAK_CLIENT_ID", defaultKeycloakClientID),
		"azp": defaultSubjectClientID,
		"exp": time.Now().Add(5 * time.Minute).Unix(),
		"iat": time.Now().Add(-time.Minute).Unix(),
	}
	unsigned := encodeBase64URLJSON(header) + "." + encodeBase64URLJSON(payload)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func encodeBase64URLJSON(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(encoded)
}

func bearerOverride(r *http.Request) (*string, error) {
	var req runRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, nil
		}
		return nil, fmt.Errorf("decode run request: %w", err)
	}
	return req.Bearer, nil
}

func normalizeBearerInput(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= len("Bearer ") && strings.EqualFold(value[:len("Bearer ")], "Bearer ") {
		return strings.TrimSpace(value[len("Bearer "):])
	}
	return value
}

func verifyDashboardToken(parent context.Context, raw string) verifyTokenResponse {
	token := normalizeBearerInput(raw)
	if token == "" {
		return verifyTokenResponse{Status: "-"}
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return verifyTokenResponse{Format: "opaque token", Status: "opaque token"}
	}

	var header struct {
		Algorithm string `json:"alg"`
		Type      string `json:"typ"`
	}
	if err := decodeBase64URLJSON(parts[0], &header); err != nil {
		return verifyTokenResponse{Format: "opaque token", Status: "opaque token", Detail: err.Error()}
	}
	resp := verifyTokenResponse{Format: "JWT", Algorithm: header.Algorithm}
	if header.Algorithm != "RS256" {
		resp.Status = "unsupported algorithm"
		resp.Detail = fmt.Sprintf("unsupported JWT alg %q", header.Algorithm)
		return resp
	}

	var claims struct {
		Issuer string   `json:"iss"`
		NBF    oidcTime `json:"nbf"`
	}
	if err := decodeBase64URLJSON(parts[1], &claims); err != nil {
		resp.Status = "opaque token"
		resp.Detail = err.Error()
		return resp
	}
	if claims.Issuer == "" {
		resp.Status = "verification unavailable"
		resp.Detail = "JWT does not contain iss claim"
		return resp
	}

	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	provider, err := oidc.NewProvider(ctx, claims.Issuer)
	if err != nil {
		resp.Status = "verification unavailable"
		resp.Detail = err.Error()
		return resp
	}
	verifier := provider.VerifierContext(ctx, &oidc.Config{
		SkipClientIDCheck:    true,
		SupportedSigningAlgs: []string{"RS256"},
	})
	if _, err := verifier.Verify(ctx, token); err != nil {
		var expired *oidc.TokenExpiredError
		if errors.As(err, &expired) {
			resp.Status = "expired"
			resp.Detail = err.Error()
			return resp
		}
		if strings.Contains(err.Error(), "before the nbf") {
			resp.Status = "not yet valid"
			resp.Detail = err.Error()
			return resp
		}
		if strings.Contains(err.Error(), "fetching keys") {
			resp.Status = "verification unavailable"
			resp.Detail = err.Error()
			return resp
		}
		resp.Status = "signature invalid"
		resp.Detail = err.Error()
		return resp
	}
	if !claims.NBF.Time.IsZero() && time.Now().Before(claims.NBF.Time) {
		resp.Status = "not yet valid"
		resp.Detail = fmt.Sprintf("token is not valid before %s", claims.NBF.Time.Format(time.RFC3339))
		return resp
	}
	resp.Verified = true
	resp.Status = "signature verified"
	return resp
}

type oidcTime struct {
	Time time.Time
}

func (t *oidcTime) UnmarshalJSON(data []byte) error {
	var seconds float64
	if err := json.Unmarshal(data, &seconds); err != nil {
		return err
	}
	t.Time = time.Unix(int64(seconds), 0)
	return nil
}

func decodeBase64URLJSON(value string, target any) error {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return err
	}
	return json.Unmarshal(decoded, target)
}

func staticHandler() http.Handler {
	sub, err := fs.Sub(staticFiles, "static")
	if err != nil {
		panic(err)
	}
	return http.FileServer(http.FS(sub))
}

func favicon(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "image/svg+xml")
	_, _ = w.Write([]byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
  <rect width="64" height="64" rx="14" fill="#111827"/>
  <path d="M16 18h32v8H26v8h18v8H26v8h23v8H16z" fill="#74a5ff"/>
  <path d="M44 12l10 10-10 10v-7H31v-6h13z" fill="#50c878"/>
</svg>`))
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		log.Printf("write response: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func envDefault(name, fallback string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	return value
}

func dashboardURL(addr string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("parse dashboard address %q: %w", addr, err)
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	u := url.URL{
		Scheme: "http",
		Host:   net.JoinHostPort(host, port),
		Path:   "/",
	}
	return u.String(), nil
}

func validKubernetesName(value string) bool {
	if value == "" || len(value) > 253 {
		return false
	}
	for i, r := range value {
		valid := r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-'
		if !valid {
			return false
		}
		if (i == 0 || i == len(value)-1) && r == '-' {
			return false
		}
	}
	return true
}
