package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/michaelw/ext-authz-token-exchange/internal/demo"
)

func TestDashboardURL(t *testing.T) {
	tests := []struct {
		name string
		addr string
		want string
	}{
		{
			name: "loopback",
			addr: "127.0.0.1:8088",
			want: "http://127.0.0.1:8088/",
		},
		{
			name: "empty host",
			addr: ":8088",
			want: "http://127.0.0.1:8088/",
		},
		{
			name: "ipv4 unspecified",
			addr: "0.0.0.0:8088",
			want: "http://127.0.0.1:8088/",
		},
		{
			name: "ipv6 unspecified",
			addr: "[::]:8088",
			want: "http://127.0.0.1:8088/",
		},
		{
			name: "ipv6 concrete",
			addr: "[::1]:8088",
			want: "http://[::1]:8088/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := dashboardURL(tt.addr)
			if err != nil {
				t.Fatalf("dashboardURL(%q) returned error: %v", tt.addr, err)
			}
			if got != tt.want {
				t.Fatalf("dashboardURL(%q) = %q, want %q", tt.addr, got, tt.want)
			}
		})
	}
}

func TestDeploymentStatus(t *testing.T) {
	tests := []struct {
		name      string
		kubectl   string
		wantReady bool
		wantAvail string
		wantWarn  string
	}{
		{
			name:      "available replicas match desired replicas",
			kubectl:   "printf '1/1'",
			wantReady: true,
			wantAvail: "1/1",
		},
		{
			name:      "scaled to zero is not ready",
			kubectl:   "printf '/0'",
			wantReady: false,
			wantAvail: "/0",
		},
		{
			name:      "missing deployment is not ready",
			kubectl:   "echo 'deployment not found' >&2\nexit 1",
			wantReady: false,
			wantWarn:  "deployment not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withKubectl(t, tt.kubectl)
			got := deploymentStatus(context.Background(), "test-namespace", "test-deploy")
			if got.Ready != tt.wantReady {
				t.Fatalf("Ready = %v, want %v", got.Ready, tt.wantReady)
			}
			if got.Available != tt.wantAvail {
				t.Fatalf("Available = %q, want %q", got.Available, tt.wantAvail)
			}
			if tt.wantWarn != "" && !strings.Contains(got.Warning, tt.wantWarn) {
				t.Fatalf("Warning = %q, want to contain %q", got.Warning, tt.wantWarn)
			}
		})
	}
}

func TestSelectIssuerDetectsKeycloakDeployment(t *testing.T) {
	withKubectl(t, `printf 'http://keycloak.ext-authz-token-exchange-e2e.svc.cluster.local:8080/realms/token-exchange-e2e/protocol/openid-connect/token'`)
	t.Setenv("DEMO_SCENARIO_CONFIG", "")

	opts := selectIssuer(context.Background(), demoOptions())

	if opts.Name != "keycloak" {
		t.Fatalf("Name = %q, want keycloak", opts.Name)
	}
	if opts.ScenarioConfig != keycloakConfigPath {
		t.Fatalf("ScenarioConfig = %q, want %q", opts.ScenarioConfig, keycloakConfigPath)
	}
	if got := opts.apply(demoOptions()).ConfigPath; got != keycloakConfigPath {
		t.Fatalf("applied ConfigPath = %q, want %q", got, keycloakConfigPath)
	}
}

func TestSelectIssuerDetectsFakeDeployment(t *testing.T) {
	withKubectl(t, `printf 'http://fake-token-endpoint.ext-authz-token-exchange-e2e.svc.cluster.local:8080/token/success'`)
	t.Setenv("DEMO_SCENARIO_CONFIG", "")

	opts := selectIssuer(context.Background(), demoOptions())

	if opts.Name != "fake" {
		t.Fatalf("Name = %q, want fake", opts.Name)
	}
	if got := opts.apply(demoOptions()).ConfigPath; got != "test/e2e/demo-scenarios.yaml" {
		t.Fatalf("applied ConfigPath = %q, want default fake scenario config", got)
	}
}

func TestSelectIssuerKeepsExplicitScenarioConfig(t *testing.T) {
	withKubectl(t, `printf 'http://keycloak.ext-authz-token-exchange-e2e.svc.cluster.local:8080/realms/token-exchange-e2e/protocol/openid-connect/token'`)
	t.Setenv("DEMO_SCENARIO_CONFIG", "custom.yaml")
	opts := demoOptions()
	opts.ConfigPath = "custom.yaml"

	selection := selectIssuer(context.Background(), opts)
	applied := selection.apply(opts)

	if selection.Name != "fake" {
		t.Fatalf("Name = %q, want fake fallback for custom config", selection.Name)
	}
	if applied.ConfigPath != "custom.yaml" {
		t.Fatalf("ConfigPath = %q, want explicit custom.yaml", applied.ConfigPath)
	}
}

func TestVerifyDashboardTokenStatuses(t *testing.T) {
	oidcServer, key := newOIDCTestServer(t)
	defer oidcServer.Close()

	valid := signJWT(t, key, oidcServer.URL, "RS256", time.Now().Add(5*time.Minute))
	expired := signJWT(t, key, oidcServer.URL, "RS256", time.Now().Add(-time.Minute))
	unsupported := signJWT(t, key, oidcServer.URL, "HS256", time.Now().Add(5*time.Minute))
	parts := strings.Split(valid, ".")
	payload := defaultJWTClaims(oidcServer.URL, time.Now().Add(5*time.Minute))
	payload["sub"] = "tampered"
	tampered := parts[0] + "." + base64URLJSON(t, payload) + "." + parts[2]
	notYetValidPayload := defaultJWTClaims(oidcServer.URL, time.Now().Add(15*time.Minute))
	notYetValidPayload["nbf"] = time.Now().Add(10 * time.Minute).Unix()
	notYetValid := signJWTClaims(t, key, "RS256", notYetValidPayload)

	tests := []struct {
		name       string
		token      string
		wantFormat string
		wantAlg    string
		wantStatus string
		wantOK     bool
	}{
		{
			name:       "valid RS256 token",
			token:      valid,
			wantFormat: "JWT",
			wantAlg:    "RS256",
			wantStatus: "signature verified",
			wantOK:     true,
		},
		{
			name:       "tampered signature",
			token:      tampered,
			wantFormat: "JWT",
			wantAlg:    "RS256",
			wantStatus: "signature invalid",
		},
		{
			name:       "expired token",
			token:      expired,
			wantFormat: "JWT",
			wantAlg:    "RS256",
			wantStatus: "expired",
		},
		{
			name:       "unsupported algorithm",
			token:      unsupported,
			wantFormat: "JWT",
			wantAlg:    "HS256",
			wantStatus: "unsupported algorithm",
		},
		{
			name:       "not yet valid token",
			token:      notYetValid,
			wantFormat: "JWT",
			wantAlg:    "RS256",
			wantStatus: "not yet valid",
		},
		{
			name:       "opaque token",
			token:      "not-a-jwt",
			wantFormat: "opaque token",
			wantStatus: "opaque token",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := verifyDashboardToken(context.Background(), tt.token)
			if got.Format != tt.wantFormat {
				t.Fatalf("Format = %q, want %q; detail=%s", got.Format, tt.wantFormat, got.Detail)
			}
			if got.Algorithm != tt.wantAlg {
				t.Fatalf("Algorithm = %q, want %q", got.Algorithm, tt.wantAlg)
			}
			if got.Status != tt.wantStatus {
				t.Fatalf("Status = %q, want %q; detail=%s", got.Status, tt.wantStatus, got.Detail)
			}
			if got.Verified != tt.wantOK {
				t.Fatalf("Verified = %v, want %v", got.Verified, tt.wantOK)
			}
		})
	}
}

func TestVerifyDashboardTokenReportsDiscoveryFailure(t *testing.T) {
	token := signJWT(t, mustRSAKey(t), "http://127.0.0.1:1", "RS256", time.Now().Add(5*time.Minute))

	got := verifyDashboardToken(context.Background(), token)

	if got.Format != "JWT" {
		t.Fatalf("Format = %q, want JWT", got.Format)
	}
	if got.Status != "verification unavailable" {
		t.Fatalf("Status = %q, want verification unavailable", got.Status)
	}
	if got.Detail == "" {
		t.Fatalf("Detail is empty, want discovery error detail")
	}
}

func TestVerifyDashboardTokenReportsJWKSFailure(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":   server.URL,
			"jwks_uri": server.URL + "/missing-keys",
		})
	}))
	defer server.Close()
	token := signJWT(t, mustRSAKey(t), server.URL, "RS256", time.Now().Add(5*time.Minute))

	got := verifyDashboardToken(context.Background(), token)

	if got.Status != "verification unavailable" {
		t.Fatalf("Status = %q, want verification unavailable; detail=%s", got.Status, got.Detail)
	}
}

func TestVerifyTokenEndpoint(t *testing.T) {
	s := &server{}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/token/verify", strings.NewReader(`{"token":"opaque"}`))

	s.verifyToken(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var got verifyTokenResponse
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.Format != "opaque token" || got.Status != "opaque token" {
		t.Fatalf("response = %+v, want opaque token format and status", got)
	}
}

func TestScenarioTokenFetchesKeycloakSubjectToken(t *testing.T) {
	keycloak := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/realms/token-exchange-e2e/protocol/openid-connect/token" {
			t.Fatalf("Path = %q, want token endpoint", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Fatalf("Method = %q, want POST", r.Method)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		want := map[string]string{
			"grant_type":    "password",
			"client_id":     "tx-subject-client",
			"client_secret": "tx-subject-secret",
			"username":      "token-user",
			"password":      "token-user-password",
			"scope":         "profile",
		}
		for key, value := range want {
			if got := r.Form.Get(key); got != value {
				t.Fatalf("form %s = %q, want %q", key, got, value)
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"access_token": "subject-token",
			"token_type":   "Bearer",
		})
	}))
	defer keycloak.Close()
	t.Setenv("DEMO_KEYCLOAK_BASE_URL", keycloak.URL)
	opts := demoOptions()
	opts.ConfigPath = writeScenarioConfig(t, `version: v1
scenarios:
  - name: keycloak-audience
    request:
      path: /anything/keycloak-audience
    behavior:
      summary: Keycloak exchanges a token.
      detail: Keycloak returns a demo token.
`)
	s := &server{opts: opts, issuer: keycloakIssuer()}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/scenarios/keycloak-audience/token", nil)
	req.SetPathValue("name", "keycloak-audience")

	s.scenarioToken(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var got tokenResponse
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.Bearer != "subject-token" {
		t.Fatalf("Bearer = %q, want subject-token", got.Bearer)
	}
	if got.Source != "keycloak" {
		t.Fatalf("Source = %q, want keycloak", got.Source)
	}
}

func TestScenarioTokenReturnsFakeScenarioBearer(t *testing.T) {
	opts := demoOptions()
	opts.ConfigPath = writeScenarioConfig(t, `version: v1
scenarios:
  - name: yellow-success
    request:
      path: /anything/yellow
      bearer: incoming-yellow
    behavior:
      summary: Returns a Bearer access token.
      detail: Returns HTTP 200 with access_token, issued_token_type=access_token, and token_type=Bearer.
`)
	s := &server{opts: opts, issuer: fakeIssuer()}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/scenarios/yellow-success/token", nil)
	req.SetPathValue("name", "yellow-success")

	s.scenarioToken(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var got tokenResponse
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.Bearer != "incoming-yellow" {
		t.Fatalf("Bearer = %q, want incoming-yellow", got.Bearer)
	}
	if got.Source != "scenario" {
		t.Fatalf("Source = %q, want scenario", got.Source)
	}
}

func TestRunOneUsesBearerOverride(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"headers": map[string][]string{
				"Authorization": []string{r.Header.Get("Authorization")},
			},
		})
	}))
	defer upstream.Close()
	opts := demoOptions()
	opts.BaseURL = upstream.URL
	opts.ConfigPath = writeScenarioConfig(t, `version: v1
scenarios:
  - name: yellow-success
    request:
      path: /anything/yellow
      bearer: configured-token
    behavior:
      summary: Returns a Bearer access token.
      detail: Returns HTTP 200 with access_token, issued_token_type=access_token, and token_type=Bearer.
    expect:
      status: 200
      upstreamAuthorization: Bearer pasted-token
`)
	s := &server{opts: opts, issuer: fakeIssuer()}
	rr := httptest.NewRecorder()
	reqBody := bytes.NewBufferString(`{"bearer":"Bearer pasted-token"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/scenarios/yellow-success/run", reqBody)
	req.SetPathValue("name", "yellow-success")

	s.runOne(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var got demo.Result
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.Scenario.Request.Bearer != "pasted-token" {
		t.Fatalf("scenario bearer = %q, want pasted-token", got.Scenario.Request.Bearer)
	}
	if got.Observed.Auth != "Bearer pasted-token" {
		t.Fatalf("observed auth = %q, want pasted token", got.Observed.Auth)
	}
}

func TestRunOneAllowsEmptyBearerOverride(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "" {
			t.Fatalf("Authorization = %q, want empty", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"headers": map[string][]string{},
		})
	}))
	defer upstream.Close()
	opts := demoOptions()
	opts.BaseURL = upstream.URL
	opts.ConfigPath = writeScenarioConfig(t, `version: v1
scenarios:
  - name: missing-bearer
    request:
      path: /anything/yellow
      bearer: configured-token
    behavior:
      summary: Returns a Bearer access token.
      detail: Returns HTTP 200 with access_token, issued_token_type=access_token, and token_type=Bearer.
    expect:
      status: 200
`)
	s := &server{opts: opts, issuer: fakeIssuer()}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/scenarios/missing-bearer/run", bytes.NewBufferString(`{"bearer":""}`))
	req.SetPathValue("name", "missing-bearer")

	s.runOne(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var got demo.Result
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.Scenario.Request.Bearer != "" {
		t.Fatalf("scenario bearer = %q, want empty", got.Scenario.Request.Bearer)
	}
}

func TestRunOneWithoutBodyKeepsConfiguredBearer(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"headers": map[string][]string{
				"Authorization": []string{r.Header.Get("Authorization")},
			},
		})
	}))
	defer upstream.Close()
	opts := demoOptions()
	opts.BaseURL = upstream.URL
	opts.ConfigPath = writeScenarioConfig(t, `version: v1
scenarios:
  - name: yellow-success
    request:
      path: /anything/yellow
      bearer: configured-token
    behavior:
      summary: Returns a Bearer access token.
      detail: Returns HTTP 200 with access_token, issued_token_type=access_token, and token_type=Bearer.
    expect:
      status: 200
      upstreamAuthorization: Bearer configured-token
`)
	s := &server{opts: opts, issuer: fakeIssuer()}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/scenarios/yellow-success/run", nil)
	req.SetPathValue("name", "yellow-success")

	s.runOne(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var got demo.Result
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.Scenario.Request.Bearer != "configured-token" {
		t.Fatalf("scenario bearer = %q, want configured-token", got.Scenario.Request.Bearer)
	}
	if got.Observed.Auth != "Bearer configured-token" {
		t.Fatalf("observed auth = %q, want configured token", got.Observed.Auth)
	}
}

func demoOptions() demo.Options {
	return demo.Options{
		ConfigPath:       "test/e2e/demo-scenarios.yaml",
		PluginNamespace:  "ext-authz-token-exchange",
		PluginDeployment: "ext-authz-token-exchange",
		SystemNamespace:  "ext-authz-token-exchange-e2e",
	}
}

func withKubectl(t *testing.T, script string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "kubectl")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script+"\n"), 0o755); err != nil {
		t.Fatalf("write fake kubectl: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func writeScenarioConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "scenarios.yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write scenario config: %v", err)
	}
	return path
}

func newOIDCTestServer(t *testing.T) (*httptest.Server, *rsa.PrivateKey) {
	t.Helper()
	key := mustRSAKey(t)
	const kid = "test-key"
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":   server.URL,
				"jwks_uri": server.URL + "/keys",
			})
		case "/keys":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"keys": []map[string]string{rsaJWK(kid, &key.PublicKey)},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	return server, key
}

func mustRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return key
}

func signJWT(t *testing.T, key *rsa.PrivateKey, issuer, alg string, exp time.Time) string {
	t.Helper()
	return signJWTClaims(t, key, alg, defaultJWTClaims(issuer, exp))
}

func defaultJWTClaims(issuer string, exp time.Time) map[string]any {
	return map[string]any{
		"iss": issuer,
		"sub": "token-user",
		"aud": "tx-audience-client",
		"azp": "tx-subject-client",
		"exp": exp.Unix(),
		"iat": time.Now().Add(-time.Minute).Unix(),
	}
}

func signJWTClaims(t *testing.T, key *rsa.PrivateKey, alg string, payload map[string]any) string {
	t.Helper()
	header := map[string]any{
		"alg": alg,
		"typ": "JWT",
		"kid": "test-key",
	}
	unsigned := base64URLJSON(t, header) + "." + base64URLJSON(t, payload)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign JWT: %v", err)
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func base64URLJSON(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal JWT JSON: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(encoded)
}

func rsaJWK(kid string, key *rsa.PublicKey) map[string]string {
	return map[string]string{
		"kty": "RSA",
		"use": "sig",
		"kid": kid,
		"alg": "RS256",
		"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}
}
