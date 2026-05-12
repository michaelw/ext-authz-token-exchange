package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/michaelw/ext-authz-token-exchange/internal/telemetry"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
)

const (
	defaultListenAddr      = ":8080"
	defaultClientID        = "e2e-client"
	defaultClientSecret    = "e2e-secret"
	defaultServiceName     = "fake-token-endpoint"
	accessTokenType        = "urn:ietf:params:oauth:token-type:access_token"
	contentTypeJSON        = "application/json"
	contentTypeFormEncoded = "application/x-www-form-urlencoded"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	addr := envDefault("FAKE_TOKEN_ENDPOINT_ADDR", defaultListenAddr)
	clientID := envDefault("FAKE_TOKEN_ENDPOINT_CLIENT_ID", defaultClientID)
	clientSecret := envDefault("FAKE_TOKEN_ENDPOINT_CLIENT_SECRET", defaultClientSecret)
	configPath := strings.TrimSpace(os.Getenv("FAKE_TOKEN_ENDPOINT_CONFIG"))
	cfg, err := loadFakeConfig(configPath)
	if err != nil {
		log.Fatalf("failed to load fake token endpoint config: %v", err)
	}

	shutdownTelemetry, err := telemetry.InitWithServiceName(ctx, defaultServiceName)
	if err != nil {
		log.Fatalf("failed to initialize telemetry: %v", err)
	}
	defer func() {
		if err := shutdownTelemetry(context.Background()); err != nil {
			log.Printf("failed to shut down telemetry: %v", err)
		}
	}()

	server := &http.Server{
		Addr:    addr,
		Handler: fakeTokenEndpointHandler(clientID, clientSecret, cfg),
	}
	go func() {
		<-ctx.Done()
		if err := server.Shutdown(context.Background()); err != nil {
			log.Printf("fake token endpoint shutdown failed: %v", err)
		}
	}()

	log.Printf("starting fake token endpoint on %s", addr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("fake token endpoint failed: %v", err)
	}
}

func fakeTokenEndpointHandler(clientID, clientSecret string, cfg fakeConfig) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.Handle("/token/", otelhttp.NewHandler(
		tokenHandler(clientID, clientSecret, cfg),
		"fake_token_endpoint token",
		otelhttp.WithPropagators(telemetry.Propagators()),
		otelhttp.WithTracerProvider(otel.GetTracerProvider()),
	))
	return mux
}

func tokenHandler(clientID, clientSecret string, cfg fakeConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "POST required")
			return
		}
		if contentType := r.Header.Get("Content-Type"); contentType != "" && !strings.HasPrefix(contentType, contentTypeFormEncoded) {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "form encoding required")
			return
		}
		if !validClient(r, clientID, clientSecret) {
			w.Header().Add("WWW-Authenticate", `Basic realm="fake-token-endpoint"`)
			writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
			return
		}
		if err := r.ParseForm(); err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid form")
			return
		}
		route := cfg.routeFor(r)
		scenario := route.scenario()
		log.Printf("token request route=%s scenario=%s", route.Name, scenario)

		switch route.Response.Type {
		case responseSuccess:
			writeJSON(w, http.StatusOK, map[string]string{
				"access_token":      exchangedToken(r, authenticatedClientID(r), scenario),
				"issued_token_type": accessTokenType,
				"token_type":        "Bearer",
			})
		case responseOAuthError:
			if route.Response.WWWAuthenticate != "" {
				w.Header().Add("WWW-Authenticate", route.Response.WWWAuthenticate)
			}
			writeOAuthError(w, statusDefault(route.Response.Status, http.StatusBadRequest), route.Response.Error, route.Response.ErrorDescription)
		case responseJSONError:
			writeJSON(w, statusDefault(route.Response.Status, http.StatusInternalServerError), map[string]string{"error": route.Response.Error})
		case responseMalformed:
			w.Header().Set("Content-Type", contentTypeJSON)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"access_token":`))
		case responseMissingAccessToken:
			writeJSON(w, http.StatusOK, map[string]string{
				"issued_token_type": accessTokenType,
				"token_type":        "Bearer",
			})
		case responseWrongTokenType:
			writeJSON(w, http.StatusOK, map[string]string{
				"access_token":      exchangedToken(r, authenticatedClientID(r), scenario),
				"issued_token_type": accessTokenType,
				"token_type":        "N_A",
			})
		case responseWrongIssuedTokenType:
			writeJSON(w, http.StatusOK, map[string]string{
				"access_token":      exchangedToken(r, authenticatedClientID(r), scenario),
				"issued_token_type": "urn:ietf:params:oauth:token-type:refresh_token",
				"token_type":        "Bearer",
			})
		case responseDelay:
			time.Sleep(time.Duration(intDefault(route.Response.DelayMilliseconds, 10000)) * time.Millisecond)
			writeJSON(w, http.StatusOK, map[string]string{
				"access_token":      exchangedToken(r, authenticatedClientID(r), scenario),
				"issued_token_type": accessTokenType,
				"token_type":        "Bearer",
			})
		default:
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "fake token endpoint route is invalid")
		}
	}
}

func validClient(r *http.Request, clientID, clientSecret string) bool {
	if gotID, gotSecret, ok := r.BasicAuth(); ok {
		return gotID == clientID && gotSecret == clientSecret
	}
	return r.FormValue("client_id") == clientID && r.FormValue("client_secret") == clientSecret
}

func authenticatedClientID(r *http.Request) string {
	if clientID, _, ok := r.BasicAuth(); ok {
		return clientID
	}
	return strings.TrimSpace(r.FormValue("client_id"))
}

func exchangedToken(r *http.Request, clientID string, scenario string) string {
	subject := strings.TrimSpace(r.FormValue("subject_token"))
	if subject == "" {
		subject = "missing-subject"
	}

	payload := map[string]any{
		"iss":                "fake-token-endpoint",
		"scenario":           scenario,
		"sub":                subject,
		"subject_token_type": strings.TrimSpace(r.FormValue("subject_token_type")),
		"grant_type":         strings.TrimSpace(r.FormValue("grant_type")),
		"client_id":          clientID,
	}
	if scope := strings.TrimSpace(r.FormValue("scope")); scope != "" {
		payload["scope"] = scope
	}
	if resources := compactFormValues(r.Form["resource"]); len(resources) > 0 {
		payload["resource"] = resources
	}
	if audiences := compactFormValues(r.Form["audience"]); len(audiences) > 0 {
		payload["aud"] = audiences
	}
	return unsignedJWT(payload)
}

func unsignedJWT(payload map[string]any) string {
	header := map[string]string{"alg": "none", "typ": "JWT"}
	return base64URLJSON(header) + "." + base64URLJSON(payload) + "."
}

func base64URLJSON(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(data)
}

func compactFormValues(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

func writeOAuthError(w http.ResponseWriter, status int, code, description string) {
	writeJSON(w, status, map[string]string{
		"error":             code,
		"error_description": description,
	})
}

func writeJSON(w http.ResponseWriter, status int, body map[string]string) {
	w.Header().Set("Content-Type", contentTypeJSON)
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		log.Printf("failed to write JSON response: %v", err)
	}
}

func envDefault(name, fallback string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	return value
}

func statusDefault(value, fallback int) int {
	if value == 0 {
		return fallback
	}
	return value
}

func intDefault(value, fallback int) int {
	if value == 0 {
		return fallback
	}
	return value
}
