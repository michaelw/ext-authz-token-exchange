package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	defaultListenAddr      = ":8080"
	defaultClientID        = "e2e-client"
	defaultClientSecret    = "e2e-secret"
	accessTokenType        = "urn:ietf:params:oauth:token-type:access_token"
	contentTypeJSON        = "application/json"
	contentTypeFormEncoded = "application/x-www-form-urlencoded"
)

func main() {
	addr := envDefault("FAKE_TOKEN_ENDPOINT_ADDR", defaultListenAddr)
	clientID := envDefault("FAKE_TOKEN_ENDPOINT_CLIENT_ID", defaultClientID)
	clientSecret := envDefault("FAKE_TOKEN_ENDPOINT_CLIENT_SECRET", defaultClientSecret)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/token/", tokenHandler(clientID, clientSecret))

	log.Printf("starting fake token endpoint on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("fake token endpoint failed: %v", err)
	}
}

func tokenHandler(clientID, clientSecret string) http.HandlerFunc {
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
		log.Printf("token request scenario=%s subject_token=%q", strings.TrimPrefix(r.URL.Path, "/token/"), r.FormValue("subject_token"))

		switch strings.TrimPrefix(r.URL.Path, "/token/") {
		case "success", "yellow", "red", "blue":
			writeJSON(w, http.StatusOK, map[string]string{
				"access_token":      exchangedToken(r),
				"issued_token_type": accessTokenType,
				"token_type":        "Bearer",
			})
		case "invalid-request":
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid token exchange request")
		case "invalid-target":
			writeOAuthError(w, http.StatusBadRequest, "invalid_target", "resource or audience is invalid")
		case "invalid-grant":
			writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "subject token is invalid")
		case "expired-subject-token":
			writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "subject_token_expired")
		case "unauthorized":
			w.Header().Add("WWW-Authenticate", `Bearer realm="issuer", error="invalid_token"`)
			writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "client rejected")
		case "forbidden":
			writeOAuthError(w, http.StatusForbidden, "invalid_target", "target rejected")
		case "server-error":
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "temporarily_unavailable"})
		case "malformed":
			w.Header().Set("Content-Type", contentTypeJSON)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"access_token":`))
		case "missing-access-token":
			writeJSON(w, http.StatusOK, map[string]string{
				"issued_token_type": accessTokenType,
				"token_type":        "Bearer",
			})
		case "wrong-token-type":
			writeJSON(w, http.StatusOK, map[string]string{
				"access_token":      exchangedToken(r),
				"issued_token_type": accessTokenType,
				"token_type":        "N_A",
			})
		case "wrong-issued-token-type":
			writeJSON(w, http.StatusOK, map[string]string{
				"access_token":      exchangedToken(r),
				"issued_token_type": "urn:ietf:params:oauth:token-type:refresh_token",
				"token_type":        "Bearer",
			})
		case "delay":
			time.Sleep(10 * time.Second)
			writeJSON(w, http.StatusOK, map[string]string{
				"access_token":      exchangedToken(r),
				"issued_token_type": accessTokenType,
				"token_type":        "Bearer",
			})
		default:
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "unknown fake token scenario")
		}
	}
}

func validClient(r *http.Request, clientID, clientSecret string) bool {
	if gotID, gotSecret, ok := r.BasicAuth(); ok {
		return gotID == clientID && gotSecret == clientSecret
	}
	return r.FormValue("client_id") == clientID && r.FormValue("client_secret") == clientSecret
}

func exchangedToken(r *http.Request) string {
	scenario := strings.TrimPrefix(r.URL.Path, "/token/")
	subject := strings.TrimSpace(r.FormValue("subject_token"))
	if subject == "" {
		subject = "missing-subject"
	}
	return fmt.Sprintf("exchanged-%s-%s", scenario, subject)
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
