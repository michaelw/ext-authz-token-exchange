package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestSuccessfulExchangeReturnsUnsignedJWTWithExchangeInputs(t *testing.T) {
	handler := tokenHandler("e2e-client", "e2e-secret")
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	form.Set("subject_token", "incoming-yellow")
	form.Set("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
	form.Set("scope", "yellow")
	form.Add("resource", "https://httpbin.int.kube/anything/yellow")
	form.Add("audience", "httpbin-yellow")

	req := httptest.NewRequest(http.MethodPost, "/token/yellow", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", contentTypeFormEncoded)
	req.SetBasicAuth("e2e-client", "e2e-secret")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body["token_type"] != "Bearer" {
		t.Fatalf("token_type = %q, want Bearer", body["token_type"])
	}
	if body["issued_token_type"] != accessTokenType {
		t.Fatalf("issued_token_type = %q, want %q", body["issued_token_type"], accessTokenType)
	}

	header, payload := decodeUnsignedJWT(t, body["access_token"])
	if header["alg"] != "none" || header["typ"] != "JWT" {
		t.Fatalf("header = %#v, want alg=none typ=JWT", header)
	}
	wantStringClaims := map[string]string{
		"iss":                "fake-token-endpoint",
		"scenario":           "yellow",
		"sub":                "incoming-yellow",
		"subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
		"grant_type":         "urn:ietf:params:oauth:grant-type:token-exchange",
		"scope":              "yellow",
		"client_id":          "e2e-client",
	}
	for key, want := range wantStringClaims {
		if got, _ := payload[key].(string); got != want {
			t.Fatalf("payload[%q] = %#v, want %q", key, payload[key], want)
		}
	}
	assertStringArrayClaim(t, payload, "resource", []string{"https://httpbin.int.kube/anything/yellow"})
	assertStringArrayClaim(t, payload, "aud", []string{"httpbin-yellow"})
	if _, ok := payload["client_secret"]; ok {
		t.Fatalf("payload must not include client_secret: %#v", payload)
	}
}

func decodeUnsignedJWT(t *testing.T, token string) (map[string]any, map[string]any) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[2] != "" {
		t.Fatalf("token = %q, want unsigned JWT with trailing dot", token)
	}
	var header map[string]any
	if err := decodeBase64URLJSON(parts[0], &header); err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var payload map[string]any
	if err := decodeBase64URLJSON(parts[1], &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	return header, payload
}

func decodeBase64URLJSON(part string, out any) error {
	decoded, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		return err
	}
	return json.Unmarshal(decoded, out)
}

func assertStringArrayClaim(t *testing.T, payload map[string]any, key string, want []string) {
	t.Helper()
	raw, ok := payload[key].([]any)
	if !ok {
		t.Fatalf("payload[%q] = %#v, want array", key, payload[key])
	}
	if len(raw) != len(want) {
		t.Fatalf("payload[%q] length = %d, want %d", key, len(raw), len(want))
	}
	for i, item := range raw {
		if got, _ := item.(string); got != want[i] {
			t.Fatalf("payload[%q][%d] = %#v, want %q", key, i, item, want[i])
		}
	}
}
