package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/michaelw/ext-authz-token-exchange/internal/telemetry"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

func TestSuccessfulExchangeReturnsUnsignedJWTWithExchangeInputs(t *testing.T) {
	handler := tokenHandler("e2e-client", "e2e-secret", defaultFakeConfig())
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

func TestTokenHandlerSupportsClientSecretPost(t *testing.T) {
	handler := tokenHandler("e2e-client", "e2e-secret", defaultFakeConfig())
	form := baseTokenForm()
	form.Set("client_id", "e2e-client")
	form.Set("client_secret", "e2e-secret")

	req := httptest.NewRequest(http.MethodPost, "/token/blue", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", contentTypeFormEncoded)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	_, payload := decodeUnsignedJWT(t, body["access_token"])
	if got, _ := payload["client_id"].(string); got != "e2e-client" {
		t.Fatalf("client_id claim = %#v, want e2e-client", payload["client_id"])
	}
}

func TestSuccessEndpointDerivesScenarioFromExchangeRequest(t *testing.T) {
	cases := []struct {
		name       string
		form       url.Values
		wantStatus int
		want       string
	}{
		{
			name: "color audience",
			form: func() url.Values {
				form := baseTokenForm()
				form.Add("audience", "httpbin-red")
				form.Set("scope", "red-v2")
				return form
			}(),
			wantStatus: http.StatusOK,
			want:       "red",
		},
		{
			name: "error resource",
			form: func() url.Values {
				form := baseTokenForm()
				form.Add("resource", "https://httpbin.int.kube/anything/error-invalid-grant")
				return form
			}(),
			wantStatus: http.StatusBadRequest,
			want:       "invalid_grant",
		},
	}

	handler := tokenHandler("e2e-client", "e2e-secret", defaultFakeConfig())
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/token/success", strings.NewReader(tc.form.Encode()))
			req.Header.Set("Content-Type", contentTypeFormEncoded)
			req.SetBasicAuth("e2e-client", "e2e-secret")
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			var body map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if rec.Code == http.StatusOK {
				_, payload := decodeUnsignedJWT(t, body["access_token"])
				if got, _ := payload["scenario"].(string); got != tc.want {
					t.Fatalf("scenario = %q, want %q", got, tc.want)
				}
				return
			}
			if got := body["error"]; got != tc.want {
				t.Fatalf("error = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestFakeConfigRoutesByExactRequestInputs(t *testing.T) {
	cfg := fakeConfig{
		Routes: []fakeRoute{
			{
				Name:     "red-audience",
				Match:    fakeMatch{Audience: "httpbin-red"},
				Response: fakeResponse{Type: responseSuccess, Scenario: "red"},
			},
			{
				Name:  "invalid-grant-resource",
				Match: fakeMatch{Resource: "https://httpbin.int.kube/anything/error-invalid-grant"},
				Response: fakeResponse{
					Type:             responseOAuthError,
					Status:           http.StatusBadRequest,
					Error:            "invalid_grant",
					ErrorDescription: "subject token is invalid",
				},
			},
		},
		DefaultResponse: fakeResponse{
			Type:             responseOAuthError,
			Status:           http.StatusBadRequest,
			Error:            "invalid_request",
			ErrorDescription: "unknown fake token scenario",
		},
	}
	if err := (&cfg).validate(); err != nil {
		t.Fatalf("validate config: %v", err)
	}
	handler := tokenHandler("e2e-client", "e2e-secret", cfg)

	t.Run("matches audience exactly", func(t *testing.T) {
		form := baseTokenForm()
		form.Add("audience", "httpbin-red")
		form.Set("scope", "red-v2")
		req := httptest.NewRequest(http.MethodPost, "/token/success", strings.NewReader(form.Encode()))
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
		_, payload := decodeUnsignedJWT(t, body["access_token"])
		if got, _ := payload["scenario"].(string); got != "red" {
			t.Fatalf("scenario = %q, want red", got)
		}
	})

	t.Run("matches resource exactly", func(t *testing.T) {
		form := baseTokenForm()
		form.Add("resource", "https://httpbin.int.kube/anything/error-invalid-grant")
		req := httptest.NewRequest(http.MethodPost, "/token/success", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", contentTypeFormEncoded)
		req.SetBasicAuth("e2e-client", "e2e-secret")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
		}
		var body map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if got := body["error"]; got != "invalid_grant" {
			t.Fatalf("error = %q, want invalid_grant", got)
		}
	})
}

func TestLoadFakeConfigDefaultsAndNormalizesRoutes(t *testing.T) {
	path := writeFakeConfig(t, `routes:
  - name: "  green route  "
    match:
      path: " /token/green "
      scope: " green "
    response:
      type: " success "
`)

	cfg, err := loadFakeConfig(path)
	if err != nil {
		t.Fatalf("loadFakeConfig: %v", err)
	}
	if len(cfg.Routes) != 1 {
		t.Fatalf("routes = %d, want 1", len(cfg.Routes))
	}
	route := cfg.Routes[0]
	if route.Name != "green route" {
		t.Fatalf("route name = %q, want green route", route.Name)
	}
	if route.Match.Path != "/token/green" || route.Match.Scope != "green" {
		t.Fatalf("route match = %#v, want trimmed path and scope", route.Match)
	}
	if route.scenario() != "green route" {
		t.Fatalf("scenario = %q, want route name fallback", route.scenario())
	}
	if cfg.DefaultResponse.Type != responseOAuthError ||
		cfg.DefaultResponse.Status != http.StatusBadRequest ||
		cfg.DefaultResponse.Error != "invalid_request" {
		t.Fatalf("default response = %#v, want configured unknown scenario OAuth error", cfg.DefaultResponse)
	}
}

func TestFakeConfigRouteOrderFirstMatchWins(t *testing.T) {
	cfg := fakeConfig{
		Routes: []fakeRoute{
			{
				Name:  "first-red-audience",
				Match: fakeMatch{Audience: "httpbin-red"},
				Response: fakeResponse{
					Type:             responseOAuthError,
					Status:           http.StatusBadRequest,
					Error:            "invalid_target",
					ErrorDescription: "first route wins",
				},
			},
			{
				Name:     "second-red-audience",
				Match:    fakeMatch{Audience: "httpbin-red"},
				Response: fakeResponse{Type: responseSuccess, Scenario: "red"},
			},
		},
		DefaultResponse: defaultUnknownResponse(),
	}
	if err := (&cfg).validate(); err != nil {
		t.Fatalf("validate config: %v", err)
	}
	handler := tokenHandler("e2e-client", "e2e-secret", cfg)
	form := baseTokenForm()
	form.Add("audience", "httpbin-red")
	req := httptest.NewRequest(http.MethodPost, "/token/success", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", contentTypeFormEncoded)
	req.SetBasicAuth("e2e-client", "e2e-secret")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body["error"] != "invalid_target" || body["error_description"] != "first route wins" {
		t.Fatalf("body = %#v, want first route OAuth error", body)
	}
}

func TestLoadFakeConfigValidatesRoutes(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "duplicate route names",
			body: `routes:
  - name: duplicate
    match:
      path: /token/one
    response:
      type: success
  - name: duplicate
    match:
      path: /token/two
    response:
      type: success
`,
			want: `duplicate route name "duplicate"`,
		},
		{
			name: "empty match",
			body: `routes:
  - name: empty
    match: {}
    response:
      type: success
`,
			want: `route "empty" must configure at least one match field`,
		},
		{
			name: "unknown response type",
			body: `routes:
  - name: strange
    match:
      path: /token/strange
    response:
      type: strange
`,
			want: `unknown type "strange"`,
		},
		{
			name: "invalid response status",
			body: `routes:
  - name: invalid-status
    match:
      path: /token/invalid-status
    response:
      type: oauth_error
      status: 99
      error: invalid_request
`,
			want: `response status must be between 100 and 599`,
		},
		{
			name: "negative delay",
			body: `routes:
  - name: negative-delay
    match:
      path: /token/negative-delay
    response:
      type: delay
      delayMilliseconds: -1
`,
			want: `response delayMilliseconds must not be negative`,
		},
		{
			name: "oauth error requires code",
			body: `routes:
  - name: missing-oauth-error
    match:
      path: /token/missing-oauth-error
    response:
      type: oauth_error
      status: 400
`,
			want: `response requires error`,
		},
		{
			name: "json error requires code",
			body: `routes:
  - name: missing-json-error
    match:
      path: /token/missing-json-error
    response:
      type: json_error
      status: 500
`,
			want: `response requires error`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeFakeConfig(t, tc.body)
			_, err := loadFakeConfig(path)
			if err == nil {
				t.Fatalf("loadFakeConfig succeeded, want error containing %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want containing %q", err.Error(), tc.want)
			}
		})
	}
}

func TestTokenHandlerScenarios(t *testing.T) {
	cases := []struct {
		name                string
		method              string
		path                string
		contentType         string
		basicAuth           bool
		wantStatus          int
		wantError           string
		wantDescription     string
		wantWWWAuthenticate string
		wantJSONFields      map[string]string
		wantBody            string
	}{
		{
			name:            "non-post",
			method:          http.MethodGet,
			path:            "/token/yellow",
			basicAuth:       true,
			wantStatus:      http.StatusBadRequest,
			wantError:       "invalid_request",
			wantDescription: "POST required",
		},
		{
			name:            "wrong content type",
			method:          http.MethodPost,
			path:            "/token/yellow",
			contentType:     "application/json",
			basicAuth:       true,
			wantStatus:      http.StatusBadRequest,
			wantError:       "invalid_request",
			wantDescription: "form encoding required",
		},
		{
			name:                "invalid client",
			method:              http.MethodPost,
			path:                "/token/yellow",
			contentType:         contentTypeFormEncoded,
			wantStatus:          http.StatusUnauthorized,
			wantError:           "invalid_client",
			wantDescription:     "client authentication failed",
			wantWWWAuthenticate: `Basic realm="fake-token-endpoint"`,
		},
		{
			name:            "invalid request scenario",
			method:          http.MethodPost,
			path:            "/token/invalid-request",
			contentType:     contentTypeFormEncoded,
			basicAuth:       true,
			wantStatus:      http.StatusBadRequest,
			wantError:       "invalid_request",
			wantDescription: "invalid token exchange request",
		},
		{
			name:            "invalid target scenario",
			method:          http.MethodPost,
			path:            "/token/invalid-target",
			contentType:     contentTypeFormEncoded,
			basicAuth:       true,
			wantStatus:      http.StatusBadRequest,
			wantError:       "invalid_target",
			wantDescription: "resource or audience is invalid",
		},
		{
			name:            "invalid grant scenario",
			method:          http.MethodPost,
			path:            "/token/invalid-grant",
			contentType:     contentTypeFormEncoded,
			basicAuth:       true,
			wantStatus:      http.StatusBadRequest,
			wantError:       "invalid_grant",
			wantDescription: "subject token is invalid",
		},
		{
			name:            "expired subject token scenario",
			method:          http.MethodPost,
			path:            "/token/expired-subject-token",
			contentType:     contentTypeFormEncoded,
			basicAuth:       true,
			wantStatus:      http.StatusBadRequest,
			wantError:       "invalid_grant",
			wantDescription: "subject_token_expired",
		},
		{
			name:                "unauthorized scenario",
			method:              http.MethodPost,
			path:                "/token/unauthorized",
			contentType:         contentTypeFormEncoded,
			basicAuth:           true,
			wantStatus:          http.StatusUnauthorized,
			wantError:           "invalid_client",
			wantDescription:     "client rejected",
			wantWWWAuthenticate: `Bearer realm="issuer", error="invalid_token"`,
		},
		{
			name:            "forbidden scenario",
			method:          http.MethodPost,
			path:            "/token/forbidden",
			contentType:     contentTypeFormEncoded,
			basicAuth:       true,
			wantStatus:      http.StatusForbidden,
			wantError:       "invalid_target",
			wantDescription: "target rejected",
		},
		{
			name:           "server error scenario",
			method:         http.MethodPost,
			path:           "/token/server-error",
			contentType:    contentTypeFormEncoded,
			basicAuth:      true,
			wantStatus:     http.StatusInternalServerError,
			wantJSONFields: map[string]string{"error": "temporarily_unavailable"},
		},
		{
			name:        "malformed success response",
			method:      http.MethodPost,
			path:        "/token/malformed",
			contentType: contentTypeFormEncoded,
			basicAuth:   true,
			wantStatus:  http.StatusOK,
			wantBody:    `{"access_token":`,
		},
		{
			name:           "missing access token response",
			method:         http.MethodPost,
			path:           "/token/missing-access-token",
			contentType:    contentTypeFormEncoded,
			basicAuth:      true,
			wantStatus:     http.StatusOK,
			wantJSONFields: map[string]string{"issued_token_type": accessTokenType, "token_type": "Bearer"},
		},
		{
			name:           "wrong token type response",
			method:         http.MethodPost,
			path:           "/token/wrong-token-type",
			contentType:    contentTypeFormEncoded,
			basicAuth:      true,
			wantStatus:     http.StatusOK,
			wantJSONFields: map[string]string{"issued_token_type": accessTokenType, "token_type": "N_A"},
		},
		{
			name:           "wrong issued token type response",
			method:         http.MethodPost,
			path:           "/token/wrong-issued-token-type",
			contentType:    contentTypeFormEncoded,
			basicAuth:      true,
			wantStatus:     http.StatusOK,
			wantJSONFields: map[string]string{"issued_token_type": "urn:ietf:params:oauth:token-type:refresh_token", "token_type": "Bearer"},
		},
		{
			name:            "unknown scenario",
			method:          http.MethodPost,
			path:            "/token/not-real",
			contentType:     contentTypeFormEncoded,
			basicAuth:       true,
			wantStatus:      http.StatusBadRequest,
			wantError:       "invalid_request",
			wantDescription: "unknown fake token scenario",
		},
	}

	handler := tokenHandler("e2e-client", "e2e-secret", defaultFakeConfig())
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			form := baseTokenForm()
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(form.Encode()))
			if tc.contentType != "" {
				req.Header.Set("Content-Type", tc.contentType)
			}
			if tc.basicAuth {
				req.SetBasicAuth("e2e-client", "e2e-secret")
			}
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if tc.wantWWWAuthenticate != "" && rec.Header().Get("WWW-Authenticate") != tc.wantWWWAuthenticate {
				t.Fatalf("WWW-Authenticate = %q, want %q", rec.Header().Get("WWW-Authenticate"), tc.wantWWWAuthenticate)
			}
			if tc.wantBody != "" {
				if got := strings.TrimSpace(rec.Body.String()); got != tc.wantBody {
					t.Fatalf("body = %q, want %q", got, tc.wantBody)
				}
				return
			}

			var body map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode response: %v; body=%s", err, rec.Body.String())
			}
			if tc.wantError != "" && body["error"] != tc.wantError {
				t.Fatalf("error = %q, want %q", body["error"], tc.wantError)
			}
			if tc.wantDescription != "" && body["error_description"] != tc.wantDescription {
				t.Fatalf("error_description = %q, want %q", body["error_description"], tc.wantDescription)
			}
			for key, want := range tc.wantJSONFields {
				if got := body[key]; got != want {
					t.Fatalf("%s = %q, want %q", key, got, want)
				}
			}
		})
	}
}

func TestFakeTokenEndpointHealthAndEnvDefault(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	fakeTokenEndpointHandler("e2e-client", "e2e-secret", defaultFakeConfig()).ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("health status = %d, want %d", rec.Code, http.StatusNoContent)
	}

	t.Setenv("FAKE_TOKEN_ENDPOINT_TEST", " configured ")
	if got := envDefault("FAKE_TOKEN_ENDPOINT_TEST", "fallback"); got != "configured" {
		t.Fatalf("envDefault configured = %q, want configured", got)
	}
	t.Setenv("FAKE_TOKEN_ENDPOINT_TEST", " ")
	if got := envDefault("FAKE_TOKEN_ENDPOINT_TEST", "fallback"); got != "fallback" {
		t.Fatalf("envDefault fallback = %q, want fallback", got)
	}
}

func TestFakeTokenEndpointRecordsServerSpanUnderIncomingTrace(t *testing.T) {
	previousProvider := otel.GetTracerProvider()
	previousPropagator := otel.GetTextMapPropagator()
	defer otel.SetTracerProvider(previousProvider)
	defer otel.SetTextMapPropagator(previousPropagator)

	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(recorder),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.AlwaysSample())),
	)
	defer func() {
		if err := provider.Shutdown(t.Context()); err != nil {
			t.Fatalf("shutdown tracer provider: %v", err)
		}
	}()
	otel.SetTracerProvider(provider)
	otel.SetTextMapPropagator(telemetry.Propagators())

	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	form.Set("subject_token", "incoming-yellow")
	form.Set("subject_token_type", accessTokenType)

	req := httptest.NewRequest(http.MethodPost, "/token/yellow", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", contentTypeFormEncoded)
	req.Header.Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	req.SetBasicAuth("e2e-client", "e2e-secret")
	rec := httptest.NewRecorder()

	fakeTokenEndpointHandler("e2e-client", "e2e-secret", defaultFakeConfig()).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	spans := recorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("ended spans = %d, want 1", len(spans))
	}
	span := spans[0]
	if span.Name() != "fake_token_endpoint token" {
		t.Fatalf("span name = %q, want fake_token_endpoint token", span.Name())
	}
	if span.SpanKind() != trace.SpanKindServer {
		t.Fatalf("span kind = %s, want server", span.SpanKind())
	}
	if got := span.SpanContext().TraceID().String(); got != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Fatalf("trace ID = %s, want fixed incoming trace ID", got)
	}
	if got := span.Parent().SpanID().String(); got != "00f067aa0ba902b7" {
		t.Fatalf("parent span ID = %s, want incoming parent", got)
	}
}

func baseTokenForm() url.Values {
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	form.Set("subject_token", "incoming-yellow")
	form.Set("subject_token_type", accessTokenType)
	return form
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

func writeFakeConfig(t *testing.T, body string) string {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "fake-config-*.yaml")
	if err != nil {
		t.Fatalf("create temp config: %v", err)
	}
	if _, err := file.WriteString(body); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close temp config: %v", err)
	}
	return file.Name()
}
