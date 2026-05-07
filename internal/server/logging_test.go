package server

import (
	"bytes"
	"context"
	"net"
	"testing"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_service_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	envoy_type_v3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/michaelw/ext-authz-token-exchange/internal/config"
	"github.com/michaelw/ext-authz-token-exchange/internal/exchange"
	"github.com/michaelw/ext-authz-token-exchange/internal/policy"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/peer"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestLoggingInterceptorDoesNotLogSensitiveResponseFields(t *testing.T) {
	var logs bytes.Buffer
	originalWriter := customLogger.Writer()
	customLogger.SetOutput(&logs)
	t.Cleanup(func() {
		customLogger.SetOutput(originalWriter)
	})

	resp := &envoy_service_auth_v3.CheckResponse{
		HttpResponse: &envoy_service_auth_v3.CheckResponse_OkResponse{
			OkResponse: &envoy_service_auth_v3.OkHttpResponse{
				Headers: []*envoy_config_core_v3.HeaderValueOption{{
					Header: &envoy_config_core_v3.HeaderValue{
						Key:   "authorization",
						Value: "Bearer exchanged-access-token",
					},
					Append: wrapperspb.Bool(false),
				}},
			},
		},
	}

	_, err := LoggingInterceptorWithOptions(LoggingOptions{Methods: AuthzLoggingMethods()})(peer.NewContext(context.Background(), &peer.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 12345},
	}), loggingCheckRequest("GET", "orders.example.com", "/api/orders?email=alice@example.com&token=subject-token"), &grpc.UnaryServerInfo{
		FullMethod: AuthzCheckMethod,
	}, func(context.Context, any) (any, error) {
		return resp, nil
	})
	if err != nil {
		t.Fatalf("interceptor returned error: %v", err)
	}

	got := logs.String()
	for _, sensitive := range []string{
		"exchanged-access-token",
		"authorization",
		"alice@example.com",
		"subject-token",
	} {
		if bytes.Contains([]byte(got), []byte(sensitive)) {
			t.Fatalf("log contained sensitive value %q: %s", sensitive, got)
		}
	}
	if !bytes.Contains([]byte(got), []byte("response=ok")) {
		t.Fatalf("log did not contain sanitized response summary: %s", got)
	}
	if !bytes.Contains([]byte(got), []byte("/api/orders")) {
		t.Fatalf("log did not retain sanitized path: %s", got)
	}
}

func TestResponseSummaryDoesNotLogDeniedBody(t *testing.T) {
	resp := &envoy_service_auth_v3.CheckResponse{
		Status: &status.Status{},
		HttpResponse: &envoy_service_auth_v3.CheckResponse_DeniedResponse{
			DeniedResponse: &envoy_service_auth_v3.DeniedHttpResponse{
				Status: &envoy_type_v3.HttpStatus{Code: envoy_type_v3.StatusCode_Unauthorized},
				Body:   `{"error_description":"subject_token_expired_for_alice@example.com"}`,
			},
		},
	}

	got := summarizeAuthzResponse(resp)
	if bytes.Contains([]byte(got), []byte("alice@example.com")) || bytes.Contains([]byte(got), []byte("subject_token_expired")) {
		t.Fatalf("summary contained denied body details: %s", got)
	}
	if got != "denied_status=Unauthorized" {
		t.Fatalf("unexpected summary: %s", got)
	}
}

func TestAuthzLoggingSummariesHandleUnexpectedValues(t *testing.T) {
	if got := summarizeAuthzRequest("not an authz request"); got != "" {
		t.Fatalf("unexpected request summary for wrong type: %q", got)
	}
	if got := summarizeAuthzRequest(&envoy_service_auth_v3.CheckRequest{}); got != "" {
		t.Fatalf("unexpected request summary for missing HTTP attributes: %q", got)
	}
	if got := summarizeAuthzResponse("not an authz response"); got != "unknown" {
		t.Fatalf("unexpected response summary for wrong type: %q", got)
	}
	if got := summarizeAuthzResponse(&envoy_service_auth_v3.CheckResponse{}); got != "unknown" {
		t.Fatalf("unexpected response summary for empty authz response: %q", got)
	}
}

func TestLoggingInterceptorUsesRegisteredMethodSummary(t *testing.T) {
	var logs bytes.Buffer
	originalWriter := customLogger.Writer()
	customLogger.SetOutput(&logs)
	t.Cleanup(func() {
		customLogger.SetOutput(originalWriter)
	})

	_, err := LoggingInterceptor()(peer.NewContext(context.Background(), &peer.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 12345},
	}), struct{}{}, &grpc.UnaryServerInfo{
		FullMethod: "/example.Service/Method",
	}, func(context.Context, any) (any, error) {
		return "response", nil
	})
	if err != nil {
		t.Fatalf("interceptor returned error: %v", err)
	}

	got := logs.String()
	if !bytes.Contains([]byte(got), []byte("response=unknown")) {
		t.Fatalf("unregistered method did not fall back to unknown: %s", got)
	}

	logs.Reset()
	_, err = LoggingInterceptorWithOptions(LoggingOptions{Methods: map[string]LoggingMethod{
		"/example.Service/Method": {
			LogEnabled:        true,
			SummarizeResponse: func(any) string { return "registered" },
		},
	}})(peer.NewContext(context.Background(), &peer.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 12345},
	}), struct{}{}, &grpc.UnaryServerInfo{
		FullMethod: "/example.Service/Method",
	}, func(context.Context, any) (any, error) {
		return "response", nil
	})
	if err != nil {
		t.Fatalf("interceptor returned error: %v", err)
	}

	got = logs.String()
	if !bytes.Contains([]byte(got), []byte("response=registered")) {
		t.Fatalf("registered method summary was not used: %s", got)
	}
}

func TestLoggingInterceptorCanSkipRegisteredMethod(t *testing.T) {
	var logs bytes.Buffer
	originalWriter := customLogger.Writer()
	customLogger.SetOutput(&logs)
	t.Cleanup(func() {
		customLogger.SetOutput(originalWriter)
	})

	_, err := LoggingInterceptorWithOptions(LoggingOptions{Methods: map[string]LoggingMethod{
		"/grpc.health.v1.Health/Check": {
			LogEnabled:        false,
			SummarizeResponse: func(any) string { return "health_status=serving" },
		},
	}})(peer.NewContext(context.Background(), &peer.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 12345},
	}), &healthpb.HealthCheckRequest{}, &grpc.UnaryServerInfo{
		FullMethod: "/grpc.health.v1.Health/Check",
	}, func(context.Context, any) (any, error) {
		return &healthpb.HealthCheckResponse{Status: healthpb.HealthCheckResponse_SERVING}, nil
	})
	if err != nil {
		t.Fatalf("interceptor returned error: %v", err)
	}

	if got := logs.String(); got != "" {
		t.Fatalf("expected registered method log to be skipped, got: %s", got)
	}
}

func TestLoggingInterceptorDoesNotSkipAuthzWhenHealthCheckLoggingDisabled(t *testing.T) {
	var logs bytes.Buffer
	originalWriter := customLogger.Writer()
	customLogger.SetOutput(&logs)
	t.Cleanup(func() {
		customLogger.SetOutput(originalWriter)
	})

	resp := &envoy_service_auth_v3.CheckResponse{
		HttpResponse: &envoy_service_auth_v3.CheckResponse_OkResponse{
			OkResponse: &envoy_service_auth_v3.OkHttpResponse{},
		},
	}

	_, err := LoggingInterceptorWithOptions(LoggingOptions{Methods: map[string]LoggingMethod{
		AuthzCheckMethod: {
			LogEnabled:        true,
			SummarizeResponse: summarizeAuthzResponse,
		},
		"/grpc.health.v1.Health/Check": {
			LogEnabled:        false,
			SummarizeResponse: func(any) string { return "health_status=serving" },
		},
	}})(peer.NewContext(context.Background(), &peer.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 12345},
	}), loggingCheckRequest("GET", "orders.example.com", "/api/orders"), &grpc.UnaryServerInfo{
		FullMethod: AuthzCheckMethod,
	}, func(context.Context, any) (any, error) {
		return resp, nil
	})
	if err != nil {
		t.Fatalf("interceptor returned error: %v", err)
	}

	got := logs.String()
	if !bytes.Contains([]byte(got), []byte(AuthzCheckMethod)) {
		t.Fatalf("expected authz request to be logged: %s", got)
	}
	if !bytes.Contains([]byte(got), []byte("response=ok")) {
		t.Fatalf("expected authz response summary to be logged: %s", got)
	}
}

func TestLogPathDropsQueryFragmentAndNormalizesControls(t *testing.T) {
	got := logPath("/api/orders?email=alice@example.com\nx-forged=true#fragment")
	if got != "/api/orders" {
		t.Fatalf("unexpected sanitized path: %q", got)
	}
}

func TestAuthzServerDoesNotLogTokensByDefault(t *testing.T) {
	var logs bytes.Buffer
	restoreLogger := captureLogger(&logs)
	defer restoreLogger()

	srv := NewAuthzGRPCServer(config.RuntimeConfig{BearerRealm: "example"}, policy.NewStaticStore(loggingIndex()), &loggingExchanger{
		result: exchange.Result{AccessToken: "exchanged-access-token"},
	})

	resp, err := srv.Check(context.Background(), loggingCheckRequestWithHeaders("GET", "orders.example.com", "/api/orders?email=alice@example.com", map[string]string{
		"authorization": "Bearer subject-token",
	}))
	if err != nil {
		t.Fatalf("Check returned error: %v", err)
	}
	if resp.GetOkResponse() == nil {
		t.Fatalf("expected OK response: %v", resp)
	}

	got := logs.String()
	for _, sensitive := range []string{"INSECURE_LOG_TOKENS", "subject-token", "exchanged-access-token"} {
		if bytes.Contains([]byte(got), []byte(sensitive)) {
			t.Fatalf("log contained sensitive value %q: %s", sensitive, got)
		}
	}
}

func TestAuthzServerLogsTokensWhenInsecureLoggingEnabled(t *testing.T) {
	var logs bytes.Buffer
	restoreLogger := captureLogger(&logs)
	defer restoreLogger()

	srv := NewAuthzGRPCServer(config.RuntimeConfig{BearerRealm: "example", InsecureLogTokens: true}, policy.NewStaticStore(loggingIndex()), &loggingExchanger{
		result: exchange.Result{AccessToken: "exchanged-access-token"},
	})

	resp, err := srv.Check(context.Background(), loggingCheckRequestWithHeaders("GET", "orders.example.com", "/api/orders?email=alice@example.com", map[string]string{
		"authorization": "Bearer subject-token",
	}))
	if err != nil {
		t.Fatalf("Check returned error: %v", err)
	}
	if resp.GetOkResponse() == nil {
		t.Fatalf("expected OK response: %v", resp)
	}

	got := logs.String()
	for _, want := range []string{
		"INSECURE_LOG_TOKENS",
		"method=GET",
		"host=orders.example.com",
		"path=/api/orders",
		"policy=orders/token-exchange",
		"subject_token=subject-token",
		"exchanged_token=exchanged-access-token",
	} {
		if !bytes.Contains([]byte(got), []byte(want)) {
			t.Fatalf("log did not contain %q: %s", want, got)
		}
	}
	if bytes.Contains([]byte(got), []byte("alice@example.com")) {
		t.Fatalf("log contained query PII: %s", got)
	}
}

func TestAuthzServerLogsDenialReasonsWithoutSensitiveValues(t *testing.T) {
	var logs bytes.Buffer
	restoreLogger := captureLogger(&logs)
	defer restoreLogger()

	srv := NewAuthzGRPCServer(
		config.RuntimeConfig{BearerRealm: "example", DefaultDenyUnmatched: true},
		policy.NewStaticStore(loggingDenyIndex()),
		&loggingExchanger{},
	)

	resp, err := srv.Check(context.Background(), loggingCheckRequestWithHeaders("GET", "orders.example.com", "/api/orders?token=secret", map[string]string{
		"authorization": "Bearer subject-token",
	}))
	if err != nil {
		t.Fatalf("Check returned error: %v", err)
	}
	if resp.GetDeniedResponse() == nil {
		t.Fatalf("expected denied response: %v", resp)
	}

	resp, err = srv.Check(context.Background(), loggingCheckRequestWithHeaders("GET", "orders.example.com", "/api/customers?token=secret", map[string]string{
		"authorization": "Bearer subject-token",
	}))
	if err != nil {
		t.Fatalf("Check returned error: %v", err)
	}
	if resp.GetDeniedResponse() == nil {
		t.Fatalf("expected denied response: %v", resp)
	}

	got := logs.String()
	for _, want := range []string{
		"DENY reason=explicit_policy",
		"policy=orders/token-exchange",
		"DENY reason=unmatched_default_deny",
		"path=/api/orders",
		"path=/api/customers",
	} {
		if !bytes.Contains([]byte(got), []byte(want)) {
			t.Fatalf("log did not contain %q: %s", want, got)
		}
	}
	for _, sensitive := range []string{"subject-token", "secret"} {
		if bytes.Contains([]byte(got), []byte(sensitive)) {
			t.Fatalf("log contained sensitive value %q: %s", sensitive, got)
		}
	}
}

func captureLogger(logs *bytes.Buffer) func() {
	originalWriter := customLogger.Writer()
	customLogger.SetOutput(logs)
	return func() {
		customLogger.SetOutput(originalWriter)
	}
}

func loggingCheckRequest(method, host, path string) *envoy_service_auth_v3.CheckRequest {
	return loggingCheckRequestWithHeaders(method, host, path, nil)
}

func loggingCheckRequestWithHeaders(method, host, path string, headers map[string]string) *envoy_service_auth_v3.CheckRequest {
	if headers == nil {
		headers = map[string]string{}
	}
	headers[":authority"] = host
	return &envoy_service_auth_v3.CheckRequest{
		Attributes: &envoy_service_auth_v3.AttributeContext{
			Request: &envoy_service_auth_v3.AttributeContext_Request{
				Http: &envoy_service_auth_v3.AttributeContext_HttpRequest{
					Method:  method,
					Host:    host,
					Path:    path,
					Headers: headers,
				},
			},
		},
	}
}

type loggingExchanger struct {
	result exchange.Result
	err    *exchange.OAuthError
}

func (f *loggingExchanger) Exchange(context.Context, policy.Entry, string) (exchange.Result, *exchange.OAuthError) {
	return f.result, f.err
}

func loggingIndex() *policy.Index {
	return policy.BuildIndex(map[policy.Source]string{{Namespace: "orders", Name: "token-exchange"}: `
version: v1
entries:
  - match:
      host: orders.example.com
      pathPrefix: /api/orders
      methods: ["GET"]
    action: exchange
    exchange:
      resources:
        - https://orders.example.com/api/
      tokenEndpoint: http://issuer.example/token
`}, config.RuntimeConfig{
		ClientID:                "client",
		ClientSecret:            "secret",
		TokenEndpointAuthMethod: config.AuthMethodClientSecretBasic,
		GrantType:               config.DefaultGrantType,
		SubjectTokenType:        config.DefaultSubjectTokenType,
		LabelSelector:           config.DefaultConfigMapLabelSelector,
		AllowHTTPTokenEndpoint:  true,
		RequireIssuedTokenType:  true,
		ExpectedIssuedTokenType: config.DefaultIssuedTokenType,
	})
}

func loggingDenyIndex() *policy.Index {
	return policy.BuildIndex(map[policy.Source]string{{Namespace: "orders", Name: "token-exchange"}: `
version: v1
entries:
  - match:
      host: orders.example.com
      pathPrefix: /api/orders
      methods: ["GET"]
    action: deny
`}, config.RuntimeConfig{
		ClientID:                "client",
		ClientSecret:            "secret",
		TokenEndpointAuthMethod: config.AuthMethodClientSecretBasic,
		GrantType:               config.DefaultGrantType,
		SubjectTokenType:        config.DefaultSubjectTokenType,
		LabelSelector:           config.DefaultConfigMapLabelSelector,
		AllowHTTPTokenEndpoint:  true,
		RequireIssuedTokenType:  true,
		ExpectedIssuedTokenType: config.DefaultIssuedTokenType,
	})
}
