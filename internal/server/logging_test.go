package server

import (
	"bytes"
	"context"
	"net"
	"testing"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_service_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	envoy_service_ext_proc_v3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	envoy_type_v3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/michaelw/ext-authz-token-exchange/internal/config"
	"github.com/michaelw/ext-authz-token-exchange/internal/exchange"
	"github.com/michaelw/ext-authz-token-exchange/internal/policy"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	grpcstatus "google.golang.org/grpc/status"
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

func TestExtProcLoggingInterceptorLogsSanitizedAllowedRequest(t *testing.T) {
	var logs bytes.Buffer
	restoreLogger := captureLogger(&logs)
	defer restoreLogger()

	request := extProcHeaderValuesRequest(
		rawHeader(":method", "GET"),
		rawHeader(":scheme", "https"),
		rawHeader(":authority", "orders.example.com"),
		rawHeader(":path", "/api/orders?email=alice@example.com&token=subject-token#fragment"),
		rawHeader("authorization", "Bearer subject-token"),
	)
	response := extProcHeadersResponse([]headerPair{{Name: "authorization", Value: "Bearer exchanged-access-token"}})
	stream := &loggingTestServerStream{
		ctx: peer.NewContext(context.Background(), &peer.Peer{
			Addr: &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 12345},
		}),
		recv: func(message any) error {
			*message.(*envoy_service_ext_proc_v3.ProcessingRequest) = *request
			return nil
		},
	}

	err := LoggingStreamInterceptorWithOptions(LoggingOptions{Methods: ExtProcLoggingMethods()})(nil, stream, &grpc.StreamServerInfo{
		FullMethod: ExtProcProcessMethod,
	}, func(_ any, serverStream grpc.ServerStream) error {
		var received envoy_service_ext_proc_v3.ProcessingRequest
		if err := serverStream.RecvMsg(&received); err != nil {
			return err
		}
		return serverStream.SendMsg(response)
	})
	if err != nil {
		t.Fatalf("stream interceptor returned error: %v", err)
	}

	got := logs.String()
	for _, expected := range []string{
		"|   0 |",
		"192.0.2.10:12345",
		ExtProcProcessMethod,
		"| GET | https://orders.example.com/api/orders",
		"response=ok",
	} {
		if !bytes.Contains([]byte(got), []byte(expected)) {
			t.Fatalf("log did not contain %q: %s", expected, got)
		}
	}
	for _, sensitive := range []string{
		"authorization",
		"alice@example.com",
		"subject-token",
		"exchanged-access-token",
	} {
		if bytes.Contains([]byte(got), []byte(sensitive)) {
			t.Fatalf("log contained sensitive value %q: %s", sensitive, got)
		}
	}
}

func TestExtProcLoggingInterceptorLogsDeniedResponseWithoutBody(t *testing.T) {
	var logs bytes.Buffer
	restoreLogger := captureLogger(&logs)
	defer restoreLogger()

	request := extProcHeaderRequest(map[string]string{
		":method":    "GET",
		":scheme":    "https",
		":authority": "orders.example.com",
		":path":      "/api/orders",
	})
	response := extProcImmediateResponse(httpEvaluation{
		Status: 401,
		Body:   `{"error_description":"subject_token_expired_for_alice@example.com"}`,
	})
	stream := loggingServerStreamFor(request, nil)

	err := LoggingStreamInterceptorWithOptions(LoggingOptions{Methods: ExtProcLoggingMethods()})(nil, stream, &grpc.StreamServerInfo{
		FullMethod: ExtProcProcessMethod,
	}, func(_ any, serverStream grpc.ServerStream) error {
		var received envoy_service_ext_proc_v3.ProcessingRequest
		if err := serverStream.RecvMsg(&received); err != nil {
			return err
		}
		return serverStream.SendMsg(response)
	})
	if err != nil {
		t.Fatalf("stream interceptor returned error: %v", err)
	}

	got := logs.String()
	if !bytes.Contains([]byte(got), []byte("response=denied_status=Unauthorized")) {
		t.Fatalf("log did not contain denied status: %s", got)
	}
	for _, sensitive := range []string{"subject_token_expired", "alice@example.com"} {
		if bytes.Contains([]byte(got), []byte(sensitive)) {
			t.Fatalf("log contained sensitive value %q: %s", sensitive, got)
		}
	}
}

func TestExtProcLoggingInterceptorLogsReceiveAndSendErrors(t *testing.T) {
	tests := []struct {
		name       string
		stream     *loggingTestServerStream
		handler    grpc.StreamHandler
		wantStatus string
	}{
		{
			name: "receive",
			stream: &loggingTestServerStream{ctx: context.Background(), recv: func(any) error {
				return grpcstatus.Error(codes.Unavailable, "receive failed")
			}},
			handler: func(_ any, serverStream grpc.ServerStream) error {
				return serverStream.RecvMsg(&envoy_service_ext_proc_v3.ProcessingRequest{})
			},
			wantStatus: "|  14 |",
		},
		{
			name:   "send",
			stream: loggingServerStreamFor(extProcHeaderRequest(map[string]string{":path": "/api/orders"}), grpcstatus.Error(codes.Unavailable, "send failed")),
			handler: func(_ any, serverStream grpc.ServerStream) error {
				var request envoy_service_ext_proc_v3.ProcessingRequest
				if err := serverStream.RecvMsg(&request); err != nil {
					return err
				}
				return serverStream.SendMsg(extProcHeadersResponse(nil))
			},
			wantStatus: "|  14 |",
		},
		{
			name:   "handler",
			stream: loggingServerStreamFor(extProcHeaderRequest(map[string]string{":path": "/api/orders"}), nil),
			handler: func(_ any, serverStream grpc.ServerStream) error {
				var request envoy_service_ext_proc_v3.ProcessingRequest
				if err := serverStream.RecvMsg(&request); err != nil {
					return err
				}
				return grpcstatus.Error(codes.Internal, "handler failed")
			},
			wantStatus: "|  13 |",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logs bytes.Buffer
			restoreLogger := captureLogger(&logs)
			defer restoreLogger()

			err := LoggingStreamInterceptorWithOptions(LoggingOptions{Methods: ExtProcLoggingMethods()})(nil, tt.stream, &grpc.StreamServerInfo{
				FullMethod: ExtProcProcessMethod,
			}, tt.handler)
			if err == nil {
				t.Fatal("expected stream interceptor error")
			}
			if got := logs.String(); !bytes.Contains([]byte(got), []byte(tt.wantStatus)) {
				t.Fatalf("log did not contain status %q: %s", tt.wantStatus, got)
			}
		})
	}
}

func TestExtProcLoggingSummariesHandleUnexpectedMessages(t *testing.T) {
	if got := summarizeExtProcRequest("not a processing request"); got != "" {
		t.Fatalf("unexpected request summary: %q", got)
	}
	if got := summarizeExtProcRequest(&envoy_service_ext_proc_v3.ProcessingRequest{}); got != "" {
		t.Fatalf("unexpected non-header request summary: %q", got)
	}
	if got := summarizeExtProcResponse("not a processing response"); got != "unknown" {
		t.Fatalf("unexpected response summary: %q", got)
	}
	if got := summarizeExtProcResponse(&envoy_service_ext_proc_v3.ProcessingResponse{}); got != "unknown" {
		t.Fatalf("unexpected empty response summary: %q", got)
	}
}

func TestLoggingStreamInterceptorLeavesUnregisteredMethodsUnlogged(t *testing.T) {
	var logs bytes.Buffer
	restoreLogger := captureLogger(&logs)
	defer restoreLogger()

	stream := &loggingTestServerStream{ctx: context.Background()}
	err := LoggingStreamInterceptorWithOptions(LoggingOptions{Methods: ExtProcLoggingMethods()})(nil, stream, &grpc.StreamServerInfo{
		FullMethod: "/grpc.health.v1.Health/Watch",
	}, func(any, grpc.ServerStream) error { return nil })
	if err != nil {
		t.Fatalf("stream interceptor returned error: %v", err)
	}
	if logs.Len() != 0 {
		t.Fatalf("unregistered stream was logged: %s", logs.String())
	}
}

type loggingTestServerStream struct {
	grpc.ServerStream
	ctx     context.Context
	recv    func(any) error
	sendErr error
}

func (s *loggingTestServerStream) Context() context.Context {
	return s.ctx
}

func (s *loggingTestServerStream) SetHeader(metadata.MD) error  { return nil }
func (s *loggingTestServerStream) SendHeader(metadata.MD) error { return nil }
func (s *loggingTestServerStream) SetTrailer(metadata.MD)       {}

func (s *loggingTestServerStream) RecvMsg(message any) error {
	return s.recv(message)
}

func (s *loggingTestServerStream) SendMsg(any) error {
	return s.sendErr
}

func loggingServerStreamFor(request *envoy_service_ext_proc_v3.ProcessingRequest, sendErr error) *loggingTestServerStream {
	return &loggingTestServerStream{
		ctx: context.Background(),
		recv: func(message any) error {
			*message.(*envoy_service_ext_proc_v3.ProcessingRequest) = *request
			return nil
		},
		sendErr: sendErr,
	}
}

func extProcHeaderRequest(headers map[string]string) *envoy_service_ext_proc_v3.ProcessingRequest {
	values := make([]*envoy_config_core_v3.HeaderValue, 0, len(headers))
	for key, value := range headers {
		values = append(values, rawHeader(key, value))
	}
	return extProcHeaderValuesRequest(values...)
}

func extProcHeaderValuesRequest(values ...*envoy_config_core_v3.HeaderValue) *envoy_service_ext_proc_v3.ProcessingRequest {
	return &envoy_service_ext_proc_v3.ProcessingRequest{
		Request: &envoy_service_ext_proc_v3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &envoy_service_ext_proc_v3.HttpHeaders{
				Headers: &envoy_config_core_v3.HeaderMap{Headers: values},
			},
		},
	}
}

func rawHeader(key, value string) *envoy_config_core_v3.HeaderValue {
	return &envoy_config_core_v3.HeaderValue{Key: key, RawValue: []byte(value)}
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
      issuerRef: primary
      resources:
        - https://orders.example.com/api/
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
		IssuerProfiles: map[string]config.IssuerProfile{
			"primary": {
				Name:          "primary",
				TokenEndpoint: "http://issuer.example/token",
				ClientID:      "client",
				ClientSecret:  "secret",
			},
		},
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
