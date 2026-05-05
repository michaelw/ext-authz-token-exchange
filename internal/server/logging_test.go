package server

import (
	"bytes"
	"context"
	"net"
	"testing"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_service_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	envoy_type_v3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
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

	_, err := LoggingInterceptor()(peer.NewContext(context.Background(), &peer.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 12345},
	}), loggingCheckRequest("GET", "orders.example.com", "/api/orders?email=alice@example.com&token=subject-token"), &grpc.UnaryServerInfo{
		FullMethod: "/envoy.service.auth.v3.Authorization/Check",
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

	got := responseSummary(resp)
	if bytes.Contains([]byte(got), []byte("alice@example.com")) || bytes.Contains([]byte(got), []byte("subject_token_expired")) {
		t.Fatalf("summary contained denied body details: %s", got)
	}
	if got != "denied_status=Unauthorized" {
		t.Fatalf("unexpected summary: %s", got)
	}
}

func TestLogPathDropsQueryFragmentAndNormalizesControls(t *testing.T) {
	got := logPath("/api/orders?email=alice@example.com\nx-forged=true#fragment")
	if got != "/api/orders" {
		t.Fatalf("unexpected sanitized path: %q", got)
	}
}

func loggingCheckRequest(method, host, path string) *envoy_service_auth_v3.CheckRequest {
	return &envoy_service_auth_v3.CheckRequest{
		Attributes: &envoy_service_auth_v3.AttributeContext{
			Request: &envoy_service_auth_v3.AttributeContext_Request{
				Http: &envoy_service_auth_v3.AttributeContext_HttpRequest{
					Method: method,
					Host:   host,
					Path:   path,
				},
			},
		},
	}
}
