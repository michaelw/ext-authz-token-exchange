package main

import (
	"testing"

	"github.com/michaelw/ext-authz-token-exchange/internal/config"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/stats"
)

func TestGRPCPortFromEnv(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		t.Setenv("GRPC_PORT", "")
		if got := grpcPortFromEnv(); got != "3001" {
			t.Fatalf("grpcPortFromEnv() = %q, want 3001", got)
		}
	})

	t.Run("configured", func(t *testing.T) {
		t.Setenv("GRPC_PORT", "4001")
		if got := grpcPortFromEnv(); got != "4001" {
			t.Fatalf("grpcPortFromEnv() = %q, want 4001", got)
		}
	})
}

func TestLoggingOptionsIncludesHealthMethod(t *testing.T) {
	opts := loggingOptions(config.RuntimeConfig{LogHealthChecks: false})
	method, ok := opts.Methods[healthCheckMethod]
	if !ok {
		t.Fatalf("logging options did not include %s", healthCheckMethod)
	}
	if method.LogEnabled {
		t.Fatalf("health logging should be disabled from config")
	}

	got := method.SummarizeResponse(&grpc_health_v1.HealthCheckResponse{
		Status: grpc_health_v1.HealthCheckResponse_SERVING,
	})
	if got != "health_status=serving" {
		t.Fatalf("unexpected health summary: %s", got)
	}
}

func TestGRPCTracingFilterSkipsHealthChecks(t *testing.T) {
	if grpcTracingFilter()(&stats.RPCTagInfo{FullMethodName: healthCheckMethod}) {
		t.Fatalf("expected health check RPC to be filtered from tracing")
	}
}

func TestGRPCTracingFilterKeepsAuthzChecks(t *testing.T) {
	if !grpcTracingFilter()(&stats.RPCTagInfo{FullMethodName: "/envoy.service.auth.v3.Authorization/Check"}) {
		t.Fatalf("expected ext-authz Check RPC to remain traceable")
	}
}

func TestSummarizeHealthResponseHandlesUnexpectedValues(t *testing.T) {
	if got := summarizeHealthResponse("not a health response"); got != "unknown" {
		t.Fatalf("unexpected health summary for wrong type: %s", got)
	}
}
