package main

import (
	"context"
	"testing"

	"github.com/michaelw/ext-authz-token-exchange/internal/config"
	"github.com/michaelw/ext-authz-token-exchange/internal/server"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	oteltrace "go.opentelemetry.io/otel/trace"
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
	if !grpcTracingFilter()(&stats.RPCTagInfo{FullMethodName: server.AuthzCheckMethod}) {
		t.Fatalf("expected ext-authz Check RPC to remain traceable")
	}
}

func TestGRPCStatsHandlerDoesNotRecordHealthChecks(t *testing.T) {
	provider := sdktrace.NewTracerProvider()
	previousProvider := otel.GetTracerProvider()
	otel.SetTracerProvider(provider)
	t.Cleanup(func() {
		otel.SetTracerProvider(previousProvider)
		if err := provider.Shutdown(context.Background()); err != nil {
			t.Fatalf("shutdown tracer provider: %v", err)
		}
	})

	ctx := grpcStatsHandler().TagRPC(context.Background(), &stats.RPCTagInfo{FullMethodName: healthCheckMethod})

	if oteltrace.SpanFromContext(ctx).IsRecording() {
		t.Fatalf("expected health check RPC not to record a span")
	}
}

func TestGRPCStatsHandlerRecordsAuthzChecks(t *testing.T) {
	provider := sdktrace.NewTracerProvider()
	previousProvider := otel.GetTracerProvider()
	otel.SetTracerProvider(provider)
	t.Cleanup(func() {
		otel.SetTracerProvider(previousProvider)
		if err := provider.Shutdown(context.Background()); err != nil {
			t.Fatalf("shutdown tracer provider: %v", err)
		}
	})

	ctx := grpcStatsHandler().TagRPC(context.Background(), &stats.RPCTagInfo{FullMethodName: server.AuthzCheckMethod})

	if !oteltrace.SpanFromContext(ctx).IsRecording() {
		t.Fatalf("expected ext-authz Check RPC to record a span")
	}
}

func TestSummarizeHealthResponseHandlesUnexpectedValues(t *testing.T) {
	if got := summarizeHealthResponse("not a health response"); got != "unknown" {
		t.Fatalf("unexpected health summary for wrong type: %s", got)
	}
}
