package telemetry

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/trace"
)

func TestExtractHTTPHeadersUsesCaseInsensitiveTraceContextAndBaggage(t *testing.T) {
	ctx := ExtractHTTPHeaders(context.Background(), map[string]string{
		"Traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		"Baggage":     "tenant=yellow",
	})

	spanContext := trace.SpanContextFromContext(ctx)
	if !spanContext.IsValid() {
		t.Fatal("span context is invalid")
	}
	if got := spanContext.TraceID().String(); got != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Fatalf("trace ID = %s, want incoming trace ID", got)
	}
	if got := spanContext.SpanID().String(); got != "00f067aa0ba902b7" {
		t.Fatalf("span ID = %s, want incoming span ID", got)
	}

	member := baggage.FromContext(ctx).Member("tenant")
	if got := member.Value(); got != "yellow" {
		t.Fatalf("tenant baggage = %q, want yellow", got)
	}
}
