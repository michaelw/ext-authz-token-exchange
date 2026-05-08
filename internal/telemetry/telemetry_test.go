package telemetry

import (
	"context"
	"slices"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

func TestInitLeavesTracingInertWhenSDKDisabled(t *testing.T) {
	t.Setenv("OTEL_SDK_DISABLED", "true")
	t.Setenv("OTEL_TRACES_EXPORTER", "otlp")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector.example:4317")

	previousPropagator := otel.GetTextMapPropagator()
	previousProvider := otel.GetTracerProvider()
	defer otel.SetTextMapPropagator(previousPropagator)
	defer otel.SetTracerProvider(previousProvider)

	shutdown, err := InitWithServiceName(context.Background(), "custom-service")
	if err != nil {
		t.Fatalf("InitWithServiceName returned error: %v", err)
	}
	if err := shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown returned error: %v", err)
	}
	if got := otel.GetTracerProvider(); got != previousProvider {
		t.Fatal("tracer provider changed while SDK was disabled")
	}

	ctx := otel.GetTextMapPropagator().Extract(context.Background(), propagation.MapCarrier{
		"traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		"baggage":     "tenant=yellow",
	})
	if got := trace.SpanContextFromContext(ctx).TraceID().String(); got != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Fatalf("trace ID = %s, want extracted incoming trace ID", got)
	}
	if got := baggage.FromContext(ctx).Member("tenant").Value(); got != "yellow" {
		t.Fatalf("tenant baggage = %q, want yellow", got)
	}
}

func TestInitLeavesTracingInertWithoutOTLPExporter(t *testing.T) {
	t.Setenv("OTEL_TRACES_EXPORTER", "none")

	previousProvider := otel.GetTracerProvider()
	previousPropagator := otel.GetTextMapPropagator()
	defer otel.SetTracerProvider(previousProvider)
	defer otel.SetTextMapPropagator(previousPropagator)

	shutdown, err := Init(context.Background())
	if err != nil {
		t.Fatalf("Init returned error: %v", err)
	}
	if err := shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown returned error: %v", err)
	}
	if got := otel.GetTracerProvider(); got != previousProvider {
		t.Fatal("tracer provider changed without OTLP exporter")
	}
}

func TestTelemetryEnvHelpers(t *testing.T) {
	t.Setenv("OTEL_SDK_DISABLED", " TRUE ")
	if sdkDisabled() {
		t.Fatal("sdkDisabled should only accept exact true ignoring case, not surrounding spaces")
	}
	t.Setenv("OTEL_SDK_DISABLED", "TrUe")
	if !sdkDisabled() {
		t.Fatal("sdkDisabled = false, want true")
	}

	t.Setenv("OTEL_TRACES_EXPORTER", " OTLP ")
	if !otlpTracingEnabled() {
		t.Fatal("otlpTracingEnabled = false, want true for trimmed otlp")
	}
	t.Setenv("OTEL_TRACES_EXPORTER", "console")
	if otlpTracingEnabled() {
		t.Fatal("otlpTracingEnabled = true, want false for non-otlp exporter")
	}

	t.Setenv("OTEL_SERVICE_NAME", " configured-service ")
	if got := serviceName("fallback-service"); got != "configured-service" {
		t.Fatalf("serviceName = %q, want configured-service", got)
	}
	t.Setenv("OTEL_SERVICE_NAME", " ")
	if got := serviceName("fallback-service"); got != "fallback-service" {
		t.Fatalf("serviceName = %q, want fallback-service", got)
	}
}

func TestOTLPTraceOptions(t *testing.T) {
	if got := otlpTraceOptions(); got != nil {
		t.Fatalf("otlpTraceOptions with no endpoint = %#v, want nil", got)
	}

	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector.example:4317")
	if got := otlpTraceOptions(); len(got) != 2 {
		t.Fatalf("otlpTraceOptions for http endpoint length = %d, want endpoint and insecure options", len(got))
	}

	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "https://traces.example:4317")
	if got := otlpTraceOptions(); len(got) != 1 {
		t.Fatalf("otlpTraceOptions for traces endpoint length = %d, want traces endpoint option only", len(got))
	}
}

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

func TestHeaderCarrierSetAndKeys(t *testing.T) {
	carrier := headerCarrier{"Traceparent": "incoming"}
	carrier.Set("baggage", "tenant=yellow")

	if got := carrier.Get("traceparent"); got != "incoming" {
		t.Fatalf("traceparent = %q, want incoming", got)
	}
	if got := carrier.Get("Baggage"); got != "tenant=yellow" {
		t.Fatalf("baggage = %q, want tenant=yellow", got)
	}
	keys := carrier.Keys()
	slices.Sort(keys)
	if got, want := keys, []string{"Traceparent", "baggage"}; !slices.Equal(got, want) {
		t.Fatalf("keys = %#v, want %#v", got, want)
	}
}
