// Package telemetry configures OpenTelemetry tracing and propagation.
package telemetry

import (
	"context"
	"errors"
	"net/url"
	"os"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

const defaultServiceName = "ext-authz-token-exchange"

// Propagators returns the propagation formats supported by the service.
func Propagators() propagation.TextMapPropagator {
	return propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	)
}

// ExtractHTTPHeaders extracts trace context from Envoy HTTP request headers.
func ExtractHTTPHeaders(ctx context.Context, headers map[string]string) context.Context {
	return Propagators().Extract(ctx, headerCarrier(headers))
}

// Init configures global OpenTelemetry propagation and, when OTLP export is
// requested, trace and metric providers. Without exporters instrumentation
// remains inert but still propagates incoming context to outbound subrequests.
func Init(ctx context.Context) (func(context.Context) error, error) {
	return InitWithServiceName(ctx, defaultServiceName)
}

// InitWithServiceName configures telemetry with the provided default service
// name when OTEL_SERVICE_NAME is not set.
func InitWithServiceName(ctx context.Context, defaultServiceName string) (func(context.Context) error, error) {
	otel.SetTextMapPropagator(Propagators())
	if sdkDisabled() || (!otlpTracingEnabled() && !otlpMetricsEnabled()) {
		return func(context.Context) error { return nil }, nil
	}

	res, err := resource.New(ctx,
		resource.WithFromEnv(),
		resource.WithAttributes(attribute.String("service.name", serviceName(defaultServiceName))),
		resource.WithTelemetrySDK(),
	)
	if err != nil {
		return nil, err
	}

	var shutdowns []func(context.Context) error
	if otlpTracingEnabled() {
		exporter, err := otlptracegrpc.New(ctx, otlpTraceOptions()...)
		if err != nil {
			return nil, err
		}
		provider := sdktrace.NewTracerProvider(
			sdktrace.WithBatcher(exporter),
			sdktrace.WithResource(res),
			sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.AlwaysSample())),
		)
		otel.SetTracerProvider(provider)
		shutdowns = append(shutdowns, provider.Shutdown)
	}
	if otlpMetricsEnabled() {
		exporter, err := otlpmetricgrpc.New(ctx, otlpMetricOptions()...)
		if err != nil {
			return nil, err
		}
		provider := sdkmetric.NewMeterProvider(
			sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exporter)),
			sdkmetric.WithResource(res),
		)
		otel.SetMeterProvider(provider)
		shutdowns = append(shutdowns, provider.Shutdown)
	}
	return func(ctx context.Context) error {
		var errs []error
		for _, shutdown := range shutdowns {
			errs = append(errs, shutdown(ctx))
		}
		return errors.Join(errs...)
	}, nil
}

func sdkDisabled() bool {
	return strings.EqualFold(os.Getenv("OTEL_SDK_DISABLED"), "true")
}

func otlpTracingEnabled() bool {
	exporter := strings.TrimSpace(os.Getenv("OTEL_TRACES_EXPORTER"))
	return strings.EqualFold(exporter, "otlp")
}

func otlpMetricsEnabled() bool {
	exporter := strings.TrimSpace(os.Getenv("OTEL_METRICS_EXPORTER"))
	return strings.EqualFold(exporter, "otlp")
}

func serviceName(defaultServiceName string) string {
	if value := strings.TrimSpace(os.Getenv("OTEL_SERVICE_NAME")); value != "" {
		return value
	}
	return defaultServiceName
}

func otlpTraceOptions() []otlptracegrpc.Option {
	endpoint := strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"))
	if endpoint == "" {
		endpoint = strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))
	}
	if endpoint == "" {
		return nil
	}
	if u, err := url.Parse(endpoint); err == nil && u.Scheme == "http" {
		return []otlptracegrpc.Option{otlptracegrpc.WithEndpointURL(endpoint), otlptracegrpc.WithInsecure()}
	}
	return []otlptracegrpc.Option{otlptracegrpc.WithEndpointURL(endpoint)}
}

func otlpMetricOptions() []otlpmetricgrpc.Option {
	endpoint := strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT"))
	if endpoint == "" {
		endpoint = strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))
	}
	if endpoint == "" {
		return nil
	}
	if u, err := url.Parse(endpoint); err == nil && u.Scheme == "http" {
		return []otlpmetricgrpc.Option{otlpmetricgrpc.WithEndpointURL(endpoint), otlpmetricgrpc.WithInsecure()}
	}
	return []otlpmetricgrpc.Option{otlpmetricgrpc.WithEndpointURL(endpoint)}
}

type headerCarrier map[string]string

func (c headerCarrier) Get(key string) string {
	for name, value := range c {
		if strings.EqualFold(name, key) {
			return value
		}
	}
	return ""
}

func (c headerCarrier) Set(key, value string) {
	c[key] = value
}

func (c headerCarrier) Keys() []string {
	keys := make([]string, 0, len(c))
	for key := range c {
		keys = append(keys, key)
	}
	return keys
}
