package server

import (
	"context"
	"strings"

	"github.com/michaelw/ext-authz-token-exchange/internal/telemetry"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc/metadata"
)

// Gateway payloads can contain the parent that ordinary gRPC instrumentation
// cannot see before decoding. Start the RPC span only after that boundary.
func startGatewaySpan(ctx context.Context, headers map[string]string, method string) (context.Context, trace.Span) {
	md, _ := metadata.FromIncomingContext(ctx)
	carrier := propagation.MapCarrier{}
	for _, name := range []string{"traceparent", "tracestate", "baggage"} {
		if values := md.Get(name); len(values) == 1 {
			carrier[name] = values[0]
		}
	}
	parent := telemetry.Propagators().Extract(ctx, carrier)
	if !trace.SpanContextFromContext(parent).IsValid() {
		parent = telemetry.RequestContext(ctx, headers)
	}
	service, operation, _ := strings.Cut(strings.TrimPrefix(method, "/"), "/")
	return otel.Tracer("github.com/michaelw/ext-authz-token-exchange/internal/server").Start(parent, method,
		trace.WithSpanKind(trace.SpanKindServer), trace.WithAttributes(
			attribute.String("rpc.system", "grpc"), attribute.String("rpc.service", service), attribute.String("rpc.method", operation)))
}
