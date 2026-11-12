package server

import (
	"context"
	"strings"

	pb "github.com/michaelw/ext-authz-token-exchange/internal/apigeepb"
	"github.com/michaelw/ext-authz-token-exchange/internal/telemetry"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// ApigeeTracing runs after authentication and protobuf decoding. Unlike ordinary
// gRPC, ExternalCallout can carry its trace parent inside the message payload.
func ApigeeTracing() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		md, _ := metadata.FromIncomingContext(ctx)
		carrier := propagation.MapCarrier{}
		for _, name := range []string{"traceparent", "tracestate", "baggage"} {
			if values := md.Get(name); len(values) == 1 {
				carrier[name] = values[0]
			}
		}
		parent := telemetry.Propagators().Extract(ctx, carrier)
		if !trace.SpanContextFromContext(parent).IsValid() {
			headers := map[string]string{}
			if message, ok := req.(*pb.MessageContext); ok {
				for name, value := range message.GetRequest().GetHeaders() {
					key := strings.ToLower(name)
					if key == "traceparent" || key == "tracestate" || key == "baggage" {
						if old, exists := headers[key]; exists {
							headers[key] = old + "," + strings.Join(value.GetStrings(), ",")
						} else {
							headers[key] = strings.Join(value.GetStrings(), ",")
						}
					}
				}
			}
			parent = telemetry.RequestContext(ctx, headers)
		}
		ctx, span := otel.Tracer("github.com/michaelw/ext-authz-token-exchange/internal/server").Start(parent, ApigeeProcessMethod, trace.WithSpanKind(trace.SpanKindServer))
		defer span.End()
		return handler(ctx, req)
	}
}
