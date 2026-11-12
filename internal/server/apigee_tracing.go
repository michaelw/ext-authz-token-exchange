package server

import (
	"context"
	"strings"

	pb "github.com/michaelw/ext-authz-token-exchange/internal/apigeepb"
	"google.golang.org/grpc"
)

// ApigeeTracing runs after authentication and protobuf decoding. Unlike ordinary
// gRPC, ExternalCallout can carry its trace parent inside the message payload.
func ApigeeTracing() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
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
		ctx, span := startGatewaySpan(ctx, headers, ApigeeProcessMethod)
		defer span.End()
		return handler(ctx, req)
	}
}
