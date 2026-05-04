package server

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	envoy_service_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// Custom logger without timestamp prefix to match Gin format
var customLogger = log.New(os.Stdout, "[gRPC] ", log.LstdFlags)

// LoggingInterceptor creates a gRPC unary interceptor for request/response logging
func LoggingInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {

		// Extract client address
		clientAddr := "UNKNOWN"
		if p, ok := peer.FromContext(ctx); ok {
			clientAddr = p.Addr.String()
		}

		start := time.Now()
		// Call the handler
		resp, err := handler(ctx, req)
		duration := time.Since(start)

		// Format similar to Gin: [gRPC] timestamp | status | duration | client | method | args
		var args string
		if checkReq, ok := req.(*envoy_service_auth_v3.CheckRequest); ok {
			httpReq := checkReq.GetAttributes().GetRequest().GetHttp()
			if httpReq != nil {
				args = fmt.Sprintf(" | %s | %s://%s%s | user-agent=%s",
					httpReq.GetMethod(),
					httpReq.GetScheme(),
					httpReq.GetHost(),
					httpReq.GetPath(),
					httpReq.GetHeaders()["user-agent"])
			}
		}

		if resp != nil {
			args += fmt.Sprintf(" | response=%v", resp)
		}

		if st, ok := status.FromError(err); ok {
			customLogger.Printf("| %3d | %13v | %15s | %s%s",
				int(st.Code()),
				duration,
				clientAddr,
				info.FullMethod,
				args)
		} else {
			customLogger.Printf("| ERR | %13v | %15s | %s - %v%s",
				duration,
				clientAddr,
				info.FullMethod,
				err,
				args)
		}

		return resp, err
	}
}
