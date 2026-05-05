package server

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
	"unicode"

	envoy_service_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// Custom logger without timestamp prefix to match Gin format
var customLogger = log.New(os.Stdout, "[gRPC] ", log.LstdFlags)

const maxLogFieldLength = 512

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
				args = fmt.Sprintf(" | %s | %s://%s%s",
					logField(httpReq.GetMethod()),
					logField(httpReq.GetScheme()),
					logField(httpReq.GetHost()),
					logPath(httpReq.GetPath()))
			}
		}

		if resp != nil {
			args += fmt.Sprintf(" | response=%s", responseSummary(resp))
		}

		if st, ok := status.FromError(err); ok {
			customLogger.Printf("| %3d | %13v | %15s | %s%s",
				int(st.Code()),
				duration,
				logField(clientAddr),
				logField(info.FullMethod),
				args)
		} else {
			customLogger.Printf("| ERR | %13v | %15s | %s - %v%s",
				duration,
				logField(clientAddr),
				logField(info.FullMethod),
				err,
				args)
		}

		return resp, err
	}
}

func responseSummary(resp any) string {
	checkResp, ok := resp.(*envoy_service_auth_v3.CheckResponse)
	if !ok {
		return "unknown"
	}
	if checkResp.GetOkResponse() != nil {
		return "ok"
	}
	if denied := checkResp.GetDeniedResponse(); denied != nil {
		return "denied_status=" + logField(denied.GetStatus().GetCode().String())
	}
	return "unknown"
}

func logPath(path string) string {
	path, _, _ = strings.Cut(path, "?")
	path, _, _ = strings.Cut(path, "#")
	return logField(path)
}

func logField(value string) string {
	if value == "" {
		return "-"
	}
	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, value)
	value = strings.Join(strings.Fields(value), " ")
	if len(value) <= maxLogFieldLength {
		return value
	}
	return value[:maxLogFieldLength] + "...<truncated>"
}
