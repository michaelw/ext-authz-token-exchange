package server

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
	"unicode"

	"google.golang.org/grpc"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// Custom logger without timestamp prefix to match Gin format
var customLogger = log.New(os.Stdout, "[gRPC] ", log.LstdFlags)

const maxLogFieldLength = 512

// LoggingOptions controls gRPC request/response logging behavior.
type LoggingOptions struct {
	Methods map[string]LoggingMethod
}

// LoggingMethod controls logging for a single gRPC full method.
type LoggingMethod struct {
	LogEnabled        bool
	SummarizeRequest  func(any) string
	SummarizeResponse func(any) string
}

// LoggingInterceptor creates a gRPC unary interceptor for request/response logging
func LoggingInterceptor() grpc.UnaryServerInterceptor {
	return LoggingInterceptorWithOptions(LoggingOptions{})
}

// LoggingInterceptorWithOptions creates a gRPC unary interceptor with explicit logging options.
func LoggingInterceptorWithOptions(opts LoggingOptions) grpc.UnaryServerInterceptor {
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

		methodLogging, hasMethodLogging := opts.Methods[info.FullMethod]
		if hasMethodLogging && !methodLogging.LogEnabled {
			return resp, err
		}

		// Format similar to Gin: [gRPC] timestamp | status | duration | client | method | args
		var args string
		if hasMethodLogging && methodLogging.SummarizeRequest != nil {
			args += methodLogging.SummarizeRequest(req)
		}

		if resp != nil {
			args += fmt.Sprintf(" | response=%s", responseSummary(resp, methodLogging, hasMethodLogging))
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

func responseSummary(resp any, method LoggingMethod, registered bool) string {
	if registered && method.SummarizeResponse != nil {
		return method.SummarizeResponse(resp)
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
