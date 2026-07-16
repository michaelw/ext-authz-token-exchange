package server

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
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
		start := time.Now()
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

		logRPC(ctx, info.FullMethod, duration, err, args)

		return resp, err
	}
}

// LoggingStreamInterceptorWithOptions creates a streaming gRPC interceptor with
// the same method summaries and output format as the unary interceptor.
func LoggingStreamInterceptorWithOptions(opts LoggingOptions) grpc.StreamServerInterceptor {
	return func(srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		methodLogging, hasMethodLogging := opts.Methods[info.FullMethod]
		if !hasMethodLogging || !methodLogging.LogEnabled {
			return handler(srv, stream)
		}

		wrapped := &summaryServerStream{
			ServerStream: stream,
			method:       methodLogging,
		}
		start := time.Now()
		err := handler(srv, wrapped)
		duration := time.Since(start)
		logRPC(stream.Context(), info.FullMethod, duration, err, wrapped.args())
		return err
	}
}

type summaryServerStream struct {
	grpc.ServerStream
	method LoggingMethod

	mu              sync.Mutex
	requestSummary  string
	responseSummary string
}

func (s *summaryServerStream) RecvMsg(message any) error {
	err := s.ServerStream.RecvMsg(message)
	if err != nil || s.method.SummarizeRequest == nil {
		return err
	}
	if summary := s.method.SummarizeRequest(message); summary != "" {
		s.mu.Lock()
		if s.requestSummary == "" {
			s.requestSummary = summary
		}
		s.mu.Unlock()
	}
	return nil
}

func (s *summaryServerStream) SendMsg(message any) error {
	if s.method.SummarizeResponse != nil {
		summary := s.method.SummarizeResponse(message)
		s.mu.Lock()
		s.responseSummary = summary
		s.mu.Unlock()
	}
	return s.ServerStream.SendMsg(message)
}

func (s *summaryServerStream) args() string {
	s.mu.Lock()
	defer s.mu.Unlock()

	args := s.requestSummary
	if s.responseSummary != "" {
		args += fmt.Sprintf(" | response=%s", s.responseSummary)
	}
	return args
}

func logRPC(ctx context.Context, method string, duration time.Duration, err error, args string) {
	clientAddr := "UNKNOWN"
	if p, ok := peer.FromContext(ctx); ok {
		clientAddr = p.Addr.String()
	}
	if st, ok := status.FromError(err); ok {
		customLogger.Printf("| %3d | %13v | %15s | %s%s",
			int(st.Code()),
			duration,
			logField(clientAddr),
			logField(method),
			args)
	} else {
		customLogger.Printf("| ERR | %13v | %15s | %s - %v%s",
			duration,
			logField(clientAddr),
			logField(method),
			err,
			args)
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
