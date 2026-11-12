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

	"github.com/michaelw/ext-authz-token-exchange/internal/config"
	"github.com/michaelw/ext-authz-token-exchange/internal/logging"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// Custom logger without timestamp prefix to match Gin format
var customLogger = log.New(os.Stdout, "[gRPC] ", log.LstdFlags)

const maxLogFieldLength = 512

// LogStartup reports only effective logging controls, never issuer settings.
func LogStartup(cfg config.RuntimeConfig, inspect bool) {
	format := logging.Format(cfg.LogFormat)
	text := fmt.Sprintf("LOGGING format=%s health_checks=%t insecure_tokens=%t apigee_inspection=%t", format, cfg.LogHealthChecks, cfg.InsecureLogTokens, inspect)
	logging.Write(customLogger, format, logging.Event{Name: "logging_settings", Severity: "INFO", Message: text}, text)
	if cfg.InsecureLogTokens {
		text := "WARNING: insecure token logging enabled; use synthetic credentials only"
		logging.Write(customLogger, format, logging.Event{Name: "insecure_logging_enabled", Severity: "WARN", Message: text}, text)
	}
}

// LoggingOptions controls gRPC request/response logging behavior.
type LoggingOptions struct {
	Format  string
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

		logRPCFormat(opts.Format, ctx, info.FullMethod, duration, err, args)

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
		logRPCFormat(opts.Format, stream.Context(), info.FullMethod, duration, err, wrapped.args())
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

func logRPCFormat(format string, ctx context.Context, method string, duration time.Duration, err error, args string) {
	if logging.Format(format) == "json" {
		severity := "INFO"
		code := status.Code(err)
		if err != nil {
			severity = "ERROR"
		}
		if code == codes.InvalidArgument || code == codes.Unauthenticated || code == codes.PermissionDenied {
			severity = "WARN"
		}
		logging.Write(customLogger, format, logging.Event{Name: "rpc_complete", Severity: severity, Adapter: adapterForMethod(method), RPCMethod: safeRPCMethod(method), GRPCStatus: code.String(), DurationMS: float64(duration) / float64(time.Millisecond)}, "")
		return
	}
	logRPC(ctx, method, duration, err, args)
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
		customLogger.Printf("| ERR | %13v | %15s | %s - failure_class=internal%s",
			duration,
			logField(clientAddr),
			logField(method),
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
	return "[redacted]"
}

func safeHTTPMethod(method string) string {
	switch strings.ToUpper(method) {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "CONNECT", "TRACE":
		return strings.ToUpper(method)
	default:
		return "OTHER"
	}
}

func safeCorrelation(value string) string {
	if len(value) == 0 || len(value) > 128 {
		return ""
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' || r == ':') {
			return ""
		}
	}
	return value
}

func safeHeaderName(name string) string {
	switch strings.ToLower(name) {
	case "authorization", "cookie", "content-type", "content-length", "accept", "host", "origin", "user-agent", "traceparent", "tracestate", "www-authenticate", ":authority", ":method", ":path", ":scheme":
		return strings.ToLower(name)
	default:
		return "[other]"
	}
}

func safeHeaderNames(headers map[string]string) []string {
	seen := map[string]string{}
	for name := range headers {
		seen[safeHeaderName(name)] = ""
	}
	return sortedMapKeys(seen)
}

func adapterForMethod(method string) string {
	switch method {
	case AuthzCheckMethod:
		return "ext_authz"
	case ExtProcProcessMethod:
		return "ext_proc"
	case ApigeeProcessMethod:
		return "apigee"
	default:
		return ""
	}
}

func safeRPCMethod(method string) string {
	if adapterForMethod(method) != "" || method == "/grpc.health.v1.Health/Check" {
		return method
	}
	return "other"
}

func logProtocolWarning(format, adapter, reason, text string) {
	logging.Write(customLogger, format, logging.Event{Name: "protocol_error", Severity: "WARN", Adapter: adapter, Reason: reason}, text)
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
