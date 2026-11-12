// Package logging renders explicit, credential-free operational events.
package logging

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"strings"
	"time"
)

const DefaultFormat = "json"

func Format(value string) string {
	if value = strings.TrimSpace(value); value != "" {
		return value
	}
	return DefaultFormat
}

// Event is the common schema for all gateway adapters. Sensitive token fields
// are populated only by the explicitly enabled insecure debugging path.
type Event struct {
	Timestamp       string  `json:"timestamp"`
	Severity        string  `json:"severity"`
	Name            string  `json:"event"`
	Adapter         string  `json:"adapter,omitempty"`
	EvaluationID    string  `json:"evaluation_id,omitempty"`
	TraceID         string  `json:"trace_id,omitempty"`
	SpanID          string  `json:"span_id,omitempty"`
	GatewayID       string  `json:"gateway_id,omitempty"`
	GatewayIDSource string  `json:"gateway_id_source,omitempty"`
	ProxyRevision   string  `json:"proxy_revision,omitempty"`
	Decision        string  `json:"decision,omitempty"`
	Policy          string  `json:"policy,omitempty"`
	Reason          string  `json:"reason,omitempty"`
	Result          string  `json:"result_class,omitempty"`
	DurationMS      float64 `json:"duration_ms,omitempty"`
	HTTPStatus      int     `json:"http_status,omitempty"`
	Diagnostic      string  `json:"diagnostic_code,omitempty"`
	OAuthError      string  `json:"oauth_error,omitempty"`
	UpstreamStatus  int     `json:"upstream_http_status,omitempty"`
	FailureClass    string  `json:"failure_class,omitempty"`
	GRPCStatus      string  `json:"grpc_status,omitempty"`
	RPCMethod       string  `json:"rpc_method,omitempty"`
	Message         string  `json:"message,omitempty"`
	SubjectToken    string  `json:"subject_token,omitempty"`
	ExchangedToken  string  `json:"exchanged_token,omitempty"`
	Inspection      *Shape  `json:"inspection,omitempty"`
}

type Shape struct {
	Direction      string            `json:"direction"`
	Fields         []string          `json:"fields,omitempty"`
	Headers        map[string]int    `json:"header_value_counts,omitempty"`
	Variables      map[string]string `json:"variable_types,omitempty"`
	MutationNames  []string          `json:"mutation_names,omitempty"`
	ChallengeCount int               `json:"challenge_count,omitempty"`
}

// Write keeps the supplied legacy text intact, or emits one complete JSON line.
func Write(logger *log.Logger, format string, event Event, text string) {
	if event.Timestamp == "" {
		event.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if Format(format) == "json" {
		data, err := json.Marshal(event)
		if err != nil {
			panic(err)
		} // The schema contains only JSON-safe concrete types.
		log.New(logger.Writer(), "", 0).Print(string(data))
		return
	}
	logger.Print(text)
}

// ConfigureStandard preserves text logging. JSON lifecycle messages use only
// their fixed diagnostic prefix, never formatted error details or arguments.
func ConfigureStandard(format string) {
	if Format(format) == "json" {
		log.SetFlags(0)
		log.SetPrefix("")
		log.SetOutput(runtimeWriter{log.Writer()})
	}
}

type runtimeWriter struct{ out io.Writer }

func (w runtimeWriter) Write(p []byte) (int, error) {
	message := strings.TrimSpace(string(p))
	message, _, _ = strings.Cut(message, ":")
	severity := "INFO"
	if strings.Contains(strings.ToLower(message), "fail") || strings.HasPrefix(message, "invalid") {
		severity = "ERROR"
	}
	data, _ := json.Marshal(Event{Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Severity: severity, Name: "runtime", Message: Bound(message)})
	_, err := fmt.Fprintln(w.out, string(data))
	return len(p), err
}

func Bound(s string) string {
	s = strings.ToValidUTF8(s, "?")
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 512 {
		s = strings.ToValidUTF8(s[:512], "?") + "...<truncated>"
	}
	return s
}
