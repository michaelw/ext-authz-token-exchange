package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	pb "github.com/michaelw/ext-authz-token-exchange/internal/apigeepb"
	"github.com/michaelw/ext-authz-token-exchange/internal/config"
	"github.com/michaelw/ext-authz-token-exchange/internal/exchange"
	"github.com/michaelw/ext-authz-token-exchange/internal/logging"
	"github.com/michaelw/ext-authz-token-exchange/internal/policy"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
)

func TestDecisionJSONIsSafeAndImmediate(t *testing.T) {
	var logs bytes.Buffer
	defer captureLogger(&logs)()
	s := NewAuthzGRPCServer(config.RuntimeConfig{LogFormat: "json"}, policy.NewStaticStore(loggingIndex()), &loggingExchanger{})
	_, err := s.Check(context.Background(), loggingCheckRequest("GET", "secret-host", "/secret-path?token=secret-query"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(logs.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("wanted one decision: %s", logs.String())
	}
	var event map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &event); err != nil {
		t.Fatal(err)
	}
	if event["event"] != "request_decision" || event["adapter"] != "ext_authz" || event["evaluation_id"] == "" {
		t.Fatalf("bad decision: %v", event)
	}
	for _, secret := range []string{"secret-host", "secret-path", "secret-query"} {
		if strings.Contains(logs.String(), secret) {
			t.Fatalf("leaked %s", secret)
		}
	}
}

func readLogEvents(t *testing.T, logs *bytes.Buffer) []logging.Event {
	t.Helper()
	var result []logging.Event
	for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		if len(line) > 16384 {
			t.Fatal("unbounded event")
		}
		var event logging.Event
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("invalid JSON: %v: %s", err, line)
		}
		if event.Timestamp == "" || event.Severity == "" {
			t.Fatalf("missing envelope: %s", line)
		}
		result = append(result, event)
	}
	return result
}

func loggingApigeeRequest(path, bearer string) *pb.MessageContext {
	return &pb.MessageContext{MessageId: "message-1", Request: &pb.Request{Verb: "GET", Content: "BODY_CANARY", Headers: map[string]*pb.Strings{"authorization": {Strings: []string{bearer}}, "cookie": {Strings: []string{"COOKIE_CANARY"}}}}, AdditionalFlowVariables: map[string]*pb.FlowVariable{
		"txe.input.host": apigeeStringVariable("orders.example.com"), "txe.input.path": apigeeStringVariable(path), "txe.input.scheme": apigeeStringVariable("https"),
	}}
}

func TestDecisionDiagnosticsAdapterParity(t *testing.T) {
	for _, adapter := range []string{"ext_authz", "ext_proc", "apigee"} {
		for _, tc := range []struct {
			name, bearer, reason, severity string
			index                          *policy.Index
			failure                        *exchange.OAuthError
			status                         int
		}{
			{"allow", "Bearer SUBJECT_CANARY", checkDecisionAllowExchange, "INFO", loggingIndex(), nil, 0},
			{"missing", "", checkDecisionDenyMissingBearer, "INFO", loggingIndex(), nil, 401},
			{"malformed", "Bearer one two", checkDecisionDenyMissingBearer, "INFO", loggingIndex(), nil, 401},
			{"deny", "Bearer SUBJECT_CANARY", checkDecisionDenyExplicitPolicy, "INFO", loggingDenyIndex(), nil, 403},
			{"unhealthy", "Bearer SUBJECT_CANARY", checkDecisionDenyPolicyUnhealthy, "ERROR", policy.BuildIndex(map[policy.Source]string{{Namespace: "orders", Name: "bad"}: "invalid: ["}, config.RuntimeConfig{}), nil, 500},
			{"oauth", "Bearer SUBJECT_CANARY", checkDecisionDenyExchangeError, "INFO", loggingIndex(), &exchange.OAuthError{StatusCode: 400, Error: "invalid_request", ErrorDescription: "ERROR_CANARY", Body: "BODY_CANARY", WWWAuthenticate: []string{"CHALLENGE_CANARY"}, Diagnostics: exchange.Diagnostics{Code: "TXE-2001", OAuthError: "invalid_request", FailureClass: "oauth_rejection", UpstreamStatus: 400}}, 400},
			{"timeout", "Bearer SUBJECT_CANARY", checkDecisionDenyExchangeError, "ERROR", loggingIndex(), &exchange.OAuthError{StatusCode: 500, Message: "ERROR_CANARY", Diagnostics: exchange.Diagnostics{Code: "TXE-1003", FailureClass: "timeout"}}, 500},
		} {
			t.Run(adapter+"/"+tc.name, func(t *testing.T) {
				var logs bytes.Buffer
				defer captureLogger(&logs)()
				cfg := config.RuntimeConfig{LogFormat: "json"}
				store := policy.NewStaticStore(tc.index)
				ex := &loggingExchanger{result: exchange.Result{AccessToken: "EXCHANGED_CANARY"}, err: tc.failure}
				path := "/api/orders/PATH_CANARY?token=QUERY_CANARY"
				switch adapter {
				case "ext_authz":
					_, err := NewAuthzGRPCServer(cfg, store, ex).Check(context.Background(), loggingCheckRequestWithHeaders("GET", "orders.example.com", path, map[string]string{"authorization": tc.bearer, "cookie": "COOKIE_CANARY"}))
					if err != nil {
						t.Fatal(err)
					}
				case "ext_proc":
					NewExtProcGRPCServer(cfg, store, ex).evaluateRequestHeaders(context.Background(), extProcHeaderRequest(map[string]string{":method": "GET", ":authority": "orders.example.com", ":path": path, "authorization": tc.bearer}))
				case "apigee":
					_, err := NewApigeeGRPCServer(cfg, store, ex, false).ProcessMessage(context.Background(), loggingApigeeRequest(path, tc.bearer))
					if err != nil {
						t.Fatal(err)
					}
				}
				events := readLogEvents(t, &logs)
				if len(events) != 1 {
					t.Fatalf("duplicate decisions: %s", logs.String())
				}
				e := events[0]
				if e.Adapter != adapter || e.Reason != tc.reason || e.Severity != tc.severity || e.HTTPStatus != tc.status {
					t.Fatalf("unexpected decision: %+v", e)
				}
				if tc.failure != nil && e.Diagnostic != tc.failure.Diagnostics.Code {
					t.Fatal("lost typed diagnostics")
				}
				if strings.Contains(logs.String(), "CANARY") {
					t.Fatalf("secret leak: %s", logs.String())
				}
			})
		}
	}
}

func TestApigeeExplicitTokenDebuggingAndInspection(t *testing.T) {
	for _, format := range []string{"text", "json"} {
		for _, enabled := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/%t", format, enabled), func(t *testing.T) {
				var logs bytes.Buffer
				defer captureLogger(&logs)()
				cfg := config.RuntimeConfig{LogFormat: format, InsecureLogTokens: enabled}
				LogStartup(cfg, true)
				ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer CALLOUT_CANARY"))
				srv := NewApigeeGRPCServer(cfg, policy.NewStaticStore(loggingIndex()), &loggingExchanger{result: exchange.Result{AccessToken: "EXCHANGED_CANARY"}}, true)
				req := loggingApigeeRequest("/api/orders/PATH_CANARY?token=QUERY_CANARY", "Bearer SUBJECT_CANARY")
				for i := 0; i < 1000; i++ {
					req.AdditionalFlowVariables[fmt.Sprintf("VARIABLE_CANARY%d", i)] = apigeeStringVariable("VALUE_CANARY")
				}
				_, err := srv.ProcessMessage(ctx, req)
				if err != nil {
					t.Fatal(err)
				}
				for _, secret := range []string{"CALLOUT_CANARY", "BODY_CANARY", "COOKIE_CANARY", "PATH_CANARY", "QUERY_CANARY", "VARIABLE_CANARY", "VALUE_CANARY"} {
					if strings.Contains(logs.String(), secret) {
						t.Fatalf("leaked %s", secret)
					}
				}
				if strings.Contains(logs.String(), "SUBJECT_CANARY") != enabled || strings.Contains(logs.String(), "EXCHANGED_CANARY") != enabled {
					t.Fatal("token flag ignored or accidentally enabled")
				}
				if format == "json" {
					for _, e := range readLogEvents(t, &logs) {
						if e.Name != "insecure_token_debug" && (e.SubjectToken != "" || e.ExchangedToken != "") {
							t.Fatal("token in ordinary event")
						}
					}
				}
			})
		}
	}
}

func TestTransportJSONRejectsRawErrorsAndAuthentication(t *testing.T) {
	var logs bytes.Buffer
	defer captureLogger(&logs)()
	opts := ApigeeLoggingOptions()
	opts.Format = "json"
	auth := ApigeeAuthentication(nil, nil)
	_, err := LoggingInterceptorWithOptions(opts)(metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Basic CALLOUT_CANARY")), nil, &grpc.UnaryServerInfo{FullMethod: ApigeeProcessMethod}, func(ctx context.Context, req any) (any, error) {
		return auth(ctx, req, &grpc.UnaryServerInfo{FullMethod: ApigeeProcessMethod}, func(context.Context, any) (any, error) { t.Fatal("authenticated invalid caller"); return nil, nil })
	})
	if err == nil {
		t.Fatal("expected authentication rejection")
	}
	e := readLogEvents(t, &logs)[0]
	if e.GRPCStatus != codes.Unauthenticated.String() || e.Severity != "WARN" || e.Adapter != "apigee" {
		t.Fatalf("missing authentication diagnostics: %+v", e)
	}
	logs.Reset()
	stream := &loggingTestServerStream{ctx: context.Background(), recv: func(any) error { return errors.New("ERROR_CANARY https://LOCATION_CANARY") }}
	err = LoggingStreamInterceptorWithOptions(LoggingOptions{Format: "json", Methods: ExtProcLoggingMethods()})(nil, stream, &grpc.StreamServerInfo{FullMethod: ExtProcProcessMethod}, func(_ any, s grpc.ServerStream) error { return s.RecvMsg(nil) })
	if err == nil {
		t.Fatal("expected stream failure")
	}
	e = readLogEvents(t, &logs)[0]
	if e.Adapter != "ext_proc" || e.Severity != "ERROR" || e.GRPCStatus != "Unknown" {
		t.Fatalf("missing stream diagnostics: %+v", e)
	}
	if strings.Contains(logs.String(), "CANARY") {
		t.Fatal("raw error leaked")
	}
	logs.Reset()
	logRPCFormat("text", context.Background(), ExtProcProcessMethod, 0, errors.New("ERROR_CANARY"), "")
	if strings.Contains(logs.String(), "CANARY") {
		t.Fatal("raw text error leaked")
	}
}

func TestEnvoyExplicitTokenDebuggingInBothFormats(t *testing.T) {
	for _, adapter := range []string{"ext_authz", "ext_proc"} {
		for _, format := range []string{"text", "json"} {
			for _, enabled := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/%t", adapter, format, enabled), func(t *testing.T) {
					var logs bytes.Buffer
					defer captureLogger(&logs)()
					cfg := config.RuntimeConfig{LogFormat: format, InsecureLogTokens: enabled}
					store := policy.NewStaticStore(loggingIndex())
					ex := &loggingExchanger{result: exchange.Result{AccessToken: "EXCHANGED_CANARY"}}
					path := "/api/orders/PATH_CANARY?token=QUERY_CANARY"
					if adapter == "ext_authz" {
						_, err := NewAuthzGRPCServer(cfg, store, ex).Check(context.Background(), loggingCheckRequestWithHeaders("GET", "orders.example.com", path, map[string]string{"authorization": "Bearer SUBJECT_CANARY", "cookie": "COOKIE_CANARY"}))
						if err != nil {
							t.Fatal(err)
						}
					} else {
						NewExtProcGRPCServer(cfg, store, ex).evaluateRequestHeaders(context.Background(), extProcHeaderRequest(map[string]string{":method": "GET", ":authority": "orders.example.com", ":path": path, "authorization": "Bearer SUBJECT_CANARY", "cookie": "COOKIE_CANARY"}))
					}
					if strings.Contains(logs.String(), "SUBJECT_CANARY") != enabled || strings.Contains(logs.String(), "EXCHANGED_CANARY") != enabled {
						t.Fatal("incorrect token flag behavior")
					}
					for _, secret := range []string{"PATH_CANARY", "QUERY_CANARY", "COOKIE_CANARY"} {
						if strings.Contains(logs.String(), secret) {
							t.Fatalf("leaked %s", secret)
						}
					}
					if format == "json" {
						readLogEvents(t, &logs)
					}
				})
			}
		}
	}
}
