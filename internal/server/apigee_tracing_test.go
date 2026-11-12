package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	pb "github.com/michaelw/ext-authz-token-exchange/internal/apigeepb"
	"github.com/michaelw/ext-authz-token-exchange/internal/config"
	"github.com/michaelw/ext-authz-token-exchange/internal/exchange"
	"github.com/michaelw/ext-authz-token-exchange/internal/policy"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

func TestApigeeTraceContinuity(t *testing.T) {
	for _, tc := range []struct {
		name, transport, payload, traceID, parent string
		sampled                                   bool
	}{
		{"transport wins", "00-11111111111111111111111111111111-1111111111111111-01", "00-22222222222222222222222222222222-2222222222222222-01", "11111111111111111111111111111111", "1111111111111111", true},
		{"payload fallback", "", "00-22222222222222222222222222222222-2222222222222222-01", "22222222222222222222222222222222", "2222222222222222", true},
		{"invalid transport fallback", "invalid", "00-22222222222222222222222222222222-2222222222222222-01", "22222222222222222222222222222222", "2222222222222222", true},
		{"unsampled", "", "00-22222222222222222222222222222222-2222222222222222-00", "22222222222222222222222222222222", "2222222222222222", false},
		{"missing", "", "", "", "", true},
		{"invalid", "invalid", "invalid", "", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := tracetest.NewSpanRecorder()
			provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder), sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.AlwaysSample())))
			previous := otel.GetTracerProvider()
			otel.SetTracerProvider(provider)
			defer otel.SetTracerProvider(previous)
			defer provider.Shutdown(context.Background())
			var endpointParent string
			endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				endpointParent = r.Header.Get("traceparent")
				_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "EXCHANGED_CANARY", "token_type": "Bearer", "issued_token_type": config.DefaultIssuedTokenType})
			}))
			defer endpoint.Close()
			cfg := config.RuntimeConfig{AllowHTTPTokenEndpoint: true, TokenEndpointAuthMethod: config.AuthMethodClientSecretBasic, IssuerProfiles: map[string]config.IssuerProfile{"primary": {TokenEndpoint: endpoint.URL, ClientID: "client", ClientSecret: "SECRET_CANARY"}}}
			srv := NewApigeeGRPCServer(cfg, policy.NewStaticStore(loggingIndex()), exchange.NewClient(cfg, nil), false)
			req := loggingApigeeRequest("/api/orders", "Bearer SUBJECT_CANARY")
			req.Request.Headers["traceparent"] = &pb.Strings{Strings: []string{tc.payload}}
			req.Request.Headers["tracestate"] = &pb.Strings{Strings: []string{"vendor=value"}}
			ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("traceparent", tc.transport, "tracestate", "vendor=transport"))
			_, err := ApigeeTracing()(ctx, req, &grpc.UnaryServerInfo{FullMethod: ApigeeProcessMethod}, func(ctx context.Context, req any) (any, error) {
				return srv.ProcessMessage(ctx, req.(*pb.MessageContext))
			})
			if err != nil {
				t.Fatal(err)
			}
			spans := recorder.Ended()
			if !tc.sampled {
				if len(endpointParent) != 55 || !strings.HasPrefix(endpointParent, "00-"+tc.traceID+"-") || !strings.HasSuffix(endpointParent, "-00") {
					t.Fatal("lost unsampled outbound propagation")
				}
				if len(spans) != 0 {
					t.Fatal("ignored unsampled parent")
				}
				return
			}
			if len(spans) != 3 {
				t.Fatalf("wanted RPC, evaluation and HTTP spans, got %d", len(spans))
			}
			rpc, evaluation, outbound := spans[2], spans[1], spans[0]
			if tc.traceID != "" && (rpc.SpanContext().TraceID().String() != tc.traceID || rpc.Parent().SpanID().String() != tc.parent) {
				t.Fatal("wrong gateway parent")
			}
			if evaluation.Parent().SpanID() != rpc.SpanContext().SpanID() || outbound.Parent().SpanID() != evaluation.SpanContext().SpanID() {
				t.Fatal("lost local span parentage")
			}
			if rpc.SpanContext().TraceID() != outbound.SpanContext().TraceID() || rpc.SpanContext().SpanID() == evaluation.SpanContext().SpanID() || endpointParent == "" {
				t.Fatal("invalid outbound propagation")
			}
			for _, span := range spans {
				for _, attr := range span.Attributes() {
					if attr.Value.AsString() == "SECRET_CANARY" || attr.Value.AsString() == "SUBJECT_CANARY" || attr.Value.AsString() == "EXCHANGED_CANARY" {
						t.Fatal("credential in span")
					}
				}
			}
		})
	}
}
