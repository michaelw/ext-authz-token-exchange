package server_test

import (
	"context"
	"net/http"
	"testing"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_service_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/baggage"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"

	"github.com/michaelw/ext-authz-token-exchange/internal/config"
	"github.com/michaelw/ext-authz-token-exchange/internal/exchange"
	"github.com/michaelw/ext-authz-token-exchange/internal/policy"
	"github.com/michaelw/ext-authz-token-exchange/internal/server"
)

func TestAuthzGRPC(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Authz gRPC Suite")
}

var _ = Describe("AuthzGRPCServer", func() {
	var cfg config.RuntimeConfig

	BeforeEach(func() {
		cfg = config.RuntimeConfig{BearerRealm: "example"}
	})

	It("allows CORS preflight OPTIONS requests without token exchange", func() {
		exchanger := &fakeExchanger{}
		srv := server.NewAuthzGRPCServer(cfg, policy.NewStaticStore(indexFor(`
version: v1
entries:
  - match:
      host: orders.example.com
      pathPrefix: /api/orders
      methods: ["OPTIONS"]
    action: exchange
    exchange:
      issuerRef: primary
      scope: read:orders
`)), exchanger)

		resp, err := srv.Check(context.Background(), checkRequest("OPTIONS", "orders.example.com", "/api/orders", map[string]string{
			"origin":                        "https://app.example.com",
			"access-control-request-method": "GET",
		}))

		Expect(err).NotTo(HaveOccurred())
		Expect(resp.GetOkResponse()).NotTo(BeNil())
		Expect(exchanger.calls).To(Equal(0))
	})

	It("allows unmatched requests through unchanged by default", func() {
		srv := server.NewAuthzGRPCServer(cfg, policy.NewStaticStore(indexFor(`
version: v1
entries:
  - match:
      host: orders.example.com
      pathPrefix: /api/orders
      methods: ["GET"]
    action: exchange
    exchange:
      issuerRef: primary
      scope: read:orders
`)), &fakeExchanger{})

		resp, err := srv.Check(context.Background(), checkRequest("GET", "orders.example.com", "/api/customers/1", map[string]string{
			"authorization": "Bearer original",
		}))

		Expect(err).NotTo(HaveOccurred())
		Expect(resp.GetOkResponse()).NotTo(BeNil())
	})

	It("denies unmatched requests when default deny is enabled", func() {
		cfg.DefaultDenyUnmatched = true
		srv := server.NewAuthzGRPCServer(cfg, policy.NewStaticStore(indexFor(`
version: v1
entries:
  - match:
      host: orders.example.com
      pathPrefix: /api/orders
      methods: ["GET"]
    action: exchange
    exchange:
      issuerRef: primary
      scope: read:orders
`)), &fakeExchanger{})

		resp, err := srv.Check(context.Background(), checkRequest("GET", "orders.example.com", "/api/customers/1", map[string]string{
			"authorization": "Bearer original",
		}))

		Expect(err).NotTo(HaveOccurred())
		denied := resp.GetDeniedResponse()
		Expect(denied).NotTo(BeNil())
		Expect(denied.GetStatus().GetCode().String()).To(Equal("Forbidden"))
		Expect(denied.GetBody()).To(MatchJSON(`{"error":"policy_denied"}`))
	})

	It("denies unmatched CORS preflight requests when default deny is enabled", func() {
		cfg.DefaultDenyUnmatched = true
		srv := server.NewAuthzGRPCServer(cfg, policy.NewStaticStore(indexFor(`
version: v1
entries:
  - match:
      host: orders.example.com
      pathPrefix: /api/orders
      methods: ["OPTIONS"]
    action: exchange
    exchange:
      issuerRef: primary
      scope: read:orders
`)), &fakeExchanger{})

		resp, err := srv.Check(context.Background(), checkRequest("OPTIONS", "orders.example.com", "/api/customers/1", map[string]string{
			"origin":                        "https://app.example.com",
			"access-control-request-method": "GET",
		}))

		Expect(err).NotTo(HaveOccurred())
		denied := resp.GetDeniedResponse()
		Expect(denied).NotTo(BeNil())
		Expect(denied.GetStatus().GetCode().String()).To(Equal("Forbidden"))
		Expect(denied.GetBody()).To(MatchJSON(`{"error":"policy_denied"}`))
	})

	It("denies explicit deny policies without token exchange", func() {
		exchanger := &fakeExchanger{}
		srv := server.NewAuthzGRPCServer(cfg, policy.NewStaticStore(indexFor(`
version: v1
entries:
  - match:
      host: orders.example.com
      pathPrefix: /api/orders
      methods: ["GET"]
    action: deny
`)), exchanger)

		resp, err := srv.Check(context.Background(), checkRequest("GET", "orders.example.com", "/api/orders/1", map[string]string{
			"authorization": "Bearer subject",
		}))

		Expect(err).NotTo(HaveOccurred())
		denied := resp.GetDeniedResponse()
		Expect(denied).NotTo(BeNil())
		Expect(denied.GetStatus().GetCode().String()).To(Equal("Forbidden"))
		Expect(denied.GetBody()).To(MatchJSON(`{"error":"policy_denied"}`))
		Expect(exchanger.calls).To(Equal(0))
	})

	It("denies explicit deny CORS preflight requests", func() {
		exchanger := &fakeExchanger{}
		srv := server.NewAuthzGRPCServer(cfg, policy.NewStaticStore(indexFor(`
version: v1
entries:
  - match:
      host: orders.example.com
      pathPrefix: /api/orders
      methods: ["OPTIONS"]
    action: deny
`)), exchanger)

		resp, err := srv.Check(context.Background(), checkRequest("OPTIONS", "orders.example.com", "/api/orders", map[string]string{
			"origin":                        "https://app.example.com",
			"access-control-request-method": "GET",
		}))

		Expect(err).NotTo(HaveOccurred())
		denied := resp.GetDeniedResponse()
		Expect(denied).NotTo(BeNil())
		Expect(denied.GetStatus().GetCode().String()).To(Equal("Forbidden"))
		Expect(denied.GetBody()).To(MatchJSON(`{"error":"policy_denied"}`))
		Expect(exchanger.calls).To(Equal(0))
	})

	It("allows matched CORS preflight requests when default deny is enabled", func() {
		cfg.DefaultDenyUnmatched = true
		exchanger := &fakeExchanger{}
		srv := server.NewAuthzGRPCServer(cfg, policy.NewStaticStore(indexFor(`
version: v1
entries:
  - match:
      host: orders.example.com
      pathPrefix: /api/orders
      methods: ["OPTIONS"]
    action: exchange
    exchange:
      issuerRef: primary
      scope: read:orders
`)), exchanger)

		resp, err := srv.Check(context.Background(), checkRequest("OPTIONS", "orders.example.com", "/api/orders", map[string]string{
			"origin":                        "https://app.example.com",
			"access-control-request-method": "GET",
		}))

		Expect(err).NotTo(HaveOccurred())
		Expect(resp.GetOkResponse()).NotTo(BeNil())
		Expect(exchanger.calls).To(Equal(0))
	})

	It("challenges non-preflight OPTIONS requests without bearer tokens by default", func() {
		srv := server.NewAuthzGRPCServer(cfg, policy.NewStaticStore(indexFor(`
version: v1
entries:
  - match:
      host: orders.example.com
      pathPrefix: /api/orders
      methods: ["OPTIONS"]
    action: exchange
    exchange:
      issuerRef: primary
      scope: read:orders
`)), &fakeExchanger{})

		resp, err := srv.Check(context.Background(), checkRequest("OPTIONS", "orders.example.com", "/api/orders", nil))

		Expect(err).NotTo(HaveOccurred())
		Expect(resp.GetDeniedResponse()).NotTo(BeNil())
		Expect(resp.GetDeniedResponse().GetStatus().GetCode().String()).To(Equal("Unauthorized"))
	})

	It("optionally allows unauthenticated non-preflight OPTIONS requests", func() {
		cfg.AllowUnauthenticatedOptions = true
		exchanger := &fakeExchanger{}
		srv := server.NewAuthzGRPCServer(cfg, policy.NewStaticStore(indexFor(`
version: v1
entries:
  - match:
      host: orders.example.com
      pathPrefix: /api/orders
      methods: ["OPTIONS"]
    action: exchange
    exchange:
      issuerRef: primary
      scope: read:orders
`)), exchanger)

		resp, err := srv.Check(context.Background(), checkRequest("OPTIONS", "orders.example.com", "/api/orders", nil))

		Expect(err).NotTo(HaveOccurred())
		Expect(resp.GetOkResponse()).NotTo(BeNil())
		Expect(exchanger.calls).To(Equal(0))
	})

	It("exchanges bearer tokens on OPTIONS requests", func() {
		exchanger := &fakeExchanger{result: exchange.Result{AccessToken: "exchanged"}}
		srv := server.NewAuthzGRPCServer(cfg, policy.NewStaticStore(indexFor(`
version: v1
entries:
  - match:
      host: orders.example.com
      pathPrefix: /api/orders
      methods: ["OPTIONS"]
    action: exchange
    exchange:
      issuerRef: primary
      resources:
        - https://orders.example.com/api/
`)), exchanger)

		resp, err := srv.Check(context.Background(), checkRequest("OPTIONS", "orders.example.com", "/api/orders", map[string]string{
			"authorization": "Bearer subject",
		}))

		Expect(err).NotTo(HaveOccurred())
		Expect(resp.GetOkResponse()).NotTo(BeNil())
		Expect(headerValue(resp.GetOkResponse().GetHeaders(), "authorization")).To(Equal("Bearer exchanged"))
		Expect(exchanger.calls).To(Equal(1))
	})

	It("returns a bearer challenge when a matched request has no token", func() {
		srv := server.NewAuthzGRPCServer(cfg, policy.NewStaticStore(indexFor(`
version: v1
entries:
  - match:
      host: orders.example.com
      pathPrefix: /api/orders
      methods: ["GET"]
    action: exchange
    exchange:
      issuerRef: primary
      scope: read:orders
`)), &fakeExchanger{})

		resp, err := srv.Check(context.Background(), checkRequest("GET", "orders.example.com", "/api/orders/1", nil))

		Expect(err).NotTo(HaveOccurred())
		denied := resp.GetDeniedResponse()
		Expect(denied).NotTo(BeNil())
		Expect(denied.GetStatus().GetCode().String()).To(Equal("Unauthorized"))
		Expect(headerValue(denied.GetHeaders(), "WWW-Authenticate")).To(Equal(`Bearer realm="example", scope="read:orders"`))
		Expect(denied.GetBody()).To(MatchJSON(`{"error":"bearer_token_required"}`))
	})

	It("uses the matched issuer profile realm for bearer challenges", func() {
		cfg.IssuerProfiles = map[string]config.IssuerProfile{
			"primary": {
				Name:          "primary",
				TokenEndpoint: "http://issuer.example/token",
				BearerRealm:   "issuer",
				ClientID:      "client",
				ClientSecret:  "secret",
			},
		}
		srv := server.NewAuthzGRPCServer(cfg, policy.NewStaticStore(indexFor(`
version: v1
entries:
  - match:
      host: orders.example.com
      pathPrefix: /api/orders
      methods: ["GET"]
    action: exchange
    exchange:
      issuerRef: primary
      scope: read:orders
`)), &fakeExchanger{})

		resp, err := srv.Check(context.Background(), checkRequest("GET", "orders.example.com", "/api/orders/1", nil))

		Expect(err).NotTo(HaveOccurred())
		denied := resp.GetDeniedResponse()
		Expect(denied).NotTo(BeNil())
		Expect(headerValue(denied.GetHeaders(), "WWW-Authenticate")).To(Equal(`Bearer realm="issuer", scope="read:orders"`))
	})

	It("overwrites authorization with the exchanged bearer token", func() {
		srv := server.NewAuthzGRPCServer(cfg, policy.NewStaticStore(indexFor(`
version: v1
entries:
  - match:
      host: orders.example.com
      pathPrefix: /api/orders
      methods: ["GET"]
    action: exchange
    exchange:
      issuerRef: primary
      resources:
        - https://orders.example.com/api/
`)), &fakeExchanger{result: exchange.Result{AccessToken: "exchanged"}})

		resp, err := srv.Check(context.Background(), checkRequest("GET", "orders.example.com", "/api/orders/1", map[string]string{
			"authorization": "Bearer subject",
		}))

		Expect(err).NotTo(HaveOccurred())
		Expect(resp.GetOkResponse()).NotTo(BeNil())
		Expect(headerValue(resp.GetOkResponse().GetHeaders(), "authorization")).To(Equal("Bearer exchanged"))
	})

	It("preserves raw OAuth error bodies and authenticate challenges from token exchange", func() {
		srv := server.NewAuthzGRPCServer(cfg, policy.NewStaticStore(indexFor(`
version: v1
entries:
  - match:
      host: orders.example.com
      pathPrefix: /api/orders
      methods: ["GET"]
    action: exchange
    exchange:
      issuerRef: primary
      resources:
        - https://orders.example.com/api/
`)), &fakeExchanger{err: &exchange.OAuthError{
			StatusCode:      http.StatusUnauthorized,
			Body:            `{"error":"invalid_client","issuer_detail":"kept only when passthrough is enabled"}`,
			WWWAuthenticate: []string{`Bearer realm="issuer", error="invalid_token"`},
		}})

		resp, err := srv.Check(context.Background(), checkRequest("GET", "orders.example.com", "/api/orders/1", map[string]string{
			"authorization": "Bearer subject",
		}))

		Expect(err).NotTo(HaveOccurred())
		denied := resp.GetDeniedResponse()
		Expect(denied).NotTo(BeNil())
		Expect(denied.GetStatus().GetCode().String()).To(Equal("Unauthorized"))
		Expect(denied.GetBody()).To(MatchJSON(`{"error":"invalid_client","issuer_detail":"kept only when passthrough is enabled"}`))
		Expect(headerValue(denied.GetHeaders(), "WWW-Authenticate")).To(Equal(`Bearer realm="issuer", error="invalid_token"`))
	})

	It("synthesizes OAuth deny JSON from sanitized error fields", func() {
		srv := server.NewAuthzGRPCServer(cfg, policy.NewStaticStore(indexFor(`
version: v1
entries:
  - match:
      host: orders.example.com
      pathPrefix: /api/orders
      methods: ["GET"]
    action: exchange
    exchange:
      issuerRef: primary
      resources:
        - https://orders.example.com/api/
`)), &fakeExchanger{err: &exchange.OAuthError{
			StatusCode:       http.StatusBadRequest,
			Error:            "invalid_target",
			ErrorDescription: "request failed (TXE-2001)",
			Message:          "token exchange failed",
			WWWAuthenticate:  []string{`Bearer realm="issuer"`},
		}})

		resp, err := srv.Check(context.Background(), checkRequest("GET", "orders.example.com", "/api/orders/1", map[string]string{
			"authorization": "Bearer subject",
		}))

		Expect(err).NotTo(HaveOccurred())
		denied := resp.GetDeniedResponse()
		Expect(denied).NotTo(BeNil())
		Expect(denied.GetStatus().GetCode().String()).To(Equal("BadRequest"))
		Expect(denied.GetBody()).To(MatchJSON(`{
			"error":"invalid_target",
			"error_description":"request failed (TXE-2001)",
			"message":"token exchange failed"
		}`))
		Expect(headerValue(denied.GetHeaders(), "WWW-Authenticate")).To(Equal(`Bearer realm="issuer"`))
	})

	It("falls back to server_error for empty OAuth deny bodies", func() {
		srv := server.NewAuthzGRPCServer(cfg, policy.NewStaticStore(indexFor(`
version: v1
entries:
  - match:
      host: orders.example.com
      pathPrefix: /api/orders
      methods: ["GET"]
    action: exchange
    exchange:
      issuerRef: primary
      resources:
        - https://orders.example.com/api/
`)), &fakeExchanger{err: &exchange.OAuthError{
			StatusCode: http.StatusInternalServerError,
		}})

		resp, err := srv.Check(context.Background(), checkRequest("GET", "orders.example.com", "/api/orders/1", map[string]string{
			"authorization": "Bearer subject",
		}))

		Expect(err).NotTo(HaveOccurred())
		denied := resp.GetDeniedResponse()
		Expect(denied).NotTo(BeNil())
		Expect(denied.GetStatus().GetCode().String()).To(Equal("InternalServerError"))
		Expect(denied.GetBody()).To(MatchJSON(`{"error":"server_error"}`))
	})

	It("extracts upstream trace context from Envoy HTTP request headers before token exchange", func() {
		recorder := tracetest.NewSpanRecorder()
		provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
		previousProvider := otel.GetTracerProvider()
		otel.SetTracerProvider(provider)
		defer otel.SetTracerProvider(previousProvider)

		exchanger := &fakeExchanger{result: exchange.Result{AccessToken: "exchanged"}}
		srv := server.NewAuthzGRPCServer(cfg, policy.NewStaticStore(indexFor(`
version: v1
entries:
  - match:
      host: orders.example.com
      pathPrefix: /api/orders
      methods: ["GET"]
    action: exchange
    exchange:
      issuerRef: primary
      resources:
        - https://orders.example.com/api/
`)), exchanger)

		resp, err := srv.Check(context.Background(), checkRequest("GET", "orders.example.com", "/api/orders/1", map[string]string{
			"authorization": "Bearer subject",
			"traceparent":   "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
			"tracestate":    "rojo=00f067aa0ba902b7",
			"baggage":       "tenant=blue",
		}))

		Expect(err).NotTo(HaveOccurred())
		Expect(resp.GetOkResponse()).NotTo(BeNil())
		spanContext := trace.SpanContextFromContext(exchanger.ctx)
		Expect(spanContext.IsValid()).To(BeTrue())
		Expect(spanContext.IsRemote()).To(BeFalse())
		Expect(spanContext.TraceID().String()).To(Equal("4bf92f3577b34da6a3ce929d0e0e4736"))
		bag := baggage.FromContext(exchanger.ctx)
		Expect(bag.Member("tenant").Value()).To(Equal("blue"))
		Expect(recorder.Ended()).To(HaveLen(1))
		Expect(recorder.Ended()[0].Name()).To(Equal("ext_authz Check"))
		Expect(recorder.Ended()[0].Parent().SpanID().String()).To(Equal("00f067aa0ba902b7"))
	})

	It("fails closed when matching policy is unhealthy", func() {
		srv := server.NewAuthzGRPCServer(cfg, policy.NewStaticStore(indexFor(`
version: v1
entries:
  - match:
      host: orders.example.com
      pathPrefix: /api/orders
      methods: ["GET"]
    action: exchange
    exchange:
      issuerRef: missing
      scope: read:orders
`)), &fakeExchanger{})

		resp, err := srv.Check(context.Background(), checkRequest("GET", "orders.example.com", "/api/orders/1", map[string]string{
			"authorization": "Bearer subject",
		}))

		Expect(err).NotTo(HaveOccurred())
		Expect(resp.GetDeniedResponse()).NotTo(BeNil())
		Expect(resp.GetDeniedResponse().GetStatus().GetCode().String()).To(Equal("InternalServerError"))
	})

	It("records service-level RED metrics by decision and result class", func() {
		srv := server.NewAuthzGRPCServer(cfg, policy.NewStaticStore(indexFor(`
version: v1
entries:
  - match:
      host: orders.example.com
      pathPrefix: /api/orders
      methods: ["GET", "OPTIONS"]
    action: exchange
    exchange:
      issuerRef: primary
      scope: read:orders
  - match:
      host: orders.example.com
      pathPrefix: /api/deny
      methods: ["GET"]
    action: deny
`)), &fakeExchanger{result: exchange.Result{AccessToken: "exchanged"}})

		_, err := srv.Check(context.Background(), checkRequest("GET", "orders.example.com", "/api/customers/1", nil))
		Expect(err).NotTo(HaveOccurred())
		_, err = srv.Check(context.Background(), checkRequest("OPTIONS", "orders.example.com", "/api/orders", map[string]string{
			"origin":                        "https://app.example.com",
			"access-control-request-method": "GET",
		}))
		Expect(err).NotTo(HaveOccurred())
		_, err = srv.Check(context.Background(), checkRequest("GET", "orders.example.com", "/api/orders/1", nil))
		Expect(err).NotTo(HaveOccurred())
		_, err = srv.Check(context.Background(), checkRequest("GET", "orders.example.com", "/api/deny/1", map[string]string{
			"authorization": "Bearer subject",
		}))
		Expect(err).NotTo(HaveOccurred())
		_, err = srv.Check(context.Background(), checkRequest("GET", "orders.example.com", "/api/orders/1", map[string]string{
			"authorization": "Bearer subject",
		}))
		Expect(err).NotTo(HaveOccurred())

		Expect(serverMetricWithLabels("ext_authz_check_requests_total", map[string]string{
			"decision": "allow_unmatched",
			"result":   "allowed",
		})).To(BeNumerically(">=", 1))
		Expect(serverMetricWithLabels("ext_authz_check_requests_total", map[string]string{
			"decision": "allow_options_bypass",
			"result":   "allowed",
		})).To(BeNumerically(">=", 1))
		Expect(serverMetricWithLabels("ext_authz_check_requests_total", map[string]string{
			"decision": "deny_missing_bearer",
			"result":   "auth_denied",
		})).To(BeNumerically(">=", 1))
		Expect(serverMetricWithLabels("ext_authz_check_requests_total", map[string]string{
			"decision": "deny_explicit_policy",
			"result":   "auth_denied",
		})).To(BeNumerically(">=", 1))
		Expect(serverMetricWithLabels("ext_authz_check_requests_total", map[string]string{
			"decision": "allow_exchange",
			"result":   "allowed",
		})).To(BeNumerically(">=", 1))
		Expect(serverMetricWithLabels("ext_authz_check_duration_seconds", map[string]string{
			"decision": "allow_exchange",
			"result":   "allowed",
		})).To(BeNumerically(">=", 1))
	})

	It("classifies exchange errors as auth denials or system errors", func() {
		authDenied := server.NewAuthzGRPCServer(cfg, policy.NewStaticStore(indexFor(`
version: v1
entries:
  - match:
      host: orders.example.com
      pathPrefix: /api/orders
      methods: ["GET"]
    action: exchange
    exchange:
      issuerRef: primary
`)), &fakeExchanger{err: &exchange.OAuthError{StatusCode: http.StatusBadRequest, Error: "invalid_grant"}})
		systemError := server.NewAuthzGRPCServer(cfg, policy.NewStaticStore(indexFor(`
version: v1
entries:
  - match:
      host: orders.example.com
      pathPrefix: /api/orders
      methods: ["GET"]
    action: exchange
    exchange:
      issuerRef: primary
`)), &fakeExchanger{err: &exchange.OAuthError{StatusCode: http.StatusInternalServerError, Error: "server_error"}})

		_, err := authDenied.Check(context.Background(), checkRequest("GET", "orders.example.com", "/api/orders/1", map[string]string{
			"authorization": "Bearer subject",
		}))
		Expect(err).NotTo(HaveOccurred())
		_, err = systemError.Check(context.Background(), checkRequest("GET", "orders.example.com", "/api/orders/1", map[string]string{
			"authorization": "Bearer subject",
		}))
		Expect(err).NotTo(HaveOccurred())

		Expect(serverMetricWithLabels("ext_authz_check_requests_total", map[string]string{
			"decision": "deny_exchange_error",
			"result":   "auth_denied",
		})).To(BeNumerically(">=", 1))
		Expect(serverMetricWithLabels("ext_authz_check_requests_total", map[string]string{
			"decision": "deny_exchange_error",
			"result":   "system_error",
		})).To(BeNumerically(">=", 1))
	})
})

type fakeExchanger struct {
	result exchange.Result
	err    *exchange.OAuthError
	calls  int
	ctx    context.Context
}

func (f *fakeExchanger) Exchange(ctx context.Context, entry policy.Entry, subjectToken string) (exchange.Result, *exchange.OAuthError) {
	f.calls++
	f.ctx = ctx
	return f.result, f.err
}

func indexFor(data string) *policy.Index {
	return policy.BuildIndex(map[policy.Source]string{{Namespace: "orders", Name: "token-exchange"}: data}, config.RuntimeConfig{
		ClientID:                "client",
		ClientSecret:            "secret",
		TokenEndpointAuthMethod: config.AuthMethodClientSecretBasic,
		GrantType:               config.DefaultGrantType,
		SubjectTokenType:        config.DefaultSubjectTokenType,
		LabelSelector:           config.DefaultConfigMapLabelSelector,
		AllowHTTPTokenEndpoint:  true,
		RequireIssuedTokenType:  true,
		ExpectedIssuedTokenType: config.DefaultIssuedTokenType,
		IssuerProfiles: map[string]config.IssuerProfile{
			"primary": {
				Name:          "primary",
				TokenEndpoint: "http://issuer.example/token",
				BearerRealm:   "issuer",
				ClientID:      "client",
				ClientSecret:  "secret",
			},
		},
	})
}

func checkRequest(method, host, path string, headers map[string]string) *envoy_service_auth_v3.CheckRequest {
	if headers == nil {
		headers = map[string]string{}
	}
	headers[":authority"] = host
	return &envoy_service_auth_v3.CheckRequest{
		Attributes: &envoy_service_auth_v3.AttributeContext{
			Request: &envoy_service_auth_v3.AttributeContext_Request{
				Http: &envoy_service_auth_v3.AttributeContext_HttpRequest{
					Method:  method,
					Host:    host,
					Path:    path,
					Headers: headers,
				},
			},
		},
	}
}

func headerValue(headers []*envoy_config_core_v3.HeaderValueOption, name string) string {
	for _, header := range headers {
		if header.GetHeader().GetKey() == name {
			return header.GetHeader().GetValue()
		}
	}
	return ""
}

func serverMetricWithLabels(name string, labels map[string]string) float64 {
	families, err := prometheus.DefaultGatherer.Gather()
	Expect(err).NotTo(HaveOccurred())
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.GetMetric() {
			if serverMetricHasLabels(metric, labels) {
				if metric.GetCounter() != nil {
					return metric.GetCounter().GetValue()
				}
				if metric.GetHistogram() != nil {
					return float64(metric.GetHistogram().GetSampleCount())
				}
				if metric.GetGauge() != nil {
					return metric.GetGauge().GetValue()
				}
			}
		}
	}
	return 0
}

func serverMetricHasLabels(metric *dto.Metric, labels map[string]string) bool {
	actual := map[string]string{}
	for _, label := range metric.GetLabel() {
		actual[label.GetName()] = label.GetValue()
	}
	for name, value := range labels {
		if actual[name] != value {
			return false
		}
	}
	return true
}
