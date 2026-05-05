package server_test

import (
	"context"
	"testing"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_service_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

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
      scope: read:orders
      tokenEndpoint: http://issuer.example/token
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
      scope: read:orders
      tokenEndpoint: http://issuer.example/token
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
      scope: read:orders
      tokenEndpoint: http://issuer.example/token
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
      scope: read:orders
      tokenEndpoint: http://issuer.example/token
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
      scope: read:orders
      tokenEndpoint: http://issuer.example/token
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
      scope: read:orders
      tokenEndpoint: http://issuer.example/token
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
      scope: read:orders
      tokenEndpoint: http://issuer.example/token
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
      resources:
        - https://orders.example.com/api/
      tokenEndpoint: http://issuer.example/token
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
      scope: read:orders
      tokenEndpoint: http://issuer.example/token
`)), &fakeExchanger{})

		resp, err := srv.Check(context.Background(), checkRequest("GET", "orders.example.com", "/api/orders/1", nil))

		Expect(err).NotTo(HaveOccurred())
		denied := resp.GetDeniedResponse()
		Expect(denied).NotTo(BeNil())
		Expect(denied.GetStatus().GetCode().String()).To(Equal("Unauthorized"))
		Expect(headerValue(denied.GetHeaders(), "WWW-Authenticate")).To(Equal(`Bearer realm="example", scope="read:orders"`))
		Expect(denied.GetBody()).To(MatchJSON(`{"error":"bearer_token_required"}`))
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
      resources:
        - https://orders.example.com/api/
      tokenEndpoint: http://issuer.example/token
`)), &fakeExchanger{result: exchange.Result{AccessToken: "exchanged"}})

		resp, err := srv.Check(context.Background(), checkRequest("GET", "orders.example.com", "/api/orders/1", map[string]string{
			"authorization": "Bearer subject",
		}))

		Expect(err).NotTo(HaveOccurred())
		Expect(resp.GetOkResponse()).NotTo(BeNil())
		Expect(headerValue(resp.GetOkResponse().GetHeaders(), "authorization")).To(Equal("Bearer exchanged"))
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
      scope: read:orders
`)), &fakeExchanger{})

		resp, err := srv.Check(context.Background(), checkRequest("GET", "orders.example.com", "/api/orders/1", map[string]string{
			"authorization": "Bearer subject",
		}))

		Expect(err).NotTo(HaveOccurred())
		Expect(resp.GetDeniedResponse()).NotTo(BeNil())
		Expect(resp.GetDeniedResponse().GetStatus().GetCode().String()).To(Equal("InternalServerError"))
	})
})

type fakeExchanger struct {
	result exchange.Result
	err    *exchange.OAuthError
	calls  int
}

func (f *fakeExchanger) Exchange(context.Context, policy.Entry, string) (exchange.Result, *exchange.OAuthError) {
	f.calls++
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
