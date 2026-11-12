package server_test

import (
	"context"
	"net"
	"time"

	pb "github.com/michaelw/ext-authz-token-exchange/internal/apigeepb"
	"github.com/michaelw/ext-authz-token-exchange/internal/config"
	"github.com/michaelw/ext-authz-token-exchange/internal/exchange"
	"github.com/michaelw/ext-authz-token-exchange/internal/policy"
	"github.com/michaelw/ext-authz-token-exchange/internal/server"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
)

var _ = Describe("Apigee ExternalCallout", func() {
	const policyYAML = `version: v1
entries:
  - match:
      host: orders.example.com
      pathPrefix: /api/orders
    action: exchange
    exchange:
      issuerRef: primary
      scope: read:orders
  - match:
      host: orders.example.com
      pathPrefix: /denied
    action: deny
`
	It("round-trips the official unary protocol over gRPC", func() {
		listener := bufconn.Listen(1 << 20)
		srv := grpc.NewServer()
		pb.RegisterExternalCalloutServiceServer(srv, server.NewApigeeGRPCServer(config.RuntimeConfig{}, policy.NewStaticStore(indexFor(policyYAML)), &fakeExchanger{result: exchange.Result{AccessToken: "exchanged"}}, false))
		go func() { _ = srv.Serve(listener) }()
		defer srv.Stop()
		conn, err := grpc.NewClient("passthrough:///apigee-test", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }))
		Expect(err).NotTo(HaveOccurred())
		defer conn.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		resp, err := pb.NewExternalCalloutServiceClient(conn).ProcessMessage(ctx, apigeeRequest("GET", "/api/orders", "Bearer subject"))
		Expect(err).NotTo(HaveOccurred())
		Expect(resp.AdditionalFlowVariables["txe.decision"].GetString_()).To(Equal("allow"))
		Expect(resp.Request.Headers["authorization"].GetStrings()).To(Equal([]string{"Bearer exchanged"}))
		Expect(srv.GetServiceInfo()).To(HaveLen(1))
	})
	DescribeTable("uses the same policy decisions as Envoy", func(method, path, authorization, want string, statusCode int, calls int) {
		exchanger := &fakeExchanger{result: exchange.Result{AccessToken: "exchanged"}}
		srv := server.NewApigeeGRPCServer(config.RuntimeConfig{BearerRealm: "example"}, policy.NewStaticStore(indexFor(policyYAML)), exchanger, false)
		req := apigeeRequest(method, path, authorization)
		original := proto.Clone(req)
		resp, err := srv.ProcessMessage(context.Background(), req)
		Expect(err).NotTo(HaveOccurred())
		Expect(resp.GetAdditionalFlowVariables()["txe.decision"].GetString_()).To(Equal(want))
		Expect(int(resp.GetAdditionalFlowVariables()["txe.status"].GetInt32())).To(Equal(statusCode))
		Expect(exchanger.calls).To(Equal(calls))
		Expect(proto.Equal(req, original)).To(BeTrue(), "adapter must not mutate its input")
		Expect(resp.GetRequest().GetContent()).To(Equal("preserved-body"))
		Expect(resp.GetRequest().GetQueryParams()["secret"].GetStrings()).To(Equal([]string{"query-value"}))
		if calls == 1 {
			Expect(resp.GetRequest().GetHeaders()["authorization"].GetStrings()).To(Equal([]string{"Bearer exchanged"}))
		}
	},
		Entry("exchange", "POST", "/api/orders?secret=query-value", "Bearer subject", "allow", 200, 1),
		Entry("missing bearer", "GET", "/api/orders", "", "deny", 401, 0),
		Entry("malformed bearer", "GET", "/api/orders", "Bearer a b", "deny", 401, 0),
		Entry("explicit deny", "GET", "/denied", "Bearer subject", "deny", 403, 0),
		Entry("unmatched", "GET", "/other", "", "allow", 200, 0),
	)
	It("fails closed without trusted original request metadata", func() {
		srv := server.NewApigeeGRPCServer(config.RuntimeConfig{}, policy.NewStaticStore(indexFor(policyYAML)), &fakeExchanger{}, false)
		req := apigeeRequest("GET", "/api/orders", "Bearer subject")
		delete(req.AdditionalFlowVariables, "txe.input.host")
		_, err := srv.ProcessMessage(context.Background(), req)
		Expect(status.Code(err)).To(Equal(codes.InvalidArgument))
	})
	It("rejects duplicate bearer headers and bypasses only true unauthenticated preflight", func() {
		exchanger := &fakeExchanger{result: exchange.Result{AccessToken: "exchanged"}}
		srv := server.NewApigeeGRPCServer(config.RuntimeConfig{}, policy.NewStaticStore(indexFor(policyYAML)), exchanger, false)
		req := apigeeRequest("GET", "/api/orders", "Bearer one")
		req.Request.Headers["authorization"] = &pb.Strings{Strings: []string{"Bearer two"}}
		resp, err := srv.ProcessMessage(context.Background(), req)
		Expect(err).NotTo(HaveOccurred())
		Expect(resp.AdditionalFlowVariables["txe.status"].GetInt32()).To(Equal(int32(401)))
		req = apigeeRequest("OPTIONS", "/api/orders", "")
		req.Request.Headers["Origin"] = &pb.Strings{Strings: []string{"https://client.example"}}
		req.Request.Headers["Access-Control-Request-Method"] = &pb.Strings{Strings: []string{"GET"}}
		resp, err = srv.ProcessMessage(context.Background(), req)
		Expect(err).NotTo(HaveOccurred())
		Expect(resp.AdditionalFlowVariables["txe.decision"].GetString_()).To(Equal("allow"))
		Expect(exchanger.calls).To(Equal(0))
	})
	It("fails closed for unhealthy policies and unmatched default-deny", func() {
		for _, tc := range []struct {
			cfg    config.RuntimeConfig
			policy string
			path   string
			status int32
		}{
			{config.RuntimeConfig{}, "invalid: [", "/api/orders", 500},
			{config.RuntimeConfig{DefaultDenyUnmatched: true}, policyYAML, "/other", 403},
		} {
			srv := server.NewApigeeGRPCServer(tc.cfg, policy.NewStaticStore(indexFor(tc.policy)), &fakeExchanger{}, false)
			resp, err := srv.ProcessMessage(context.Background(), apigeeRequest("GET", tc.path, "Bearer subject"))
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.AdditionalFlowVariables["txe.status"].GetInt32()).To(Equal(tc.status))
		}
	})
	It("preserves denial body and multiple challenges", func() {
		exchanger := &fakeExchanger{err: &exchange.OAuthError{StatusCode: 401, Error: "invalid_token", WWWAuthenticate: []string{`Bearer realm="one"`, `Bearer realm="two"`}}}
		srv := server.NewApigeeGRPCServer(config.RuntimeConfig{}, policy.NewStaticStore(indexFor(policyYAML)), exchanger, false)
		resp, err := srv.ProcessMessage(context.Background(), apigeeRequest("GET", "/api/orders", "Bearer subject"))
		Expect(err).NotTo(HaveOccurred())
		Expect(resp.AdditionalFlowVariables["txe.www_authenticate"].GetString_()).To(Equal(`Bearer realm="one", Bearer realm="two"`))
		Expect(resp.AdditionalFlowVariables["txe.body"].GetString_()).To(ContainSubstring("invalid_token"))
	})
})

func apigeeRequest(method, path, authorization string) *pb.MessageContext {
	return &pb.MessageContext{
		MessageId: "message-1",
		Request: &pb.Request{Verb: method, Uri: path, Content: "preserved-body", Headers: map[string]*pb.Strings{
			"Authorization": {Strings: []string{authorization}}, "host": {Strings: []string{"rewritten.invalid"}},
		}, QueryParams: map[string]*pb.Strings{"secret": {Strings: []string{"query-value"}}}},
		AdditionalFlowVariables: map[string]*pb.FlowVariable{
			"txe.input.host":   {Value: &pb.FlowVariable_String_{String_: "orders.example.com"}},
			"txe.input.path":   {Value: &pb.FlowVariable_String_{String_: path}},
			"txe.input.scheme": {Value: &pb.FlowVariable_String_{String_: "https"}},
		},
	}
}
