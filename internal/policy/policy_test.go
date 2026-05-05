package policy_test

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/michaelw/ext-authz-token-exchange/internal/config"
	"github.com/michaelw/ext-authz-token-exchange/internal/policy"
)

func TestPolicy(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Policy Suite")
}

var _ = Describe("Index", func() {
	var cfg config.RuntimeConfig

	BeforeEach(func() {
		cfg = config.RuntimeConfig{
			ClientID:                "client",
			ClientSecret:            "secret",
			TokenEndpointAuthMethod: config.AuthMethodClientSecretBasic,
			GrantType:               config.DefaultGrantType,
			SubjectTokenType:        config.DefaultSubjectTokenType,
			LabelSelector:           config.DefaultConfigMapLabelSelector,
			NamespaceSelector:       config.DefaultConfigMapNamespaceSelector,
			DefaultTokenEndpoint:    "http://issuer.example/token",
			AllowHTTPTokenEndpoint:  true,
			RequireIssuedTokenType:  true,
			ExpectedIssuedTokenType: config.DefaultIssuedTokenType,
		}
	})

	It("matches the most-specific path prefix", func() {
		index := policy.BuildIndex(map[policy.Source]string{
			{Namespace: "orders", Name: "token-exchange"}: `
version: v1
entries:
  - match:
      host: orders.example.com
      pathPrefix: /api
      methods: ["GET"]
    action: exchange
    exchange:
      scope: read:any
  - match:
      host: orders.example.com
      pathPrefix: /api/orders
      methods: ["GET"]
    action: exchange
    exchange:
      resources:
        - https://orders.example.com/api/
`,
		}, cfg)

		decision := index.Match("orders.example.com", "/api/orders/1", "GET")

		Expect(decision.Matched).To(BeTrue())
		Expect(decision.Unhealthy).To(BeFalse())
		Expect(decision.Entry.PathPrefix).To(Equal("/api/orders"))
	})

	It("requires policy action", func() {
		index := policy.BuildIndex(map[policy.Source]string{
			{Namespace: "orders", Name: "token-exchange"}: `
version: v1
entries:
  - match:
      host: orders.example.com
      pathPrefix: /api/orders
      methods: ["GET"]
    exchange:
      scope: read:orders
`,
		}, cfg)

		decision := index.Match("orders.example.com", "/api/orders/1", "GET")

		Expect(decision.Matched).To(BeTrue())
		Expect(decision.Unhealthy).To(BeTrue())
		Expect(decision.Reason).To(ContainSubstring("entries[0].action is required"))
	})

	It("accepts explicit exchange action", func() {
		index := policy.BuildIndex(map[policy.Source]string{
			{Namespace: "orders", Name: "token-exchange"}: `
version: v1
entries:
  - match:
      host: orders.example.com
      pathPrefix: /api/orders
      methods: ["GET"]
    action: exchange
    exchange:
      scope: read:orders
`,
		}, cfg)

		decision := index.Match("orders.example.com", "/api/orders/1", "GET")

		Expect(decision.Matched).To(BeTrue())
		Expect(decision.Unhealthy).To(BeFalse())
		Expect(decision.Entry.Action).To(Equal(policy.ActionExchange))
	})

	It("accepts deny action without exchange fields", func() {
		index := policy.BuildIndex(map[policy.Source]string{
			{Namespace: "orders", Name: "token-exchange"}: `
version: v1
entries:
  - match:
      host: orders.example.com
      pathPrefix: /api/orders
      methods: ["GET"]
    action: deny
`,
		}, cfg)

		decision := index.Match("orders.example.com", "/api/orders/1", "GET")

		Expect(decision.Matched).To(BeTrue())
		Expect(decision.Unhealthy).To(BeFalse())
		Expect(decision.Entry.Action).To(Equal(policy.ActionDeny))
	})

	It("ignores exchange config on deny entries", func() {
		index := policy.BuildIndex(map[policy.Source]string{
			{Namespace: "orders", Name: "token-exchange"}: `
version: v1
entries:
  - match:
      host: orders.example.com
      pathPrefix: /api/orders
      methods: ["GET"]
    action: deny
    exchange:
      scope: ignored
      resources:
        - https://orders.example.com/api/
      audiences:
        - ignored
      tokenEndpoint: not-a-url
`,
		}, cfg)

		decision := index.Match("orders.example.com", "/api/orders/1", "GET")

		Expect(decision.Matched).To(BeTrue())
		Expect(decision.Unhealthy).To(BeFalse())
		Expect(decision.Entry.Action).To(Equal(policy.ActionDeny))
	})

	It("allows requests without matching configured policy", func() {
		index := policy.BuildIndex(nil, cfg)

		Expect(index.Match("orders.example.com", "/api/orders/1", "GET").Matched).To(BeFalse())
	})

	It("fails closed for invalid configured regions", func() {
		cfg.DefaultTokenEndpoint = ""
		index := policy.BuildIndex(map[policy.Source]string{
			{Namespace: "orders", Name: "token-exchange"}: `
version: v1
entries:
  - match:
      host: orders.example.com
      pathPrefix: /api/orders
      methods: ["GET"]
    action: exchange
    exchange:
      scope: read:orders
`,
		}, cfg)

		decision := index.Match("orders.example.com", "/api/orders/1", "GET")

		Expect(decision.Matched).To(BeTrue())
		Expect(decision.Unhealthy).To(BeTrue())
		Expect(decision.Reason).To(ContainSubstring("entries[0].exchange.tokenEndpoint is required"))
	})

	It("fails closed for unknown actions", func() {
		index := policy.BuildIndex(map[policy.Source]string{
			{Namespace: "orders", Name: "token-exchange"}: `
version: v1
entries:
  - match:
      host: orders.example.com
      pathPrefix: /api/orders
      methods: ["GET"]
    action: reject
`,
		}, cfg)

		decision := index.Match("orders.example.com", "/api/orders/1", "GET")

		Expect(decision.Matched).To(BeTrue())
		Expect(decision.Unhealthy).To(BeTrue())
		Expect(decision.Reason).To(ContainSubstring("entries[0].action must be exchange or deny"))
	})

	It("uses the most-specific action when deny and exchange overlap", func() {
		index := policy.BuildIndex(map[policy.Source]string{
			{Namespace: "orders", Name: "token-exchange"}: `
version: v1
entries:
  - match:
      host: orders.example.com
      pathPrefix: /api
      methods: ["GET"]
    action: deny
  - match:
      host: orders.example.com
      pathPrefix: /api/orders
      methods: ["GET"]
    action: exchange
    exchange:
      scope: read:orders
`,
		}, cfg)

		decision := index.Match("orders.example.com", "/api/orders/1", "GET")

		Expect(decision.Matched).To(BeTrue())
		Expect(decision.Unhealthy).To(BeFalse())
		Expect(decision.Entry.Action).To(Equal(policy.ActionExchange))

		decision = index.Match("orders.example.com", "/api/customers/1", "GET")

		Expect(decision.Matched).To(BeTrue())
		Expect(decision.Unhealthy).To(BeFalse())
		Expect(decision.Entry.Action).To(Equal(policy.ActionDeny))
	})

	It("fails closed when entries tie for most-specific match", func() {
		index := policy.BuildIndex(map[policy.Source]string{
			{Namespace: "orders", Name: "one"}: `
version: v1
entries:
  - match:
      host: orders.example.com
      pathPrefix: /api/orders
      methods: ["GET"]
    action: exchange
    exchange:
      scope: read:orders
`,
			{Namespace: "orders", Name: "two"}: `
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
`,
		}, cfg)

		decision := index.Match("orders.example.com", "/api/orders/1", "GET")

		Expect(decision.Matched).To(BeTrue())
		Expect(decision.Unhealthy).To(BeTrue())
		Expect(decision.Reason).To(ContainSubstring("tie"))
	})

	It("fails closed when deny and exchange entries tie for most-specific match", func() {
		index := policy.BuildIndex(map[policy.Source]string{
			{Namespace: "orders", Name: "one"}: `
version: v1
entries:
  - match:
      host: orders.example.com
      pathPrefix: /api/orders
      methods: ["GET"]
    action: deny
`,
			{Namespace: "orders", Name: "two"}: `
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
`,
		}, cfg)

		decision := index.Match("orders.example.com", "/api/orders/1", "GET")

		Expect(decision.Matched).To(BeTrue())
		Expect(decision.Unhealthy).To(BeTrue())
		Expect(decision.Reason).To(ContainSubstring("tie"))
	})

	It("fails closed when exchange action omits exchange config", func() {
		index := policy.BuildIndex(map[policy.Source]string{
			{Namespace: "orders", Name: "token-exchange"}: `
version: v1
entries:
  - match:
      host: orders.example.com
      pathPrefix: /api/orders
      methods: ["GET"]
    action: exchange
`,
		}, cfg)

		decision := index.Match("orders.example.com", "/api/orders/1", "GET")

		Expect(decision.Matched).To(BeTrue())
		Expect(decision.Unhealthy).To(BeTrue())
		Expect(decision.Reason).To(ContainSubstring("entries[0].exchange is required when action is exchange"))
	})

	It("fails closed when match section is missing", func() {
		index := policy.BuildIndex(map[policy.Source]string{
			{Namespace: "orders", Name: "token-exchange"}: `
version: v1
entries:
  - action: exchange
    exchange:
      scope: read:orders
`,
		}, cfg)

		decision := index.Match("orders.example.com", "/api/orders/1", "GET")

		Expect(decision.Matched).To(BeTrue())
		Expect(decision.Unhealthy).To(BeTrue())
		Expect(decision.Reason).To(ContainSubstring("entries[0].match is required"))
	})

	DescribeTable("fails closed when policy has unknown fields", func(data, field string) {
		index := policy.BuildIndex(map[policy.Source]string{
			{Namespace: "orders", Name: "token-exchange"}: data,
		}, cfg)

		decision := index.Match("orders.example.com", "/api/orders/1", "GET")

		Expect(decision.Matched).To(BeTrue())
		Expect(decision.Unhealthy).To(BeTrue())
		Expect(decision.Reason).To(ContainSubstring("not valid policy YAML"))
		Expect(decision.Reason).To(ContainSubstring(field))
	},
		Entry("file", `
version: v1
unknown: true
entries:
  - match:
      host: orders.example.com
      pathPrefix: /api/orders
    action: deny
`, "unknown"),
		Entry("entry", `
version: v1
entries:
  - match:
      host: orders.example.com
      pathPrefix: /api/orders
    action: deny
    unknown: true
`, "unknown"),
		Entry("match", `
version: v1
entries:
  - match:
      host: orders.example.com
      pathPrefix: /api/orders
      port: 443
    action: deny
`, "port"),
		Entry("exchange", `
version: v1
entries:
  - match:
      host: orders.example.com
      pathPrefix: /api/orders
    action: exchange
    exchange:
      resource: https://orders.example.com/api/
      tokenEndpoint: http://issuer.example/token
`, "resource"),
	)

	It("loads matching ConfigMaps through the Kubernetes watcher", func() {
		client := fake.NewSimpleClientset(
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
				Name: "orders",
				Labels: map[string]string{
					"ext-authz-token-exchange.magneticflux.net/policy": "enabled",
				},
			}},
			&corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "orders",
					Name:      "token-exchange",
					Labels: map[string]string{
						"ext-authz-token-exchange.magneticflux.net/enabled": "true",
					},
				},
				Data: map[string]string{
					"config.yaml": `
version: v1
entries:
  - match:
      host: orders.example.com
      pathPrefix: /api/orders
      methods: ["GET"]
    action: exchange
    exchange:
      scope: read:orders
`,
				},
			},
		)
		store := policy.NewConfigMapStoreWithClient(client, cfg)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		go func() {
			_ = store.Run(ctx)
		}()

		Eventually(func() bool {
			return store.Index().Match("orders.example.com", "/api/orders/1", "GET").Matched
		}, 2*time.Second, 25*time.Millisecond).Should(BeTrue())
	})

	It("ignores ConfigMaps in namespaces that do not match the namespace selector", func() {
		client := fake.NewSimpleClientset(
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
				Name: "orders",
				Labels: map[string]string{
					"ext-authz-token-exchange.magneticflux.net/policy": "enabled",
				},
			}},
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ignored"}},
			&corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "orders",
					Name:      "token-exchange",
					Labels: map[string]string{
						"ext-authz-token-exchange.magneticflux.net/enabled": "true",
					},
				},
				Data: map[string]string{
					"config.yaml": `
version: v1
entries:
  - match:
      host: orders.example.com
      pathPrefix: /api/orders
      methods: ["GET"]
    action: exchange
    exchange:
      scope: read:orders
`,
				},
			},
			&corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ignored",
					Name:      "token-exchange",
					Labels: map[string]string{
						"ext-authz-token-exchange.magneticflux.net/enabled": "true",
					},
				},
				Data: map[string]string{
					"config.yaml": `
version: v1
entries:
  - match:
      host: ignored.example.com
      pathPrefix: /api/ignored
      methods: ["GET"]
    action: exchange
    exchange:
      scope: read:ignored
`,
				},
			},
		)
		store := policy.NewConfigMapStoreWithClient(client, cfg)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		go func() {
			_ = store.Run(ctx)
		}()

		Eventually(func() bool {
			return store.Index().Match("orders.example.com", "/api/orders/1", "GET").Matched
		}, 2*time.Second, 25*time.Millisecond).Should(BeTrue())
		Consistently(func() bool {
			return store.Index().Match("ignored.example.com", "/api/ignored/1", "GET").Matched
		}, 200*time.Millisecond, 25*time.Millisecond).Should(BeFalse())
	})

})
