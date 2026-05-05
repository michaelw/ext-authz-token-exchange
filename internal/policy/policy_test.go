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
  - host: orders.example.com
    pathPrefix: /api
    methods: ["GET"]
    scope: read:any
  - host: orders.example.com
    pathPrefix: /api/orders
    methods: ["GET"]
    resource: https://orders.example.com/api/
`,
		}, cfg)

		decision := index.Match("orders.example.com", "/api/orders/1", "GET")

		Expect(decision.Matched).To(BeTrue())
		Expect(decision.Unhealthy).To(BeFalse())
		Expect(decision.Entry.PathPrefix).To(Equal("/api/orders"))
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
  - host: orders.example.com
    pathPrefix: /api/orders
    methods: ["GET"]
    scope: read:orders
`,
		}, cfg)

		decision := index.Match("orders.example.com", "/api/orders/1", "GET")

		Expect(decision.Matched).To(BeTrue())
		Expect(decision.Unhealthy).To(BeTrue())
		Expect(decision.Reason).To(ContainSubstring("tokenEndpoint is required"))
	})

	It("fails closed when entries tie for most-specific match", func() {
		index := policy.BuildIndex(map[policy.Source]string{
			{Namespace: "orders", Name: "one"}: `
version: v1
entries:
  - host: orders.example.com
    pathPrefix: /api/orders
    methods: ["GET"]
    scope: read:orders
`,
			{Namespace: "orders", Name: "two"}: `
version: v1
entries:
  - host: orders.example.com
    pathPrefix: /api/orders
    methods: ["GET"]
    resource: https://orders.example.com/api/
`,
		}, cfg)

		decision := index.Match("orders.example.com", "/api/orders/1", "GET")

		Expect(decision.Matched).To(BeTrue())
		Expect(decision.Unhealthy).To(BeTrue())
		Expect(decision.Reason).To(ContainSubstring("tie"))
	})

	It("loads matching ConfigMaps through the Kubernetes watcher", func() {
		client := fake.NewSimpleClientset(&corev1.ConfigMap{
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
  - host: orders.example.com
    pathPrefix: /api/orders
    methods: ["GET"]
    scope: read:orders
`,
			},
		})
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
})
