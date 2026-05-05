package policy

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/michaelw/ext-authz-token-exchange/internal/config"
)

func testRuntimeConfig() config.RuntimeConfig {
	return config.RuntimeConfig{
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
}

func TestConfigMapStoreRemoveNamespaceClearsPolicies(t *testing.T) {
	cfg := testRuntimeConfig()
	store := NewConfigMapStoreWithClient(fake.NewSimpleClientset(), cfg)

	store.mu.Lock()
	store.selected["orders"] = struct{}{}
	store.configs[Source{Namespace: "orders", Name: "token-exchange"}] = `
version: v1
entries:
  - match:
      host: orders.example.com
      pathPrefix: /api/orders
      methods: ["GET"]
    action: exchange
    exchange:
      scope: read:orders
`
	store.rebuildLocked()
	store.mu.Unlock()

	if !store.Index().Match("orders.example.com", "/api/orders/1", "GET").Matched {
		t.Fatal("expected seeded namespace policy to match")
	}

	store.removeNamespace("orders")

	if store.Index().Match("orders.example.com", "/api/orders/1", "GET").Matched {
		t.Fatal("expected namespace policy to be removed")
	}
}

func TestConfigMapStoreNamespaceLabelTransitionsEnableAndDisablePolicies(t *testing.T) {
	cfg := testRuntimeConfig()
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
  - match:
      host: orders.example.com
      pathPrefix: /api/orders
      methods: ["GET"]
    action: exchange
    exchange:
      scope: read:orders
`,
		},
	})
	store := NewConfigMapStoreWithClient(client, cfg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	store.upsertNamespace(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name: "orders",
	}})
	if store.Index().Match("orders.example.com", "/api/orders/1", "GET").Matched {
		t.Fatal("expected unlabeled namespace policy to stay inactive")
	}

	store.upsertNamespace(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name: "orders",
		Labels: map[string]string{
			"ext-authz-token-exchange.magneticflux.net/policy": "enabled",
		},
	}})
	if !store.Index().Match("orders.example.com", "/api/orders/1", "GET").Matched {
		t.Fatal("expected labeled namespace policy to become active")
	}

	store.upsertNamespace(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name: "orders",
	}})
	if store.Index().Match("orders.example.com", "/api/orders/1", "GET").Matched {
		t.Fatal("expected policy to be removed when namespace label is removed")
	}
}
