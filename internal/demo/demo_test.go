package demo

import (
	"net/http"
	"strings"
	"testing"
)

func TestBearerTokenEnvRendersIntoScenarioTemplate(t *testing.T) {
	t.Setenv(DefaultBearerTokenEnv, "subject-token")

	opts := LoadOptionsFromEnv()
	if opts.BearerToken != "subject-token" {
		t.Fatalf("unexpected bearer token option: %q", opts.BearerToken)
	}

	rendered, err := RenderConfig([]byte(`bearer: "{{ .BearerToken }}"`), opts)
	if err != nil {
		t.Fatalf("render config: %v", err)
	}
	if got := strings.TrimSpace(string(rendered)); got != `bearer: "subject-token"` {
		t.Fatalf("unexpected rendered config: %q", got)
	}
}

func TestExchangeBehaviorClassifiesNoExchangeDenial(t *testing.T) {
	got := ExchangeBehavior("-", Request{Method: http.MethodGet}, Expectation{Status: http.StatusForbidden})

	if got.Summary != "Denied before token exchange." {
		t.Fatalf("unexpected summary: %q", got.Summary)
	}
}

func TestExchangeBehaviorClassifiesNoExchangePassThrough(t *testing.T) {
	got := ExchangeBehavior("-", Request{Method: http.MethodGet}, Expectation{Status: http.StatusOK})

	if got.Summary != "Passes through without token exchange." {
		t.Fatalf("unexpected summary: %q", got.Summary)
	}
}

func TestExchangeBehaviorClassifiesIssuerBackedErrorByExchangePath(t *testing.T) {
	got := ExchangeBehavior("/token/invalid-grant", Request{Method: http.MethodGet}, Expectation{Status: http.StatusBadRequest})

	if got.Summary != "Rejects the subject token as invalid." {
		t.Fatalf("unexpected summary: %q", got.Summary)
	}
}

func TestExchangeBehaviorTreatsEmptyExchangeAsNoExchange(t *testing.T) {
	got := ExchangeBehavior("", Request{Method: http.MethodGet}, Expectation{Status: http.StatusForbidden})

	if got.Summary != "Denied before token exchange." {
		t.Fatalf("unexpected summary: %q", got.Summary)
	}
}
