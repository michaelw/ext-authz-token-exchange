package demo

import (
	"strings"
	"testing"
)

func TestScenarioTemplateRendersDemoContext(t *testing.T) {
	opts := Options{NamespacePrefix: "team", BaseURL: "https://demo.example.test"}
	rendered, err := RenderConfig([]byte(`policy: "{{ .NamespacePrefix }}-yellow/yellow-policy"`), opts)
	if err != nil {
		t.Fatalf("render config: %v", err)
	}
	if got := strings.TrimSpace(string(rendered)); got != `policy: "team-yellow/yellow-policy"` {
		t.Fatalf("unexpected rendered config: %q", got)
	}
}

func TestScenarioConfigRequiresBehavior(t *testing.T) {
	cfg := Config{
		Version: "v1",
		Scenarios: []Scenario{{
			Name:    "missing-behavior",
			Request: Request{Path: "/anything/demo"},
		}},
	}

	err := cfg.Validate()

	if err == nil || !strings.Contains(err.Error(), `scenario "missing-behavior" must configure behavior.summary`) {
		t.Fatalf("Validate() error = %v, want missing behavior.summary", err)
	}
}

func TestWithDefaultsPreservesExplicitBehavior(t *testing.T) {
	sc := Scenario{
		Name: "explicit-behavior",
		Request: Request{
			Path: "/anything/demo",
		},
		Behavior: Behavior{
			Summary: "Auth server returns a token.",
			Detail:  "Scenario-authored behavior is shown in the dashboard.",
		},
	}

	got := sc.WithDefaults()

	if got.Behavior != sc.Behavior {
		t.Fatalf("Behavior = %+v, want %+v", got.Behavior, sc.Behavior)
	}
}

func TestScenarioTokenValidation(t *testing.T) {
	tests := []struct {
		name      string
		token     RequestToken
		wantError string
	}{
		{name: "none", token: RequestToken{Prefill: "none"}},
		{name: "literal", token: RequestToken{Prefill: "literal", Value: "incoming-token"}},
		{name: "keycloak subject", token: RequestToken{Prefill: "keycloak-subject"}},
		{name: "keycloak expired", token: RequestToken{Prefill: "keycloak-expired-subject"}},
		{name: "literal missing value", token: RequestToken{Prefill: "literal"}, wantError: "request.token.value is required"},
		{name: "unknown", token: RequestToken{Prefill: "mystery"}, wantError: "unsupported request.token.prefill"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.token.Validate("demo")
			if tt.wantError == "" {
				if err != nil {
					t.Fatalf("Validate() error = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("Validate() error = %v, want %q", err, tt.wantError)
			}
		})
	}
}

func TestCheckedInScenarioConfigsValidate(t *testing.T) {
	path := "../../test/e2e/demo-scenarios.yaml"
	cfg, err := LoadConfig(Options{ConfigPath: path})
	if err != nil {
		t.Fatalf("LoadConfig(%q): %v", path, err)
	}
	for _, sc := range cfg.Scenarios {
		if sc.Behavior.Summary == "" || sc.Behavior.Detail == "" {
			t.Fatalf("scenario %q has incomplete behavior: %+v", sc.Name, sc.Behavior)
		}
	}
}
