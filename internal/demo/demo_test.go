package demo

import (
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

func TestCheckedInScenarioConfigsValidate(t *testing.T) {
	for _, path := range []string{
		"../../test/e2e/demo-scenarios.yaml",
		"../../test/e2e/keycloak-demo-scenarios.yaml",
	} {
		t.Run(path, func(t *testing.T) {
			cfg, err := LoadConfig(Options{ConfigPath: path})
			if err != nil {
				t.Fatalf("LoadConfig(%q): %v", path, err)
			}
			for _, sc := range cfg.Scenarios {
				if sc.Behavior.Summary == "" || sc.Behavior.Detail == "" {
					t.Fatalf("scenario %q has incomplete behavior: %+v", sc.Name, sc.Behavior)
				}
			}
		})
	}
}
