package e2e_test

import (
	"context"
	"os"
	"testing"

	"github.com/michaelw/ext-authz-token-exchange/internal/demo"
)

// This contract exercises the same scenario expectations through every gateway.
func TestGatewayContract(t *testing.T) {
	if os.Getenv("E2E_GATEWAY_CONTRACT") != "true" {
		t.Skip("developer-run gateway contract")
	}
	path := "test/e2e/demo-scenarios.yaml"
	if _, err := os.Stat(path); err != nil {
		path = "demo-scenarios.yaml"
	}
	baseURL := os.Getenv("E2E_CONTRACT_BASE_URL")
	if baseURL == "" {
		baseURL = os.Getenv("E2E_BASE_URL")
	}
	opts := demo.Options{
		BaseURL: baseURL, ConfigPath: path,
		DirectAddress: os.Getenv("E2E_DIRECT_ADDRESS"), CACertFile: os.Getenv("E2E_CA_CERT_FILE"),
		NamespacePrefix: os.Getenv("E2E_NAMESPACE_PREFIX"),
		InsecureTLS:     os.Getenv("E2E_INSECURE_SKIP_VERIFY") == "true",
	}
	config, err := demo.LoadConfig(opts)
	if err != nil {
		t.Fatal(err)
	}
	wanted := map[string]bool{"yellow-success": true, "missing-bearer": true, "cors-preflight": true,
		"options-missing-bearer": true, "options-bearer": true, "unmatched": true, "explicit-deny": true, "invalid-grant": true}
	for _, scenario := range config.Scenarios {
		if !wanted[scenario.Name] {
			continue
		}
		t.Run(scenario.Name, func(t *testing.T) {
			result, err := demo.Run(context.Background(), opts, scenario)
			if err != nil {
				t.Fatal(err)
			}
			if !result.Passed {
				for _, failure := range result.Failures {
					t.Errorf("%s: expected %s, got %s", failure.Label, failure.Want, failure.Got)
				}
			}
		})
		delete(wanted, scenario.Name)
	}
	if len(wanted) != 0 {
		t.Fatal("required gateway contract scenarios are missing")
	}
}
