package scripts_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestDevspaceDetectIssuerHonorsExplicitProfiles(t *testing.T) {
	tests := []struct {
		name     string
		profiles string
		want     string
	}{
		{name: "keycloak", profiles: "local-test,with-keycloak", want: "keycloak"},
		{name: "fake", profiles: "local-test with-fake-issuer", want: "fake"},
		{name: "last explicit profile wins", profiles: "with-keycloak,with-fake-issuer", want: "fake"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := runDetector(t, tt.profiles, "")
			if got != tt.want {
				t.Fatalf("issuer = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDevspaceDetectIssuerClassifiesDeployedEndpoint(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		want     string
	}{
		{name: "keycloak endpoint", endpoint: "http://keycloak.ext-authz-token-exchange-e2e.svc.cluster.local:8080/realms/token-exchange-e2e/protocol/openid-connect/token", want: "keycloak"},
		{name: "fake endpoint", endpoint: "http://fake-token-endpoint.ext-authz-token-exchange-e2e.svc.cluster.local:8080/token/success", want: "fake"},
		{name: "missing endpoint", endpoint: "", want: "fake"},
		{name: "unknown endpoint", endpoint: "https://issuer.example.com/token", want: "fake"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := runDetector(t, "", tt.endpoint)
			if got != tt.want {
				t.Fatalf("issuer = %q, want %q", got, tt.want)
			}
		})
	}
}

func runDetector(t *testing.T, profiles, endpoint string) string {
	t.Helper()
	repo := repoRoot(t)
	kubectl := fakeKubectl(t, endpoint)
	cmd := exec.Command(filepath.Join(repo, "scripts", "devspace-detect-issuer.sh"), profiles)
	cmd.Dir = repo
	cmd.Env = append(os.Environ(),
		"DEVSPACE_PROFILE=",
		"KUBECTL="+kubectl,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run detector: %v\n%s", err, out)
	}
	return strings.TrimSpace(string(out))
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Dir(dir)
}

func fakeKubectl(t *testing.T, endpoint string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "kubectl")
	script := "#!/bin/sh\nprintf '%s' " + shellQuote(endpoint) + "\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake kubectl: %v", err)
	}
	return path
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}
