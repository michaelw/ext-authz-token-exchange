package main

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestRemoveSmokeTempDirHandlesReadOnlyModuleCache(t *testing.T) {
	path := filepath.Join(t.TempDir(), "smoke")
	module := filepath.Join(path, "go-mod-cache", "example.com", "module@v1")
	if err := os.MkdirAll(module, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(module, "go.mod"), []byte("module example.com/module\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(module, 0o500); err != nil {
		t.Fatal(err)
	}

	removeSmokeTempDir(path)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("temporary directory remains: %v", err)
	}
}

func TestCommandOutputKeepsSuccessfulStderrOutOfJSON(t *testing.T) {
	got, err := commandOutput(context.Background(), nil, "sh", "-c", `printf 'diagnostic\n' >&2; printf '{"ok":true}'`)
	if err != nil {
		t.Fatal(err)
	}
	if got != `{"ok":true}` {
		t.Fatalf("commandOutput = %q, want JSON stdout only", got)
	}
}

func TestDeployProfiles(t *testing.T) {
	tests := []struct {
		mode string
		want []string
	}{
		{mode: "ext-authz", want: []string{"with-infra-smoke", "with-keycloak"}},
		{mode: "ext-proc", want: []string{"with-infra-smoke", "with-keycloak", "ext-proc"}},
		{mode: "ext-proc-inferencepool", want: []string{"with-infra-smoke", "ext-proc", "inferencepool-test"}},
	}
	for _, tt := range tests {
		got, err := deployProfiles(tt.mode)
		if err != nil {
			t.Fatalf("deployProfiles(%q) returned error: %v", tt.mode, err)
		}
		if len(got) != len(tt.want) {
			t.Fatalf("deployProfiles(%q) = %v, want %v", tt.mode, got, tt.want)
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Fatalf("deployProfiles(%q) = %v, want %v", tt.mode, got, tt.want)
			}
		}
	}
	if _, err := deployProfiles("other"); err == nil {
		t.Fatal("deployProfiles(other) returned nil error")
	}
}

func TestParsePodReadiness(t *testing.T) {
	input := `
default ready-7c5d 1/1 Running 0 1m
default pending-7c5d 0/1 Pending 0 1m
batch completed 0/1 Completed 0 1m
istio-ingress gateway 1/2 Running 0 1m
`
	got := parsePodReadiness(input)
	want := []string{
		"default pending-7c5d 0/1 Pending 0 1m",
		"istio-ingress gateway 1/2 Running 0 1m",
	}
	if len(got) != len(want) {
		t.Fatalf("parsePodReadiness returned %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("parsePodReadiness returned %v, want %v", got, want)
		}
	}
}

func TestHasInferenceOverride(t *testing.T) {
	withOverride := []byte(`{"typed_per_filter_config":{"envoy.filters.http.ext_proc":{"@type":"type.googleapis.com/envoy.extensions.filters.http.ext_proc.v3.ExtProcPerRoute","overrides":{"grpc_service":{"envoy_grpc":{"cluster_name":"outbound|9002||e2e-inferencepool-epp.test.svc.cluster.local"}}}}}}`)
	if !hasInferenceOverride(withOverride) {
		t.Fatal("expected EPP ExtProcPerRoute override")
	}
	if hasInferenceOverride([]byte(`{"@type":"type.googleapis.com/envoy.extensions.filters.http.ext_proc.v3.ExternalProcessor"}`)) {
		t.Fatal("base ext_proc filter should not count as a per-route override")
	}
}

func TestHasIsolatedFilters(t *testing.T) {
	isolated := []byte(`{"http_filters":[{"name":"envoy.filters.http.ext_proc"},{"name":"ext-authz-token-exchange.ext_proc","typed_config":{"grpc_service":{"envoy_grpc":{"cluster_name":"outbound|3001||ext-authz-token-exchange.test.svc.cluster.local"}}}}]}`)
	if !hasIsolatedFilters(isolated) {
		t.Fatal("expected distinct endpoint picker and token-exchange filters")
	}
	duplicate := []byte(`{"http_filters":[{"name":"envoy.filters.http.ext_proc"},{"name":"envoy.filters.http.ext_proc","typed_config":{"grpc_service":{"envoy_grpc":{"cluster_name":"outbound|3001||ext-authz-token-exchange.test.svc.cluster.local"}}}}]}`)
	if hasIsolatedFilters(duplicate) {
		t.Fatal("duplicate generic ext_proc filters must not count as isolated")
	}
}

func TestExchangedAuthorization(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "array value",
			body: `{"headers":{"Authorization":["Bearer exchanged"]}}`,
			want: "Bearer exchanged",
		},
		{
			name: "string value",
			body: `{"headers":{"authorization":"Bearer exchanged"}}`,
			want: "Bearer exchanged",
		},
		{
			name: "missing",
			body: `{"headers":{"Host":["httpbin.int.kube"]}}`,
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := exchangedAuthorization([]byte(tt.body)); got != tt.want {
				t.Fatalf("exchangedAuthorization() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTokenProbeReady(t *testing.T) {
	if !tokenProbeReady(tokenProbeResult{
		allowCode: http.StatusOK,
		denyCode:  http.StatusUnauthorized,
		allowAuth: "Bearer exchanged",
	}) {
		t.Fatal("expected exchanged bearer probe to be ready")
	}
	if tokenProbeReady(tokenProbeResult{
		allowCode: http.StatusOK,
		denyCode:  http.StatusUnauthorized,
		allowAuth: "Bearer readiness-yellow",
	}) {
		t.Fatal("original bearer token should not count as exchanged")
	}
}

func TestKeycloakIssuerURL(t *testing.T) {
	t.Setenv("E2E_KEYCLOAK_ISSUER", "")
	got := keycloakIssuerURL("https://httpbin.int.kube")
	want := "https://keycloak.int.kube/realms/token-exchange-e2e"
	if got != want {
		t.Fatalf("keycloakIssuerURL() = %q, want %q", got, want)
	}
}

func TestKeycloakBaseURLPrefersEnv(t *testing.T) {
	t.Setenv("E2E_KEYCLOAK_BASE_URL", "https://issuer.example.test")
	if got := keycloakBaseURL("https://httpbin.int.kube"); got != "https://issuer.example.test" {
		t.Fatalf("keycloakBaseURL() = %q, want env override", got)
	}
}
