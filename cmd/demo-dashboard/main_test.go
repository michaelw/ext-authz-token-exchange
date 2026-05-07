package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/michaelw/ext-authz-token-exchange/internal/demo"
)

func TestDashboardURL(t *testing.T) {
	tests := []struct {
		name string
		addr string
		want string
	}{
		{
			name: "loopback",
			addr: "127.0.0.1:8088",
			want: "http://127.0.0.1:8088/",
		},
		{
			name: "empty host",
			addr: ":8088",
			want: "http://127.0.0.1:8088/",
		},
		{
			name: "ipv4 unspecified",
			addr: "0.0.0.0:8088",
			want: "http://127.0.0.1:8088/",
		},
		{
			name: "ipv6 unspecified",
			addr: "[::]:8088",
			want: "http://127.0.0.1:8088/",
		},
		{
			name: "ipv6 concrete",
			addr: "[::1]:8088",
			want: "http://[::1]:8088/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := dashboardURL(tt.addr)
			if err != nil {
				t.Fatalf("dashboardURL(%q) returned error: %v", tt.addr, err)
			}
			if got != tt.want {
				t.Fatalf("dashboardURL(%q) = %q, want %q", tt.addr, got, tt.want)
			}
		})
	}
}

func TestDeploymentStatus(t *testing.T) {
	tests := []struct {
		name      string
		kubectl   string
		wantReady bool
		wantAvail string
		wantWarn  string
	}{
		{
			name:      "available replicas match desired replicas",
			kubectl:   "printf '1/1'",
			wantReady: true,
			wantAvail: "1/1",
		},
		{
			name:      "scaled to zero is not ready",
			kubectl:   "printf '/0'",
			wantReady: false,
			wantAvail: "/0",
		},
		{
			name:      "missing deployment is not ready",
			kubectl:   "echo 'deployment not found' >&2\nexit 1",
			wantReady: false,
			wantWarn:  "deployment not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withKubectl(t, tt.kubectl)
			got := deploymentStatus(context.Background(), "test-namespace", "test-deploy")
			if got.Ready != tt.wantReady {
				t.Fatalf("Ready = %v, want %v", got.Ready, tt.wantReady)
			}
			if got.Available != tt.wantAvail {
				t.Fatalf("Available = %q, want %q", got.Available, tt.wantAvail)
			}
			if tt.wantWarn != "" && !strings.Contains(got.Warning, tt.wantWarn) {
				t.Fatalf("Warning = %q, want to contain %q", got.Warning, tt.wantWarn)
			}
		})
	}
}

func TestSelectIssuerDetectsKeycloakDeployment(t *testing.T) {
	withKubectl(t, `printf 'http://keycloak.ext-authz-token-exchange-e2e.svc.cluster.local:8080/realms/token-exchange-e2e/protocol/openid-connect/token'`)
	t.Setenv("DEMO_SCENARIO_CONFIG", "")

	opts := selectIssuer(context.Background(), demoOptions())

	if opts.Name != "keycloak" {
		t.Fatalf("Name = %q, want keycloak", opts.Name)
	}
	if opts.ScenarioConfig != keycloakConfigPath {
		t.Fatalf("ScenarioConfig = %q, want %q", opts.ScenarioConfig, keycloakConfigPath)
	}
	if got := opts.apply(demoOptions()).ConfigPath; got != keycloakConfigPath {
		t.Fatalf("applied ConfigPath = %q, want %q", got, keycloakConfigPath)
	}
}

func TestSelectIssuerDetectsFakeDeployment(t *testing.T) {
	withKubectl(t, `printf 'http://fake-token-endpoint.ext-authz-token-exchange-e2e.svc.cluster.local:8080/token/success'`)
	t.Setenv("DEMO_SCENARIO_CONFIG", "")

	opts := selectIssuer(context.Background(), demoOptions())

	if opts.Name != "fake" {
		t.Fatalf("Name = %q, want fake", opts.Name)
	}
	if got := opts.apply(demoOptions()).ConfigPath; got != "test/e2e/demo-scenarios.yaml" {
		t.Fatalf("applied ConfigPath = %q, want default fake scenario config", got)
	}
}

func TestSelectIssuerKeepsExplicitScenarioConfig(t *testing.T) {
	withKubectl(t, `printf 'http://keycloak.ext-authz-token-exchange-e2e.svc.cluster.local:8080/realms/token-exchange-e2e/protocol/openid-connect/token'`)
	t.Setenv("DEMO_SCENARIO_CONFIG", "custom.yaml")
	opts := demoOptions()
	opts.ConfigPath = "custom.yaml"

	selection := selectIssuer(context.Background(), opts)
	applied := selection.apply(opts)

	if selection.Name != "fake" {
		t.Fatalf("Name = %q, want fake fallback for custom config", selection.Name)
	}
	if applied.ConfigPath != "custom.yaml" {
		t.Fatalf("ConfigPath = %q, want explicit custom.yaml", applied.ConfigPath)
	}
}

func demoOptions() demo.Options {
	return demo.Options{
		ConfigPath:       "test/e2e/demo-scenarios.yaml",
		PluginNamespace:  "ext-authz-token-exchange",
		PluginDeployment: "ext-authz-token-exchange",
		SystemNamespace:  "ext-authz-token-exchange-e2e",
	}
}

func withKubectl(t *testing.T, script string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "kubectl")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script+"\n"), 0o755); err != nil {
		t.Fatalf("write fake kubectl: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}
