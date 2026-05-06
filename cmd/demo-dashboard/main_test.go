package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
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

func withKubectl(t *testing.T, script string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "kubectl")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script+"\n"), 0o755); err != nil {
		t.Fatalf("write fake kubectl: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}
