package main

import (
	"net/http"
	"testing"
)

func TestDeployProfiles(t *testing.T) {
	tests := []struct {
		mode string
		want []string
	}{
		{mode: "ext-authz", want: []string{"with-infra", "with-keycloak"}},
		{mode: "ext-proc", want: []string{"with-infra", "with-keycloak", "ext-proc"}},
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
