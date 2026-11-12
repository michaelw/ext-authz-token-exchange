package exchange_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/michaelw/ext-authz-token-exchange/internal/config"
	"github.com/michaelw/ext-authz-token-exchange/internal/exchange"
	"github.com/michaelw/ext-authz-token-exchange/internal/policy"
)

func TestExchangeCarriesTypedSafeDiagnostics(t *testing.T) {
	cfg := config.RuntimeConfig{AllowHTTPTokenEndpoint: true, TokenEndpointAuthMethod: config.AuthMethodClientSecretBasic, IssuerProfiles: map[string]config.IssuerProfile{"primary": {TokenEndpoint: "http://issuer.example/token", ClientID: "client", ClientSecret: "secret"}}}
	for _, tc := range []struct {
		name               string
		status             int
		body               string
		err                error
		code, class, oauth string
	}{
		{"oauth", 400, `{"error":"invalid_request","error_description":"SECRET_CANARY"}`, nil, "TXE-2001", "oauth_rejection", "invalid_request"},
		{"unknown-oauth", 400, `{"error":"SECRET_CANARY"}`, nil, "TXE-2002", "upstream_http", ""},
		{"upstream", 503, "SECRET_CANARY", nil, "TXE-2005", "upstream_http", ""},
		{"invalid-json", 200, "SECRET_CANARY", nil, "TXE-3001", "invalid_response", ""},
		{"timeout", 0, "", context.DeadlineExceeded, "TXE-1003", "timeout", ""},
		{"connection", 0, "", errors.New("SECRET_CANARY"), "TXE-1003", "connection", ""},
		{"tls", 0, "", &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}, "TXE-1003", "tls", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := clientWithRoundTripper(roundTripFunc(func(*http.Request) (*http.Response, error) {
				if tc.err != nil {
					return nil, tc.err
				}
				return &http.Response{StatusCode: tc.status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(tc.body))}, nil
			}))
			_, failure := exchange.NewClient(cfg, client).Exchange(context.Background(), policy.Entry{IssuerRef: "primary"}, "subject")
			if failure == nil {
				t.Fatal("wanted failure")
			}
			d := failure.SafeDiagnostics()
			if d.Code != tc.code || d.FailureClass != tc.class || d.UpstreamStatus != tc.status || d.OAuthError != tc.oauth {
				t.Fatalf("unexpected diagnostics: %+v", d)
			}
		})
	}
	failure := &exchange.OAuthError{Diagnostics: exchange.Diagnostics{Code: "SECRET_CANARY", FailureClass: "SECRET_CANARY", OAuthError: "SECRET_CANARY", UpstreamStatus: 9999}}
	if d := failure.SafeDiagnostics(); d != (exchange.Diagnostics{}) {
		t.Fatalf("untrusted diagnostic leaked: %+v", d)
	}
}

type timedOutBody struct{}

func (timedOutBody) Read([]byte) (int, error) { return 0, context.DeadlineExceeded }

func TestResponseBodyTimeoutHasTypedDiagnostics(t *testing.T) {
	cfg := config.RuntimeConfig{AllowHTTPTokenEndpoint: true, IssuerProfiles: map[string]config.IssuerProfile{"primary": {TokenEndpoint: "http://issuer.example/token"}}}
	client := clientWithRoundTripper(roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(timedOutBody{})}, nil
	}))
	_, failure := exchange.NewClient(cfg, client).Exchange(context.Background(), policy.Entry{IssuerRef: "primary"}, "subject")
	if failure == nil || failure.SafeDiagnostics().FailureClass != "timeout" || failure.SafeDiagnostics().Code != "TXE-1004" {
		t.Fatal("missing body timeout diagnostics")
	}
}
