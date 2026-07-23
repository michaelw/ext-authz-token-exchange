package directhttp

import "testing"

func TestNewTransportRejectsInvalidAddress(t *testing.T) {
	if _, err := NewTransport("gateway.example.test", false); err == nil {
		t.Fatal("NewTransport error = nil, want invalid address error")
	}
}

func TestNewTransportDialsDirectIPv4AndIPv6(t *testing.T) {
	tests := map[string]string{
		"192.0.2.10":   "192.0.2.10:443",
		"2001:db8::10": "[2001:db8::10]:443",
	}
	for address, want := range tests {
		got, err := directDialAddress("httpbin.example.test:443", address)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("directDialAddress(%q) = %q, want %q", address, got, want)
		}
	}
}

func TestCurlResolve(t *testing.T) {
	if got := CurlResolve("httpbin.example.test", "443", "192.0.2.10"); got != "httpbin.example.test:443:192.0.2.10" {
		t.Fatalf("IPv4 resolve = %q", got)
	}
	if got := CurlResolve("httpbin.example.test", "443", "2001:db8::10"); got != "httpbin.example.test:443:[2001:db8::10]" {
		t.Fatalf("IPv6 resolve = %q", got)
	}
	if got := CurlResolve("httpbin.example.test", "443", ""); got != "" {
		t.Fatalf("DNS resolve = %q, want empty", got)
	}
}
