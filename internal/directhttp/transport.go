// Package directhttp creates HTTP transports that can dial a specific gateway
// address while preserving the request hostname for HTTP Host and TLS SNI.
package directhttp

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
)

// NewTransport returns a transport that uses normal DNS when directAddress is
// empty and otherwise replaces the dialed host with the supplied IP address.
func NewTransport(directAddress string, insecureTLS bool) (*http.Transport, error) {
	directAddress = strings.TrimSpace(directAddress)
	if directAddress != "" && net.ParseIP(directAddress) == nil {
		return nil, fmt.Errorf("direct gateway address must be an IPv4 or IPv6 address, got %q", directAddress)
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: insecureTLS}
	if directAddress == "" {
		return transport, nil
	}

	dialer := &net.Dialer{}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		address, err := directDialAddress(address, directAddress)
		if err != nil {
			return nil, err
		}
		return dialer.DialContext(ctx, network, address)
	}
	return transport, nil
}

func directDialAddress(address, directAddress string) (string, error) {
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", fmt.Errorf("split HTTP dial address %q: %w", address, err)
	}
	return net.JoinHostPort(directAddress, port), nil
}

// CurlResolve returns curl's --resolve value for a public host and direct IP.
func CurlResolve(host string, port string, directAddress string) string {
	if directAddress == "" {
		return ""
	}
	if strings.Contains(directAddress, ":") {
		return host + ":" + port + ":[" + directAddress + "]"
	}
	return host + ":" + port + ":" + directAddress
}
