package exchange

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

type timeoutError struct{}

func (timeoutError) Error() string   { return "timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return false }

var _ net.Error = timeoutError{}

func TestExchangeRequestErrorKind(t *testing.T) {
	cases := []struct {
		name string
		ctx  context.Context
		err  error
		want string
	}{
		{name: "context canceled error", ctx: context.Background(), err: context.Canceled, want: "context_canceled"},
		{name: "context canceled state", ctx: canceledContext(), err: errors.New("transport failed"), want: "context_canceled"},
		{name: "deadline exceeded error", ctx: context.Background(), err: context.DeadlineExceeded, want: "timeout"},
		{name: "deadline exceeded state", ctx: deadlineExceededContext(), err: errors.New("transport failed"), want: "timeout"},
		{name: "net timeout", ctx: context.Background(), err: timeoutError{}, want: "timeout"},
		{name: "transport error", ctx: context.Background(), err: errors.New("connection refused"), want: "transport_error"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := exchangeRequestErrorKind(tc.ctx, tc.err); got != tc.want {
				t.Fatalf("exchangeRequestErrorKind() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestStatusClass(t *testing.T) {
	cases := map[int]string{
		0:   metricStatusNone,
		-1:  metricStatusNone,
		200: "2xx",
		404: "4xx",
		503: "5xx",
	}

	for status, want := range cases {
		if got := statusClass(status); got != want {
			t.Fatalf("statusClass(%d) = %q, want %q", status, got, want)
		}
	}
}

func TestTokenEndpointHost(t *testing.T) {
	cases := map[string]string{
		"https://ISSUER.example:8443/token": "issuer.example",
		"://bad":                            "invalid",
		"https:///missing-host":             "invalid",
	}

	for endpoint, want := range cases {
		if got := tokenEndpointHost(endpoint); got != want {
			t.Fatalf("tokenEndpointHost(%q) = %q, want %q", endpoint, got, want)
		}
	}
}

func TestMustPanicsOnInstrumentCreationError(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("must did not panic")
		}
	}()
	must(0, errors.New("boom"))
}

func canceledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func deadlineExceededContext() context.Context {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	cancel()
	return ctx
}
