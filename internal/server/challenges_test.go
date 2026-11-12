package server

import (
	"context"
	"strings"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"github.com/michaelw/ext-authz-token-exchange/internal/config"
	"github.com/michaelw/ext-authz-token-exchange/internal/exchange"
	"github.com/michaelw/ext-authz-token-exchange/internal/policy"
)

func TestValidChallengesSurviveAllAdapters(t *testing.T) {
	for _, values := range [][]string{
		{`Basic realm="a,b", charset="UTF-8"`, `Bearer realm="escaped\"quote"`, "Custom\tvalue"},
		{strings.Repeat("a", 4095), strings.Repeat("b", 4095)},
		strings.Split(strings.TrimSuffix(strings.Repeat("Bearer,", 32), ","), ","),
	} {
		cfg := config.RuntimeConfig{}
		store := policy.NewStaticStore(loggingIndex())
		ex := &loggingExchanger{err: &exchange.OAuthError{StatusCode: 401, WWWAuthenticate: values}}
		authz, err := NewAuthzGRPCServer(cfg, store, ex).Check(context.Background(), loggingCheckRequestWithHeaders("GET", "orders.example.com", "/api/orders", map[string]string{"authorization": "Bearer subject"}))
		if err != nil || authz.GetDeniedResponse().GetStatus().GetCode() != 401 {
			t.Fatal("ext-authz changed a valid denial")
		}
		proc := NewExtProcGRPCServer(cfg, store, ex).evaluateRequestHeaders(context.Background(), extProcHeaderRequest(map[string]string{":method": "GET", ":authority": "orders.example.com", ":path": "/api/orders", "authorization": "Bearer subject"}))
		if proc.GetImmediateResponse().GetStatus().GetCode() != 401 {
			t.Fatal("ext-proc changed a valid denial")
		}
		for _, headers := range [][]*corev3.HeaderValueOption{authz.GetDeniedResponse().GetHeaders(), proc.GetImmediateResponse().GetHeaders().GetSetHeaders()} {
			var got []string
			for _, option := range headers {
				if h := option.GetHeader(); strings.EqualFold(h.GetKey(), "WWW-Authenticate") {
					value := h.GetValue()
					if h.GetRawValue() != nil {
						value = string(h.GetRawValue())
					}
					got = append(got, value)
				}
			}
			if len(got) != len(values) || strings.Join(got, "\x00") != strings.Join(values, "\x00") {
				t.Fatal("Envoy challenge values or order changed")
			}
		}
		response, err := NewApigeeGRPCServer(cfg, store, ex, false).ProcessMessage(context.Background(), loggingApigeeRequest("/api/orders", "Bearer subject"))
		if err != nil || response.GetAdditionalFlowVariables()["txe.status"].GetInt32() != 401 || response.GetAdditionalFlowVariables()["txe.www_authenticate"].GetString_() != strings.Join(values, ", ") {
			t.Fatal("Apigee changed valid joined challenges")
		}
	}
}

func TestChallengeValidation(t *testing.T) {
	valid := []string{`Basic realm="a,b", charset="UTF-8"`, `Bearer realm="escaped\"quote"`, "Custom\tvalue\x80"}
	for _, tc := range []struct {
		name   string
		values []string
		ok     bool
	}{
		{"multiple and quoted", valid, true},
		{"empty", nil, true},
		{"byte boundary", []string{strings.Repeat("a", 8192)}, true},
		{"joined byte boundary", []string{strings.Repeat("a", 4095), strings.Repeat("b", 4095)}, true},
		{"count boundary", make([]string, 32), true},
		{"too many", make([]string, 33), false},
		{"too large", []string{strings.Repeat("a", 8193)}, false},
		{"separator counts", []string{strings.Repeat("a", 4096), strings.Repeat("b", 4095)}, false},
		{"crlf", []string{"Bearer realm=x\r\nX-Injected: yes"}, false},
		{"nul", []string{"Bearer\x00value"}, false},
		{"del", []string{"Bearer\x7fvalue"}, false},
		{"control", []string{"Bearer\x01value"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := (&requestEvaluator{}).oauthDenyEvaluation(&exchange.OAuthError{StatusCode: 401, Body: `{"error":"invalid_client"}`, WWWAuthenticate: tc.values})
			var got []string
			for _, h := range e.Headers {
				if strings.EqualFold(h.Name, "WWW-Authenticate") {
					got = append(got, h.Value)
				}
			}
			if tc.ok {
				if e.Status != 401 || strings.Join(got, "\x00") != strings.Join(tc.values, "\x00") || len(got) != len(tc.values) {
					t.Fatalf("valid values changed: status=%d count=%d", e.Status, len(got))
				}
			} else if e.Status != 500 || len(got) != 0 || !strings.Contains(e.Body, "server_error") || strings.Contains(e.Body, "Injected") || e.Diagnostics.Code == "" {
				t.Fatalf("unsafe challenge was not rejected safely: %+v", e)
			}
		})
	}
}

func TestInvalidChallengesFailClosedAcrossAdapters(t *testing.T) {
	for _, value := range []string{"invalid\r\nInjected: yes", strings.Repeat("x", 8193)} {
		cfg := config.RuntimeConfig{ErrorPassthrough: true}
		store := policy.NewStaticStore(loggingIndex())
		ex := &loggingExchanger{err: &exchange.OAuthError{StatusCode: 401, Body: `{"secret":"UPSTREAM_CANARY"}`, WWWAuthenticate: []string{value}}}
		authz, err := NewAuthzGRPCServer(cfg, store, ex).Check(context.Background(), loggingCheckRequestWithHeaders("GET", "orders.example.com", "/api/orders", map[string]string{"authorization": "Bearer subject"}))
		if err != nil || authz.GetDeniedResponse().GetStatus().GetCode() != 500 || strings.Contains(authz.GetDeniedResponse().GetBody(), "CANARY") {
			t.Fatal("ext-authz did not fail closed")
		}
		proc := NewExtProcGRPCServer(cfg, store, ex).evaluateRequestHeaders(context.Background(), extProcHeaderRequest(map[string]string{":method": "GET", ":authority": "orders.example.com", ":path": "/api/orders", "authorization": "Bearer subject"}))
		if proc.GetImmediateResponse().GetStatus().GetCode() != 500 || strings.Contains(string(proc.GetImmediateResponse().GetBody()), "CANARY") {
			t.Fatal("ext-proc did not fail closed")
		}
		apigee, err := NewApigeeGRPCServer(cfg, store, ex, false).ProcessMessage(context.Background(), loggingApigeeRequest("/api/orders", "Bearer subject"))
		if err != nil || apigee.GetAdditionalFlowVariables()["txe.status"].GetInt32() != 500 || apigee.GetAdditionalFlowVariables()["txe.www_authenticate"].GetString_() != "" {
			t.Fatal("Apigee did not fail closed")
		}
	}
}

func FuzzChallengeValidation(f *testing.F) {
	f.Add(`Bearer realm="a,b"`, `Basic realm="other"`)
	f.Add("bad\r\nheader", "")
	f.Fuzz(func(t *testing.T, a, b string) {
		values := []string{a, b}
		valid := len(a)+len(b)+2 <= 8192
		for _, s := range values {
			for i := range s {
				if s[i] == 127 || (s[i] < 32 && s[i] != '\t') {
					valid = false
				}
			}
		}
		e := (&requestEvaluator{}).oauthDenyEvaluation(&exchange.OAuthError{StatusCode: 401, WWWAuthenticate: values})
		if valid && (e.Status != 401 || len(e.Headers) != 3 || e.Headers[1].Value != a || e.Headers[2].Value != b) {
			t.Fatal("valid challenge changed")
		}
		if !valid && (e.Status != 500 || len(e.Headers) != 1) {
			t.Fatal("invalid challenge forwarded")
		}
	})
}
