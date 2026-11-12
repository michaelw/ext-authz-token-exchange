package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/michaelw/ext-authz-token-exchange/internal/config"
	"github.com/michaelw/ext-authz-token-exchange/internal/exchange"
	"github.com/michaelw/ext-authz-token-exchange/internal/logging"
	"github.com/michaelw/ext-authz-token-exchange/internal/policy"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
)

type requestEvaluator struct {
	cfg       config.RuntimeConfig
	store     policy.Store
	exchanger tokenExchanger
}

func newRequestEvaluator(cfg config.RuntimeConfig, store policy.Store, exchanger tokenExchanger) *requestEvaluator {
	return &requestEvaluator{cfg: cfg, store: store, exchanger: exchanger}
}

type tokenExchanger interface {
	Exchange(ctx context.Context, entry policy.Entry, subjectToken string) (exchange.Result, *exchange.OAuthError)
}

type httpEvaluationRequest struct {
	Adapter       string
	GatewayID     string
	ProxyRevision string
	Method        string
	Scheme        string
	Host          string
	Path          string
	Headers       map[string]string
}

type httpEvaluation struct {
	Policy         string
	Diagnostics    exchange.Diagnostics
	Allowed        bool
	Status         int
	Body           string
	Headers        []headerPair
	MetricDecision string
	MetricResult   string
}

var evaluationSequence atomic.Uint64

func (s *requestEvaluator) evaluateHTTPWithMetrics(ctx context.Context, req httpEvaluationRequest) httpEvaluation {
	started := time.Now()
	otelAuthzCheckInFlight.Add(ctx, 1)
	defer otelAuthzCheckInFlight.Add(ctx, -1)
	authzCheckInFlight.Inc()
	defer authzCheckInFlight.Dec()

	evaluation := s.evaluateHTTP(ctx, req)
	recordAuthzCheckMetrics(started, evaluation.MetricDecision, evaluation.MetricResult)
	s.logDecision(ctx, req, evaluation, time.Since(started))
	return evaluation
}

func (s *requestEvaluator) evaluateHTTP(ctx context.Context, req httpEvaluationRequest) (evaluation httpEvaluation) {
	method := strings.ToUpper(req.Method)
	headers := req.Headers
	if headers == nil {
		headers = map[string]string{}
	}
	s.logHeaderKeysIfInsecureEnabled(req.Adapter, headers)
	subjectToken, hasBearerToken := bearerToken(header(headers, "authorization"))

	host := req.Host
	if host == "" {
		host = header(headers, ":authority")
	}
	if host == "" {
		host = header(headers, "host")
	}

	decision := s.store.Index().Match(host, req.Path, method)
	defer func() {
		if decision.Entry.Source.Name != "" {
			evaluation.Policy = logField(decision.Entry.Source.Namespace) + "/" + logField(decision.Entry.Source.Name)
		}
	}()
	if !decision.Matched {
		if s.cfg.DefaultDenyUnmatched {
			return s.denyJSONEvaluation(http.StatusForbidden, map[string]string{
				"error": "policy_denied",
			}, nil, checkDecisionDenyUnmatchedDefault, checkResultAuthDenied)
		}
		return allowEvaluation(nil, checkDecisionAllowUnmatched, checkResultAllowed)
	}
	if decision.Unhealthy {
		return s.denyJSONEvaluation(http.StatusInternalServerError, map[string]string{
			"error":             "server_error",
			"error_description": "internal server error",
		}, nil, checkDecisionDenyPolicyUnhealthy, checkResultSystemError)
	}
	if decision.Entry.Action == policy.ActionDeny {
		return s.denyJSONEvaluation(http.StatusForbidden, map[string]string{
			"error": "policy_denied",
		}, nil, checkDecisionDenyExplicitPolicy, checkResultAuthDenied)
	}
	if shouldBypassOptions(method, headers, s.cfg.AllowUnauthenticatedOptions, hasBearerToken) {
		return allowEvaluation(nil, checkDecisionAllowOptionsBypass, checkResultAllowed)
	}

	if !hasBearerToken {
		// RFC6750 Section 3 defines Bearer challenges for protected resources.
		// https://www.rfc-editor.org/rfc/rfc6750#section-3
		return s.denyJSONEvaluation(http.StatusUnauthorized, map[string]string{
			"error": "bearer_token_required",
		}, []headerPair{{Name: "WWW-Authenticate", Value: bearerChallenge(s.bearerRealm(decision.Entry), decision.Entry.Scope)}}, checkDecisionDenyMissingBearer, checkResultAuthDenied)
	}

	ctx, span := otel.Tracer("github.com/michaelw/ext-authz-token-exchange/internal/server").Start(
		ctx,
		"ext_authz Check",
		trace.WithSpanKind(trace.SpanKindServer),
	)
	defer span.End()

	result, oauthErr := s.exchanger.Exchange(ctx, decision.Entry, subjectToken)
	if oauthErr != nil {
		return s.oauthDenyEvaluation(oauthErr)
	}
	s.logTokensIfInsecureEnabled(req.Adapter, method, decision.Entry, subjectToken, result.AccessToken)
	return allowEvaluation([]headerPair{{Name: "authorization", Value: "Bearer " + result.AccessToken}}, checkDecisionAllowExchange, checkResultAllowed)
}

func (s *requestEvaluator) bearerRealm(entry policy.Entry) string {
	if profile, ok := s.cfg.IssuerProfile(entry.IssuerRef); ok && strings.TrimSpace(profile.BearerRealm) != "" {
		return profile.BearerRealm
	}
	return s.cfg.BearerRealm
}

func allowEvaluation(headers []headerPair, decision, result string) httpEvaluation {
	return httpEvaluation{
		Allowed:        true,
		Headers:        headers,
		MetricDecision: decision,
		MetricResult:   result,
	}
}

func (s *requestEvaluator) denyJSONEvaluation(status int, body map[string]string, headers []headerPair, decision, result string) httpEvaluation {
	data, err := json.Marshal(body)
	if err != nil {
		data = []byte(`{"error":"server_error"}`)
	}
	headers = append([]headerPair{{Name: "Content-Type", Value: "application/json"}}, headers...)
	return httpEvaluation{
		Status:         status,
		Body:           string(data),
		Headers:        headers,
		MetricDecision: decision,
		MetricResult:   result,
	}
}

func (s *requestEvaluator) oauthDenyEvaluation(oauthErr *exchange.OAuthError) httpEvaluation {
	if !validChallenges(oauthErr.WWWAuthenticate) {
		result := s.denyJSONEvaluation(http.StatusInternalServerError, map[string]string{"error": "server_error"}, nil, checkDecisionDenyExchangeError, checkResultSystemError)
		result.Diagnostics = exchange.Diagnostics{Code: "TXE-3005", FailureClass: "invalid_response", UpstreamStatus: oauthErr.SafeDiagnostics().UpstreamStatus}
		return result
	}
	headers := []headerPair{{Name: "Content-Type", Value: "application/json"}}
	for _, value := range oauthErr.WWWAuthenticate {
		headers = append(headers, headerPair{Name: "WWW-Authenticate", Value: value})
	}
	body := oauthErr.Body
	if body == "" {
		fields := map[string]string{}
		if oauthErr.Error != "" {
			fields["error"] = oauthErr.Error
		}
		if oauthErr.ErrorDescription != "" {
			fields["error_description"] = oauthErr.ErrorDescription
		}
		if oauthErr.Message != "" {
			fields["message"] = oauthErr.Message
		}
		if len(fields) == 0 {
			fields["error"] = "server_error"
		}
		data, err := json.Marshal(fields)
		if err != nil {
			data = []byte(`{"error":"server_error"}`)
		}
		body = string(data)
	}
	return httpEvaluation{
		Diagnostics:    oauthErr.SafeDiagnostics(),
		Status:         oauthErr.StatusCode,
		Body:           body,
		Headers:        headers,
		MetricDecision: checkDecisionDenyExchangeError,
		MetricResult:   checkResultForOAuthError(oauthErr),
	}
}

// Challenges are opaque HTTP field values, not comma-delimited tokens.
func validChallenges(values []string) bool {
	if len(values) > 32 {
		return false
	}
	size := 0
	for i, value := range values {
		if i > 0 {
			size += 2
		}
		if len(value) > 8192-size {
			return false
		}
		size += len(value)
		for j := range value {
			if value[j] == 127 || (value[j] < 32 && value[j] != '\t') {
				return false
			}
		}
	}
	return true
}

func (s *requestEvaluator) logDecision(ctx context.Context, req httpEvaluationRequest, result httpEvaluation, duration time.Duration) {
	decision, prefix, severity := "deny", "DENY", "INFO"
	if result.Allowed {
		decision, prefix = "allow", "DECISION"
	}
	d := result.Diagnostics
	if result.MetricResult == checkResultSystemError || (result.MetricDecision == checkDecisionDenyExchangeError && d.FailureClass != "oauth_rejection") {
		severity = "ERROR"
	}
	e := logging.Event{Name: "request_decision", Severity: severity, Adapter: req.Adapter, EvaluationID: fmt.Sprintf("eval-%d", evaluationSequence.Add(1)), Decision: decision, Reason: result.MetricDecision, Result: result.MetricResult, DurationMS: float64(duration) / float64(time.Millisecond), HTTPStatus: result.Status, Diagnostic: d.Code, OAuthError: d.OAuthError, UpstreamStatus: d.UpstreamStatus, FailureClass: d.FailureClass}
	e.Policy = result.Policy
	if span := trace.SpanContextFromContext(ctx); span.IsValid() {
		e.TraceID, e.SpanID = span.TraceID().String(), span.SpanID().String()
	}
	if req.Adapter == "apigee" {
		e.GatewayID = safeCorrelation(req.GatewayID)
		e.GatewayIDSource = "apigee_message_context"
		e.ProxyRevision = safeCorrelation(req.ProxyRevision)
	}
	reason := result.MetricDecision
	if reason == checkDecisionDenyExplicitPolicy {
		reason = "explicit_policy"
	}
	if reason == checkDecisionDenyUnmatchedDefault {
		reason = "unmatched_default_deny"
	}
	text := fmt.Sprintf("%s reason=%s method=%s host=[redacted] path=[redacted] policy=%s adapter=%s decision=%s result_class=%s evaluation_id=%s duration_ms=%.3f", prefix, reason, safeHTTPMethod(req.Method), logField(result.Policy), req.Adapter, decision, result.MetricResult, e.EvaluationID, e.DurationMS)
	if result.Status != 0 {
		text += fmt.Sprintf(" http_status=%d", result.Status)
	}
	if d.Code != "" {
		text += " diagnostic_code=" + d.Code
	}
	if d.FailureClass != "" {
		text += " failure_class=" + d.FailureClass
	}
	if d.OAuthError != "" {
		text += " oauth_error=" + d.OAuthError
	}
	if d.UpstreamStatus != 0 {
		text += fmt.Sprintf(" upstream_http_status=%d", d.UpstreamStatus)
	}
	if e.TraceID != "" {
		text += " trace_id=" + e.TraceID + " span_id=" + e.SpanID
	}
	if e.GatewayID != "" {
		text += " gateway_id=" + e.GatewayID + " gateway_id_source=" + e.GatewayIDSource
	}
	if e.ProxyRevision != "" {
		text += " proxy_revision=" + e.ProxyRevision
	}
	logging.Write(customLogger, s.cfg.LogFormat, e, text)
}

func (s *requestEvaluator) logTokensIfInsecureEnabled(adapter, method string, entry policy.Entry, subjectToken, exchangedToken string) {
	if !s.cfg.InsecureLogTokens {
		return
	}
	text := fmt.Sprintf("INSECURE_LOG_TOKENS method=%s host=[redacted] path=[redacted] policy=%s/%s subject_token=%s exchanged_token=%s",
		safeHTTPMethod(method),
		logField(entry.Source.Namespace),
		logField(entry.Source.Name),
		logField(subjectToken),
		logField(exchangedToken))
	logging.Write(customLogger, s.cfg.LogFormat, logging.Event{Name: "insecure_token_debug", Severity: "WARN", Adapter: adapter, SubjectToken: logField(subjectToken), ExchangedToken: logField(exchangedToken)}, text)
}

func (s *requestEvaluator) logHeaderKeysIfInsecureEnabled(adapter string, requestHeaders map[string]string) {
	if !s.cfg.InsecureLogTokens {
		return
	}
	names := safeHeaderNames(requestHeaders)
	logging.Write(customLogger, s.cfg.LogFormat, logging.Event{Name: "insecure_header_names", Severity: "DEBUG", Adapter: adapter, Message: strings.Join(names, ",")}, "INSECURE_LOG_HEADER_KEYS request_headers="+strings.Join(names, ","))
}
