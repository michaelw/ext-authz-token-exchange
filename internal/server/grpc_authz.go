package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_service_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	envoy_type_v3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/michaelw/ext-authz-token-exchange/internal/config"
	"github.com/michaelw/ext-authz-token-exchange/internal/exchange"
	"github.com/michaelw/ext-authz-token-exchange/internal/policy"
	"github.com/michaelw/ext-authz-token-exchange/internal/telemetry"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
	grpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const AuthzCheckMethod = "/envoy.service.auth.v3.Authorization/Check"

const (
	checkDecisionMissingAttributes    = "missing_http_attributes"
	checkDecisionAllowUnmatched       = "allow_unmatched"
	checkDecisionDenyUnmatchedDefault = "deny_unmatched_default"
	checkDecisionDenyPolicyUnhealthy  = "deny_policy_unhealthy"
	checkDecisionDenyExplicitPolicy   = "deny_explicit_policy"
	checkDecisionAllowOptionsBypass   = "allow_options_bypass"
	checkDecisionDenyMissingBearer    = "deny_missing_bearer"
	checkDecisionDenyExchangeError    = "deny_exchange_error"
	checkDecisionAllowExchange        = "allow_exchange"
	checkResultAllowed                = "allowed"
	checkResultAuthDenied             = "auth_denied"
	checkResultSystemError            = "system_error"
)

var (
	meter                  = otel.Meter("github.com/michaelw/ext-authz-token-exchange/internal/server")
	otelAuthzCheckRequests = mustMetric(meter.Int64Counter("ext_authz_check_requests_total"))
	otelAuthzCheckDuration = mustMetric(meter.Float64Histogram("ext_authz_check_duration_seconds", metric.WithExplicitBucketBoundaries(0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1, 2.5)))
	otelAuthzCheckInFlight = mustMetric(meter.Int64UpDownCounter("ext_authz_check_in_flight"))
	authzCheckRequests     = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ext_authz_check_requests_total",
		Help: "Total Envoy ext-authz Check requests by decision and result class.",
	}, []string{"decision", "result"})
	authzCheckDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "ext_authz_check_duration_seconds",
		Help:    "Envoy ext-authz Check request duration by decision and result class.",
		Buckets: []float64{0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1, 2.5},
	}, []string{"decision", "result"})
	authzCheckInFlight = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "ext_authz_check_in_flight",
		Help: "Envoy ext-authz Check requests currently in flight.",
	})
)

// AuthzGRPCServer implements the Envoy external authorization gRPC service.
type AuthzGRPCServer struct {
	envoy_service_auth_v3.UnimplementedAuthorizationServer

	cfg       config.RuntimeConfig
	store     policy.Store
	exchanger tokenExchanger
}

type tokenExchanger interface {
	Exchange(ctx context.Context, entry policy.Entry, subjectToken string) (exchange.Result, *exchange.OAuthError)
}

// NewAuthzGRPCServer creates a gRPC authorization server.
func NewAuthzGRPCServer(cfg config.RuntimeConfig, store policy.Store, exchanger tokenExchanger) *AuthzGRPCServer {
	return &AuthzGRPCServer{cfg: cfg, store: store, exchanger: exchanger}
}

// AuthzLoggingMethods returns gRPC logging rules for this service's endpoints.
func AuthzLoggingMethods() map[string]LoggingMethod {
	return map[string]LoggingMethod{
		AuthzCheckMethod: {
			LogEnabled:        true,
			SummarizeRequest:  summarizeAuthzRequest,
			SummarizeResponse: summarizeAuthzResponse,
		},
	}
}

func summarizeAuthzRequest(req any) string {
	checkReq, ok := req.(*envoy_service_auth_v3.CheckRequest)
	if !ok {
		return ""
	}
	httpReq := checkReq.GetAttributes().GetRequest().GetHttp()
	if httpReq == nil {
		return ""
	}
	return fmt.Sprintf(" | %s | %s://%s%s",
		logField(httpReq.GetMethod()),
		logField(httpReq.GetScheme()),
		logField(httpReq.GetHost()),
		logPath(httpReq.GetPath()))
}

func summarizeAuthzResponse(resp any) string {
	checkResp, ok := resp.(*envoy_service_auth_v3.CheckResponse)
	if !ok {
		return "unknown"
	}
	if checkResp.GetOkResponse() != nil {
		return "ok"
	}
	if denied := checkResp.GetDeniedResponse(); denied != nil {
		return "denied_status=" + logField(denied.GetStatus().GetCode().String())
	}
	return "unknown"
}

// Check implements the Envoy external authorization check.
func (s *AuthzGRPCServer) Check(ctx context.Context, req *envoy_service_auth_v3.CheckRequest) (*envoy_service_auth_v3.CheckResponse, error) {
	started := time.Now()
	metricDecision := checkDecisionMissingAttributes
	metricResult := checkResultSystemError
	otelAuthzCheckInFlight.Add(ctx, 1)
	defer otelAuthzCheckInFlight.Add(ctx, -1)
	authzCheckInFlight.Inc()
	defer func() {
		authzCheckInFlight.Dec()
		recordAuthzCheckMetrics(started, metricDecision, metricResult)
	}()

	httpReq := req.GetAttributes().GetRequest().GetHttp()
	if httpReq == nil {
		return s.denyJSON(http.StatusInternalServerError, map[string]string{
			"error":   "server_error",
			"message": "missing HTTP request attributes",
		}, nil), nil
	}

	method := strings.ToUpper(httpReq.GetMethod())
	headers := httpReq.GetHeaders()
	subjectToken, hasBearerToken := bearerToken(header(headers, "authorization"))

	host := header(headers, ":authority")
	if host == "" {
		host = header(headers, "host")
	}
	if host == "" {
		host = httpReq.GetHost()
	}

	decision := s.store.Index().Match(host, httpReq.GetPath(), method)
	if !decision.Matched {
		if s.cfg.DefaultDenyUnmatched {
			s.logDeny("unmatched_default_deny", method, host, httpReq.GetPath(), policy.Entry{})
			metricDecision = checkDecisionDenyUnmatchedDefault
			metricResult = checkResultAuthDenied
			return s.denyJSON(http.StatusForbidden, map[string]string{
				"error": "policy_denied",
			}, nil), nil
		}
		metricDecision = checkDecisionAllowUnmatched
		metricResult = checkResultAllowed
		return allowResponse(nil), nil
	}
	if decision.Unhealthy {
		metricDecision = checkDecisionDenyPolicyUnhealthy
		metricResult = checkResultSystemError
		return s.denyJSON(http.StatusInternalServerError, map[string]string{
			"error":             "server_error",
			"error_description": "internal server error",
		}, nil), nil
	}
	if decision.Entry.Action == policy.ActionDeny {
		s.logDeny("explicit_policy", method, host, httpReq.GetPath(), decision.Entry)
		metricDecision = checkDecisionDenyExplicitPolicy
		metricResult = checkResultAuthDenied
		return s.denyJSON(http.StatusForbidden, map[string]string{
			"error": "policy_denied",
		}, nil), nil
	}
	if shouldBypassOptions(method, headers, s.cfg.AllowUnauthenticatedOptions, hasBearerToken) {
		metricDecision = checkDecisionAllowOptionsBypass
		metricResult = checkResultAllowed
		return allowResponse(nil), nil
	}

	if !hasBearerToken {
		// RFC6750 Section 3 defines Bearer challenges for protected resources.
		// https://www.rfc-editor.org/rfc/rfc6750#section-3
		metricDecision = checkDecisionDenyMissingBearer
		metricResult = checkResultAuthDenied
		return s.denyJSON(http.StatusUnauthorized, map[string]string{
			"error": "bearer_token_required",
		}, []headerPair{{Name: "WWW-Authenticate", Value: bearerChallenge(s.bearerRealm(decision.Entry), decision.Entry.Scope)}}), nil
	}

	ctx = telemetry.ExtractHTTPHeaders(ctx, headers)
	ctx, span := otel.Tracer("github.com/michaelw/ext-authz-token-exchange/internal/server").Start(
		ctx,
		"ext_authz Check",
		trace.WithSpanKind(trace.SpanKindServer),
	)
	defer span.End()

	result, oauthErr := s.exchanger.Exchange(ctx, decision.Entry, subjectToken)
	if oauthErr != nil {
		metricDecision = checkDecisionDenyExchangeError
		metricResult = checkResultForOAuthError(oauthErr)
		return s.oauthDeny(oauthErr), nil
	}
	s.logTokensIfInsecureEnabled(method, host, httpReq.GetPath(), decision.Entry, subjectToken, result.AccessToken)
	metricDecision = checkDecisionAllowExchange
	metricResult = checkResultAllowed
	return allowResponse([]headerPair{{Name: "authorization", Value: "Bearer " + result.AccessToken}}), nil
}

func (s *AuthzGRPCServer) bearerRealm(entry policy.Entry) string {
	if profile, ok := s.cfg.IssuerProfile(entry.IssuerRef); ok && strings.TrimSpace(profile.BearerRealm) != "" {
		return profile.BearerRealm
	}
	return s.cfg.BearerRealm
}

func (s *AuthzGRPCServer) logDeny(reason, method, host, path string, entry policy.Entry) {
	policyName := "-"
	if entry.Source.Namespace != "" || entry.Source.Name != "" {
		policyName = logField(entry.Source.Namespace) + "/" + logField(entry.Source.Name)
	}
	customLogger.Printf("DENY reason=%s method=%s host=%s path=%s policy=%s",
		logField(reason),
		logField(method),
		logField(host),
		logPath(path),
		policyName)
}

func (s *AuthzGRPCServer) logTokensIfInsecureEnabled(method, host, path string, entry policy.Entry, subjectToken, exchangedToken string) {
	if !s.cfg.InsecureLogTokens {
		return
	}
	customLogger.Printf("INSECURE_LOG_TOKENS method=%s host=%s path=%s policy=%s/%s subject_token=%s exchanged_token=%s",
		logField(method),
		logField(host),
		logPath(path),
		logField(entry.Source.Namespace),
		logField(entry.Source.Name),
		logField(subjectToken),
		logField(exchangedToken))
}

func (s *AuthzGRPCServer) oauthDeny(oauthErr *exchange.OAuthError) *envoy_service_auth_v3.CheckResponse {
	headers := []headerPair{{Name: "Content-Type", Value: "application/json"}}
	for _, value := range oauthErr.WWWAuthenticate {
		headers = append(headers, headerPair{Name: "WWW-Authenticate", Value: value})
	}
	if oauthErr.Body != "" {
		return denyResponse(oauthErr.StatusCode, oauthErr.Body, headers)
	}
	body := map[string]string{}
	if oauthErr.Error != "" {
		body["error"] = oauthErr.Error
	}
	if oauthErr.ErrorDescription != "" {
		body["error_description"] = oauthErr.ErrorDescription
	}
	if oauthErr.Message != "" {
		body["message"] = oauthErr.Message
	}
	if len(body) == 0 {
		body["error"] = "server_error"
	}
	return s.denyJSON(oauthErr.StatusCode, body, headers)
}

func (s *AuthzGRPCServer) denyJSON(status int, body map[string]string, headers []headerPair) *envoy_service_auth_v3.CheckResponse {
	data, err := json.Marshal(body)
	if err != nil {
		data = []byte(`{"error":"server_error"}`)
	}
	headers = append([]headerPair{{Name: "Content-Type", Value: "application/json"}}, headers...)
	return denyResponse(status, string(data), headers)
}

func allowResponse(headers []headerPair) *envoy_service_auth_v3.CheckResponse {
	return &envoy_service_auth_v3.CheckResponse{
		Status: &grpcstatus.Status{Code: int32(codes.OK)},
		HttpResponse: &envoy_service_auth_v3.CheckResponse_OkResponse{
			OkResponse: &envoy_service_auth_v3.OkHttpResponse{
				Headers: headerOptions(headers),
			},
		},
	}
}

func denyResponse(status int, body string, headers []headerPair) *envoy_service_auth_v3.CheckResponse {
	return &envoy_service_auth_v3.CheckResponse{
		Status: &grpcstatus.Status{Code: int32(codes.PermissionDenied)},
		HttpResponse: &envoy_service_auth_v3.CheckResponse_DeniedResponse{
			DeniedResponse: &envoy_service_auth_v3.DeniedHttpResponse{
				Status:  &envoy_type_v3.HttpStatus{Code: envoyStatus(status)},
				Headers: headerOptions(headers),
				Body:    body,
			},
		},
	}
}

type headerPair struct {
	Name  string
	Value string
}

func headerOptions(headers []headerPair) []*envoy_config_core_v3.HeaderValueOption {
	options := make([]*envoy_config_core_v3.HeaderValueOption, 0, len(headers))
	for _, h := range headers {
		if h.Name == "" {
			continue
		}
		options = append(options, &envoy_config_core_v3.HeaderValueOption{
			Header: &envoy_config_core_v3.HeaderValue{Key: h.Name, Value: h.Value},
			Append: wrapperspb.Bool(false),
		})
	}
	return options
}

func envoyStatus(status int) envoy_type_v3.StatusCode {
	switch status {
	case http.StatusBadRequest:
		return envoy_type_v3.StatusCode_BadRequest
	case http.StatusUnauthorized:
		return envoy_type_v3.StatusCode_Unauthorized
	case http.StatusForbidden:
		return envoy_type_v3.StatusCode_Forbidden
	case http.StatusInternalServerError:
		return envoy_type_v3.StatusCode_InternalServerError
	default:
		return envoy_type_v3.StatusCode_InternalServerError
	}
}

func header(headers map[string]string, name string) string {
	for key, value := range headers {
		if strings.EqualFold(key, name) {
			return value
		}
	}
	return ""
}

func shouldBypassOptions(method string, headers map[string]string, allowUnauthenticatedOptions bool, hasBearerToken bool) bool {
	if method != http.MethodOptions || hasBearerToken {
		return false
	}
	if header(headers, "origin") != "" && header(headers, "access-control-request-method") != "" {
		return true
	}
	return allowUnauthenticatedOptions
}

func bearerToken(value string) (string, bool) {
	parts := strings.Fields(value)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
		return "", false
	}
	return parts[1], true
}

func bearerChallenge(realm, scope string) string {
	value := fmt.Sprintf("Bearer realm=%q", realm)
	if scope != "" {
		value += fmt.Sprintf(", scope=%q", scope)
	}
	return value
}

func recordAuthzCheckMetrics(started time.Time, decision, result string) {
	attrs := metric.WithAttributes(
		attribute.String("decision", decision),
		attribute.String("result", result),
	)
	otelAuthzCheckRequests.Add(context.Background(), 1, attrs)
	otelAuthzCheckDuration.Record(context.Background(), time.Since(started).Seconds(), attrs)
	authzCheckRequests.WithLabelValues(decision, result).Inc()
	authzCheckDuration.WithLabelValues(decision, result).Observe(time.Since(started).Seconds())
}

func checkResultForOAuthError(oauthErr *exchange.OAuthError) string {
	if oauthErr.StatusCode >= http.StatusInternalServerError {
		return checkResultSystemError
	}
	return checkResultAuthDenied
}

func mustMetric[T any](instrument T, err error) T {
	if err != nil {
		panic(err)
	}
	return instrument
}
