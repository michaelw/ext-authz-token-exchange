// Package exchange implements the OAuth 2.0 token exchange subrequest.
package exchange

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/michaelw/ext-authz-token-exchange/internal/config"
	"github.com/michaelw/ext-authz-token-exchange/internal/policy"
	"github.com/michaelw/ext-authz-token-exchange/internal/telemetry"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const (
	contentTypeForm = "application/x-www-form-urlencoded"
	contentTypeJSON = "application/json"
)

const (
	metricResultSuccess = "success"
	metricResultFailure = "failure"
	metricStatusNone    = "none"
)

var (
	meter                                 = otel.Meter("github.com/michaelw/ext-authz-token-exchange/internal/exchange")
	otelTokenEndpointRequests             = must(meter.Int64Counter("ext_authz_token_exchange_requests_total"))
	otelTokenEndpointTimeouts             = must(meter.Int64Counter("ext_authz_token_exchange_timeouts_total"))
	otelTokenEndpointContextCancellations = must(meter.Int64Counter("ext_authz_token_exchange_context_cancellations_total"))
	otelTokenEndpointInFlight             = must(meter.Int64UpDownCounter("ext_authz_token_exchange_in_flight"))
	otelTokenEndpointLatency              = must(meter.Float64Histogram("ext_authz_token_exchange_latency_seconds", metric.WithExplicitBucketBoundaries(0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1, 2.5, 5)))
	tokenEndpointRequests                 = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ext_authz_token_exchange_requests_total",
		Help: "Total token endpoint exchange attempts by endpoint host, result, error kind, and HTTP status class.",
	}, []string{"endpoint_host", "result", "error_kind", "http_status_class"})
	tokenEndpointTimeouts = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ext_authz_token_exchange_timeouts_total",
		Help: "Total token endpoint exchange attempts that failed because the token endpoint request timed out.",
	}, []string{"endpoint_host"})
	tokenEndpointContextCancellations = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ext_authz_token_exchange_context_cancellations_total",
		Help: "Total token endpoint exchange attempts that failed because the incoming context was canceled.",
	}, []string{"endpoint_host"})
	tokenEndpointInFlight = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ext_authz_token_exchange_in_flight",
		Help: "Token endpoint exchange requests currently in flight.",
	}, []string{"endpoint_host"})
	tokenEndpointLatency = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "ext_authz_token_exchange_latency_seconds",
		Help:    "Token endpoint exchange latency by endpoint host, result, error kind, and HTTP status class.",
		Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1, 2.5, 5},
	}, []string{"endpoint_host", "result", "error_kind", "http_status_class"})
)

const (
	// Diagnostic codes are stable grep-able operational markers. Allocate new
	// codes intentionally; do not derive them from file names, line numbers, or
	// generated/random values.
	diagInvalidTokenEndpoint       = "TXE-1001"
	diagCreateExchangeRequest      = "TXE-1002"
	diagExchangeRequestFailed      = "TXE-1003"
	diagReadExchangeResponseFailed = "TXE-1004"
	diagUnknownIssuerProfile       = "TXE-1005"

	diagRecognizedOAuthError = "TXE-2001"
	diagNonOAuthBadRequest   = "TXE-2002"
	diagNonOAuthUnauthorized = "TXE-2003"
	diagForbiddenFailure     = "TXE-2004"
	diagOtherNonOKFailure    = "TXE-2005"

	diagMalformedSuccessJSON = "TXE-3001"
	diagMissingAccessToken   = "TXE-3002"
	diagNonBearerTokenType   = "TXE-3003"
	diagWrongIssuedTokenType = "TXE-3004"
)

// Client exchanges incoming subject tokens for upstream bearer tokens.
type Client struct {
	cfg        config.RuntimeConfig
	httpClient *http.Client
}

// Result contains a successfully exchanged bearer token.
type Result struct {
	AccessToken string
}

// OAuthError is a sanitized error response suitable for downstream clients.
type OAuthError struct {
	StatusCode       int
	Error            string
	ErrorDescription string
	Message          string
	Body             string
	WWWAuthenticate  []string
}

// NewClient returns a token exchange client.
func NewClient(cfg config.RuntimeConfig, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = NewHTTPClient(cfg)
	}
	return &Client{cfg: cfg, httpClient: httpClient}
}

// NewHTTPClient returns an HTTP client with bounded token-endpoint timeouts and
// connection pooling. The transport keeps TLS verification enabled and avoids
// the unbounded defaults from http.DefaultClient.
func NewHTTPClient(cfg config.RuntimeConfig) *http.Client {
	return &http.Client{
		Timeout: durationDefault(cfg.TokenEndpointRequestTimeout, 5*time.Second),
		Transport: otelhttp.NewTransport(
			NewHTTPTransport(cfg),
			otelhttp.WithPropagators(telemetry.Propagators()),
			otelhttp.WithTracerProvider(otel.GetTracerProvider()),
		),
	}
}

// NewHTTPTransport returns the bounded base transport used by NewHTTPClient.
func NewHTTPTransport(cfg config.RuntimeConfig) *http.Transport {
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   durationDefault(cfg.TokenEndpointDialTimeout, 3*time.Second),
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   durationDefault(cfg.TokenEndpointTLSHandshakeTimeout, 3*time.Second),
		ResponseHeaderTimeout: durationDefault(cfg.TokenEndpointResponseHeaderTimeout, 5*time.Second),
		ExpectContinueTimeout: 1 * time.Second,
		IdleConnTimeout:       durationDefault(cfg.TokenEndpointIdleConnTimeout, 90*time.Second),
		MaxIdleConns:          intDefault(cfg.TokenEndpointMaxIdleConns, 100),
		MaxIdleConnsPerHost:   intDefault(cfg.TokenEndpointMaxIdleConnsPerHost, 10),
	}
}

// Exchange performs an RFC8693 token exchange request for entry.
func (c *Client) Exchange(ctx context.Context, entry policy.Entry, subjectToken string) (Result, *OAuthError) {
	started := time.Now()
	issuer, ok := c.cfg.IssuerProfile(entry.IssuerRef)
	if !ok {
		recordExchangeMetrics(started, "unknown", metricResultFailure, "unknown_issuer_profile", metricStatusNone)
		return Result{}, internalError("unknown issuer profile", diagUnknownIssuerProfile)
	}
	authMethod := strings.TrimSpace(issuer.TokenEndpointAuthMethod)
	if authMethod == "" {
		authMethod = c.cfg.TokenEndpointAuthMethod
	}
	endpointHost := tokenEndpointHost(issuer.TokenEndpoint)
	otelTokenEndpointInFlight.Add(ctx, 1, metric.WithAttributes(attribute.String("endpoint_host", endpointHost)))
	defer otelTokenEndpointInFlight.Add(ctx, -1, metric.WithAttributes(attribute.String("endpoint_host", endpointHost)))
	tokenEndpointInFlight.WithLabelValues(endpointHost).Inc()
	defer tokenEndpointInFlight.WithLabelValues(endpointHost).Dec()
	if err := c.cfg.ValidateTokenEndpoint(issuer.TokenEndpoint); err != nil {
		recordExchangeMetrics(started, endpointHost, metricResultFailure, "invalid_token_endpoint", metricStatusNone)
		return Result{}, internalError("invalid token endpoint", diagInvalidTokenEndpoint)
	}

	form := url.Values{}
	// RFC8693 Section 2.1 defines token exchange request parameters.
	// https://www.rfc-editor.org/rfc/rfc8693#section-2.1
	form.Set("grant_type", c.cfg.GrantType)
	form.Set("subject_token", subjectToken)
	form.Set("subject_token_type", c.cfg.SubjectTokenType)
	if entry.Scope != "" {
		form.Set("scope", entry.Scope)
	}
	for _, resource := range entry.Resources {
		form.Add("resource", resource)
	}
	for _, audience := range entry.Audiences {
		form.Add("audience", audience)
	}

	if authMethod == config.AuthMethodClientSecretPost {
		form.Set("client_id", issuer.ClientID)
		form.Set("client_secret", issuer.ClientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, issuer.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		recordExchangeMetrics(started, endpointHost, metricResultFailure, "create_request", metricStatusNone)
		return Result{}, internalError("failed to create token exchange request", diagCreateExchangeRequest)
	}
	req.Header.Set("Content-Type", contentTypeForm)
	req.Header.Set("Accept", contentTypeJSON)
	// RFC6749 Section 2.3.1: client_secret_basic is the required-to-support
	// password authentication method for token endpoints.
	// https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1
	if authMethod == config.AuthMethodClientSecretBasic {
		req.SetBasicAuth(issuer.ClientID, issuer.ClientSecret)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		errorKind := exchangeRequestErrorKind(ctx, err)
		recordExchangeMetrics(started, endpointHost, metricResultFailure, errorKind, metricStatusNone)
		return Result{}, internalError("token exchange request failed", diagExchangeRequestFailed)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		recordExchangeMetrics(started, endpointHost, metricResultFailure, "read_response", statusClass(resp.StatusCode))
		return Result{}, internalError("failed to read token exchange response", diagReadExchangeResponseFailed)
	}

	if resp.StatusCode != http.StatusOK {
		recordExchangeMetrics(started, endpointHost, metricResultFailure, "http_status", statusClass(resp.StatusCode))
		return Result{}, c.mapErrorResponse(resp, body)
	}

	var success successResponse
	if err := json.Unmarshal(body, &success); err != nil {
		recordExchangeMetrics(started, endpointHost, metricResultFailure, "malformed_success_json", statusClass(resp.StatusCode))
		return Result{}, invalidTokenResponse(diagMalformedSuccessJSON)
	}
	// RFC8693 Section 2.2.1 requires access_token, issued_token_type, and token_type.
	// https://www.rfc-editor.org/rfc/rfc8693#section-2.2.1
	if success.AccessToken == "" {
		recordExchangeMetrics(started, endpointHost, metricResultFailure, "missing_access_token", statusClass(resp.StatusCode))
		return Result{}, invalidTokenResponse(diagMissingAccessToken)
	}
	if !strings.EqualFold(success.TokenType, "Bearer") {
		recordExchangeMetrics(started, endpointHost, metricResultFailure, "non_bearer_token_type", statusClass(resp.StatusCode))
		return Result{}, invalidTokenResponse(diagNonBearerTokenType)
	}
	if c.cfg.RequireIssuedTokenType && success.IssuedTokenType != c.cfg.ExpectedIssuedTokenType {
		recordExchangeMetrics(started, endpointHost, metricResultFailure, "wrong_issued_token_type", statusClass(resp.StatusCode))
		return Result{}, invalidTokenResponse(diagWrongIssuedTokenType)
	}
	recordExchangeMetrics(started, endpointHost, metricResultSuccess, "none", statusClass(resp.StatusCode))
	return Result{AccessToken: success.AccessToken}, nil
}

func (c *Client) mapErrorResponse(resp *http.Response, body []byte) *OAuthError {
	// RFC6749 Section 5.2 defines token endpoint error responses.
	// https://www.rfc-editor.org/rfc/rfc6749#section-5.2
	//
	// RFC8693 Section 2.2.2 says invalid subject_token cases use
	// invalid_request, and adds invalid_target for resource/audience failures.
	// https://www.rfc-editor.org/rfc/rfc8693#section-2.2.2
	//
	// Compatibility note: RFC6749 invalid_grant includes expired/revoked grants.
	// We preserve recognized AS errors such as invalid_grant, while sanitizing
	// descriptions unless TOKEN_EXCHANGE_ERROR_PASSTHROUGH is enabled.
	parsed, valid := parseOAuthError(body)
	wwwAuthenticate := resp.Header.Values("WWW-Authenticate")
	if valid && c.cfg.ErrorPassthrough {
		return &OAuthError{
			StatusCode:       downstreamStatus(resp.StatusCode),
			Error:            parsed.Error,
			ErrorDescription: parsed.ErrorDescription,
			Body:             string(body),
			WWWAuthenticate:  wwwAuthenticate,
		}
	}
	if valid {
		return sanitizedOAuthError(downstreamStatus(resp.StatusCode), parsed.Error, "", diagRecognizedOAuthError, wwwAuthenticate)
	}

	switch resp.StatusCode {
	case http.StatusBadRequest:
		return sanitizedOAuthError(http.StatusBadRequest, "invalid_request", "", diagNonOAuthBadRequest, wwwAuthenticate)
	case http.StatusUnauthorized:
		return sanitizedOAuthError(http.StatusUnauthorized, "invalid_client", "", diagNonOAuthUnauthorized, wwwAuthenticate)
	case http.StatusForbidden:
		return sanitizedOAuthError(http.StatusInternalServerError, "server_error", "internal server error", diagForbiddenFailure, wwwAuthenticate)
	default:
		return sanitizedOAuthError(http.StatusInternalServerError, "server_error", "internal server error", diagOtherNonOKFailure, wwwAuthenticate)
	}
}

type successResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
}

type oauthErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func parseOAuthError(body []byte) (oauthErrorResponse, bool) {
	var parsed oauthErrorResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return parsed, false
	}
	if parsed.Error == "" || !recognizedOAuthError(parsed.Error) {
		return parsed, false
	}
	return parsed, true
}

func recognizedOAuthError(errorCode string) bool {
	switch errorCode {
	case "invalid_request", "invalid_client", "invalid_grant", "unauthorized_client",
		"unsupported_grant_type", "invalid_scope", "invalid_target":
		return true
	default:
		return false
	}
}

func downstreamStatus(upstream int) int {
	switch upstream {
	case http.StatusBadRequest:
		return http.StatusBadRequest
	case http.StatusUnauthorized:
		return http.StatusUnauthorized
	case http.StatusForbidden:
		return http.StatusInternalServerError
	default:
		return http.StatusInternalServerError
	}
}

func sanitizedOAuthError(status int, errorCode, description, diagnosticCode string, wwwAuthenticate []string) *OAuthError {
	if description == "" {
		description = "request failed"
	}
	if diagnosticCode != "" {
		description = fmt.Sprintf("%s (%s)", description, diagnosticCode)
	}
	return &OAuthError{
		StatusCode:       status,
		Error:            errorCode,
		ErrorDescription: description,
		WWWAuthenticate:  wwwAuthenticate,
	}
}

func invalidTokenResponse(diagnosticCode string) *OAuthError {
	return &OAuthError{
		StatusCode:       http.StatusInternalServerError,
		Error:            "invalid_request",
		ErrorDescription: fmt.Sprintf("internal server error (%s)", diagnosticCode),
	}
}

func internalError(message, diagnosticCode string) *OAuthError {
	return &OAuthError{
		StatusCode: http.StatusInternalServerError,
		Error:      "server_error",
		Message:    fmt.Sprintf("%s (%s)", message, diagnosticCode),
	}
}

func durationDefault(value, fallback time.Duration) time.Duration {
	if value > 0 {
		return value
	}
	return fallback
}

func intDefault(value, fallback int) int {
	if value > 0 {
		return value
	}
	return fallback
}

func recordExchangeMetrics(started time.Time, endpointHost, result, errorKind, httpStatusClass string) {
	attrs := metric.WithAttributes(
		attribute.String("endpoint_host", endpointHost),
		attribute.String("result", result),
		attribute.String("error_kind", errorKind),
		attribute.String("http_status_class", httpStatusClass),
	)
	otelTokenEndpointRequests.Add(context.Background(), 1, attrs)
	tokenEndpointRequests.WithLabelValues(endpointHost, result, errorKind, httpStatusClass).Inc()
	if errorKind == "timeout" {
		otelTokenEndpointTimeouts.Add(context.Background(), 1, metric.WithAttributes(attribute.String("endpoint_host", endpointHost)))
		tokenEndpointTimeouts.WithLabelValues(endpointHost).Inc()
	}
	if errorKind == "context_canceled" {
		otelTokenEndpointContextCancellations.Add(context.Background(), 1, metric.WithAttributes(attribute.String("endpoint_host", endpointHost)))
		tokenEndpointContextCancellations.WithLabelValues(endpointHost).Inc()
	}
	otelTokenEndpointLatency.Record(context.Background(), time.Since(started).Seconds(), attrs)
	tokenEndpointLatency.WithLabelValues(endpointHost, result, errorKind, httpStatusClass).Observe(time.Since(started).Seconds())
}

func must[T any](instrument T, err error) T {
	if err != nil {
		panic(err)
	}
	return instrument
}

func exchangeRequestErrorKind(ctx context.Context, err error) string {
	if errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
		return "context_canceled"
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return "timeout"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}
	return "transport_error"
}

func statusClass(status int) string {
	if status <= 0 {
		return metricStatusNone
	}
	return fmt.Sprintf("%dxx", status/100)
}

func tokenEndpointHost(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return "invalid"
	}
	if host := u.Hostname(); host != "" {
		return strings.ToLower(host)
	}
	return "invalid"
}
