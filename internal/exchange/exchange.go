// Package exchange implements the OAuth 2.0 token exchange subrequest.
package exchange

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/michaelw/ext-authz-token-exchange/internal/config"
	"github.com/michaelw/ext-authz-token-exchange/internal/policy"
)

const (
	contentTypeForm = "application/x-www-form-urlencoded"
	contentTypeJSON = "application/json"
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
		Transport: &http.Transport{
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
		},
	}
}

// Exchange performs an RFC8693 token exchange request for entry.
func (c *Client) Exchange(ctx context.Context, entry policy.Entry, subjectToken string) (Result, *OAuthError) {
	if err := c.cfg.ValidateTokenEndpoint(entry.TokenEndpoint); err != nil {
		return Result{}, internalError("invalid token endpoint")
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

	if c.cfg.TokenEndpointAuthMethod == config.AuthMethodClientSecretPost {
		form.Set("client_id", c.cfg.ClientID)
		form.Set("client_secret", c.cfg.ClientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, entry.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return Result{}, internalError("failed to create token exchange request")
	}
	req.Header.Set("Content-Type", contentTypeForm)
	req.Header.Set("Accept", contentTypeJSON)
	// RFC6749 Section 2.3.1: client_secret_basic is the required-to-support
	// password authentication method for token endpoints.
	// https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1
	if c.cfg.TokenEndpointAuthMethod == config.AuthMethodClientSecretBasic {
		req.SetBasicAuth(c.cfg.ClientID, c.cfg.ClientSecret)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return Result{}, internalError("token exchange request failed")
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Result{}, internalError("failed to read token exchange response")
	}

	if resp.StatusCode != http.StatusOK {
		return Result{}, c.mapErrorResponse(resp, body)
	}

	var success successResponse
	if err := json.Unmarshal(body, &success); err != nil {
		return Result{}, invalidTokenResponse()
	}
	// RFC8693 Section 2.2.1 requires access_token, issued_token_type, and token_type.
	// https://www.rfc-editor.org/rfc/rfc8693#section-2.2.1
	if success.AccessToken == "" {
		return Result{}, invalidTokenResponse()
	}
	if !strings.EqualFold(success.TokenType, "Bearer") {
		return Result{}, invalidTokenResponse()
	}
	if c.cfg.RequireIssuedTokenType && success.IssuedTokenType != c.cfg.ExpectedIssuedTokenType {
		return Result{}, invalidTokenResponse()
	}
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
		return sanitizedOAuthError(downstreamStatus(resp.StatusCode), parsed.Error, "", wwwAuthenticate)
	}

	switch resp.StatusCode {
	case http.StatusBadRequest:
		return sanitizedOAuthError(http.StatusBadRequest, "invalid_request", "", wwwAuthenticate)
	case http.StatusUnauthorized:
		return sanitizedOAuthError(http.StatusUnauthorized, "invalid_client", "", wwwAuthenticate)
	case http.StatusForbidden:
		return sanitizedOAuthError(http.StatusInternalServerError, "server_error", "internal server error", wwwAuthenticate)
	default:
		return sanitizedOAuthError(http.StatusInternalServerError, "server_error", "internal server error", wwwAuthenticate)
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

func sanitizedOAuthError(status int, errorCode, description string, wwwAuthenticate []string) *OAuthError {
	if description == "" {
		description = fmt.Sprintf("request failed (%s)", diagnosticID())
	}
	return &OAuthError{
		StatusCode:       status,
		Error:            errorCode,
		ErrorDescription: description,
		WWWAuthenticate:  wwwAuthenticate,
	}
}

func invalidTokenResponse() *OAuthError {
	return &OAuthError{
		StatusCode:       http.StatusInternalServerError,
		Error:            "invalid_request",
		ErrorDescription: "internal server error",
	}
}

func internalError(message string) *OAuthError {
	return &OAuthError{
		StatusCode: http.StatusInternalServerError,
		Error:      "server_error",
		Message:    message,
	}
}

func diagnosticID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "unavailable"
	}
	return hex.EncodeToString(b[:])
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
