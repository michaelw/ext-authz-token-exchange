package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_service_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	envoy_type_v3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/michaelw/ext-authz-token-exchange/internal/config"
	"github.com/michaelw/ext-authz-token-exchange/internal/exchange"
	"github.com/michaelw/ext-authz-token-exchange/internal/policy"
	grpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/wrapperspb"
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

// Check implements the Envoy external authorization check.
func (s *AuthzGRPCServer) Check(ctx context.Context, req *envoy_service_auth_v3.CheckRequest) (*envoy_service_auth_v3.CheckResponse, error) {
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
	if shouldBypassOptions(method, headers, s.cfg.AllowUnauthenticatedOptions, hasBearerToken) {
		return allowResponse(nil), nil
	}

	host := header(headers, ":authority")
	if host == "" {
		host = header(headers, "host")
	}
	if host == "" {
		host = httpReq.GetHost()
	}

	decision := s.store.Index().Match(host, httpReq.GetPath(), method)
	if !decision.Matched {
		return allowResponse(nil), nil
	}
	if decision.Unhealthy {
		return s.denyJSON(http.StatusInternalServerError, map[string]string{
			"error":             "server_error",
			"error_description": "internal server error",
		}, nil), nil
	}

	if !hasBearerToken {
		// RFC6750 Section 3 defines Bearer challenges for protected resources.
		// https://www.rfc-editor.org/rfc/rfc6750#section-3
		return s.denyJSON(http.StatusUnauthorized, map[string]string{
			"error": "bearer_token_required",
		}, []headerPair{{Name: "WWW-Authenticate", Value: bearerChallenge(s.cfg.BearerRealm, decision.Entry.Scope)}}), nil
	}

	result, oauthErr := s.exchanger.Exchange(ctx, decision.Entry, subjectToken)
	if oauthErr != nil {
		return s.oauthDeny(oauthErr), nil
	}
	s.logTokensIfInsecureEnabled(method, host, httpReq.GetPath(), decision.Entry, subjectToken, result.AccessToken)
	return allowResponse([]headerPair{{Name: "authorization", Value: "Bearer " + result.AccessToken}}), nil
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
