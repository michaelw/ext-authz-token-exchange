package main

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	responseSuccess              = "success"
	responseOAuthError           = "oauth_error"
	responseJSONError            = "json_error"
	responseMalformed            = "malformed"
	responseMissingAccessToken   = "missing_access_token"
	responseWrongTokenType       = "wrong_token_type"
	responseWrongIssuedTokenType = "wrong_issued_token_type"
	responseDelay                = "delay"
)

type fakeConfig struct {
	Routes          []fakeRoute  `yaml:"routes"`
	DefaultResponse fakeResponse `yaml:"defaultResponse"`
}

type fakeRoute struct {
	Name     string       `yaml:"name"`
	Match    fakeMatch    `yaml:"match"`
	Response fakeResponse `yaml:"response"`
}

type fakeMatch struct {
	Path     string `yaml:"path"`
	Scope    string `yaml:"scope"`
	Resource string `yaml:"resource"`
	Audience string `yaml:"audience"`
}

type fakeResponse struct {
	Type              string `yaml:"type"`
	Scenario          string `yaml:"scenario"`
	Status            int    `yaml:"status"`
	Error             string `yaml:"error"`
	ErrorDescription  string `yaml:"errorDescription"`
	WWWAuthenticate   string `yaml:"wwwAuthenticate"`
	DelayMilliseconds int    `yaml:"delayMilliseconds"`
}

func loadFakeConfig(path string) (fakeConfig, error) {
	if strings.TrimSpace(path) == "" {
		cfg := defaultFakeConfig()
		return cfg, (&cfg).validate()
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fakeConfig{}, fmt.Errorf("read fake token endpoint config %q: %w", path, err)
	}
	var cfg fakeConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return fakeConfig{}, fmt.Errorf("parse fake token endpoint config %q: %w", path, err)
	}
	if err := (&cfg).validate(); err != nil {
		return fakeConfig{}, fmt.Errorf("validate fake token endpoint config %q: %w", path, err)
	}
	return cfg, nil
}

func (cfg *fakeConfig) validate() error {
	if len(cfg.Routes) == 0 {
		return fmt.Errorf("routes must not be empty")
	}
	seen := map[string]struct{}{}
	for i := range cfg.Routes {
		route := &cfg.Routes[i]
		route.Name = strings.TrimSpace(route.Name)
		route.Match.normalize()
		if route.Name == "" {
			return fmt.Errorf("routes[%d].name must not be empty", i)
		}
		if _, ok := seen[route.Name]; ok {
			return fmt.Errorf("duplicate route name %q", route.Name)
		}
		seen[route.Name] = struct{}{}
		if route.Match.empty() {
			return fmt.Errorf("route %q must configure at least one match field", route.Name)
		}
		if err := route.Response.validate(route.Name); err != nil {
			return fmt.Errorf("route %q: %w", route.Name, err)
		}
	}
	if cfg.DefaultResponse.Type == "" && cfg.DefaultResponse.Error == "" {
		cfg.DefaultResponse = defaultUnknownResponse()
	} else if cfg.DefaultResponse.Type == "" {
		cfg.DefaultResponse.Type = responseOAuthError
	}
	return cfg.DefaultResponse.validate("defaultResponse")
}

func (match fakeMatch) empty() bool {
	return match.Path == "" &&
		match.Scope == "" &&
		match.Resource == "" &&
		match.Audience == ""
}

func (match *fakeMatch) normalize() {
	match.Path = strings.TrimSpace(match.Path)
	match.Scope = strings.TrimSpace(match.Scope)
	match.Resource = strings.TrimSpace(match.Resource)
	match.Audience = strings.TrimSpace(match.Audience)
}

func (response *fakeResponse) validate(name string) error {
	response.Type = strings.TrimSpace(response.Type)
	response.Scenario = strings.TrimSpace(response.Scenario)
	response.Error = strings.TrimSpace(response.Error)
	response.ErrorDescription = strings.TrimSpace(response.ErrorDescription)
	response.WWWAuthenticate = strings.TrimSpace(response.WWWAuthenticate)
	if response.Status != 0 && (response.Status < 100 || response.Status > 599) {
		return fmt.Errorf("%s response status must be between 100 and 599", name)
	}
	if response.DelayMilliseconds < 0 {
		return fmt.Errorf("%s response delayMilliseconds must not be negative", name)
	}
	switch response.Type {
	case responseSuccess, responseDelay:
		return nil
	case responseOAuthError, responseJSONError:
		if strings.TrimSpace(response.Error) == "" {
			return fmt.Errorf("%s response requires error", name)
		}
		return nil
	case responseMalformed, responseMissingAccessToken, responseWrongTokenType, responseWrongIssuedTokenType:
		return nil
	default:
		return fmt.Errorf("%s response has unknown type %q", name, response.Type)
	}
}

func (cfg fakeConfig) routeFor(r *http.Request) fakeRoute {
	for _, route := range cfg.Routes {
		if route.Match.matches(r) {
			return route
		}
	}
	return fakeRoute{Name: "default", Response: cfg.DefaultResponse}
}

func (match fakeMatch) matches(r *http.Request) bool {
	if path := strings.TrimSpace(match.Path); path != "" && r.URL.Path != path {
		return false
	}
	if scope := strings.TrimSpace(match.Scope); scope != "" && strings.TrimSpace(r.FormValue("scope")) != scope {
		return false
	}
	if resource := strings.TrimSpace(match.Resource); resource != "" && !formValuesContain(r.Form["resource"], resource) {
		return false
	}
	if audience := strings.TrimSpace(match.Audience); audience != "" && !formValuesContain(r.Form["audience"], audience) {
		return false
	}
	return true
}

func formValuesContain(values []string, want string) bool {
	for _, value := range compactFormValues(values) {
		if value == want {
			return true
		}
	}
	return false
}

func (route fakeRoute) scenario() string {
	scenario := strings.TrimSpace(route.Response.Scenario)
	if scenario != "" {
		return scenario
	}
	if strings.TrimSpace(route.Response.Type) == responseSuccess || strings.TrimSpace(route.Response.Type) == responseDelay {
		return strings.TrimSpace(route.Name)
	}
	return ""
}

func defaultFakeConfig() fakeConfig {
	return fakeConfig{
		Routes: []fakeRoute{
			successPathRoute("yellow"),
			successPathRoute("red"),
			successPathRoute("blue"),
			oauthErrorPathRoute("invalid-request", http.StatusBadRequest, "invalid_request", "invalid token exchange request"),
			oauthErrorPathRoute("invalid-target", http.StatusBadRequest, "invalid_target", "resource or audience is invalid"),
			oauthErrorPathRoute("invalid-grant", http.StatusBadRequest, "invalid_grant", "subject token is invalid"),
			oauthErrorPathRoute("expired-subject-token", http.StatusBadRequest, "invalid_grant", "subject_token_expired"),
			{
				Name:  "unauthorized",
				Match: fakeMatch{Path: "/token/unauthorized"},
				Response: fakeResponse{
					Type:             responseOAuthError,
					Status:           http.StatusUnauthorized,
					Error:            "invalid_client",
					ErrorDescription: "client rejected",
					WWWAuthenticate:  `Bearer realm="issuer", error="invalid_token"`,
				},
			},
			oauthErrorPathRoute("forbidden", http.StatusForbidden, "invalid_target", "target rejected"),
			jsonErrorPathRoute("server-error", http.StatusInternalServerError, "temporarily_unavailable"),
			typedPathRoute("malformed", responseMalformed),
			typedPathRoute("missing-access-token", responseMissingAccessToken),
			typedPathRoute("wrong-token-type", responseWrongTokenType),
			typedPathRoute("wrong-issued-token-type", responseWrongIssuedTokenType),
			typedPathRoute("delay", responseDelay),
			oauthErrorResourceRoute("resource-invalid-target", "https://httpbin.int.kube/anything/error-invalid-target", "invalid_target", "resource or audience is invalid"),
			oauthErrorResourceRoute("resource-invalid-grant", "https://httpbin.int.kube/anything/error-invalid-grant", "invalid_grant", "subject token is invalid"),
			oauthErrorResourceRoute("resource-expired-subject-token", "https://httpbin.int.kube/anything/error-expired-subject-token", "invalid_grant", "subject_token_expired"),
			successAudienceRoute("yellow", "httpbin-yellow"),
			successAudienceRoute("red", "httpbin-red"),
			successAudienceRoute("blue", "httpbin-blue"),
			successResourceRoute("resource-yellow", "yellow", "https://httpbin.int.kube/anything/yellow"),
			successResourceRoute("resource-red", "red", "https://httpbin.int.kube/anything/red"),
			successResourceRoute("resource-blue", "blue", "https://httpbin.int.kube/anything/blue"),
			successScopeRoute("scope-yellow", "yellow", "yellow"),
			successScopeRoute("scope-red", "red", "red"),
			successScopeRoute("scope-blue", "blue", "blue"),
			{
				Name:     "success",
				Match:    fakeMatch{Path: "/token/success"},
				Response: fakeResponse{Type: responseSuccess, Scenario: "success"},
			},
		},
		DefaultResponse: fakeResponse{
			Type:             defaultUnknownResponse().Type,
			Status:           defaultUnknownResponse().Status,
			Error:            defaultUnknownResponse().Error,
			ErrorDescription: defaultUnknownResponse().ErrorDescription,
		},
	}
}

func defaultUnknownResponse() fakeResponse {
	return fakeResponse{
		Type:             responseOAuthError,
		Status:           http.StatusBadRequest,
		Error:            "invalid_request",
		ErrorDescription: "unknown fake token scenario",
	}
}

func successPathRoute(scenario string) fakeRoute {
	return fakeRoute{
		Name:     scenario,
		Match:    fakeMatch{Path: "/token/" + scenario},
		Response: fakeResponse{Type: responseSuccess, Scenario: scenario},
	}
}

func successAudienceRoute(name, audience string) fakeRoute {
	return fakeRoute{
		Name:     "audience-" + name,
		Match:    fakeMatch{Audience: audience},
		Response: fakeResponse{Type: responseSuccess, Scenario: name},
	}
}

func successResourceRoute(name, scenario, resource string) fakeRoute {
	return fakeRoute{
		Name:     name,
		Match:    fakeMatch{Resource: resource},
		Response: fakeResponse{Type: responseSuccess, Scenario: scenario},
	}
}

func successScopeRoute(name, scenario, scope string) fakeRoute {
	return fakeRoute{
		Name:     name,
		Match:    fakeMatch{Scope: scope},
		Response: fakeResponse{Type: responseSuccess, Scenario: scenario},
	}
}

func oauthErrorPathRoute(name string, status int, code, description string) fakeRoute {
	return fakeRoute{
		Name:  name,
		Match: fakeMatch{Path: "/token/" + name},
		Response: fakeResponse{
			Type:             responseOAuthError,
			Status:           status,
			Error:            code,
			ErrorDescription: description,
		},
	}
}

func oauthErrorResourceRoute(name, resource, code, description string) fakeRoute {
	return fakeRoute{
		Name:  name,
		Match: fakeMatch{Resource: resource},
		Response: fakeResponse{
			Type:             responseOAuthError,
			Status:           http.StatusBadRequest,
			Error:            code,
			ErrorDescription: description,
		},
	}
}

func jsonErrorPathRoute(name string, status int, code string) fakeRoute {
	return fakeRoute{
		Name:  name,
		Match: fakeMatch{Path: "/token/" + name},
		Response: fakeResponse{
			Type:   responseJSONError,
			Status: status,
			Error:  code,
		},
	}
}

func typedPathRoute(name, responseType string) fakeRoute {
	return fakeRoute{
		Name:     name,
		Match:    fakeMatch{Path: "/token/" + name},
		Response: fakeResponse{Type: responseType, Scenario: name},
	}
}
