package server

import (
	"context"

	envoy_service_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	envoy_type_v3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	grpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
)

// AuthzGRPCServer implements the Envoy external authorization gRPC service
type AuthzGRPCServer struct {
	envoy_service_auth_v3.UnimplementedAuthorizationServer
}

// NewAuthzGRPCServer creates a new gRPC authorization server
func NewAuthzGRPCServer() *AuthzGRPCServer {
	return &AuthzGRPCServer{}
}

// Check implements the authorization check
func (s *AuthzGRPCServer) Check(ctx context.Context, req *envoy_service_auth_v3.CheckRequest) (*envoy_service_auth_v3.CheckResponse, error) {
	return s.denyResponse(codes.Unimplemented, "authorization logic is not implemented"), nil
}

// denyResponse creates a denial response
func (s *AuthzGRPCServer) denyResponse(code codes.Code, message string) *envoy_service_auth_v3.CheckResponse {
	return &envoy_service_auth_v3.CheckResponse{
		Status: &grpcstatus.Status{
			Code:    int32(code),
			Message: message,
		},
		HttpResponse: &envoy_service_auth_v3.CheckResponse_DeniedResponse{
			DeniedResponse: &envoy_service_auth_v3.DeniedHttpResponse{
				Status: &envoy_type_v3.HttpStatus{Code: envoy_type_v3.StatusCode_Forbidden},
				Body:   message,
			},
		},
	}
}
