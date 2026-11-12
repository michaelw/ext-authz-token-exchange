package server

import (
	"context"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// GoogleCalloutVerifier uses Google's signing keys and verifies issuer, expiry,
// signature and audience. Use the service account's immutable numeric subject ID.
func GoogleCalloutVerifier(ctx context.Context, audience string) *oidc.IDTokenVerifier {
	return oidc.NewVerifier("https://accounts.google.com", oidc.NewRemoteKeySet(ctx, "https://www.googleapis.com/oauth2/v3/certs"), &oidc.Config{ClientID: audience, SupportedSigningAlgs: []string{"RS256"}})
}

func ApigeeAuthentication(verifier *oidc.IDTokenVerifier, subjects []string) grpc.UnaryServerInterceptor {
	allowed := map[string]bool{}
	for _, subject := range subjects {
		if subject != "" {
			allowed[subject] = true
		}
	}
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		md, _ := metadata.FromIncomingContext(ctx)
		values := md.Get("authorization")
		if info.FullMethod != ApigeeProcessMethod || len(values) != 1 {
			return nil, status.Error(codes.Unauthenticated, "callout authentication required")
		}
		parts := strings.Fields(values[0])
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			return nil, status.Error(codes.Unauthenticated, "callout authentication required")
		}
		token, err := verifier.Verify(ctx, parts[1])
		if err != nil || token.Subject == "" || !allowed[token.Subject] {
			return nil, status.Error(codes.Unauthenticated, "invalid callout identity")
		}
		return handler(ctx, req)
	}
}
