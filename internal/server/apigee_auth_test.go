package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"
	pb "github.com/michaelw/ext-authz-token-exchange/internal/apigeepb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type calloutTestKeys struct{ key *rsa.PublicKey }

func (k calloutTestKeys) VerifySignature(_ context.Context, raw string) ([]byte, error) {
	token, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return nil, err
	}
	return token.Verify(k.key)
}

func TestApigeeAuthentication(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, nil)
	if err != nil {
		t.Fatal(err)
	}
	sign := func(issuer, audience, subject string, expiry int64) string {
		data, _ := json.Marshal(map[string]any{"iss": issuer, "aud": audience, "sub": subject, "exp": expiry, "iat": time.Now().Add(-time.Minute).Unix()})
		signed, err := signer.Sign(data)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := signed.CompactSerialize()
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	verifier := oidc.NewVerifier("https://accounts.google.com", calloutTestKeys{&key.PublicKey}, &oidc.Config{ClientID: "callout", SupportedSigningAlgs: []string{"RS256"}})
	auth := ApigeeAuthentication(verifier, []string{"12345"})
	for _, tc := range []struct {
		name, issuer, audience, subject string
		expiry                          int64
		want                            codes.Code
	}{
		{"valid", "https://accounts.google.com", "callout", "12345", time.Now().Add(time.Minute).Unix(), codes.OK},
		{"issuer", "https://evil.example", "callout", "12345", time.Now().Add(time.Minute).Unix(), codes.Unauthenticated},
		{"audience", "https://accounts.google.com", "other", "12345", time.Now().Add(time.Minute).Unix(), codes.Unauthenticated},
		{"identity", "https://accounts.google.com", "callout", "other", time.Now().Add(time.Minute).Unix(), codes.Unauthenticated},
		{"expired", "https://accounts.google.com", "callout", "12345", time.Now().Add(-time.Hour).Unix(), codes.Unauthenticated},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+sign(tc.issuer, tc.audience, tc.subject, tc.expiry)))
			called := false
			_, err := auth(ctx, nil, &grpc.UnaryServerInfo{FullMethod: ApigeeProcessMethod}, func(context.Context, any) (any, error) { called = true; return nil, nil })
			if status.Code(err) != tc.want || called != (tc.want == codes.OK) {
				t.Fatalf("code=%v called=%v", status.Code(err), called)
			}
		})
	}
	for _, md := range []metadata.MD{nil, metadata.Pairs("authorization", "Bearer malformed"), metadata.Pairs("authorization", "Bearer one", "authorization", "Bearer two")} {
		_, err := auth(metadata.NewIncomingContext(context.Background(), md), nil, &grpc.UnaryServerInfo{FullMethod: ApigeeProcessMethod}, func(context.Context, any) (any, error) { return nil, fmt.Errorf("must not run") })
		if status.Code(err) != codes.Unauthenticated {
			t.Fatal(err)
		}
	}
}

func TestApigeeInspectionDoesNotExposeValues(t *testing.T) {
	// Existing logging test helpers capture the shared logger without network I/O.
	var output strings.Builder
	previous := customLogger.Writer()
	customLogger.SetOutput(&output)
	defer customLogger.SetOutput(previous)
	m := &pb.MessageContext{MessageId: "id", Request: &pb.Request{Uri: "/secret?token=QUERY_SECRET", Content: "BODY_SECRET", Headers: map[string]*pb.Strings{"Authorization": {Strings: []string{"Bearer TOKEN_SECRET"}}, "cookie": {Strings: []string{"COOKIE_SECRET"}}}}, AdditionalFlowVariables: map[string]*pb.FlowVariable{"arbitrary": apigeeStringVariable("VARIABLE_SECRET")}}
	m.AdditionalFlowVariables["txe.input.path"] = apigeeStringVariable("/safe?token=QUERY_SECRET")
	(&ApigeeGRPCServer{}).inspectMessage("request", m)
	for _, secret := range []string{"QUERY_SECRET", "BODY_SECRET", "TOKEN_SECRET", "COOKIE_SECRET", "VARIABLE_SECRET"} {
		if strings.Contains(output.String(), secret) {
			t.Fatalf("inspection leaked %s", secret)
		}
	}
	if !strings.Contains(output.String(), "header_value_counts") {
		t.Fatal("missing message shape")
	}
}
