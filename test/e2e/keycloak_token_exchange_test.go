package e2e_test

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("keycloak token exchange", Ordered, func() {
	BeforeEach(func() {
		if env.issuer != keycloakIssuer {
			Skip("Keycloak scenarios run only when E2E_ISSUER=keycloak")
		}
	})

	It("exchanges a Keycloak subject token for a signed audience token", func(ctx SpecContext) {
		subjectToken := fetchKeycloakSubjectToken(ctx)

		Eventually(func(g Gomega) {
			resp, body := request(ctx, http.MethodGet, "/anything/keycloak-audience", subjectToken, nil)
			g.Expect(resp.StatusCode).To(Equal(http.StatusOK), string(body))
			claims := verifyKeycloakJWT(ctx, g, headerFromHTTPBin(body, "Authorization"))
			g.Expect(claims).To(HaveKeyWithValue("iss", env.keycloakIssuerURL))
			g.Expect(claims).To(HaveKeyWithValue("azp", env.keycloakClientID))
			g.Expect(claims).To(HaveKeyWithValue("typ", "Bearer"))
			g.Expect(claims["sub"]).To(BeAssignableToTypeOf(""))
			g.Expect(scopeClaim(claims)).To(ContainElement("profile"))
			g.Expect(audienceClaim(claims)).To(ContainElement(env.audienceClientID))
		}, 45*time.Second, time.Second).Should(Succeed())
	})

	It("exchanges a Keycloak subject token when resource is configured separately", func(ctx SpecContext) {
		subjectToken := fetchKeycloakSubjectToken(ctx)

		Eventually(func(g Gomega) {
			resp, body := request(ctx, http.MethodGet, "/anything/keycloak-resource", subjectToken, nil)
			g.Expect(resp.StatusCode).To(Equal(http.StatusOK), string(body))
			claims := verifyKeycloakJWT(ctx, g, headerFromHTTPBin(body, "Authorization"))
			g.Expect(claims).To(HaveKeyWithValue("iss", env.keycloakIssuerURL))
			g.Expect(claims).To(HaveKeyWithValue("azp", env.keycloakClientID))
			g.Expect(scopeClaim(claims)).To(ContainElement("profile"))
			g.Expect(audienceClaim(claims)).To(ContainElement(env.audienceClientID))
		}, 45*time.Second, time.Second).Should(Succeed())
	})
})

func fetchKeycloakSubjectToken(ctx context.Context) string {
	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("client_id", env.subjectClientID)
	form.Set("client_secret", env.subjectClientSecret)
	form.Set("username", env.keycloakUser)
	form.Set("password", env.keycloakPassword)
	form.Set("scope", "profile")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, env.keycloakBaseURL+"/realms/"+env.keycloakRealm+"/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	Expect(err).NotTo(HaveOccurred())
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient().Do(req)
	Expect(err).NotTo(HaveOccurred())
	defer resp.Body.Close()

	var parsed struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	Expect(json.NewDecoder(resp.Body).Decode(&parsed)).To(Succeed())
	Expect(resp.StatusCode).To(Equal(http.StatusOK))
	Expect(parsed.TokenType).To(Equal("Bearer"))
	Expect(parsed.AccessToken).NotTo(BeEmpty())
	return parsed.AccessToken
}

func verifyKeycloakJWT(ctx context.Context, g Gomega, auth string) map[string]any {
	g.Expect(auth).To(HavePrefix("Bearer "))
	token := strings.TrimPrefix(auth, "Bearer ")
	parts := strings.Split(token, ".")
	g.Expect(parts).To(HaveLen(3))

	var header map[string]any
	g.Expect(decodeBase64URLJSON(parts[0], &header)).To(Succeed())
	g.Expect(header).To(HaveKeyWithValue("alg", "RS256"))
	kid, _ := header["kid"].(string)
	g.Expect(kid).NotTo(BeEmpty())

	var claims map[string]any
	g.Expect(decodeBase64URLJSON(parts[1], &claims)).To(Succeed())

	key := keycloakVerificationKey(ctx, g, kid)
	signed := []byte(parts[0] + "." + parts[1])
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	g.Expect(err).NotTo(HaveOccurred())
	digest := sha256.Sum256(signed)
	g.Expect(rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature)).To(Succeed())
	return claims
}

func keycloakVerificationKey(ctx context.Context, g Gomega, kid string) *rsa.PublicKey {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, env.keycloakBaseURL+"/realms/"+env.keycloakRealm+"/protocol/openid-connect/certs", nil)
	g.Expect(err).NotTo(HaveOccurred())
	resp, err := httpClient().Do(req)
	g.Expect(err).NotTo(HaveOccurred())
	defer resp.Body.Close()
	g.Expect(resp.StatusCode).To(Equal(http.StatusOK))

	var jwks struct {
		Keys []struct {
			Kid string   `json:"kid"`
			Kty string   `json:"kty"`
			N   string   `json:"n"`
			E   string   `json:"e"`
			X5C []string `json:"x5c"`
		} `json:"keys"`
	}
	g.Expect(json.NewDecoder(resp.Body).Decode(&jwks)).To(Succeed())
	for _, candidate := range jwks.Keys {
		if candidate.Kid != kid || candidate.Kty != "RSA" {
			continue
		}
		if len(candidate.X5C) > 0 {
			der, err := base64.StdEncoding.DecodeString(candidate.X5C[0])
			g.Expect(err).NotTo(HaveOccurred())
			cert, err := x509.ParseCertificate(der)
			g.Expect(err).NotTo(HaveOccurred())
			key, ok := cert.PublicKey.(*rsa.PublicKey)
			g.Expect(ok).To(BeTrue())
			return key
		}
		key, err := rsaKeyFromJWK(candidate.N, candidate.E)
		g.Expect(err).NotTo(HaveOccurred())
		return key
	}
	g.Expect(fmt.Sprintf("jwks kid %q", kid)).To(Equal("present"))
	return nil
}

func rsaKeyFromJWK(n, e string) (*rsa.PublicKey, error) {
	modulusBytes, err := base64.RawURLEncoding.DecodeString(n)
	if err != nil {
		return nil, err
	}
	exponentBytes, err := base64.RawURLEncoding.DecodeString(e)
	if err != nil {
		return nil, err
	}
	exponent := 0
	for _, b := range exponentBytes {
		exponent = exponent<<8 + int(b)
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(modulusBytes),
		E: exponent,
	}, nil
}

func audienceClaim(claims map[string]any) []string {
	switch raw := claims["aud"].(type) {
	case string:
		return []string{raw}
	case []any:
		values := make([]string, 0, len(raw))
		for _, item := range raw {
			if value, ok := item.(string); ok {
				values = append(values, value)
			}
		}
		return values
	default:
		return nil
	}
}

func scopeClaim(claims map[string]any) []string {
	raw, _ := claims["scope"].(string)
	return strings.Fields(raw)
}
