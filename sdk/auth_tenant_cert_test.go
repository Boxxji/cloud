package cloud

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/hanzoai/cloud/sdk/brand"
)

// A token signed by an ORGANIZATION'S OWN cert is refused at the boundary.
//
// An org's applications sign with a cert of the org's, under the org's own issuer
// and published only in the org's own JWKS. The platform's boundary trusts the
// platform's issuers and the platform's JWKS, and nothing an org publishes: a
// person who signed in to an org's app holds a credential for that org's app, not
// a credential for this API. Held here through the real middleware, because it is
// the one in front of production.
//
// Three ways a tenant token could present, each refused on its own: under the
// tenant's issuer, under the platform's issuer with a kid the platform never
// published, and under a kid the platform DID publish but signed by the tenant's
// key (a collision between a tenant cert's name and a platform cert's).
func TestATokenSignedByATenantCertIsRefusedAtTheBoundary(t *testing.T) {
	platform, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tenant, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	// The platform's JWKS: its own certs only. The tenant's key is in the org's
	// JWKS, a document this boundary never reads.
	jwk := func(kid string, pub *rsa.PublicKey) map[string]any {
		return map[string]any{
			"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
			"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}
	}
	body, _ := json.Marshal(map[string]any{"keys": []map[string]any{jwk("cert-hanzo", &platform.PublicKey)}})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) }))
	defer srv.Close()

	v := newIdentityValidator(testIssuer, srv.URL, 0)
	app, got := newIdentityApp(t, v)

	const tenantIssuer = "https://test.iam/acme"
	sign := func(key *rsa.PrivateKey, kid, issuer string) string {
		t.Helper()
		c := tokenClaims("acme-portal", "acme", "dave@acme.io", false, time.Now().Add(time.Hour))
		c.Issuer = issuer
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, c.Claims)
		tok.Header["kid"] = kid
		raw, err := tok.SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}

	// The control: the same person, claims and audience, signed by the platform.
	if _, err := v.validate(sign(platform, "cert-hanzo", testIssuer)); err != nil {
		t.Fatalf("a platform-signed token was refused: %v", err)
	}
	probe(t, app, bearer(sign(platform, "cert-hanzo", testIssuer)))
	if got.org != "acme" {
		t.Fatalf("control: the platform-signed token did not authenticate: org %q", got.org)
	}

	for name, tok := range map[string]string{
		"the tenant's own issuer and cert":                          sign(tenant, "acme-signing", tenantIssuer),
		"the platform's issuer, a kid the platform never published": sign(tenant, "acme-signing", testIssuer),
		"a platform kid, signed by the tenant's key":                sign(tenant, "cert-hanzo", testIssuer),
		"the tenant's issuer, a platform kid, the platform's key":   sign(platform, "cert-hanzo", tenantIssuer),
	} {
		if _, err := v.validate(tok); err == nil {
			t.Errorf("SECURITY: %s verified at the boundary", name)
		}
		*got = captured{}
		probe(t, app, bearer(tok))
		if got.org != "" || got.user != "" || got.admin || got.orgAdmin {
			t.Errorf("SECURITY: %s authenticated a request: %+v", name, *got)
		}
	}
}

// During the platform's issuer move the boundary trusts both platform issuers, each
// exactly, and still nothing an organization publishes: a platform-signed token under
// https://hanzo.ai authenticates as the hanzo brand; a token under an organization's own
// issuer, https://hanzo.ai/<org>, signed by the platform key or by the tenant's, does not.
func TestBothPlatformIssuersAuthenticateAndATenantIssuerDoesNot(t *testing.T) {
	platform, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tenant, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pub := &platform.PublicKey
	body, _ := json.Marshal(map[string]any{"keys": []map[string]any{{
		"kty": "RSA", "kid": "cert-hanzo", "use": "sig", "alg": "RS256",
		"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}}})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) }))
	defer srv.Close()
	v := newIdentityValidator("https://hanzo.id", srv.URL, 0)
	app, got := newIdentityApp(t, v)

	sign := func(key *rsa.PrivateKey, kid, issuer string) string {
		t.Helper()
		c := tokenClaims("hanzo-cloud", "acme", "dave@acme.io", false, time.Now().Add(time.Hour))
		c.Issuer = issuer
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, c.Claims)
		tok.Header["kid"] = kid
		raw, err := tok.SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	for _, iss := range []string{"https://hanzo.id", "https://hanzo.ai"} {
		*got = captured{}
		probe(t, app, bearer(sign(platform, "cert-hanzo", iss)))
		if got.org != "acme" {
			t.Errorf("a platform-signed token under %s did not authenticate: %+v", iss, *got)
		}
		if id, ok := brand.ForIssuer(iss); !ok || id != "hanzo" {
			t.Errorf("%s does not name the hanzo brand", iss)
		}
	}
	for name, tok := range map[string]string{
		"an organization's issuer, signed by the platform key": sign(platform, "cert-hanzo", "https://hanzo.ai/acme"),
		"an organization's issuer, signed by its own key":      sign(tenant, "acme-signing", "https://hanzo.ai/acme"),
		"the new issuer, signed by a tenant key":               sign(tenant, "cert-hanzo", "https://hanzo.ai"),
	} {
		if _, err := v.validate(tok); err == nil {
			t.Errorf("SECURITY: %s verified at the boundary", name)
		}
		*got = captured{}
		probe(t, app, bearer(tok))
		if got.org != "" || got.user != "" || got.admin || got.orgAdmin {
			t.Errorf("SECURITY: %s authenticated a request: %+v", name, *got)
		}
	}
}
