package cloud

// The `orgs` membership-set claim must survive verification into
// VerifiedIdentity.Orgs — that is the value clients/team copies into a session so
// a user's spaces union across every org. These drive a real RSA-signed token
// through the SAME validator the identity boundary uses.

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/hanzoai/authz"
	model "github.com/hanzoai/iam/pkg/model"
)

// TestVerifiedIdentityCarriesOrgs proves a signed `orgs` claim is verified and
// copied verbatim (order preserved, home first) into VerifiedIdentity.Orgs.
func TestVerifiedIdentityCarriesOrgs(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks := jwksServer(t, &key.PublicKey)
	v := &TokenValidator{v: newIdentityValidator(testIssuer, jwks.URL, 0)}

	claims := tokenClaims("hanzo-team", "maxpower", "dave@example.com", false, time.Now().Add(time.Hour))
	claims.Orgs = []authz.Membership{
		{Org: "maxpower", Role: "admin"},
		{Org: "acme", Role: "member"},
	}
	id, err := v.Validate(signWith(t, key, claims))
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if id.Owner != "maxpower" {
		t.Fatalf("owner = %q, want maxpower", id.Owner)
	}
	// VerifiedIdentity publishes []model.OrgRef — clients/team copies it verbatim into
	// a session — so the conversion at that surface is asserted here, order preserved.
	if len(id.Orgs) != 2 ||
		id.Orgs[0] != (model.OrgRef{Org: "maxpower", Role: "admin"}) ||
		id.Orgs[1] != (model.OrgRef{Org: "acme", Role: "member"}) {
		t.Fatalf("orgs = %+v, want [maxpower/admin acme/member]", id.Orgs)
	}
}

// TestVerifiedIdentityLegacyNoOrgs proves a token minted before the claim shipped
// (no `orgs`) verifies with an empty set — the caller falls back to Owner.
func TestVerifiedIdentityLegacyNoOrgs(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks := jwksServer(t, &key.PublicKey)
	v := &TokenValidator{v: newIdentityValidator(testIssuer, jwks.URL, 0)}

	claims := tokenClaims("hanzo-team", "acme", "ada@example.com", false, time.Now().Add(time.Hour))
	// tokenClaims seeds the ordinary case (orgs[0] == owner) because that is what a
	// real IAM token carries. This test is specifically about the PRE-CLAIM shape, so
	// it clears the set explicitly rather than relying on the fixture's default.
	claims.Orgs = nil
	id, err := v.Validate(signWith(t, key, claims))
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if len(id.Orgs) != 0 {
		t.Fatalf("legacy token orgs = %+v, want empty", id.Orgs)
	}
	if id.Owner != "acme" {
		t.Fatalf("owner = %q, want acme", id.Owner)
	}
}

// TestVerifiedIdentitySuper is the SuperAdmin verdict a caller deciding before any
// request exists reads (the deploy console's sign-in): owner == "admin", the
// person's own org, and nothing else — not the application's `owner` claim, and
// not a membership of the admin org held from a brand org.
func TestVerifiedIdentitySuper(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks := jwksServer(t, &key.PublicKey)
	v := &TokenValidator{v: newIdentityValidator(testIssuer, jwks.URL, 0)}

	for _, tc := range []struct {
		name   string
		appOrg string
		orgs   []authz.Membership
		want   bool
	}{
		{"owner is admin", "hanzo", []authz.Membership{{Org: "admin", Role: authz.Admin}}, true},
		{"brand owner who is a member of admin", "hanzo", []authz.Membership{{Org: "hanzo", Role: authz.Owner}, {Org: "admin", Role: authz.Admin}}, false},
		{"minted through an admin-org application", "admin", []authz.Membership{{Org: "acme", Role: authz.Owner}}, false},
		{"no membership set", "admin", nil, false},
	} {
		claims := tokenClaims("hanzo-console", tc.appOrg, "op@example.com", true, time.Now().Add(time.Hour))
		claims.Orgs = tc.orgs
		id, err := v.Validate(signWith(t, key, claims))
		if err != nil {
			t.Fatalf("%s: validate: %v", tc.name, err)
		}
		if id.Super != tc.want {
			t.Errorf("%s: Super = %v, want %v", tc.name, id.Super, tc.want)
		}
	}
}
