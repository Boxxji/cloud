package cloud

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"testing"
	"time"

	"github.com/hanzoai/authz"
)

// CLOUD'S ORG SWITCH IS THE LEAF'S.
//
// Which org a request acts in is ONE rule — the client's selection when the signed
// membership set admits it, the home org otherwise, and any org for a platform
// operator — and SanitizeIdentity asks authz.Claims.EffectiveOrg for it rather than
// restating it. Cloud keeps only the home ANCHOR, which it resolves from facts the
// claims do not carry (an API key's subject, a machine's own owner).
//
// This pins the wiring end to end: wherever cloud's home org equals the leaf's, the
// org the boundary mints must be the one the leaf names.
func TestOrgSwitchAgreesWithTheLeaf(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks := jwksServer(t, &key.PublicKey)
	v := newIdentityValidator(testIssuer, jwks.URL, 0)
	future := time.Now().Add(time.Hour)

	member := func(orgs ...authz.Membership) idClaims {
		c := tokenClaims("hanzo-console", "app-org", "u@example.test", false, future)
		c.Orgs = orgs
		return c
	}

	for _, tc := range []struct {
		name     string
		claims   idClaims
		selected string
	}{
		{"no selection", member(authz.Membership{Org: "acme", Role: authz.Member}), ""},
		{"selects home", member(authz.Membership{Org: "acme", Role: authz.Member}), "acme"},
		{"selects a granted org", member(
			authz.Membership{Org: "acme", Role: authz.Member},
			authz.Membership{Org: "beta", Role: authz.Member}), "beta"},
		{"selects an ungranted org", member(
			authz.Membership{Org: "acme", Role: authz.Member}), "victim"},
		{"selects a non-injective org", member(
			authz.Membership{Org: "acme", Role: authz.Member}), "acme "},
		{"org admin selects a granted org", member(
			authz.Membership{Org: "acme", Role: authz.Admin},
			authz.Membership{Org: "beta", Role: authz.Member}), "beta"},
		{"platform operator selects any org", member(
			authz.Membership{Org: authz.AdminOrg, Role: authz.Admin}), "customer"},
		{"platform operator, no selection", member(
			authz.Membership{Org: authz.AdminOrg, Role: authz.Admin}), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The premise: this case is one where cloud and the leaf resolve the same
			// home. Where they legitimately differ (an API key, a KMS machine) cloud has
			// more information and there is nothing to compare.
			if got, want := tc.claims.homeOrg(), tc.claims.Claims.Home(); got != want {
				t.Skipf("cloud resolves home %q, the leaf %q — nothing to compare", got, want)
			}

			app, seen := newIdentityApp(t, v)
			probe(t, app, func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer "+signWith(t, key, tc.claims))
				if tc.selected != "" {
					r.Header.Set(authz.HeaderOrg, tc.selected)
				}
			})

			want, _ := tc.claims.Claims.EffectiveOrg(tc.selected)
			if seen.org != want {
				t.Errorf("cloud acts in %q, the leaf says %q — the org-switch rule has drifted",
					seen.org, want)
			}
		})
	}
}
