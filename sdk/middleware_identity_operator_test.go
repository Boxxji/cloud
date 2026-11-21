package cloud

// SuperAdmin ⟺ owner == "admin": a person whose own org — the org IAM keeps their
// user row in, the first entry of the signed `orgs` set — is the reserved admin
// org. Nothing else is platform authority.
//
// A membership of the admin org held by a person whose row lives in a brand org
// is an ordinary membership. It confers neither X-User-IsAdmin nor the right to
// act inside the reserved org, and it does not let its holder select an org its
// membership set does not name. Operators are named users provisioned in the
// admin org itself.

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"testing"
	"time"

	"github.com/hanzoai/authz"
)

// TestSuperIsOwner drives real JWKS-validated tokens through SanitizeIdentity and
// reads what principal.Super and X-Org-Id say downstream, with a forged
// X-User-IsAdmin on every request so the ingress strip is exercised in the same
// pass. For each principal it asks three selections: none, the reserved org, and
// an org the principal belongs to nowhere.
func TestSuperIsOwner(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks := jwksServer(t, &key.PublicKey)
	v := newIdentityValidator(testIssuer, jwks.URL, 0)
	future := time.Now().Add(time.Hour)

	for _, tc := range []struct {
		name string
		orgs []authz.Membership
		// super is the verdict; home is the org acted in with no selection, and
		// also with a refused one. A SuperAdmin's selections are honoured, so its
		// row names the org each selection lands in.
		super         bool
		home          string
		reserved      string // acting org when X-Org-Id: admin
		elsewhere     string // acting org when X-Org-Id: victim
		ownMembership string // an org the membership set names, "" for none
	}{
		{
			name:          "owner is admin",
			orgs:          []authz.Membership{{Org: "admin", Role: authz.Admin}},
			super:         true,
			home:          "admin",
			reserved:      "admin",
			elsewhere:     "victim",
			ownMembership: "",
		},
		{
			// The role inside the reserved org is not a term: IAM's HomeRole gives
			// an admin-org user whose row carries isAdmin=false {admin, member}.
			name:      "owner is admin with a member role",
			orgs:      []authz.Membership{{Org: "admin", Role: authz.Member}, {Org: "hanzo", Role: authz.Admin}},
			super:     true,
			home:      "admin",
			reserved:  "admin",
			elsewhere: "victim",
		},
		{
			name:          "brand owner who is a member of admin",
			orgs:          []authz.Membership{{Org: "hanzo", Role: authz.Admin}, {Org: "admin", Role: authz.Admin}},
			super:         false,
			home:          "hanzo",
			reserved:      "hanzo",
			elsewhere:     "hanzo",
			ownMembership: "",
		},
		{
			name: "brand owner who is a member of admin and of other brands",
			orgs: []authz.Membership{
				{Org: "hanzo", Role: authz.Admin}, {Org: "admin", Role: authz.Admin},
				{Org: "lux", Role: authz.Admin}, {Org: "zoo", Role: authz.Admin},
			},
			super:         false,
			home:          "hanzo",
			reserved:      "hanzo",
			elsewhere:     "hanzo",
			ownMembership: "lux",
		},
		{
			name:      "admin membership last in a long set",
			orgs:      []authz.Membership{{Org: "a", Role: authz.Member}, {Org: "b", Role: authz.Member}, {Org: "admin", Role: authz.Owner}},
			super:     false,
			home:      "a",
			reserved:  "a",
			elsewhere: "a",
		},
		{
			name:          "admin of many orgs, none of them reserved",
			orgs:          []authz.Membership{{Org: "hanzo", Role: authz.Admin}, {Org: "lux", Role: authz.Owner}},
			super:         false,
			home:          "hanzo",
			reserved:      "hanzo",
			elsewhere:     "hanzo",
			ownMembership: "lux",
		},
		{
			// Verbatim comparison: a fold would make an org someone can self-serve
			// the reserved one.
			name:      "a look-alike reserved org as owner",
			orgs:      []authz.Membership{{Org: "Admin", Role: authz.Admin}},
			super:     false,
			home:      "Admin",
			reserved:  "Admin",
			elsewhere: "Admin",
		},
		{
			name:      "no memberships at all is a machine, never an operator",
			orgs:      nil,
			super:     false,
			home:      "",
			reserved:  "",
			elsewhere: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := tokenClaims("hanzo-cli", "some-app-org", "op@hanzo.ai", true, future)
			claims.Orgs = tc.orgs
			tok := signWith(t, key, claims)

			for _, sel := range []struct{ org, want string }{
				{"", tc.home},
				{authz.AdminOrg, tc.reserved},
				{"victim", tc.elsewhere},
				{tc.ownMembership, cmpOr(tc.ownMembership, tc.home)},
			} {
				app, seen := newIdentityApp(t, v)
				probe(t, app, func(r *http.Request) {
					r.Header.Set("Authorization", "Bearer "+tok)
					r.Header.Set("X-User-IsAdmin", "true")
					r.Header.Set("X-User-Owner", authz.AdminOrg)
					if sel.org != "" {
						r.Header.Set("X-Org-Id", sel.org)
					}
				})
				if seen.admin != tc.super {
					t.Errorf("X-Org-Id %q: principal.Super = %v; want %v (orgs=%v)", sel.org, seen.admin, tc.super, tc.orgs)
				}
				if seen.org != sel.want {
					t.Errorf("X-Org-Id %q: acting org = %q; want %q (orgs=%v)", sel.org, seen.org, sel.want, tc.orgs)
				}
			}
		})
	}
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// TestActs is the org-selection rule on its own: a SuperAdmin may act anywhere,
// anyone else in an org its membership set names other than the reserved one.
func TestActs(t *testing.T) {
	super := &authz.Claims{Orgs: []authz.Membership{{Org: authz.AdminOrg, Role: authz.Admin}}}
	member := &authz.Claims{Orgs: []authz.Membership{{Org: "hanzo", Role: authz.Admin}, {Org: authz.AdminOrg, Role: authz.Admin}, {Org: "acme", Role: authz.Member}, {Org: "lux", Role: authz.Member}}}
	program := &authz.Claims{Type: authz.Program, Orgs: []authz.Membership{{Org: authz.AdminOrg}, {Org: "acme"}}}

	for _, tc := range []struct {
		name string
		c    *authz.Claims
		org  string
		want bool
	}{
		{"SuperAdmin, any org", super, "victim", true},
		{"SuperAdmin, the reserved org", super, authz.AdminOrg, true},
		{"SuperAdmin, an unsafe org", super, "victim\n", false},
		{"SuperAdmin, no org", super, "", false},
		{"member, own org", member, "hanzo", true},
		{"member, a member org", member, "acme", true},
		{"plain member of a brand org", member, "lux", false},
		{"a brand's directory", &authz.Claims{Orgs: []authz.Membership{{Org: "hanzo-id", Role: authz.Member}, {Org: "ann", Role: authz.Owner}}}, "hanzo-id", false},
		{"member of admin from a brand org, the reserved org", member, authz.AdminOrg, false},
		{"member, a stranger's org", member, "victim", false},
		{"program granted admin, the reserved org", program, authz.AdminOrg, false},
		{"program, a granted org", program, "acme", true},
		{"no claims", nil, "hanzo", false},
	} {
		if got := Acts(tc.c, tc.org); got != tc.want {
			t.Errorf("%s: Acts(%q) = %v; want %v", tc.name, tc.org, got, tc.want)
		}
	}
}

// TestSudoDoesNotRideTheAppOrg pins that the grant reads the SUBJECT's own org and
// never the `owner` claim, which IAM stamps with the APPLICATION's org. Signing in
// through an admin-org-owned app must not confer platform authority — otherwise
// the authority is a property of whichever client you logged in through.
func TestSudoDoesNotRideTheAppOrg(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks := jwksServer(t, &key.PublicKey)
	v := newIdentityValidator(testIssuer, jwks.URL, 0)

	// owner = "admin" (the APP's org), but the subject belongs only to "acme".
	claims := tokenClaims("admin-console", "admin", "user@acme.test", true, time.Now().Add(time.Hour))
	claims.Orgs = []authz.Membership{{Org: "acme", Role: authz.Admin}}

	app, seen := newIdentityApp(t, v)
	probe(t, app, bearer(signWith(t, key, claims)))

	if seen.admin {
		t.Error("the app's org conferred platform authority on a user whose own org is acme")
	}
	if seen.org != "acme" {
		t.Errorf("effective org = %q; want %q (the SUBJECT's org, not the app's)", seen.org, "acme")
	}
}

// TestOperatorTokenIsNotSpecialToAnyClient pins that platform authority is a
// property of the PRINCIPAL, not of the client that minted the token. hanzo-cli is
// a PUBLIC client — it ships to users' machines and holds no secret by design — so
// the same operator arriving through it must get the same authority and no more.
func TestOperatorTokenIsNotSpecialToAnyClient(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks := jwksServer(t, &key.PublicKey)
	v := newIdentityValidator(testIssuer, jwks.URL, 0)
	operator := []authz.Membership{{Org: "admin", Role: authz.Admin}, {Org: "hanzo", Role: authz.Admin}}
	tenant := []authz.Membership{{Org: "acme", Role: authz.Admin}}

	for _, aud := range []string{"hanzo-cli", "hanzo-console", "hanzo-studio"} {
		t.Run("operator via "+aud, func(t *testing.T) {
			claims := tokenClaims(aud, "hanzo", "z@admin.hanzo.ai", false, time.Now().Add(time.Hour))
			claims.Orgs = operator
			app, seen := newIdentityApp(t, v)
			probe(t, app, bearer(signWith(t, key, claims)))
			if !seen.admin {
				t.Errorf("operator was refused platform authority through client %q", aud)
			}
		})
		t.Run("tenant via "+aud, func(t *testing.T) {
			claims := tokenClaims(aud, "acme", "user@acme.test", true, time.Now().Add(time.Hour))
			claims.Orgs = tenant
			app, seen := newIdentityApp(t, v)
			probe(t, app, bearer(signWith(t, key, claims)))
			if seen.admin {
				t.Errorf("a tenant was granted platform authority through client %q", aud)
			}
			if !seen.orgAdmin {
				t.Errorf("an org admin lost their OWN org's admin scope through client %q", aud)
			}
		})
	}
}

// A customer who landed in a brand org as a plain member acts in none of it: the
// request carries no org unless they select one of their own, a selection of the
// brand org is discarded, and the set offered to choose from leaves it out. The
// brand's admin still acts in it.
func TestABrandOrgsPlainMemberActsInNoneOfIt(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks := jwksServer(t, &key.PublicKey)
	v := newIdentityValidator(testIssuer, jwks.URL, 0)

	alone := tokenClaims("hanzo-app", "hanzo", "eve@x.test", false, time.Now().Add(time.Hour))
	alone.Orgs = []authz.Membership{{Org: "hanzo", Role: authz.Member}}
	app, seen := newIdentityApp(t, v)
	probe(t, app, func(r *http.Request) {
		bearer(signWith(t, key, alone))(r)
		r.Header.Set(authz.HeaderOrg, "hanzo")
	})
	if seen.org != "" || seen.orgs != "" {
		t.Fatalf("a plain member of hanzo acts in %q (offered %q), want nothing", seen.org, seen.orgs)
	}

	owned := tokenClaims("hanzo-app", "hanzo", "eve@x.test", false, time.Now().Add(time.Hour))
	owned.Orgs = []authz.Membership{{Org: "hanzo", Role: authz.Member}, {Org: "eve-co", Role: authz.Owner}}
	app, seen = newIdentityApp(t, v)
	probe(t, app, func(r *http.Request) {
		bearer(signWith(t, key, owned))(r)
		r.Header.Set(authz.HeaderOrg, "hanzo")
	})
	if seen.org != "eve-co" || seen.orgs != "eve-co" {
		t.Fatalf("a plain member of hanzo with an org of her own acts in %q (offered %q), want eve-co", seen.org, seen.orgs)
	}

	staff := tokenClaims("hanzo-app", "hanzo", "lead@hanzo.ai", true, time.Now().Add(time.Hour))
	staff.Orgs = []authz.Membership{{Org: "hanzo", Role: authz.Admin}}
	app, seen = newIdentityApp(t, v)
	probe(t, app, bearer(signWith(t, key, staff)))
	if seen.org != "hanzo" || !seen.orgAdmin {
		t.Fatalf("hanzo's admin acts in %q (orgAdmin %v), want hanzo", seen.org, seen.orgAdmin)
	}
}
