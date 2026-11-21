// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package cloud

import (
	"strings"
	"testing"

	"github.com/hanzoai/authz"
)

// TestUsernamePrefersPreferredUsername pins the claim precedence the money path
// depends on. OIDC `name` is a DISPLAY name — IAM fills it from User.DisplayName,
// and a real token carried "Zach Kelling". Reading it as the username addressed
// wallet `hanzo/Zach Kelling`, which no funding path can name, while the balance
// sat in `hanzo/z`; every signed-in completion 402'd against a funded account.
func TestUsernamePrefersPreferredUsername(t *testing.T) {
	// Both present: the username wins, never the human label.
	c := &idClaims{Name: "Zach Kelling", PreferredUsername: "z"}
	if got := c.username(); got != "z" {
		t.Fatalf("username() = %q; want %q (preferred_username must win over the display name)", got, "z")
	}
	// A display name must never be returned when the username is available, and a
	// space is the tell that a display name leaked into an account key.
	if strings.ContainsRune(c.username(), ' ') {
		t.Fatalf("username() = %q; an account key can never contain a space", c.username())
	}
	// Legacy token minted before IAM emitted preferred_username: `name` is all
	// there is, so it stays the answer rather than becoming empty.
	legacy := &idClaims{Name: "z"}
	if got := legacy.username(); got != "z" {
		t.Fatalf("legacy username() = %q; want %q (fallback must be retained)", got, "z")
	}
	// Neither present: empty, never a guess.
	if got := (&idClaims{}).username(); got != "" {
		t.Fatalf("empty username() = %q; want \"\"", got)
	}
}

// TestOrgAdminAdmitsOwner pins the role vocabulary this gate reads. IAM's coarse
// membership set is exactly {owner, admin, member}, and `owner` is what it writes
// for whoever CREATES an org — self-service provisioning calls
// EnsureMembership(..., RoleOwner) precisely so a new org is not "born with nobody
// on it". Matching only "admin" therefore locked every self-serve founder out of
// their own org's admin surface, and an owner cannot escalate their way back in.
//
// The role is FOLDED (a closed vocabulary IAM controls); the org is compared
// VERBATIM, because a fold there would let a member of "acme" claim "ACME".
func TestOrgAdminAdmitsOwner(t *testing.T) {
	for _, tc := range []struct {
		name string
		orgs []authz.Membership
		org  string
		want bool
	}{
		{"owner of the org", []authz.Membership{{Org: "acme", Role: "owner"}}, "acme", true},
		{"admin of the org", []authz.Membership{{Org: "acme", Role: "admin"}}, "acme", true},
		{"role case is folded", []authz.Membership{{Org: "acme", Role: "Owner"}}, "acme", true},
		{"role is trimmed", []authz.Membership{{Org: "acme", Role: " owner "}}, "acme", true},
		{"plain member is not an admin", []authz.Membership{{Org: "acme", Role: "member"}}, "acme", false},
		{"unknown role admits nothing", []authz.Membership{{Org: "acme", Role: "billing"}}, "acme", false},
		{"owner ELSEWHERE does not admit here", []authz.Membership{{Org: "other", Role: "owner"}}, "acme", false},
		{"org compare stays VERBATIM", []authz.Membership{{Org: "ACME", Role: "owner"}}, "acme", false},
		{"empty set admits nothing", nil, "acme", false},
		{"empty org admits nothing", []authz.Membership{{Org: "acme", Role: "owner"}}, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := &idClaims{Orgs: tc.orgs}
			if got := orgAdmin(claims, tc.org); got != tc.want {
				t.Fatalf("orgAdmin(%v, %q) = %v; want %v", tc.orgs, tc.org, got, tc.want)
			}
		})
	}
}

// A user id is a subject to key a record on only when no two people can present
// it: a token's `sub`, or an API key's IAM user. A token with no `sub` falls back
// to its username and then to its display name — two people named Zach Kelling
// present the same one — so it is attributed and never keyed on.
func TestAStableSubjectIsASubOrAKeysUser(t *testing.T) {
	for _, c := range []struct {
		name   string
		claims *idClaims
		want   bool
	}{
		{"a token's sub", &idClaims{Claims: authz.Claims{Subject: "4f1c-uuid", PreferredUsername: "z"}}, true},
		{"a home key's user", &idClaims{Claims: authz.Claims{Subject: "hanzo/z", Name: "z", PreferredUsername: "z"}, subjectOrg: "hanzo"}, true},
		{"an application", &idClaims{Claims: authz.Claims{Subject: "acme/bot", Type: authz.Program}}, true},
		{"a member's key", &idClaims{Claims: authz.Claims{Subject: "lux/z"}, subjectOrg: "hanzo"}, true},
		{"a token with no sub, by username", &idClaims{PreferredUsername: "z"}, false},
		{"a token with no sub, by display name", &idClaims{Name: "Zach Kelling"}, false},
	} {
		if got := c.claims.stable(); got != c.want {
			t.Errorf("%s: stable = %v (userID %q), want %v", c.name, got, c.claims.userID(), c.want)
		}
	}
}
