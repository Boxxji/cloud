// Copyright © 2026 Hanzo AI. MIT License.

package cloud

import (
	"net/http"
	"testing"
)

// A caller the boundary cannot attribute to a principal arrives as NOBODY: no
// user, no admin, no org-admin, and no org. An opaque bearer is such a caller,
// and so is a request carrying nothing but an X-Org-Id. An org is authority to
// every surface that scopes by it, so the org a client names is deleted with the
// other authority headers and never put back.
//
// This asserts the BOUNDARY, not a copy of it.
func TestAnOpaqueBearerIsNobody(t *testing.T) {
	const tok = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	app, got := newIdentityApp(t, nil)
	probe(t, app, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+tok)
		r.Header.Set("X-Org-Id", "hanzo")
	})

	if got.org != "" {
		t.Errorf("an opaque bearer's X-Org-Id reached the surfaces as %q", got.org)
	}
	if got.user != "" {
		t.Errorf("an opaque bearer minted a user: %q", got.user)
	}
	if got.admin || got.orgAdmin {
		t.Errorf("an opaque bearer gained admin authority (admin=%v orgAdmin=%v)", got.admin, got.orgAdmin)
	}
}

// TestClientOrgIsNotAnIdentity is the other half: the header alone is nobody, and
// names no org.
func TestClientOrgIsNotAnIdentity(t *testing.T) {
	app, got := newIdentityApp(t, nil)
	probe(t, app, func(r *http.Request) { r.Header.Set("X-Org-Id", "acme") })

	if got.user != "" || got.admin || got.orgAdmin || got.org != "" {
		t.Errorf("an anonymous X-Org-Id granted identity: user=%q org=%q admin=%v orgAdmin=%v",
			got.user, got.org, got.admin, got.orgAdmin)
	}
}

// TestOrgWithAnUnsafeRuneIsRefused pins the anti-forgery on the org rule itself:
// an org carrying a format rune is a non-injective identifier (folding it would put two
// distinct IAM orgs in one namespace), so it grants NO scoping at all. A zero-width
// space rather than a plain one, because the transport OWS-trims the plain one before
// the boundary ever sees it — the invisible rune is the one that reaches here.
func TestOrgWithAnUnsafeRuneIsRefused(t *testing.T) {
	const tok = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	app, got := newIdentityApp(t, nil)
	probe(t, app, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+tok)
		r.Header.Set("X-Org-Id", "han​zo")
	})

	if got.org != "" {
		t.Errorf("an org bearing a zero-width rune was scoped to %q", got.org)
	}
}
