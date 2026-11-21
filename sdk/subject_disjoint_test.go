package cloud

// THREE KINDS OF SUBJECT, AND THEY NEVER MEET. A person's token names them by a
// UUID `sub`; an API key by its holder's row, `<owner>/<name>`; an application by
// `app:` and the `<owner>/<name>` IAM signs for it. A record one principal holds —
// a sandbox's lessee, a session's actor, a person's settings — is keyed on that
// user id, so two principals presenting one of them hold each other's.
//
// Red's reproduction: IAM admits a UUID-shaped username (its usernameRe, verbatim
// below), so a user named after a colleague's `sub` minted a home key whose user
// id WAS that `sub`; and an org admin who names an application after a member
// held that member's key-held records through it.

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/cloud/sdk/principal"
)

// iamUsername is IAM's pkg/schema/username.go usernameRe, verbatim.
var iamUsername = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// minted runs one request through the boundary and answers the user id it
// stamped and the principal it attested.
func minted(t *testing.T, v *Boundary, bearerTok string) (string, principal.Principal) {
	t.Helper()
	app := zip.New(zip.Config{})
	app.Use(SanitizeIdentity(v))
	var user string
	var p principal.Principal
	app.Raw(http.MethodGet, "/probe", func(c *zip.Ctx) error {
		user = c.User()
		p, _ = principal.Minted(c)
		return c.JSON(http.StatusOK, nil)
	})
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	req.Header.Set("Authorization", "Bearer "+bearerTok)
	if _, err := app.Test(req, zip.TestConfig{Timeout: 30 * time.Second, FailOnTimeout: true}); err != nil {
		t.Fatalf("probe: %v", err)
	}
	return user, p
}

func TestAKeyNamedAfterAColleaguesSubIsNotThem(t *testing.T) {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6], b[8] = b[6]&0x0f|0x40, b[8]&0x3f|0x80
	victim := fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
	if !iamUsername.MatchString(victim) {
		t.Fatalf("IAM refuses %q as a username; the attack needs it accepted", victim)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	// The attacker's home key: IAM resolves it to hanzo/<victim's sub>.
	v := keyValidator(t, "hanzo", victim)
	v.verifier = newIdentityValidator(testIssuer, jwksServer(t, &key.PublicKey).URL, 0).verifier

	tc := tokenClaims("hanzo-console", "hanzo", "victim@example.test", false, time.Now().Add(time.Hour))
	tc.Subject = victim
	tokUser, tokP := minted(t, v, signWith(t, key, tc))
	keyUser, keyP := minted(t, v, "sk-attacker-home-key")

	if tokUser != victim || !tokP.Stable {
		t.Fatalf("the colleague's token = %q (stable %v), want their sub", tokUser, tokP.Stable)
	}
	if keyUser != "hanzo/"+victim || keyP.User != keyUser || !keyP.Stable || keyP.Subject != keyUser {
		t.Fatalf("the home key = %q %+v, want its row hanzo/%s, stable", keyUser, keyP, victim)
	}
	if keyUser == tokUser {
		t.Fatal("a home key named after a colleague's sub holds what they hold")
	}
	if tokP.Kind != principal.Person || keyP.Kind != principal.Key {
		t.Fatalf("the token is a %q and the key a %q, want person and key", tokP.Kind, keyP.Kind)
	}
}

func TestAnApplicationNamedAfterAMemberIsNotThem(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	// bob's key in acme, and the application acme's admin named "bob".
	v := keyValidator(t, "acme", "bob")
	v.verifier = newIdentityValidator(testIssuer, jwksServer(t, &key.PublicKey).URL, 0).verifier

	appUser, appP := minted(t, v, appToken(t, key, "bob", "acme"))
	keyUser, keyP := minted(t, v, "sk-bob-key")

	if appUser != "app:acme/bob" || appP.User != appUser || !appP.Stable {
		t.Fatalf("the application = %q %+v, want app:acme/bob, stable", appUser, appP)
	}
	// The token's sub itself is carried verbatim, for what matches IAM's own
	// claim (the fabric's ext-jwt login).
	if appP.Subject != "acme/bob" {
		t.Fatalf("the application's Subject = %q, want IAM's sub verbatim", appP.Subject)
	}
	if keyUser != "acme/bob" || keyUser == appUser {
		t.Fatalf("bob's key = %q beside the application's %q: the two must differ", keyUser, appUser)
	}
	// Their Subjects are one string, so what serves one kind asks the Kind, and
	// what keys a record on the caller keys on SubjectOf, where they differ.
	if keyP.Subject != appP.Subject {
		t.Fatalf("bob's key's Subject %q and the application's %q: this pins that they meet", keyP.Subject, appP.Subject)
	}
	if appP.Kind != principal.App || keyP.Kind != principal.Key {
		t.Fatalf("the application is a %q and bob's key a %q, want app and key", appP.Kind, keyP.Kind)
	}
	appID, _ := principal.SubjectOf(appP)
	keyID, _ := principal.SubjectOf(keyP)
	if appID != "app:acme/bob" || keyID != "acme/bob" {
		t.Fatalf("SubjectOf the application = %q and of bob's key = %q, want two different ids", appID, keyID)
	}
}

// A person's token keeps the id it always had, so everything already keyed on a
// `sub` stays theirs.
func TestAPersonsSubIsUnchanged(t *testing.T) {
	c := &idClaims{}
	c.Subject = "4f1c0e8a-0000-4000-8000-000000000001"
	c.Audience = jwt.ClaimStrings{"hanzo-console"}
	if got := c.userID(); got != c.Subject {
		t.Fatalf("a person's user id = %q, want their sub", got)
	}
	if c.kind() != principal.Person {
		t.Fatalf("a person's token is a %q", c.kind())
	}
	id, ok := principal.SubjectOf(principal.Principal{User: c.userID(), Subject: c.Subject, Stable: c.stable()})
	if !ok || id != c.Subject {
		t.Fatalf("SubjectOf a person = %q, %v; want their sub", id, ok)
	}
}
