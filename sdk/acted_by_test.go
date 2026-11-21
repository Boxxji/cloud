package cloud

// A SuperAdmin impersonation token carries the TARGET's claims and names the
// operator in `act`. The boundary is the one place that reads it, so these pin
// that X-Acted-By is written from the verified token, never from the request, and
// only for an impersonation.

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/hanzoai/authz"
	"github.com/zap-proto/zip"
)

// impClaims is an IAM access token minted for a SuperAdmin acting as someone else.
type impClaims struct {
	authz.Claims
	Act map[string]string `json:"act,omitempty"`
	Imp bool              `json:"imp,omitempty"`
}

func signImp(t *testing.T, key *rsa.PrivateKey, c impClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
	tok.Header["kid"] = "test-key"
	raw, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return raw
}

func TestTheBoundaryNamesTheOperatorOfAnImpersonation(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	v := newIdentityValidator(testIssuer, jwksServer(t, &key.PublicKey).URL, 0)
	ada := tokenClaims("hanzo-console", "acme", "ada@acme.test", false, time.Now().Add(time.Hour))
	ada.TokenType, ada.PreferredUsername = "access-token", "ada"

	// IAM's `act` is the operator's row: subject, owner and name.
	op := map[string]string{"sub": "u-op", "owner": "admin", "name": "z"}
	root := tokenClaims("hanzo-console", "admin", "root@hanzo.test", false, time.Now().Add(time.Hour))
	root.TokenType, root.PreferredUsername = "access-token", "root"
	machine := ada
	machine.Orgs = nil
	for _, tc := range []struct {
		what     string
		bearer   string
		forged   string
		user, by string
	}{
		{"the operator is named from act", signImp(t, key, impClaims{Claims: ada.Claims, Act: op, Imp: true}), "", "u-acme", "u-op"},
		{"a forged header never survives", signImp(t, key, impClaims{Claims: ada.Claims, Act: op, Imp: true}), "u-mallory", "u-acme", "u-op"},
		{"an org key acting for a member is not an impersonation", signImp(t, key, impClaims{Claims: ada.Claims, Act: map[string]string{"sub": "acme/key-1"}}), "u-mallory", "u-acme", ""},
		{"the person's own token names no operator", signWith(t, key, ada), "u-mallory", "u-acme", ""},
		{"an impersonation naming nobody authenticates nobody", signImp(t, key, impClaims{Claims: ada.Claims, Imp: true}), "u-mallory", "", ""},
		{"an operator outside the admin org authenticates nobody", signImp(t, key, impClaims{Claims: ada.Claims, Act: map[string]string{"sub": "u-eve", "owner": "acme", "name": "eve"}, Imp: true}), "", "", ""},
		{"an operator named as a bare string authenticates nobody", signImp(t, key, impClaims{Claims: ada.Claims, Act: map[string]string{"sub": "admin/z"}, Imp: true}), "", "", ""},
		{"a SuperAdmin is never the target", signImp(t, key, impClaims{Claims: root.Claims, Act: op, Imp: true}), "", "", ""},
		{"a target with no membership set is never one", signImp(t, key, impClaims{Claims: machine.Claims, Act: op, Imp: true}), "", "", ""},
		{"no credential, no operator", "", "u-mallory", "", ""},
	} {
		var user, by string
		app := zip.New(zip.Config{})
		app.Use(SanitizeIdentity(v))
		app.Raw(http.MethodGet, "/probe", func(c *zip.Ctx) error {
			user, by = c.User(), c.Header(zip.HeaderActedBy)
			return c.JSON(http.StatusOK, map[string]string{"ok": "1"})
		})
		req := httptest.NewRequest(http.MethodGet, "/probe", nil)
		if tc.bearer != "" {
			req.Header.Set("Authorization", "Bearer "+tc.bearer)
		}
		if tc.forged != "" {
			req.Header.Set(zip.HeaderActedBy, tc.forged)
		}
		if _, err := app.Test(req, zip.TestConfig{Timeout: 30 * time.Second, FailOnTimeout: true}); err != nil {
			t.Fatalf("%s: %v", tc.what, err)
		}
		if user != tc.user || by != tc.by {
			t.Errorf("%s: user=%q acted-by=%q, want %q %q", tc.what, user, by, tc.user, tc.by)
		}
	}
}
