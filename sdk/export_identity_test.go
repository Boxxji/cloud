package cloud

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/hanzoai/authz"
	"github.com/zap-proto/zip"
)

// IdentityForTest hands an external test package the identity boundary as it runs,
// validating tokens from a test issuer, and a mint for bearers it accepts: a person
// whose signed membership set is orgs, home first.
func IdentityForTest(t *testing.T) (zip.Handler, func(orgs ...authz.Membership) string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	v := newIdentityValidator(testIssuer, jwksServer(t, &key.PublicKey).URL, 0)
	mint := func(orgs ...authz.Membership) string {
		c := tokenClaims("hanzo-cli", orgs[0].Org, "someone@example.com", false, time.Now().Add(time.Hour))
		c.Orgs = orgs
		return signWith(t, key, c)
	}
	return SanitizeIdentity(v), mint
}
