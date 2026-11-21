package iam

// statement.go — which org an agent answers to, as a statement anyone can verify
// offline: a JSON Web Signature in compact serialization (RFC 7515) over Claims,
// signed with Ed25519 (EdDSA, RFC 8037), against keys published as a JSON Web Key
// Set (RFC 7517) at GET /v1/principal/keys. The signing is served by
// apps/principals; the shape and the check are here, so any app — or any
// verifier with this package — reads and verifies a statement the same way.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Typ is the header typ every statement carries (RFC 8725 §3.11): a statement is
// never an access token, is signed by a key that signs nothing else, and names an
// issuer no token does, so neither can be taken for the other.
const Typ = "agent-principal+jwt"

// Claims is what a statement says.
type Claims struct {
	// Iss is the issuer: the deployment's /v1/principal.
	Iss string `json:"iss"`
	// Sub is the agent's id.
	Sub string `json:"sub"`
	// Name is the agent's name in its org.
	Name string `json:"name"`
	// Org is the principal the agent answers to.
	Org string `json:"org"`
	// Parents are the agents that spawned it, nearest first — all of them the same
	// org's.
	Parents []string `json:"parents"`
	// Iat is when it was issued, unix seconds.
	Iat int64 `json:"iat"`
	// Exp is when it stops being valid, unix seconds.
	Exp int64 `json:"exp"`
	// Jti is the statement's own id.
	Jti string `json:"jti"`
	// Tax makes the statement a TaxPrincipalCredential: the principal holds a
	// certified tax form of this class, valid until Exp. Absent on a statement that
	// says only which principal the agent answers to.
	Tax *TaxClaim `json:"tax,omitempty"`
}

// TaxClaim is what a TaxPrincipalCredential states about the principal's form.
// It names the class of form and when it was signed — never a number, a name or
// an address on it.
type TaxClaim struct {
	// Form is w9, w8ben or w8bene.
	Form string `json:"form"`
	// Signed is when the form's certification was signed, unix seconds.
	Signed int64 `json:"signed"`
}

// Header is a statement's JOSE header.
type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// JWK is one public key as RFC 7517 and RFC 8037 publish it.
type JWK struct {
	// Kty is OKP, an octet key pair.
	Kty string `json:"kty"`
	// Crv is Ed25519.
	Crv string `json:"crv"`
	// X is the public key, base64url without padding.
	X string `json:"x"`
	// Kid names the key; a statement's header carries it.
	Kid string `json:"kid"`
	// Alg is EdDSA.
	Alg string `json:"alg"`
	// Use is sig.
	Use string `json:"use"`
}

// JWKS is the published key set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// Attestation is which principal an agent answers to.
type Attestation struct {
	// Agent is the agent.
	Agent AgentBrief `json:"agent"`
	// Org is the principal it answers to — the org it was defined in.
	Org string `json:"org"`
	// Parents are the agents that spawned it, nearest first.
	Parents []AgentBrief `json:"parents"`
	// Statement is the same, signed: a JWS a verifier checks offline against GET
	// /v1/principal/keys.
	Statement string `json:"statement"`
	// Kid is the key that signed it.
	Kid string `json:"kid"`
	// Expires is when the statement stops being valid, unix seconds.
	Expires int64 `json:"expires"`
}

// Verify checks a statement against a published key set at now, and answers what
// it says. It is what a verifier runs offline, and it refuses anything that is
// not exactly a statement: another alg or typ, a kid the set does not hold, a
// signature that does not verify, or a statement outside its validity. The
// issuer is answered in the claims for the verifier to hold to the deployment it
// trusts.
func Verify(statement string, set JWKS, now time.Time) (Claims, error) {
	parts := strings.Split(statement, ".")
	if len(parts) != 3 {
		return Claims{}, errors.New("principal: a statement is three dot-separated parts")
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Claims{}, errors.New("principal: the header is not base64url")
	}
	var h Header
	if err := json.Unmarshal(hb, &h); err != nil {
		return Claims{}, errors.New("principal: the header is not JSON")
	}
	if h.Alg != "EdDSA" || h.Typ != Typ {
		return Claims{}, fmt.Errorf("principal: a statement is EdDSA and typ %s", Typ)
	}
	var pub ed25519.PublicKey
	for _, k := range set.Keys {
		if k.Kid == h.Kid && k.Kty == "OKP" && k.Crv == "Ed25519" {
			x, err := base64.RawURLEncoding.DecodeString(k.X)
			if err == nil && len(x) == ed25519.PublicKeySize {
				pub = x
			}
		}
	}
	if pub == nil {
		return Claims{}, errors.New("principal: the statement's key is not in the set")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sig) {
		return Claims{}, errors.New("principal: the signature does not verify")
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Claims{}, errors.New("principal: the claims are not base64url")
	}
	var c Claims
	if err := json.Unmarshal(pb, &c); err != nil {
		return Claims{}, errors.New("principal: the claims are not JSON")
	}
	if t := now.Unix(); t < c.Iat || t >= c.Exp {
		return Claims{}, errors.New("principal: the statement is not valid at this time")
	}
	return c, nil
}
