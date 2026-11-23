// Package oidctest is a fake OIDC provider for tests of code that trusts one by
// discovery: it answers an issuer's discovery document and nothing else, over no
// network, so a test can name any issuer and any key set.
package oidctest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
)

// WellKnown is where an issuer publishes its discovery document.
const WellKnown = "/.well-known/openid-configuration"

// Discovery is the discovery URL of issuer.
func Discovery(issuer string) string { return issuer + WellKnown }

// Client is an HTTP client that answers issuer's discovery document, naming jwks as
// its key set, and every other URL with 404.
func Client(issuer, jwks string) *http.Client {
	return &http.Client{Transport: provider{issuer: issuer, jwks: jwks}}
}

type provider struct{ issuer, jwks string }

func (p provider) RoundTrip(r *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	if r.URL.String() != Discovery(p.issuer) {
		rec.WriteHeader(http.StatusNotFound)
	} else {
		_ = json.NewEncoder(rec).Encode(map[string]string{"issuer": p.issuer, "jwks_uri": p.jwks})
	}
	return rec.Result(), nil
}
