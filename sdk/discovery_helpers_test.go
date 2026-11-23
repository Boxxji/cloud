package cloud

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"time"
)

// fakeProvider answers one issuer's discovery document, naming jwks as its keys, and
// nothing else: no network is touched, so a test can name any issuer.
type fakeProvider struct{ issuer, jwks string }

func (p fakeProvider) RoundTrip(r *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	if r.URL.String() != p.issuer+WellKnown {
		rec.WriteHeader(http.StatusNotFound)
	} else {
		_ = json.NewEncoder(rec).Encode(map[string]string{"issuer": p.issuer, "jwks_uri": p.jwks})
	}
	return rec.Result(), nil
}

func fakeClient(issuer, jwks string) *http.Client {
	return &http.Client{Transport: fakeProvider{issuer, jwks}}
}

// newIdentityValidator is the validator for one issuer whose discovery document names
// jwksURL, assembled the way production assembles it.
func newIdentityValidator(issuer, jwksURL string, ttl time.Duration) *Boundary {
	b, err := newBoundary([]string{issuer + WellKnown}, fakeClient(issuer, jwksURL), ttl)
	if err != nil {
		panic(err)
	}
	return b
}

// fakeProviders answers several providers' discovery documents.
type fakeProviders []fakeProvider

func (ps fakeProviders) RoundTrip(r *http.Request) (*http.Response, error) {
	for _, p := range ps {
		if r.URL.String() == p.issuer+WellKnown {
			return p.RoundTrip(r)
		}
	}
	rec := httptest.NewRecorder()
	rec.WriteHeader(http.StatusNotFound)
	return rec.Result(), nil
}
