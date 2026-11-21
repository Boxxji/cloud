package cloud

import (
	"net/http"
	"time"
)

// These let the edge tests (middleware_edge_identity_ext_test.go, an external test:
// they run the host's limiter in front of the identity boundary) set the boundary's
// API-key resolver to a fake IAM and read what it has remembered. They are in a test
// file, so none of it is the SDK's API.

// FakeIAMKeys points the boundary's API-key resolver at an IAM at base, with refusals
// remembered for the same minute as principals when refusals is set.
func (v *Boundary) FakeIAMKeys(base string, hc *http.Client, refusals bool) {
	k := &iamKeys{base: base, auth: "Basic test", http: hc,
		cache: NewCache[keyID, keyAnswer](time.Minute)}
	if refusals {
		k.refused = NewCache[keyID, keyAnswer](time.Minute)
	}
	v.keys = k
}

// KnownKey reports whether the boundary holds a remembered answer for key, and
// whether that answer is a principal.
func (v *Boundary) KnownKey(key string) (known, principal bool) {
	a, ok := v.keys.(*iamKeys).known(key)
	return ok, a.claims != nil
}

// RaiseKeyRate rewrites the remembered principal of key so its own rate is rpm.
func (v *Boundary) RaiseKeyRate(key string, rpm int) {
	k := v.keys.(*iamKeys)
	a, _ := k.known(key)
	raised := *a.claims
	raised.grant = Grant(nil).Policy(0, 0, rpm)
	k.cache.Put(idOf(key), keyAnswer{claims: &raised})
}

// PaidReads is the reads price.go declares as the paid unit of work.
func PaidReads() []string { return paidReads }
