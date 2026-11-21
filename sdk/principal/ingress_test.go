package principal

import (
	"slices"
	"testing"

	"github.com/hanzoai/authz"
	"github.com/zap-proto/zip"
)

// TestStrippedIsEveryNameACallerMayNotAssert pins the one list both strippers
// read: everything authz names (retired names too) but the correlation id, cloud's
// five authority headers, and zip's impersonation actor.
func TestStrippedIsEveryNameACallerMayNotAssert(t *testing.T) {
	want := []string{HeaderUserBrand, HeaderUserIsApp, HeaderUserOrgs, HeaderKey, HeaderUserApproved, zip.HeaderActedBy}
	for _, h := range append(append([]string{}, authz.Headers...), authz.Retired...) {
		if h != authz.HeaderRequestID {
			want = append(want, h)
		}
	}
	for _, h := range want {
		if !slices.Contains(Stripped, h) {
			t.Errorf("%s is not stripped", h)
		}
	}
	if slices.Contains(Stripped, authz.HeaderRequestID) {
		t.Error("the correlation id is stripped; it is the caller's to send and authorizes nothing")
	}
	if len(Stripped) != len(want) {
		t.Errorf("Stripped holds %d names, want %d: %v", len(Stripped), len(want), Stripped)
	}
}
