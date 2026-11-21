package plane

import (
	"context"
	"testing"

	"github.com/zap-proto/zip"
)

// OrgAdmin says the caller administers the org the call was for. Pointing the
// call at another org carries it nowhere — the same rule zip.ActingAs keeps.
func TestForDropsTheOrgAdminBitWhenTheOrgChanges(t *testing.T) {
	base := zip.WithCaller(context.Background(), zip.Caller{Org: "admin", User: "op", Admin: true, OrgAdmin: true})
	if who := zip.CallerOf(For(base, "acme")); who.Org != "acme" || who.OrgAdmin {
		t.Fatalf("For(acme) over an admin-org caller = %+v, want org acme and no org-admin bit", who)
	}
	if who := zip.CallerOf(For(base, "admin")); !who.OrgAdmin {
		t.Fatalf("For over the caller's own org dropped its org-admin bit: %+v", who)
	}
}
