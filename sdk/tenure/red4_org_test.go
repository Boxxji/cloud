package tenure

import (
	"context"
	"testing"

	"github.com/hanzoai/vfs/replica"
)

// P2: two pods, KV down past a heartbeat, so each pod's live set is itself alone
// (coord.Members ages members out on their signed times). Both elect themselves for
// every org. Acknowledged writes stay safe (ship-before-ack + CarryForward), but
// Owned() — the gate the sandbox/agent reapers, park and sync scheduler act on
// WITHOUT shipping — is true on both at once, and the deposed one reads stale rows.
func TestRed4KVOutageTwoOwnedPods(t *testing.T) {
	ctx := context.Background()
	cs := newFakeCondStore()
	const orgID = "acme"
	dbKey := replica.DBPath(orgID, "", "research")

	a := newDurablePod(t, cs, "cloud-0", []Member{{ID: "cloud-0"}}, orgID, dbKey)
	if err := a.d.Hydrate(ctx); err != nil {
		t.Fatal(err)
	}
	a.open(t)
	putKV(t, a.db, "lease", "expires-10:00")
	if ok, err := a.d.Sync(ctx); err != nil || !ok {
		t.Fatalf("a sync: %v %v", ok, err)
	}
	b := newDurablePod(t, cs, "cloud-1", []Member{{ID: "cloud-1"}}, orgID, dbKey)
	if err := b.d.Hydrate(ctx); err != nil {
		t.Fatal(err)
	}
	b.open(t)
	putKV(t, b.db, "lease", "expires-11:00") // the new owner extends the sandbox
	if ok, err := b.d.Sync(ctx); err != nil || !ok {
		t.Fatalf("b sync: %v %v", ok, err)
	}
	var av string
	_ = a.db.QueryRow(`SELECT v FROM kv WHERE k='lease'`).Scan(&av)
	t.Logf("a.Owned=%v (reads %q)  b.Owned=%v", a.d.Owned(), av, b.d.Owned())
	if a.d.Owned() && b.d.Owned() {
		t.Errorf("P2: both pods answer Owned() for one org; the deposed one reaps from %q", av)
	}
}
