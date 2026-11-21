package tenure

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/hanzoai/vfs/replica"
)

// rollView is one pod's live set that a test changes as the deployment does, with
// the departures Membership.Gone reports.
type rollView struct {
	id   string
	mu   sync.Mutex
	set  []Member
	gone map[string]bool
}

func (v *rollView) Self() string { return v.id }
func (v *rollView) Members() []Member {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]Member(nil), v.set...)
}
func (v *rollView) Gone(id string) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.gone[id]
}
func (v *rollView) put(set []Member, gone ...string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.set, v.gone = set, map[string]bool{}
	for _, id := range gone {
		v.gone[id] = true
	}
}

// AN ORG RETURNS TO THE POD IT LEFT AT ONCE WHEN ITS HOLDER IS GONE, AND WAITS WHILE
// THE HOLDER MAY STILL BE LIVE. cloud-1 joins and takes an org from cloud-0; then
// either cloud-1 leaves (a scale-in, a rolling restart) and cloud-0 claims the org
// back at once, or cloud-0 merely cannot see cloud-1 (its set is behind, or split
// from cloud-1's) and backs off rather than trade the org back and forth.
func TestADeposedReplicaClaimsBackOnlyFromAHolderThatLeft(t *testing.T) {
	ctx := context.Background()
	zero, one := Member{ID: "cloud-0"}, Member{ID: "cloud-1"}
	orgID := orgElecting(t, []Member{zero, one}, "cloud-1")
	for _, tc := range []struct {
		name  string
		left  bool
		claim bool
	}{
		{"the holder left", true, true},
		{"the holder may be live", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cs := newFakeCondStore()
			va := &rollView{id: "cloud-0", set: []Member{zero}}
			vb := &rollView{id: "cloud-1", set: []Member{zero, one}}
			a := durableOn(t, cs, va, orgID) // asked nothing yet, so its next Owned reads the lease
			if b := durableOn(t, cs, vb, orgID); !b.Owned() {
				t.Fatal("cloud-1 did not take the org it is elected for")
			}
			if tc.left {
				va.put([]Member{zero}, "cloud-1")
			}
			if a.Owned() {
				t.Fatal("cloud-0 owns an org cloud-1 holds at a newer round")
			}
			if got := a.PendingPromotion(); got != tc.claim {
				t.Fatalf("PendingPromotion = %v, want %v", got, tc.claim)
			}
			if !tc.claim {
				return
			}
			if ok, err := a.TryClaim(ctx); !ok || err != nil {
				t.Fatalf("claiming back from a holder that left: %v %v", ok, err)
			}
		})
	}
}

// ANOTHER OF THE ORG'S DATABASES CLAIMING THE LEASE IS NO CONTEST. The org's files
// share one lease; one that is promoted at a newer round leaves the others naming an
// older one, and they renew it at once rather than back off from their own pod.
func TestALeaseThisReplicaHoldsAtANewerRoundIsNoContest(t *testing.T) {
	ctx := context.Background()
	cs := newFakeCondStore()
	zero, one := Member{ID: "cloud-0"}, Member{ID: "cloud-1"}
	orgID := orgElecting(t, []Member{zero, one}, "cloud-1")
	va := &rollView{id: "cloud-0", set: []Member{zero}}
	files := durableOn(t, cs, va, orgID)
	durableOn(t, cs, &rollView{id: "cloud-1", set: []Member{zero, one}}, orgID) // takes it
	if ok, err := durableOn(t, cs, va, orgID).TryClaim(ctx); !ok || err != nil {
		t.Fatalf("cloud-0 could not take it back: %v %v", ok, err)
	}
	if files.Owned() {
		t.Fatal("a database still at the old round owns the org")
	}
	if !files.PendingPromotion() {
		t.Fatal("a database whose own pod holds the lease at a newer round backs off from it")
	}
}

// The store's last word on who took the org is kept when a refused ship deposes the
// replica too, so a ship refused by a holder that has since left is claimed back at
// once as well.
func TestARefusedShipNamesItsRival(t *testing.T) {
	cs := newFakeCondStore()
	zero, one := Member{ID: "cloud-0"}, Member{ID: "cloud-1"}
	orgID := orgElecting(t, []Member{zero, one}, "cloud-1")
	va := &rollView{id: "cloud-0", set: []Member{zero}}
	a := durableOn(t, cs, va, orgID)
	durableOn(t, cs, &rollView{id: "cloud-1", set: []Member{zero, one}}, orgID)
	db := openBoundDB(t, a)
	putKV(t, db, "k", "v")
	if acked, err := a.Sync(context.Background()); acked || err != nil {
		t.Fatalf("a deposed replica's ship: acked=%v err=%v", acked, err)
	}
	if a.PendingPromotion() {
		t.Fatal("a refused ship claimed back from a holder that may be live")
	}
	va.put([]Member{zero}, "cloud-1")
	if !a.PendingPromotion() {
		t.Fatal("a refused ship does not claim back from a holder that left")
	}
}

// durableOn hydrates one research database of orgID on the pod view v names.
func durableOn(t *testing.T, cs replica.ConditionalStore, v ownerView, orgID string) *Durable {
	t.Helper()
	d := NewDurability(cs, v, nil).For(testNS(orgID), "research", replica.DBPath(orgID, "", "research"), t.TempDir()+"/research.db")
	if err := d.Hydrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return d
}

// Gone reports the members a refresh dropped, forgets one that comes back, and
// never names a member that was never there.
func TestMembershipRemembersWhoLeft(t *testing.T) {
	var mu sync.Mutex
	set := []Member{{ID: "r1"}, {ID: "r2"}}
	m := NewMembership("r1", func(context.Context) ([]Member, error) {
		mu.Lock()
		defer mu.Unlock()
		return append([]Member(nil), set...), nil
	}, time.Hour)
	ctx := context.Background()
	if err := m.refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if m.Gone("r2") || m.Gone("r9") {
		t.Fatal("a member in the set, or one never seen, reads as gone")
	}
	mu.Lock()
	set = []Member{{ID: "r1"}}
	mu.Unlock()
	_ = m.refresh(ctx)
	if !m.Gone("r2") {
		t.Fatal("a member a refresh dropped is not gone")
	}
	mu.Lock()
	set = []Member{{ID: "r1"}, {ID: "r2"}}
	mu.Unlock()
	_ = m.refresh(ctx)
	if m.Gone("r2") {
		t.Fatal("a member that came back is still gone")
	}
}
