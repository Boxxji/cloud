package coord

import (
	"context"
	"slices"
	"sync/atomic"
	"testing"
	"time"
)

// readOnly is a KV that answers reads and refuses writes: a Valkey replica left as
// the endpoint after a failover ("READONLY"), or maxmemory with noeviction ("OOM").
type readOnly struct {
	Backend
	ro atomic.Bool
}

func (r *readOnly) Join(ctx context.Context, set string, rec Record, ttl time.Duration, force bool) (*Record, error) {
	if r.ro.Load() {
		return nil, ErrUnavailable
	}
	return r.Backend.Join(ctx, set, rec, ttl, force)
}

// The hold-still fix covers a KV that cannot be READ. A KV that reads but refuses
// writes lets every heartbeat lapse while every refresh succeeds, so each pod's
// set ages to itself and two live pods each elect themselves for every org.
func TestRed5ReadOnlyKVEmptiesTheLiveSet(t *testing.T) {
	t.Parallel()
	kv := newMem()
	va, vb := &readOnly{Backend: kv}, &readOnly{Backend: kv}
	a := pod(t, va, "cloud-0", true, nil)
	b := pod(t, vb, "cloud-1", true, nil)
	eventually(t, 2*time.Second, "pods never saw each other", func() bool {
		return len(a.Members()) == 2 && len(b.Members()) == 2
	})
	va.ro.Store(true)
	vb.ro.Store(true)
	deadline := time.Now().Add(presenceTTL + skew + 3*time.Second)
	for time.Now().Before(deadline) {
		if slices.Equal(ids(a.Members()), []string{"cloud-0"}) && slices.Equal(ids(b.Members()), []string{"cloud-1"}) {
			t.Errorf("read-only KV: cloud-0 sees %v and cloud-1 sees %v — each alone, each elects itself for every org",
				ids(a.Members()), ids(b.Members()))
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Logf("sets after %v of a read-only KV: %v / %v", presenceTTL+skew, ids(a.Members()), ids(b.Members()))
}

// One pod's writes fail (its connection, not the KV): its peer drops it, it keeps
// its peer. Divergent views: the peer elects itself for every org, the pod still
// elects itself for its own.
func TestRed5OnePodsHeartbeatFailsViewsDiverge(t *testing.T) {
	t.Parallel()
	kv := newMem()
	va := &readOnly{Backend: kv}
	a := pod(t, va, "cloud-0", true, nil)
	b := pod(t, kv, "cloud-1", true, nil)
	eventually(t, 2*time.Second, "pods never saw each other", func() bool {
		return len(a.Members()) == 2 && len(b.Members()) == 2
	})
	va.ro.Store(true)
	eventually(t, presenceTTL+skew+3*time.Second, "cloud-1 never dropped cloud-0", func() bool {
		return len(b.Members()) == 1
	})
	// Each pod reads the set on its own ticker, so which of them reads it first after
	// the drop is the scheduler's to decide. What this asks is what cloud-0 makes of
	// its next read, so that read is taken here rather than raced.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	a.refresh(ctx)
	cancel()
	t.Logf("cloud-0 sees %v, cloud-1 sees %v", ids(a.Members()), ids(b.Members()))
	if len(a.Members()) == 2 {
		t.Errorf("divergent views: cloud-0 still elects itself for its orgs while cloud-1 elects itself for all")
	}
}
