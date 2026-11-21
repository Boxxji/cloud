package coord

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// ambiguous lands the write and then reports failure, as a PUT whose reply was lost
// (client timeout, reset, 5xx after commit).
type ambiguous struct {
	*casStore
	lie atomic.Bool
}

// part is one pod's view of the shared store; cut makes it unreachable from that pod.
type part struct {
	s   *ambiguous
	cut atomic.Bool
}

func (p *part) Get(ctx context.Context, key string) ([]byte, string, error) {
	if p.cut.Load() {
		return nil, "", errors.New("partitioned")
	}
	return p.s.Get(ctx, key)
}

func (p *part) PutIfVersion(ctx context.Context, key string, data []byte, expect string) (string, error) {
	if p.cut.Load() {
		return "", errors.New("partitioned")
	}
	return p.s.PutIfVersion(ctx, key, data, expect)
}

func (s *ambiguous) PutIfVersion(ctx context.Context, key string, data []byte, expect string) (string, error) {
	v, err := s.casStore.PutIfVersion(ctx, key, data, expect)
	if err == nil && s.lie.Load() {
		s.lie.Store(false)
		return "", context.DeadlineExceeded
	}
	return v, err
}

// R2: a takeover whose PUT reply is lost skips the full-term wait: the next read
// finds this process the owner and Hold admits at once, while the old holder's
// term is still running.
func TestRedAmbiguousTakeoverSkipsWait(t *testing.T) {
	t.Parallel()
	b := newMem()
	st := &ambiguous{casStore: newCAS()}
	pa := &part{s: st}
	a := pod(t, b, "cloud-0", true, pa)
	la := a.Lead("x")
	eventually(t, 2*time.Second, "a never held", func() bool { return la.Hold(context.Background()) == nil })

	c := pod(t, b, "cloud-1", true, st)
	lc := c.Lead("x")
	// cloud-0 drops out of the live set while it still holds (KV failover lost it,
	// its heartbeat path to the KV is broken, or someone deleted it); simulate by
	// draining its presence without closing its leases.
	st.lie.Store(true)
	pa.cut.Store(true) // cloud-0's node is partitioned: no KV, no store
	a.mu.Lock()
	p := a.presence
	a.presence = nil
	a.mu.Unlock()
	close(p.stop)
	<-p.done
	_ = b.Leave(context.Background(), a.Key("set", membersSet), "cloud-0", "cloud-0-host")

	var overlap time.Duration
	deadline := time.Now().Add(3 * term)
	var first time.Time
	for time.Now().Before(deadline) {
		ah := la.Hold(context.Background()) == nil
		ch := lc.Hold(context.Background()) == nil
		if ah && ch {
			if first.IsZero() {
				first = time.Now()
			}
			overlap = time.Since(first)
		}
		time.Sleep(time.Millisecond)
	}
	r, o := st.lease("x")
	t.Logf("lease round=%d owner=%s; both held for %v (term=%v)", r, o, overlap, term)
	if overlap > 0 {
		t.Errorf("two holders admitted effects at once for %v", overlap)
	}
}

// R3: one pod (prod), KV down, the previous pod hard-killed (its lease never let
// go): the new pod can never take any loop.
func TestRedKVDownPredecessorLeaseStrandsLoops(t *testing.T) {
	t.Parallel()
	st := newCAS()
	// predecessor pod (different name: a Deployment rollout) held "x" and died hard
	_, _ = st.PutIfVersion(context.Background(), leaseKey("x"), encodeLease(lease{round: 7, owner: "cloud-abc-old#000000000000"}), "")
	// KV down: no question to it is answered
	n := over(down{ErrUnavailable}, newMem(), true, Config{Periods: fast, Deployment: "test", Self: Member{ID: "cloud-abc-new", Addr: "x:8443"}, Instance: "i", Secret: secret, Root: true})
	n.SetStore(st)
	n.Start(context.Background())
	defer n.Close(context.Background())
	l := n.Lead("x")
	time.Sleep(5 * term)
	r, o := st.lease("x")
	t.Logf("after %v: lease round=%d owner=%s; new pod Hold=%v", 5*term, r, o, l.Hold(context.Background()))
	if l.Hold(context.Background()) != nil {
		t.Errorf("one pod with KV down never runs a loop a dead predecessor held")
	}
}

// R5: one pod, KV up or absent, object store unreachable/read-only/unproven at boot:
// no loop runs (main ran them at one pod regardless of the store).
func TestRedOnePodStoreDownNoLoops(t *testing.T) {
	t.Parallel()
	st := newCAS()
	st.fail(true)
	c := solo(t, newMem(), "cloud-0", st)
	l := c.Lead("x")
	time.Sleep(3 * term)
	t.Logf("one pod, Peered=%v, store down: Hold=%v", c.Peered(), l.Hold(context.Background()))
	if l.Hold(context.Background()) != nil {
		t.Errorf("a single-writer deployment runs no loop while its object store is down")
	}
}
