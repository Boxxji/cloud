package coord

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// gone is a KV that can be cut off for every call, joins and reads and counts.
type gone struct {
	Backend
	off atomic.Bool
}

func (g *gone) Join(ctx context.Context, set string, r Record, ttl time.Duration, force bool) (*Record, error) {
	if g.off.Load() {
		return nil, ErrUnavailable
	}
	return g.Backend.Join(ctx, set, r, ttl, force)
}
func (g *gone) Members(ctx context.Context, set string, ttl time.Duration) ([]Record, error) {
	if g.off.Load() {
		return nil, ErrUnavailable
	}
	return g.Backend.Members(ctx, set, ttl)
}
func (g *gone) Once(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	if g.off.Load() {
		return false, ErrUnavailable
	}
	return g.Backend.Once(ctx, key, ttl)
}

// blip fails the first n reads of one process's view of the shared store.
type blip struct {
	*casStore
	n atomic.Int32
}

func (b *blip) Get(ctx context.Context, key string) ([]byte, string, error) {
	if b.n.Add(-1) >= 0 {
		return nil, "", errors.New("store: 503 slow down")
	}
	return b.casStore.Get(ctx, key)
}

// loop runs Do back to back, as every loop in the binary does.
func loop(ctx context.Context, l *Leader, who string, fx *effects) {
	for ctx.Err() == nil {
		_ = l.Do(ctx, work(l, who, fx, 2*time.Millisecond))
		time.Sleep(5 * time.Millisecond)
	}
}

func overlapOf(fx *effects, a, b string) bool {
	for _, x := range fx.by(a) {
		for _, y := range fx.by(b) {
			if x.start.Before(y.end) && y.start.Before(x.end) {
				return true
			}
		}
	}
	return false
}

// N1: no KV (one replica), a second process starts while the first holds and renews
// the lease (a RollingUpdate surge pod; a stuck-Terminating pod's replacement). One
// failed read at its first claim makes it "alone": two writers with the store UP.
func TestRed3StartingPodFirstClaimBlipTwoWriters(t *testing.T) {
	t.Parallel()
	st := newCAS()
	a := over(newMem(), newMem(), false, Config{Periods: fast, Deployment: "t", Self: Member{ID: "cloud-a"}, Instance: "a", Secret: secret})
	a.SetStore(st)
	a.Start(context.Background())
	defer a.Close(context.Background())
	la := a.Lead("x")
	eventually(t, time.Second, "a never held", func() bool { return la.Hold(context.Background()) == nil })

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	fx := &effects{}
	go loop(ctx, la, "a", fx)

	bs := &blip{casStore: st}
	bs.n.Store(1)
	b := over(newMem(), newMem(), false, Config{Periods: fast, Deployment: "t", Self: Member{ID: "cloud-b"}, Instance: "b", Secret: secret})
	b.SetStore(bs)
	b.Start(context.Background())
	defer b.Close(context.Background())
	go loop(ctx, b.Lead("x"), "b", fx)
	<-ctx.Done()
	r, o := st.lease("x")
	t.Logf("lease round=%d owner=%s; a effects=%d b effects=%d", r, o, len(fx.by("a")), len(fx.by("b")))
	if overlapOf(fx, "a", "b") {
		t.Errorf("N1: a starting process's one failed read made it a second writer beside a live holder")
	}
}

// N2: two pods with a KV. The KV goes down and so does the object store (one link
// carries both, or the store is the LAN's across the AWS link). After a heartbeat
// each pod's aged view holds only itself, so each is "alone" and runs every loop.
// At 39237a9359 both stopped.
func TestRed3KVAndStoreDownTwoPodsBothAlone(t *testing.T) {
	t.Parallel()
	kv := &gone{Backend: newMem()}
	st := newCAS()
	a := pod(t, kv, "cloud-0", true, st)
	b := pod(t, kv, "cloud-1", true, st)
	eventually(t, time.Second, "never peered", func() bool { return a.Peered() && b.Peered() })
	la, lb := a.Lead("x"), b.Lead("x")
	eventually(t, 2*time.Second, "nobody held", func() bool {
		return la.Hold(context.Background()) == nil || lb.Hold(context.Background()) == nil
	})
	kv.off.Store(true)
	st.fail(true)
	ctx, cancel := context.WithTimeout(context.Background(), presenceTTL+skew+2*term)
	defer cancel()
	fx := &effects{}
	go loop(ctx, la, "a", fx)
	go loop(ctx, lb, "b", fx)
	<-ctx.Done()
	t.Logf("peered a=%v b=%v; effects a=%d b=%d", a.Peered(), b.Peered(), len(fx.by("a")), len(fx.by("b")))
	if overlapOf(fx, "a", "b") {
		t.Errorf("N2: two pods, KV and store down: both ran the loop at once")
	}
}

// N3: two pods, KV down for both; the holder alone is cut from the store (its node
// partitioned). The healthy pod takes the stale lease; the cut one, aged out of
// peers and with a store error, runs as "single writer". Two writers.
func TestRed3PartitionedHolderAndTakerBothRun(t *testing.T) {
	t.Parallel()
	kv := &gone{Backend: newMem()}
	st := newCAS()
	ca := &cut{ConditionalStore: st}
	a := pod(t, kv, "cloud-0", true, ca)
	la := a.Lead("x")
	eventually(t, time.Second, "a never held", func() bool { return la.Hold(context.Background()) == nil })
	b := pod(t, kv, "cloud-1", true, st)
	lb := b.Lead("x")
	eventually(t, time.Second, "never peered", func() bool { return a.Peered() && b.Peered() })
	kv.off.Store(true)
	ca.off.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), presenceTTL+skew+3*term)
	defer cancel()
	fx := &effects{}
	go loop(ctx, la, "a", fx)
	go loop(ctx, lb, "b", fx)
	<-ctx.Done()
	r, o := st.lease("x")
	t.Logf("lease round=%d owner=%s; effects a=%d b=%d", r, o, len(fx.by("a")), len(fx.by("b")))
	if overlapOf(fx, "a", "b") {
		t.Errorf("N3: a partitioned holder and the pod that took its lease both ran the loop")
	}
}

// N4: two pods, KV down past a heartbeat: each counts single-use tokens in its own
// process, so one token redeems once per pod. At 39237a9359 both answered
// ErrUnavailable.
func TestRed3OnceRedeemsPerPodDuringKVOutage(t *testing.T) {
	t.Parallel()
	kv := &gone{Backend: newMem()}
	a := pod(t, kv, "cloud-0", true, nil)
	b := pod(t, kv, "cloud-1", true, nil)
	eventually(t, time.Second, "never peered", func() bool { return a.Peered() && b.Peered() })
	kv.off.Store(true)
	time.Sleep(presenceTTL + skew + 200*time.Millisecond)
	ctx := context.Background()
	fa, ea := a.Once(ctx, "slack-link", "nonce-1", time.Hour)
	fb, eb := b.Once(ctx, "slack-link", "nonce-1", time.Hour)
	t.Logf("a: first=%v err=%v; b: first=%v err=%v", fa, ea, fb, eb)
	if fa && fb && ea == nil && eb == nil {
		t.Errorf("N4: one single-use token redeemed on both pods")
	}
}

// N5: a lease object that is gone (deleted, lifecycle rule, bucket restore or move)
// is taken at once while its holder is inside its term.
func TestRed3MissingLeaseTakenInsideHoldersTerm(t *testing.T) {
	t.Parallel()
	st := newCAS()
	a := over(newMem(), newMem(), false, Config{Periods: fast, Deployment: "t", Self: Member{ID: "cloud-a"}, Instance: "a", Secret: secret, Declared: 2})
	a.SetStore(st)
	a.Start(context.Background())
	defer a.Close(context.Background())
	la := a.Lead("x")
	eventually(t, time.Second, "a never held", func() bool { return la.Hold(context.Background()) == nil })
	b := over(newMem(), newMem(), false, Config{Periods: fast, Deployment: "t", Self: Member{ID: "cloud-b"}, Instance: "b", Secret: secret, Declared: 2})
	b.SetStore(st)
	b.Start(context.Background())
	defer b.Close(context.Background())
	lb := b.Lead("x")
	time.Sleep(3 * confirmEvery)
	st.mu.Lock()
	delete(st.objs, leaseKey("x"))
	st.mu.Unlock()
	var both time.Duration
	var first time.Time
	deadline := time.Now().Add(term)
	for time.Now().Before(deadline) {
		if la.Hold(context.Background()) == nil && lb.Hold(context.Background()) == nil {
			if first.IsZero() {
				first = time.Now()
			}
			both = time.Since(first)
		}
		time.Sleep(time.Millisecond)
	}
	t.Logf("both held for %v (confirmEvery=%v)", both, confirmEvery)
	if both > 0 {
		t.Errorf("N5: a missing lease was taken inside its holder's term")
	}
}
