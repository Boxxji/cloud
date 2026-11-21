package coord

import (
	"context"
	"math/rand/v2"
	"testing"
	"time"
)

// slow applies each operation after a random delay up to max, ignoring ctx, and
// answers ctx's error if it expired meanwhile (a write that lands after its caller
// gave up), and loses a fraction of replies after applying.
type slow struct {
	*casStore
	max  time.Duration
	lose float64
}

func (s *slow) nap() { time.Sleep(time.Duration(rand.Int64N(int64(s.max)))) }

func (s *slow) Get(ctx context.Context, key string) ([]byte, string, error) {
	s.nap()
	d, v, err := s.casStore.Get(ctx, key)
	s.nap()
	if ctx.Err() != nil {
		return nil, "", ctx.Err()
	}
	return d, v, err
}

func (s *slow) PutIfVersion(ctx context.Context, key string, data []byte, expect string) (string, error) {
	s.nap()
	v, err := s.casStore.PutIfVersion(ctx, key, data, expect)
	s.nap()
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	if err == nil && rand.Float64() < s.lose {
		return "", context.DeadlineExceeded
	}
	return v, err
}

// L1: three peered processes on a store with latency up to 1.5 renewal periods per
// leg, writes landing after their caller gave up, and lost replies. No two may act
// at once.
func TestRed3LatencyNeverTwoHolders(t *testing.T) {
	t.Parallel()
	st := newCAS()
	fx := &effects{}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	for i, id := range []string{"p0", "p1", "p2"} {
		c := over(newMem(), newMem(), false, Config{Periods: fast, Deployment: "t", Self: Member{ID: id}, Instance: id, Secret: secret, Declared: 3})
		c.SetStore(&slow{casStore: st, max: confirmEvery * 3 / 2, lose: 0.2})
		c.Start(context.Background())
		l := c.Lead("x")
		who := id
		go loop(ctx, l, who, fx)
		if i == 0 {
			// p0 dies hard every so often: stops renewing without letting go
			go func() {
				time.Sleep(3 * time.Second)
				c.closed.Store(true)
			}()
		}
	}
	<-ctx.Done()
	r, o := st.lease("x")
	t.Logf("round=%d owner=%s effects p0=%d p1=%d p2=%d", r, o, len(fx.by("p0")), len(fx.by("p1")), len(fx.by("p2")))
	fx.disjoint(t)
}
