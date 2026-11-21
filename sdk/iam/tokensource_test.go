package iam

// This deployment's own IAM token (tokensource.go): kept fresh before it is needed, and one refresh
// among all who need it, which none of them waits on longer than its own context allows. A token
// endpoint that hangs must not hold every run's delegation one thirty seconds after another.

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

// aheadRig is a source over a fetch the test controls, on a clock the test moves.
type aheadRig struct {
	a      *ahead
	mu     sync.Mutex
	at     time.Time
	timers []func()
	fetchN atomic.Int32
	gate   chan struct{} // when set, a fetch waits on it
	life   time.Duration
}

func newAheadRig(life time.Duration) *aheadRig {
	r := &aheadRig{at: time.Now(), life: life}
	r.a = newAhead(func(ctx context.Context) (*oauth2.Token, error) {
		n := int(r.fetchN.Add(1))
		r.mu.Lock()
		gate, now := r.gate, r.at
		r.mu.Unlock()
		if gate != nil {
			select {
			case <-gate:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return &oauth2.Token{AccessToken: "machine-" + strconv.Itoa(n), Expiry: now.Add(r.life)}, nil
	})
	r.a.now = func() time.Time { r.mu.Lock(); defer r.mu.Unlock(); return r.at }
	r.a.after = func(_ time.Duration, f func()) {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.timers = append(r.timers, f)
	}
	return r
}

// advance moves the clock and fires every timer set.
func (r *aheadRig) advance(d time.Duration) {
	r.mu.Lock()
	r.at = r.at.Add(d)
	fire := r.timers
	r.timers = nil
	r.mu.Unlock()
	for _, f := range fire {
		f()
	}
}

func happens(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for end := time.Now().Add(10 * time.Second); time.Now().Before(end); time.Sleep(2 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("never happened: %s", what)
}

// The token is asked for again before it is needed: when half its life has passed, by a timer, with no
// caller waiting on it. So once the endpoint stops answering, a caller after the first token's end is
// handed the second at once instead of waiting on a refresh that will not come.
//
// MUTATION: leave out the timer and a caller after the first token's end waits on a hung endpoint.
func TestTheMachineTokenIsAskedForAgainBeforeItIsNeeded(t *testing.T) {
	r := newAheadRig(time.Hour)
	first, err := r.a.Token()
	if err != nil || first.AccessToken != "machine-1" {
		t.Fatalf("first token: %v / %v", first, err)
	}
	if again, _ := r.a.Token(); again != first || r.fetchN.Load() != 1 {
		t.Fatalf("a token in hand was asked for again: %d fetches", r.fetchN.Load())
	}
	r.advance(30 * time.Minute)
	happens(t, "the token is refreshed with nobody waiting", func() bool { return r.fetchN.Load() == 2 })
	happens(t, "the refreshed token is held", func() bool {
		r.a.mu.Lock()
		defer r.a.mu.Unlock()
		return r.a.flight == nil && r.a.tok != nil && r.a.tok.AccessToken == "machine-2"
	})

	// The endpoint hangs from now on, and the first token's life ends.
	r.mu.Lock()
	r.gate = make(chan struct{})
	r.mu.Unlock()
	r.advance(31 * time.Minute)
	got := make(chan *oauth2.Token, 1)
	go func() { tok, _ := r.a.Token(); got <- tok }()
	select {
	case tok := <-got:
		if tok.AccessToken != "machine-2" {
			t.Fatalf("a caller was handed %q, want the token refreshed ahead", tok.AccessToken)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a caller waited on a hung endpoint although a fresh token was in hand")
	}
}

// A caller waits for a token as long as its own context allows and no longer, and all who wait share
// one refresh: a hung endpoint is one call, not one after another.
//
// MUTATION: make Token take a lock across fetch and the second caller waits out the first's.
func TestACallerWaitsOnATokenOnlyAsLongAsItsOwnContextAllows(t *testing.T) {
	r := newAheadRig(time.Hour)
	r.mu.Lock()
	r.gate = make(chan struct{})
	r.mu.Unlock()
	const callers = 4
	took := make([]time.Duration, callers)
	errs := make([]error, callers)
	var wg sync.WaitGroup
	for i := range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(t.Context(), time.Duration(40*(i+1))*time.Millisecond)
			defer cancel()
			start := time.Now()
			_, errs[i] = TokenWithin(ctx, r.a)
			took[i] = time.Since(start)
		}()
	}
	wg.Wait()
	for i := range callers {
		if !errors.Is(errs[i], context.DeadlineExceeded) {
			t.Fatalf("caller %d: %v, want its own deadline", i, errs[i])
		}
		if want := time.Duration(40*(i+1)) * time.Millisecond; took[i] > want+time.Second {
			t.Fatalf("caller %d waited %v for a limit of %v", i, took[i], want)
		}
	}
	if n := r.fetchN.Load(); n != 1 {
		t.Fatalf("the endpoint was called %d times for %d callers, want one refresh among them", n, callers)
	}

	// The refresh they all left is still under way: released, the next caller has its token.
	close(r.gate)
	tok, err := TokenWithin(t.Context(), r.a)
	if err != nil || tok.AccessToken == "" {
		t.Fatalf("after the endpoint answered: %v / %v", tok, err)
	}
}
