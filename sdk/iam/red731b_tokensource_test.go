package iam

// RED 731b L5: attempts to break the shared, ahead-refreshing machine token. Each of these is expected to PASS (the
// defence holds); they stay as regression tests.

import (
	"context"
	"errors"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

// A refresh that fails at half life keeps serving the token in hand, re-arms ONE timer, and a later success replaces it.
func TestRed731bAFailedRefreshAtHalfLifeKeepsServingAndRearmsOnce(t *testing.T) {
	var fail atomic.Bool
	var n atomic.Int32
	a := newAhead(func(ctx context.Context) (*oauth2.Token, error) {
		i := int(n.Add(1))
		if fail.Load() {
			return nil, errors.New("iam down")
		}
		return &oauth2.Token{AccessToken: "m" + strconv.Itoa(i), Expiry: time.Now().Add(time.Hour)}, nil
	})
	var mu sync.Mutex
	var due []func()
	now := time.Now()
	a.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	a.after = func(_ time.Duration, f func()) { mu.Lock(); due = append(due, f); mu.Unlock() }
	first, err := a.Token()
	if err != nil {
		t.Fatal(err)
	}
	fire := func() {
		mu.Lock()
		fs := due
		due = nil
		mu.Unlock()
		for _, f := range fs {
			f()
		}
		time.Sleep(50 * time.Millisecond)
	}
	fail.Store(true)
	mu.Lock()
	now = now.Add(31 * time.Minute)
	mu.Unlock()
	fire()
	got, err := a.Token()
	if err != nil || got.AccessToken != first.AccessToken {
		t.Fatalf("after a failed refresh the token in hand must keep serving: %v %v", got, err)
	}
	mu.Lock()
	pending := len(due)
	mu.Unlock()
	if pending != 1 {
		t.Fatalf("%d timers pending after a failed refresh, want exactly one", pending)
	}
	fail.Store(false)
	mu.Lock()
	now = now.Add(15 * time.Minute)
	mu.Unlock()
	fire()
	got, _ = a.Token()
	if got.AccessToken == first.AccessToken {
		t.Fatalf("the retry at the next half never replaced the token")
	}
	mu.Lock()
	pending = len(due)
	mu.Unlock()
	if pending != 1 {
		t.Fatalf("%d timers pending after recovery, want exactly one (one chain, not two)", pending)
	}
}

// The caller that STARTED the shared refresh leaves; the refresh must go on for the caller that stays.
func TestRed731bTheCallerThatStartedTheRefreshLeavingDoesNotKillItForOthers(t *testing.T) {
	r := newAheadRig(time.Hour)
	gate := make(chan struct{})
	r.mu.Lock()
	r.gate = gate
	r.mu.Unlock()
	starter, cancel := context.WithCancel(t.Context())
	var wg sync.WaitGroup
	var errStarter, errStayer error
	var tok *oauth2.Token
	wg.Add(2)
	go func() { defer wg.Done(); _, errStarter = TokenWithin(starter, r.a) }()
	happens(t, "the refresh began", func() bool { return r.fetchN.Load() == 1 })
	go func() {
		defer wg.Done()
		ctx, c := context.WithTimeout(t.Context(), 5*time.Second)
		defer c()
		tok, errStayer = TokenWithin(ctx, r.a)
	}()
	time.Sleep(50 * time.Millisecond)
	cancel() // the starter's context dies while the fetch is in flight
	time.Sleep(50 * time.Millisecond)
	close(gate)
	wg.Wait()
	if !errors.Is(errStarter, context.Canceled) {
		t.Fatalf("starter: %v", errStarter)
	}
	if errStayer != nil || tok == nil || tok.AccessToken == "" {
		t.Fatalf("the caller that stayed was failed by the starter's cancellation: %v %v", tok, errStayer)
	}
	if r.fetchN.Load() != 1 {
		t.Fatalf("fetches = %d, want 1", r.fetchN.Load())
	}
}

// A failing endpoint and many calls: no goroutine is left behind per call.
func TestRed731bAFailingIAMLeavesNoGoroutinePerCall(t *testing.T) {
	a := newAhead(func(ctx context.Context) (*oauth2.Token, error) { return nil, errors.New("iam down") })
	a.after = func(time.Duration, func()) {}
	runtime.GC()
	before := runtime.NumGoroutine()
	var wg sync.WaitGroup
	for range 2000 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, c := context.WithTimeout(t.Context(), time.Second)
			defer c()
			_, _ = TokenWithin(ctx, a)
		}()
	}
	wg.Wait()
	time.Sleep(200 * time.Millisecond)
	after := runtime.NumGoroutine()
	if after > before+5 {
		t.Fatalf("goroutines %d -> %d after 2000 failed calls", before, after)
	}
}

// A thundering herd at process start is one fetch.
func TestRed731bAHerdOfFirstCallersIsOneFetch(t *testing.T) {
	r := newAheadRig(time.Hour)
	gate := make(chan struct{})
	r.mu.Lock()
	r.gate = gate
	r.mu.Unlock()
	var wg sync.WaitGroup
	for range 500 {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = r.a.Token() }()
	}
	time.Sleep(100 * time.Millisecond)
	close(gate)
	wg.Wait()
	if r.fetchN.Load() != 1 {
		t.Fatalf("fetches = %d for a herd, want 1", r.fetchN.Load())
	}
}
