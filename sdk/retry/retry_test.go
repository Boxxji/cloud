package retry

import (
	"context"
	"testing"
	"time"
)

func paused(t *testing.T) *[]time.Duration {
	t.Helper()
	var waits []time.Duration
	was := Pause
	Pause = func(_ context.Context, d time.Duration) error { waits = append(waits, d); return nil }
	t.Cleanup(func() { Pause = was })
	return &waits
}

// A call is made until it is answered, waiting what the other side named, else a doubling wait.
func TestDoWaitsWhatWasNamedElseBacksOff(t *testing.T) {
	waits := paused(t)
	calls := 0
	Do(t.Context(), func() (bool, time.Duration) {
		calls++
		if calls == 1 {
			return true, 7 * time.Second
		}
		return calls < 3, 0
	})
	if calls != 3 || len(*waits) != 2 || (*waits)[0] != 7*time.Second {
		t.Fatalf("%d calls, waits %v, want 3 calls and the named 7s first", calls, *waits)
	}
	if w := (*waits)[1]; w < First || w > First*2 {
		t.Fatalf("the second wait is %v, want a backoff of the second try (%v to %v)", w, First, First*2)
	}
}

func TestDoIsBounded(t *testing.T) {
	waits := paused(t)
	calls := 0
	Do(t.Context(), func() (bool, time.Duration) { calls++; return true, 0 })
	if calls != Tries || len(*waits) != Tries-1 {
		t.Fatalf("%d calls and %d waits, want %d and %d", calls, len(*waits), Tries, Tries-1)
	}
}

// A wait the other side names beyond Hold ends the tries at once.
func TestDoGivesUpOnAWaitBeyondTheHold(t *testing.T) {
	waits := paused(t)
	calls := 0
	Do(t.Context(), func() (bool, time.Duration) { calls++; return true, Hold + time.Second })
	if calls != 1 || len(*waits) != 0 {
		t.Fatalf("%d calls and waits %v, want one call and no wait", calls, *waits)
	}
}

func TestDoStopsWhenItsContextEnds(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	calls := 0
	Do(ctx, func() (bool, time.Duration) { calls++; cancel(); return true, 0 })
	if calls != 1 {
		t.Fatalf("%d calls after the context ended, want 1", calls)
	}
	ctx, cancel = context.WithCancel(t.Context())
	calls = 0
	time.AfterFunc(20*time.Millisecond, cancel)
	Do(ctx, func() (bool, time.Duration) { calls++; return true, time.Hour })
	if calls != 1 {
		t.Fatalf("%d calls after the context ended mid-wait, want 1", calls)
	}
}

func TestBackoffDoublesToItsCeilingWithJitter(t *testing.T) {
	for try, ceil := range []time.Duration{First, 2 * First, 4 * First, 8 * First, 16 * First, Longest, Longest} {
		for range 50 {
			if w := Backoff(try + 1); w < ceil/2 || w > ceil {
				t.Fatalf("Backoff(%d) = %v, want %v to %v", try+1, w, ceil/2, ceil)
			}
		}
	}
}
