package coord

import (
	"context"
	"testing"
	"time"
)

// Holds are summed across pods: each pod's hold is part of the total every pod is
// answered, a hold given back leaves it, and a hold nobody gave back lapses with its
// ttl instead of standing for ever.
func TestHoldsAreSummedAcrossPods(t *testing.T) {
	run := func(t *testing.T, a, b *Coord) {
		ctx := context.Background()
		if got := a.Commit(ctx, "reserve", "acme", "a1", 100, time.Minute); got != 100 {
			t.Fatalf("a's first hold: total %d, want 100", got)
		}
		if got := b.Commit(ctx, "reserve", "acme", "b1", 250, time.Minute); got != 350 {
			t.Fatalf("b's hold: total %d, want 350 (a's 100 and its own 250)", got)
		}
		if got := b.Commit(ctx, "reserve", "other", "b2", 7, time.Minute); got != 7 {
			t.Fatalf("another key's hold: total %d, want 7", got)
		}
		if got := a.Committed(ctx, "reserve", "acme"); got != 350 {
			t.Fatalf("a reads %d held, want 350", got)
		}
		b.Uncommit(ctx, "reserve", "acme", "b1", 250)
		b.Uncommit(ctx, "reserve", "acme", "b1", 250) // already given back
		if got := a.Committed(ctx, "reserve", "acme"); got != 100 {
			t.Fatalf("after b gave its hold back: %d, want 100", got)
		}
		a.Commit(ctx, "reserve", "acme", "a2", 5, 80*time.Millisecond)
		time.Sleep(120 * time.Millisecond)
		if got := b.Committed(ctx, "reserve", "acme"); got != 100 {
			t.Fatalf("a hold past its ttl still counts: %d, want 100", got)
		}
		a.Uncommit(ctx, "reserve", "acme", "a1", 100)
		if got := b.Committed(ctx, "reserve", "acme"); got != 0 {
			t.Fatalf("all holds given back: %d, want 0", got)
		}
	}
	m := NewMemory()
	run(t, m.Pod("cloud-0"), m.Pod("cloud-1"))
}

// A KV that cannot be asked leaves each pod the total of its own holds, and a hold made
// then is given back there.
func TestHoldsFallBackToThePodsOwn(t *testing.T) {
	// Every question to the KV goes unanswered.
	c := over(down{ErrUnavailable}, newMem(), true, Config{Periods: fast, Self: Member{ID: "cloud-0"}, Secret: secret})
	ctx := context.Background()
	if got := c.Commit(ctx, "reserve", "acme", "a1", 40, time.Minute); got != 40 {
		t.Fatalf("with the KV down: total %d, want this pod's 40", got)
	}
	if got := c.Commit(ctx, "reserve", "acme", "a2", 2, time.Minute); got != 42 {
		t.Fatalf("a second hold with the KV down: total %d, want 42", got)
	}
	c.Uncommit(ctx, "reserve", "acme", "a1", 40)
	if got := c.Committed(ctx, "reserve", "acme"); got != 2 {
		t.Fatalf("after giving one back: %d, want 2", got)
	}
}
