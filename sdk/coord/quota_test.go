package coord

import (
	"context"
	"slices"
	"testing"
	"time"
)

// A quota is charged to every window or to none: a window at its limit refuses the
// call and the other window keeps its count, and the count stops at the limit.
func TestAQuotaChargesEveryWindowOrNone(t *testing.T) {
	c := Alone()
	ctx := context.Background()
	ws := []Window{{Key: "hour:u", Limit: 2, TTL: time.Hour}, {Key: "day:u", Limit: 3, TTL: time.Hour}}
	for i := range 2 {
		if used, ok := c.Quota(ctx, "ai", ws); !ok || used[0] != i+1 || used[1] != i+1 {
			t.Fatalf("call %d: used %v ok %v", i+1, used, ok)
		}
	}
	if used, ok := c.Quota(ctx, "ai", ws); ok || !slices.Equal(used, []int{2, 2}) {
		t.Fatalf("the hour at its limit: used %v ok %v; want refused with nothing charged", used, ok)
	}
	if got := c.Counted(ctx, "ai", []string{"hour:u", "day:u"}); !slices.Equal(got, []int{2, 2}) {
		t.Fatalf("a refused call was charged: %v", got)
	}
	if got := c.Counted(ctx, "ai", []string{"hour:v"}); !slices.Equal(got, []int{0}) {
		t.Fatalf("another key reads %v", got)
	}
}

// A window's key lives as long as its TTL and then counts from nothing.
func TestAQuotaKeyExpires(t *testing.T) {
	c := Alone()
	ctx := context.Background()
	ws := []Window{{Key: "k", Limit: 1, TTL: 50 * time.Millisecond}}
	if _, ok := c.Quota(ctx, "ai", ws); !ok {
		t.Fatal("the first call was refused")
	}
	if _, ok := c.Quota(ctx, "ai", ws); ok {
		t.Fatal("a second call against a limit of one was admitted")
	}
	time.Sleep(80 * time.Millisecond)
	if used, ok := c.Quota(ctx, "ai", ws); !ok || used[0] != 1 {
		t.Fatalf("after its TTL the key still counts: used %v ok %v", used, ok)
	}
}

// Quotas are the deployment's, whichever pod is asked.
func TestAQuotaIsShared(t *testing.T) {
	kv := newMem()
	a, b := pod(t, kv, "cloud-0", true, nil), pod(t, kv, "cloud-1", true, nil)
	ctx := context.Background()
	ws := []Window{{Key: "day:u", Limit: 5, TTL: time.Hour}}
	admitted := 0
	for i := range 10 {
		c := a
		if i%2 == 1 {
			c = b
		}
		if _, ok := c.Quota(ctx, "ai", ws); ok {
			admitted++
		}
	}
	if admitted != 5 {
		t.Fatalf("ten calls over two pods against a limit of five admitted %d", admitted)
	}
	if got := b.Counted(ctx, "ai", []string{"day:u"}); got[0] != 5 {
		t.Fatalf("the other pod reads %v", got)
	}
}

// A KV that cannot answer does not admit everyone, and does not give every pod the
// whole limit either: one writer counts exactly here, and each of several admits its
// share, so the deployment together admits no more than the limit.
func TestAnUnansweringKVHoldsEachPodToItsShare(t *testing.T) {
	ctx := context.Background()
	ws := []Window{{Key: "day:u", Limit: 50, TTL: time.Hour}}
	for _, tc := range []struct {
		declared, want int
	}{{1, 50}, {2, 25}, {3, 16}} {
		c := over(down{ErrUnavailable}, newMem(), true, Config{Periods: fast, Self: Member{ID: "x"}, Secret: secret, Declared: tc.declared})
		admitted := 0
		for range 60 {
			if _, ok := c.Quota(ctx, "ai", ws); ok {
				admitted++
			}
		}
		if admitted != tc.want {
			t.Fatalf("%d writers, KV down: one pod admitted %d of 50; want %d", tc.declared, admitted, tc.want)
		}
	}
}
