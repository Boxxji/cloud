package coord

import (
	"context"
	"slices"
	"testing"
	"time"
)

// A rate ceiling is Quota's count: every window charged at once or none, over pods
// that share one KV, and each window's time to its reset alongside.
func TestACeilingIsOneCountOverEveryWindow(t *testing.T) {
	kv := newMem()
	a, b := pod(t, kv, "cloud-0", true, nil), pod(t, kv, "cloud-1", true, nil)
	ctx := context.Background()
	ws := []Window{{Key: "key/acme/k1", Limit: 5, TTL: time.Minute}, {Key: "org/acme", Limit: 2, TTL: time.Minute}}
	for i, c := range []*Coord{a, b} {
		used, wait, ok := c.Ceiling(ctx, "rate", ws)
		if !ok || !slices.Equal(used, []int{i + 1, i + 1}) {
			t.Fatalf("call %d: used %v ok %v", i+1, used, ok)
		}
		if wait[0] <= 0 || wait[0] > time.Minute || wait[1] <= 0 || wait[1] > time.Minute {
			t.Fatalf("call %d: waits %v, want each inside the minute", i+1, wait)
		}
	}
	used, wait, ok := a.Ceiling(ctx, "rate", ws)
	if ok || !slices.Equal(used, []int{2, 2}) {
		t.Fatalf("the org's third: used %v ok %v; want refused and the key's window not charged", used, ok)
	}
	if wait[1] <= 0 || wait[1] > time.Minute {
		t.Fatalf("a refusal says when the org's window resets: %v", wait[1])
	}
}

// With the KV down, a pod admits its SHARE of a rate ceiling rounded up, never
// zero: a ceiling of 2 on three pods admits one request a pod, where a quota of 2
// on three pods — money — admits none.
func TestAnUnansweringKVLeavesEachPodItsShareOfACeiling(t *testing.T) {
	ctx := context.Background()
	c := over(down{ErrUnavailable}, newMem(), true, Config{Periods: fast, Self: Member{ID: "x"}, Secret: secret, Declared: 3})
	ws := []Window{{Key: "org/acme", Limit: 2, TTL: time.Minute}}
	if _, _, ok := c.Ceiling(ctx, "rate", ws); !ok {
		t.Fatal("a ceiling of 2 on three pods refused the first request while the KV was down")
	}
	if _, _, ok := c.Ceiling(ctx, "rate", ws); ok {
		t.Fatal("a pod admitted more than its share of a ceiling while the KV was down")
	}
	if _, ok := c.Quota(ctx, "ai", []Window{{Key: "day:u", Limit: 2, TTL: time.Hour}}); ok {
		t.Fatal("a quota's share rounds down: 2 over three pods is 0")
	}
}

// Spend's fallback is a share too: with the KV down, each of several pods admits
// the limit over the pods, rounded up, so they do not each admit the whole limit.
func TestAnUnansweringKVHoldsSpendToEachPodsShare(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct{ declared, want int }{{1, 5}, {2, 3}, {3, 2}} {
		c := over(down{ErrUnavailable}, newMem(), true, Config{Periods: fast, Self: Member{ID: "x"}, Secret: secret, Declared: tc.declared})
		admitted := 0
		for range 10 {
			if left, _ := c.Spend(ctx, "login", []string{"203.0.113.9"}, []int{1}, 5, time.Minute); left >= 0 {
				admitted++
			}
		}
		if admitted != tc.want {
			t.Fatalf("%d writers, KV down: one pod admitted %d of 5; want %d", tc.declared, admitted, tc.want)
		}
	}
}
