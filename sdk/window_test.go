package cloud

import (
	"fmt"
	"testing"
	"time"

	"github.com/hanzoai/ai/address"
)

// A key spends its own window, a refused request still counts, and a key whose
// window has ended is admitted again.
func TestWindow(t *testing.T) {
	w := NewWindow("test", 1, 20*time.Millisecond)
	if !w.Take("a") {
		t.Fatal("the first request was refused")
	}
	if w.Take("a") || w.Take("a") {
		t.Fatal("a key over its limit was admitted")
	}
	if !w.Take("b") {
		t.Fatal("another key shares the first key's window")
	}
	time.Sleep(30 * time.Millisecond)
	if !w.Take("a") {
		t.Fatal("a key whose window expired was refused")
	}
}

// An IPv6 caller is charged to its /64 and to its /48 at sixteen times the limit, so a
// site moving across its /64s is sixteen callers; an IPv4 address is one bucket.
func TestWindowCountsASiteBySlash48(t *testing.T) {
	w := NewWindow("test", 1, time.Minute)
	for i := range 16 {
		if !w.Take(fmt.Sprintf("2001:470:1f00:%x::1", i)) {
			t.Fatalf("/64 %d of 16 in one /48 was refused", i+1)
		}
	}
	if w.Take("2001:470:1f00:ffff::1") {
		t.Fatal("a 17th /64 of a /48 that spent sixteen limits was admitted")
	}
	if !w.Take("2001:470:1f01::1") || !w.Take("203.0.113.7") {
		t.Fatal("another site was refused")
	}
}

// fullSite leaves w with addr's /64 full for short and its /48 full for long, by
// spending the /48 from other /64s inside it.
func fullSite(w *Window, addr string, limit int, short, long time.Duration) {
	b := address.Buckets(addr)
	other := func(i int) []address.Bucket { return address.Buckets(fmt.Sprintf("2001:470:1f00:%x::1", 0x100+i)) }
	w.Spend(other(0), limit, long) // opens the /48 for long
	spent := 1
	for range limit {
		w.Spend(b, limit, short)
		spent++
	}
	for i := 1; spent < limit*b[1].Scale; i++ {
		w.Spend(other(i), limit, long)
		spent++
	}
}

// Spend answers when the caller may next be admitted: past a refusing /64, a /48 that
// is full and resets later sets the reset, and is read, never charged. With room
// everywhere it is the tightest bucket's.
func TestWindowResetWaitsForEveryFullBucket(t *testing.T) {
	w := NewWindow("test", 2, time.Minute)
	const addr = "2001:470:1f00:1::1"
	fullSite(w, addr, 2, 5*time.Second, 50*time.Second)
	left, reset := w.Spend(address.Buckets(addr), 2, time.Minute)
	if left >= 0 {
		t.Fatalf("a full /64 admitted, left=%d", left)
	}
	if time.Until(reset) < 49*time.Second {
		t.Fatalf("reset in %v; the /48 is full for 50s", time.Until(reset).Round(time.Second))
	}
	// The /48 was not charged for the refused request: a neighbour /64 is still refused
	// by it alone, at exactly its limit.
	if left, _ := w.Spend(address.Buckets("2001:470:1f00:ffff::1"), 2, time.Minute); left != -1 {
		t.Fatalf("a neighbour behind the full /48: left=%d, want -1 (the /48 charged once more, never twice)", left)
	}

	fresh := NewWindow("test", 2, time.Minute)
	left, reset = fresh.Spend(address.Buckets("2001:470:1f00:2::1"), 2, time.Minute)
	if left != 1 || time.Until(reset) < 59*time.Second {
		t.Fatalf("a fresh caller: left=%d reset in %v, want 1 and the window", left, time.Until(reset).Round(time.Second))
	}
}
