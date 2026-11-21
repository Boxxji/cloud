package coord

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
)

// Pods of one Memory that declare two writers and share a Leases store run a loop on
// the one that claims it first, and the other is told ErrNotHeld at once: the pass a
// replica's test asks of its pods is what production gives them.
func TestReplicasOfAMemoryLeadOneLoop(t *testing.T) {
	m, leases := NewMemory(), NewLeases()
	a, b := m.Replica("cloud-0", 2, leases), m.Replica("cloud-1", 2, leases)
	t.Cleanup(func() { a.Close(context.Background()); b.Close(context.Background()) })

	var ran atomic.Int64
	held, notHeld := 0, 0
	for _, c := range []*Coord{a, b} {
		switch err := c.Lead("sweep").Do(context.Background(), func(context.Context) { ran.Add(1) }); {
		case err == nil:
			held++
		case errors.Is(err, ErrNotHeld):
			notHeld++
		default:
			t.Fatalf("Do: %v", err)
		}
	}
	if held != 1 || notHeld != 1 || ran.Load() != 1 {
		t.Fatalf("two replicas ran the loop %d times (%d held, %d refused); want it once", ran.Load(), held, notHeld)
	}
}

// A process is named by its pod and a nonce no other process of the pod shares: a record
// that carries it names this incarnation, and a question to it reaches this process and
// not the one that held the pod's id before.
func TestAnOwnerNamesTheProcessAndNotThePod(t *testing.T) {
	m := NewMemory()
	before, after := m.Pod("cloud-0"), m.Pod("cloud-0")
	t.Cleanup(func() { before.Close(context.Background()); after.Close(context.Background()) })
	for _, c := range []*Coord{before, after} {
		if got := c.Owner(); !strings.HasPrefix(got, "cloud-0#") || len(got) <= len("cloud-0#") {
			t.Fatalf("owner %q does not name the pod and a nonce", got)
		}
	}
	if before.Owner() == after.Owner() {
		t.Fatalf("two processes of one pod share the owner %q", before.Owner())
	}
}
