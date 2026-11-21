package tenure

import (
	"context"
	"errors"
	"testing"

	"github.com/hanzoai/cloud/sdk/object"
	"github.com/hanzoai/vfs/replica"
)

// The fence over the process's object store (local disk here): a create that finds the
// object, a write against a stale version, and a write against the current one.
func TestConditionalWritesAreCompareAndSet(t *testing.T) {
	ctx := context.Background()
	store := &object.Local{Dir: t.TempDir()}
	if err := store.Ensure(ctx, "orgs"); err != nil {
		t.Fatal(err)
	}
	cs := NewConditional(store, "orgs")
	if _, _, err := cs.Get(ctx, "k"); !errors.Is(err, replica.ErrNotFound) {
		t.Fatalf("get of an absent key = %v, want ErrNotFound", err)
	}
	v1, err := cs.PutIfVersion(ctx, "k", []byte("one"), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cs.PutIfVersion(ctx, "k", []byte("again"), ""); !errors.Is(err, replica.ErrConflict) {
		t.Fatalf("second create = %v, want ErrConflict", err)
	}
	if _, err := cs.PutIfVersion(ctx, "k", []byte("stale"), `"0123456789abcdef0123456789abcdef"`); !errors.Is(err, replica.ErrConflict) {
		t.Fatalf("stale write = %v, want ErrConflict", err)
	}
	v2, err := cs.PutIfVersion(ctx, "k", []byte("two"), v1)
	if err != nil || v2 == v1 {
		t.Fatalf("current write = %q, %v", v2, err)
	}
	data, v, err := cs.Get(ctx, "k")
	if err != nil || string(data) != "two" || v != v2 {
		t.Fatalf("get = %q %q %v", data, v, err)
	}
	keys, err := cs.List(ctx, "")
	if err != nil || len(keys) != 1 || keys[0] != "k" {
		t.Fatalf("list = %v %v", keys, err)
	}
}
