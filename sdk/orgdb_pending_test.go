package cloud

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hanzoai/cloud/sdk/principal"
	"github.com/hanzoai/namespace"
)

// A sweep opens only the orgs that were asked for and not since settled — never
// every org on disk.
func TestOrgStoreEachOpensOnlyPending(t *testing.T) {
	dir := t.TempDir()
	open := func(n *int) *OrgStore[*sql.DB] {
		return NewOrgStore(Base{DataDir: dir}, "widget", func(db *sql.DB) (*sql.DB, error) { *n++; return db, nil })
	}
	nsA, nsB := principal.MustOrgNamespace("orga", ""), principal.MustOrgNamespace("orgb", "")

	var n1 int
	s1 := open(&n1)
	for _, ns := range []namespace.Namespace{nsA, nsB} {
		if _, err := s1.For(ns); err != nil {
			t.Fatal(err)
		}
	}
	_ = s1.CloseAll()

	// A restart still knows both are pending; settling one takes it out.
	var n2 int
	s2 := open(&n2)
	s2.loadPending()
	s2.Settle(nsB, time.Now())
	_ = s2.CloseAll()

	var n3 int
	s3 := open(&n3)
	t.Cleanup(func() { _ = s3.CloseAll() })
	var seen []namespace.Namespace
	if err := s3.Each(func(ns namespace.Namespace, _ *sql.DB, err error) {
		if err != nil {
			t.Fatal(err)
		}
		seen = append(seen, ns)
	}); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 1 || seen[0] != nsA || n3 != 1 {
		t.Fatalf("Each visited %v with %d opens, want only orga with 1", seen, n3)
	}

	// A handle just handed out may still be written through, so it is not settled.
	if _, err := s3.For(nsB); err != nil {
		t.Fatal(err)
	}
	s3.Settle(nsB, time.Now())
	if _, err := os.Stat(filepath.Join(dir, "orgs", "orgb", "widget.db.pending")); err != nil {
		t.Fatalf("orgb was settled while its handle was fresh: %v", err)
	}
}

// A volume no release has swept carries no marks: every org with the store is
// pending once, so the first sweep sees work written before the upgrade.
func TestOrgStorePendingBackfill(t *testing.T) {
	dir := t.TempDir()
	var n int
	s1 := NewOrgStore(Base{DataDir: dir}, "widget", func(db *sql.DB) (*sql.DB, error) { n++; return db, nil })
	if _, err := s1.For(principal.MustOrgNamespace("orga", "")); err != nil {
		t.Fatal(err)
	}
	_ = s1.CloseAll()
	_ = os.Remove(filepath.Join(dir, "orgs", "orga", "widget.db.pending"))
	_ = os.RemoveAll(filepath.Join(dir, "orgs", "_pending"))

	s2 := NewOrgStore(Base{DataDir: dir}, "widget", func(db *sql.DB) (*sql.DB, error) { return db, nil })
	t.Cleanup(func() { _ = s2.CloseAll() })
	var seen int
	_ = s2.Each(func(namespace.Namespace, *sql.DB, error) { seen++ })
	if seen != 1 {
		t.Fatalf("backfill swept %d orgs, want 1", seen)
	}
}
