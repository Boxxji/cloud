// Copyright 2025 Hanzo AI Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package tenure

// reconcile_test.go proves that hydrate never discards a committed local write. A
// process that is killed leaves its database and -wal on disk exactly as they were;
// the next process to open the store must find every row the last one committed,
// whether or not it shipped, and whatever the durable object says.

import (
	"context"
	"database/sql"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hanzoai/cloud/sdk/locus"
	"github.com/hanzoai/vfs/replica"
)

// crashImage copies a live store's files — database, -wal, -shm and mark — into a
// fresh directory while its handle is still open: what a kill leaves on the volume.
func crashImage(t *testing.T, path string) string {
	t.Helper()
	to := filepath.Join(t.TempDir(), filepath.Base(path))
	for _, side := range []string{"", "-wal", "-shm", ".durable"} {
		src, err := os.Open(path + side)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatalf("crash image %s: %v", side, err)
		}
		dst, err := os.Create(to + side)
		if err != nil {
			t.Fatalf("crash image %s: %v", side, err)
		}
		if _, err := io.Copy(dst, src); err != nil {
			t.Fatalf("crash image %s: %v", side, err)
		}
		src.Close()
		dst.Close()
	}
	return to
}

// podAt is newDurablePod over a given local path rather than a fresh one.
func podAt(cs replica.ConditionalStore, id string, set []Member, orgID, dbKey, path string) *durablePod {
	dy := NewDurability(cs, stubView{id: id, set: set}, nil)
	return &durablePod{id: id, d: dy.For(testNS(orgID), "research", dbKey, path)}
}

func openAt(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", testDSN(path))
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	locus.Single(db)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// shippedThenWrote is the state every case starts from: an owner that wrote k1 and
// shipped it, then wrote k2 and was killed before shipping again.
func shippedThenWrote(t *testing.T, cs replica.ConditionalStore, orgID, dbKey string) string {
	t.Helper()
	ctx := context.Background()
	p := newDurablePod(t, cs, "pod-a", []Member{{ID: "pod-a"}}, orgID, dbKey)
	if err := p.d.Hydrate(ctx); err != nil {
		t.Fatalf("hydrate: %v", err)
	}
	p.open(t)
	putKV(t, p.db, "k1", "v1")
	if acked, err := p.d.Sync(ctx); err != nil || !acked {
		t.Fatalf("ship k1: acked=%v err=%v", acked, err)
	}
	putKV(t, p.db, "k2", "v2")
	if fi, err := os.Stat(p.d.dbPath + "-wal"); err != nil || fi.Size() == 0 {
		t.Fatalf("k2 must be committed to the -wal and not yet in the database file: %v", err)
	}
	return crashImage(t, p.d.dbPath)
}

// TestRestartReplaysUnshippedWrites: kill after a commit, without a checkpoint or a
// ship, remount, and the row is there — and the next ship carries it.
func TestRestartReplaysUnshippedWrites(t *testing.T) {
	ctx := context.Background()
	cs := newFakeCondStore()
	const orgID = "acme"
	dbKey := replica.DBPath(orgID, "", "research")
	image := shippedThenWrote(t, cs, orgID, dbKey)

	next := podAt(cs, "pod-a", []Member{{ID: "pod-a"}}, orgID, dbKey, image)
	if err := next.d.Hydrate(ctx); err != nil {
		t.Fatalf("remount hydrate: %v", err)
	}
	if at := next.d.SetAside(); at != "" {
		t.Fatalf("the only writer's own file was set aside at %s", at)
	}
	next.open(t)
	if !hasKV(t, next.db, "k1") || !hasKV(t, next.db, "k2") {
		t.Fatal("remount lost a committed write: hydrate replaced the local file and its -wal with the older durable copy")
	}
	if !next.d.Dirty() {
		t.Fatal("a file kept ahead of the durable object must report dirty, or nothing ships it")
	}
	if acked, err := next.d.Sync(ctx); err != nil || !acked {
		t.Fatalf("ship after remount: acked=%v err=%v", acked, err)
	}
	if v, ok := durableValue(t, ctx, cs, dbKey, "k2"); !ok || v != "v2" {
		t.Fatalf("durable k2 = %q,%v after the ship, want v2,true", v, ok)
	}
	if next.d.Dirty() {
		t.Fatal("a store just shipped with nothing written since must not report dirty")
	}
}

// TestRestartWithoutAMarkKeepsTheLocalFile: a file written before marks existed has
// none, and nothing shows another writer shipped since — so it is kept, not replaced.
func TestRestartWithoutAMarkKeepsTheLocalFile(t *testing.T) {
	ctx := context.Background()
	cs := newFakeCondStore()
	const orgID = "acme"
	dbKey := replica.DBPath(orgID, "", "research")
	image := shippedThenWrote(t, cs, orgID, dbKey)
	if err := os.Remove(image + ".durable"); err != nil {
		t.Fatalf("drop mark: %v", err)
	}

	next := podAt(cs, "pod-a", []Member{{ID: "pod-a"}}, orgID, dbKey, image)
	if err := next.d.Hydrate(ctx); err != nil {
		t.Fatalf("hydrate: %v", err)
	}
	next.open(t)
	if !hasKV(t, next.db, "k2") {
		t.Fatal("an unmarked local file was replaced by the durable copy, discarding its -wal")
	}
}

// TestReadOnlyHydrateKeepsTheLocalFile: the non-owner path reconciles too.
func TestReadOnlyHydrateKeepsTheLocalFile(t *testing.T) {
	ctx := context.Background()
	cs := newFakeCondStore()
	const orgID = "acme"
	dbKey := replica.DBPath(orgID, "", "research")
	image := shippedThenWrote(t, cs, orgID, dbKey)

	// A view that elects someone else: this pod hydrates read-only.
	set := []Member{{ID: "pod-a"}, {ID: "pod-b"}, {ID: "pod-c"}}
	self := "pod-a"
	for _, m := range set {
		if m.ID != electedOwnerID(orgID, set) {
			self = m.ID
			break
		}
	}
	ro := podAt(cs, self, set, orgID, dbKey, image)
	if err := ro.d.Hydrate(ctx); err != nil {
		t.Fatalf("read-only hydrate: %v", err)
	}
	if ro.d.Owned() {
		t.Fatal("this pod is not elected; the case needs the read-only path")
	}
	db := openAt(t, image)
	ensureKV(t, db)
	if !hasKV(t, db, "k2") {
		t.Fatal("the read-only hydrate replaced the local file and discarded its -wal")
	}
}

// TestHydrateSetsADivergedFileAside: when another writer shipped after the local
// file last reconciled, the object wins — and the local file, which holds a write
// the object never saw, is renamed beside it, never removed.
func TestHydrateSetsADivergedFileAside(t *testing.T) {
	ctx := context.Background()
	cs := newFakeCondStore()
	const orgID = "acme"
	dbKey := replica.DBPath(orgID, "", "research")
	image := shippedThenWrote(t, cs, orgID, dbKey)

	// Another replica takes the org over, writes k3 and ships at a higher round.
	b := newDurablePod(t, cs, "pod-b", []Member{{ID: "pod-b"}}, orgID, dbKey)
	if err := b.d.Hydrate(ctx); err != nil {
		t.Fatalf("b hydrate: %v", err)
	}
	b.open(t)
	putKV(t, b.db, "k3", "v3")
	if acked, err := b.d.Sync(ctx); err != nil || !acked {
		t.Fatalf("b ship: acked=%v err=%v", acked, err)
	}

	back := podAt(cs, "pod-a", []Member{{ID: "pod-a"}}, orgID, dbKey, image)
	if err := back.d.Hydrate(ctx); err != nil {
		t.Fatalf("a hydrate: %v", err)
	}
	at := back.d.SetAside()
	if at == "" || !strings.HasPrefix(at, image+".aside-") {
		t.Fatalf("SetAside = %q, want %s.aside-<n>: the diverged file must be kept and named", at, image)
	}
	back.open(t)
	if !hasKV(t, back.db, "k1") || !hasKV(t, back.db, "k3") {
		t.Fatal("the restored store is not the object the other writer shipped")
	}
	if hasKV(t, back.db, "k2") {
		t.Fatal("the diverged write k2 is in the live store; it belongs in the copy set aside")
	}
	aside := openAt(t, at)
	if !hasKV(t, aside, "k2") {
		t.Fatal("the file set aside lost k2: its -wal did not travel with it")
	}
}
