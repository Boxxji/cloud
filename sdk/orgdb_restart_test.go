package cloud

// orgdb_restart_test.go — A KILLED PROCESS LOSES NO COMMITTED ROW.
//
// A host stops its subsystem processes without warning, so a store's last act is
// never a close: its database and -wal stay on the volume as the last commit left
// them. The next process must open that store and find every row, shipped or not,
// and the ship loop must then carry the local file to the object store.

import (
	"context"
	"testing"
	"time"

	"github.com/hanzoai/cloud/sdk/principal"
	"github.com/hanzoai/cloud/sdk/tenure"
	sqlitedrv "github.com/hanzoai/sqlite"
)

func TestRemountAfterKillFindsTheUnshippedRow(t *testing.T) {
	if !sqlitedrv.CodecLinked() {
		// The pure-Go envelope holds a keyed database's writes in a plaintext copy
		// until a seal, so a kill there loses them by construction; the shipped image
		// links the SQLCipher codec, which commits to the -wal on disk.
		t.Skip("needs the SQLCipher codec (CGO_ENABLED=1 -tags libsqlite3, linked against libsqlcipher)")
	}
	cond := &recordingStore{objects: map[string]versioned{}}
	members := tenure.NewMembership("pod-0", tenure.StaticSource(tenure.Member{ID: "pod-0", Addr: "pod-0"}), time.Minute)
	if err := members.Start(context.Background()); err != nil {
		t.Fatalf("membership: %v", err)
	}
	dur := tenure.NewDurability(cond, members, nil, tenure.WithSeal(sqlitedrv.Checkpoint), tenure.WithReader(OrgReader))
	dir := t.TempDir()
	ns := principal.MustOrgNamespace("acme", "")

	first := NewOrgStore(Base{DataDir: dir, Durable: dur}, "widget", openRows)
	db, err := first.For(ns)
	if err != nil {
		t.Fatalf("For: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO rows(v) VALUES(1)`); err != nil {
		t.Fatalf("write 1: %v", err)
	}
	if acked, err := first.Sync(ns); err != nil || !acked {
		t.Fatalf("ship 1: acked=%v err=%v", acked, err)
	}
	if _, err := db.Exec(`INSERT INTO rows(v) VALUES(2)`); err != nil {
		t.Fatalf("write 2: %v", err)
	}
	// Killed here: no CloseAll, no ship, no checkpoint. Its handle is left as a dead
	// process leaves its files.
	t.Cleanup(func() { _ = db.Close() })

	second := NewOrgStore(Base{DataDir: dir, Durable: dur}, "widget", openRows)
	t.Cleanup(func() { _ = second.CloseAll() })
	db2, err := second.For(ns)
	if err != nil {
		t.Fatalf("remount For: %v", err)
	}
	var n int
	if err := db2.QueryRow(`SELECT count(*) FROM rows`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 2 {
		t.Fatalf("remounted store holds %d rows, want 2: the row committed after the last ship was discarded", n)
	}

	before := cond.writes()
	second.shipChanged()
	if got := cond.writes(); got != before+1 {
		t.Fatalf("the ship loop made %d writes for a store kept ahead of its object, want 1", got-before)
	}
	second.shipChanged()
	if got := cond.writes(); got != before+1 {
		t.Fatalf("the ship loop shipped a store with nothing new in it (%d writes, want 1)", got-before)
	}
}
