package locus

import (
	"database/sql"
	"errors"
	"testing"

	"github.com/hanzoai/namespace"
)

// With no server named a store is its SQLite file under the data directory, and a
// reopen reaches the same data.
func TestAStoreIsItsFileByDefault(t *testing.T) {
	t.Setenv(Env, "")
	dir := t.TempDir()
	ns := namespace.MustOrg("acme")
	db, err := Open(ns, "widget", dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE t (a INTEGER)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO t VALUES (7)`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	again, err := Open(ns, "widget", dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = again.Close() }()
	var a int
	if err := again.QueryRow(`SELECT a FROM t`).Scan(&a); err != nil || a != 7 {
		t.Fatalf("reopened locus: a=%d err=%v", a, err)
	}
	if place, err := Where(ns, "widget", dir); err != nil || place != OnFile {
		t.Fatalf("Where = %v, %v; want the file", place, err)
	}
}

type closer struct{ db *sql.DB }

func (c closer) Close() error { return c.db.Close() }

// A server named and no driver linked fails every open: a store never falls back
// to a file the deployment did not mean it to have.
func TestANamedServerWithNoDriverRefusesToOpen(t *testing.T) {
	t.Setenv(Env, "postgres://u@127.0.0.1:1/x")
	ns := namespace.MustOrg("acme")
	if _, err := Open(ns, "widget", t.TempDir()); !errors.Is(err, ErrNoServer) {
		t.Fatalf("Open = %v, want ErrNoServer", err)
	}
	if _, err := Use(t.Context(), nil, ns, "widget", t.TempDir(), func(db *sql.DB) (closer, error) { return closer{db}, nil }); !errors.Is(err, ErrNoServer) {
		t.Fatalf("Use = %v, want ErrNoServer", err)
	}
	if _, err := File(ns, "widget", t.TempDir()); !errors.Is(err, ErrNoServer) {
		t.Fatalf("File = %v, want ErrNoServer", err)
	}
}

func TestUseOpensAndMigratesOnTheFile(t *testing.T) {
	t.Setenv(Env, "")
	st, err := Use(t.Context(), nil, namespace.MustOrg("acme"), "widget", t.TempDir(), func(db *sql.DB) (closer, error) {
		_, err := db.Exec(`CREATE TABLE t (a INTEGER)`)
		return closer{db}, err
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = st.Close()
}
