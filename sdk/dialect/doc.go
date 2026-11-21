// Package dialect is the one place the two engines a store can run on differ.
//
// A store's SQL is written once and runs on SQLite and on PostgreSQL (hanzo-sql):
// numbered $n placeholders, INSERT ... ON CONFLICT, explicit id columns instead of
// rowid, times as integers set from Go, ->> for JSON. Those are the statements the
// engines agree on. What they do not agree on is DDL, and the few operations that
// ask the catalog or a lock a question the other engine answers differently. Each
// of those is a method here, answered by the engine the handle is on, so a store
// has no `if postgres` of its own.
//
// The engine is read off the handle's driver, never configured: a *sql.DB from
// locus.Open is on whichever engine the deployment chose, and the store cannot be
// told the wrong one.
package dialect
