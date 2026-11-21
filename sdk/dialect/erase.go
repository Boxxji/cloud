package dialect

import (
	"context"
	"database/sql"
)

// erase.go — what an erasure asks of the file it leaves.
//
// A DELETE removes a row from every read; it does not remove the bytes. SQLite keeps
// them in the file's free pages and, in WAL mode, in frames the delete has not yet
// outlived. An erasure that is owed to a person is owed in the file, so a store that
// erases says so to the dialect and the dialect does what the engine can.

// Shred makes the deletes tx goes on to make leave nothing behind in the database
// file, for the tables of the Words indexes named. SQLite zeroes the pages a delete
// frees (secure_delete) and has each index drop the deleted terms rather than mask
// them. PostgreSQL has no file for a statement to scrub: the delete leaves a dead row
// for VACUUM to reclaim, and the WAL, the replicas and the backups keep what they were
// sent for as long as the server retains it. On PostgreSQL an erasure is its commit,
// and how long a deleted row survives is the server's retention to bound.
func (d Dialect) Shred(ctx context.Context, tx *sql.Tx, indexes ...Words) error {
	if d.postgres {
		return nil
	}
	if _, err := tx.ExecContext(ctx, `PRAGMA secure_delete = ON`); err != nil {
		return err
	}
	for _, w := range indexes {
		fts := w.table + "_fts"
		if _, err := tx.ExecContext(ctx, `INSERT INTO `+fts+`(`+fts+`, rank) VALUES ('secure-delete', 1)`); err != nil {
			return err
		}
	}
	return nil
}

// Flush takes the frames written before a committed erasure out of the write-ahead
// log, so the file no longer holds what was erased. SQLite checkpoints and truncates
// the log; PostgreSQL has no log of the file's to take them from.
func (d Dialect) Flush(ctx context.Context, db *sql.DB) error {
	if d.postgres {
		return nil
	}
	_, err := db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`)
	return err
}

// Index is the clause that makes a query read a table through the named index. SQLite's
// planner prefers a constraint it can seek (`relation IN (...)`) to a range it can
// walk (`entity >= x AND entity < y`) and will scan every row under a relation to
// avoid the range; INDEXED BY says which. PostgreSQL has no such clause and plans from
// its statistics, so there it is nothing: write `FROM t` + d.Index("t_idx") + ` WHERE`.
func (d Dialect) Index(name string) string {
	if d.postgres {
		return ``
	}
	return ` INDEXED BY ` + name
}
