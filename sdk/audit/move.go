package audit

// The chain's move from its SQLite file to hanzo-sql, while it is being written.
//
// locus.Move holds the file's write lock for the whole copy, and the live chain is
// 17 GB: every audited request in the fleet fails closed while it runs. audit_log is
// append-only and ordered by a gapless seq, which is exactly the shape locus.MoveOnline
// carries without stopping the writer: the history is copied while appends continue, and
// appends wait only for the tail that landed meanwhile.
//
// The writer is the recorder's own append loop, so "held still" is r.mu: Append takes it
// to commit, and the freeze takes it, then the file's write lock, for the tail. The
// switch to the schema's pool is made under r.mu too, so no append can land on the file
// after the registry says moved.
//
// The chains the fleet wrote before it appended through one holder (audit, audit-iam, ...)
// are never written, so they move with locus.Move, one at a time, after the live one.

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"time"

	"github.com/hanzoai/cloud/sdk/dialect"
	"github.com/hanzoai/cloud/sdk/locus"
	"github.com/hanzoai/namespace"
	luxlog "github.com/luxfi/log"
)

// moveRetry is how long the background move waits after an attempt that did not finish
// before it tries again; locus keeps a failed store a file for its own backoff first.
var moveRetry = 11 * time.Minute

// storeOpen is the store's own open over a database handle, for the schema a move
// makes: its migration, nothing else.
func storeOpen(db *sql.DB) (io.Closer, error) {
	if err := migrate(db); err != nil {
		return nil, err
	}
	return db, nil
}

// online describes this live chain to locus.MoveOnline.
func (r *Recorder) online() locus.Online {
	return locus.Online{
		Table:  "audit_log",
		Key:    "seq",
		Read:   r.read,
		Freeze: r.freeze,
		Switch: r.switchTo,
	}
}

// freeze holds the chain still and runs fn on the connection that holds the file's
// write lock. No append lands while it runs: Append commits under r.mu, which is held.
func (r *Recorder) freeze(ctx context.Context, fn func(locus.Querier) error) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	tx, err := r.d.BeginWrite(ctx, r.db)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if !r.d.Postgres() {
		// A deferred SQLite transaction takes the write lock at its first write; this
		// is a write that changes nothing, so the lock is held from here.
		if _, err := tx.ExecContext(ctx, `DELETE FROM audit_log WHERE 1 = 0`); err != nil {
			return err
		}
	}
	return fn(tx)
}

// switchTo makes the schema's pool the chain's: reads and the next append use it. It is
// called under r.mu, with the file's transaction still open; the file's handles are
// closed by the caller once that has ended.
func (r *Recorder) switchTo(db *sql.DB) {
	r.sm.Lock()
	defer r.sm.Unlock()
	r.retired = []*sql.DB{r.db}
	if r.read != r.db {
		r.retired = append(r.retired, r.read)
	}
	r.db, r.read, r.d = db, db, dialect.Of(db)
}

// MoveOnline moves this chain to hanzo-sql while it is appended to. The chain is its
// file until the registry says moved, whatever happens before: an error here is the
// chain still serving from the file.
func (r *Recorder) MoveOnline(ctx context.Context, log luxlog.Logger) (locus.Report, error) {
	return r.moveOnline(ctx, log, r.online())
}

func (r *Recorder) moveOnline(ctx context.Context, log luxlog.Logger, on locus.Online) (locus.Report, error) {
	rep, err := locus.MoveOnline(ctx, log, namespace.System(), r.name, r.dir, storeOpen, on)
	if err == nil {
		for _, db := range r.retired {
			_ = db.Close()
		}
		r.retired = nil
	}
	return rep, err
}

// StartMove moves the chains this deployment keeps to hanzo-sql in the background, when
// CLOUD_SQL_DSN and CLOUD_SQL_MOVE say to: this chain first, online, then the history
// chains. An attempt that does not finish is tried again every moveRetry. Close stops it.
func (r *Recorder) StartMove(log luxlog.Logger) {
	if r.db == nil || locus.DSN() == "" {
		return
	}
	mode, err := locus.MoveMode()
	if err != nil {
		if log != nil {
			log.Warn("audit: the chains are not moved", "err", err)
		}
		return
	}
	if mode == locus.Never {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	r.moveStop, r.moveDone = cancel, done
	go func() {
		defer close(done)
		for {
			if err := r.moveAll(ctx, log); err == nil || ctx.Err() != nil {
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(moveRetry):
			}
		}
	}()
}

func (r *Recorder) stopMove() {
	if r.moveStop != nil {
		r.moveStop()
		<-r.moveDone
		r.moveStop = nil
	}
}

// moveAll moves what is still a file, the live chain first. It reports the first
// failure after trying every chain, so one that cannot move does not hold back the rest.
func (r *Recorder) moveAll(ctx context.Context, log luxlog.Logger) error {
	var failed error
	note := func(name string, err error) {
		if err == nil {
			return
		}
		failed = errors.Join(failed, err)
		if log != nil && !errors.Is(err, locus.ErrBackoff) {
			log.Warn("audit: the chain stays on its file", "chain", name, "err", err)
		}
	}
	if place, err := locus.Where(namespace.System(), r.name, r.dir); err != nil {
		note(r.name, err)
	} else if place == locus.OnFile {
		_, err := r.MoveOnline(ctx, log)
		note(r.name, err)
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	names, err := chains(r.dir)
	if err != nil {
		return errors.Join(failed, err)
	}
	for _, name := range names {
		if name == r.name {
			continue
		}
		place, err := locus.Where(namespace.System(), name, r.dir)
		if err != nil {
			note(name, err)
			continue
		}
		if place == locus.OnServer {
			continue
		}
		_, err = locus.Move(ctx, log, namespace.System(), name, r.dir, storeOpen)
		note(name, err)
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	return failed
}
