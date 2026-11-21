package locus

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hanzoai/cloud/sdk/env"
)

// Place is where a store lives now.
type Place int

const (
	// OnFile: the store is its encrypted SQLite file under the data directory.
	OnFile Place = iota
	// OnServer: the store is on the server the deployment names.
	OnServer
)

// ErrMoving is what a store answers while another process is moving it to the
// server. It is retried, not served.
var ErrMoving = errors.New("locus: the store is being moved to the server")

// ErrBackoff is the answer for a store whose last move failed a short while ago.
var ErrBackoff = errors.New("locus: a move of this store failed recently and is not tried again yet")

// MoveEnv names the policy for stores that are still files while a server is named.
//
//	(unset)  they stay files: naming the server moves nothing
//	lazy     a store is moved the first time this process opens it
//	sweep    lazy, and a background walk moves the rest, smallest first, one at a time
const MoveEnv = "CLOUD_SQL_MOVE"

// Mode is the move policy.
type Mode string

const (
	Never Mode = ""
	Lazy  Mode = "lazy"
	Sweep Mode = "sweep"
)

// MoveMode reads the policy. A word it does not know is an error and not a guess: a
// typo would otherwise leave every store a file under a deployment that meant to move.
func MoveMode() (Mode, error) {
	switch m := Mode(strings.TrimSpace(env.Or(MoveEnv, ""))); m {
	case Never, Lazy, Sweep:
		return m, nil
	default:
		return Never, fmt.Errorf("%s=%q: it is lazy or sweep, or unset", MoveEnv, string(m))
	}
}

// Report is what one move did.
type Report struct {
	// Already is set when the store had been moved before the call took its lock.
	Already bool
	Tables  []TableReport
	Rows    int64
	Bytes   int64
	Took    time.Duration
	Dropped []string // what the file has that the server's tables do not
}

// TableReport is one table of a move.
type TableReport struct {
	Name  string
	Rows  int64
	Bytes int64
	Took  time.Duration
}

// Querier is what a move reads a file through: a connection, a transaction or a pool.
type Querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// Online describes a live store for [MoveOnline].
type Online struct {
	// Table is the store's one append-only table and Key its integer column that only
	// ever rises: rows are added in key order, and never updated or deleted.
	Table, Key string
	// Batch is how many rows phase 1 copies at a time; 0 is 10,000.
	Batch int
	// Read is a handle on the file for phase 1.
	Read Querier
	// Freeze runs fn while no row can be appended and the file's write lock is held.
	Freeze func(ctx context.Context, fn func(Querier) error) error
	// Switch is told, inside the freeze and after the move, the pool the store lives on.
	Switch func(*sql.DB)
}

// Files is a store that is not a handle over one database: an engine that opens its
// own SQLite file from a path and its own server pool from a schema.
type Files struct {
	// Path is the SQLite file. It must exist, and it is plain.
	Path string
	// Settle brings the file to the shape the current code writes and lets go of it.
	Settle func() error
	// Make makes the store's tables on the server, as the engine's own open makes
	// them, and closes everything it opened before it answers. dial answers a pool of
	// its own onto the store each time; the pool is Make's to close.
	Make func(dial func() (*sql.DB, error)) error
}

// Host hands out pools on one store of the server. Each call returns a pool of its
// own, which the caller sizes and closes.
type Host func() (*sql.DB, error)
