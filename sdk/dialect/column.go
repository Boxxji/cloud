package dialect

import (
	"context"
	"database/sql"
	"fmt"
)

// Bytewise is the collation of a TEXT column that is ordered or read by range:
// write `entity TEXT NOT NULL ` + d.Bytewise(). SQLite compares text by its bytes;
// PostgreSQL by the database's collation, under which `entity >= 'acme/' AND entity
// < 'acme0'` is not the keys that start with `acme/`, ORDER BY disagrees with the
// order SQLite gave, and a prefix read walks the wrong index range. "C" is bytes.
// A column only compared for equality needs none.
func (d Dialect) Bytewise() string {
	if d.postgres {
		return `COLLATE "C"`
	}
	return ``
}

// Clustered is the tail of a CREATE TABLE whose primary key is its whole use, an
// inverted index read as a run of keys: write `) ` + d.Clustered(). SQLite stores
// the table in the key's own b-tree instead of beside it (WITHOUT ROWID); PostgreSQL
// has no such table, and the key's index is the nearest thing it offers.
func (d Dialect) Clustered() string {
	if d.postgres {
		return ``
	}
	return `WITHOUT ROWID`
}

// HasTable reports whether the schema the handle is on has the table, as HasColumn
// does for a column. A view or an index of that name is not a table.
func (d Dialect) HasTable(ctx context.Context, q Querier, table string) (bool, error) {
	query := `SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = $1`
	if d.postgres {
		query = `SELECT COUNT(*) FROM information_schema.tables
		          WHERE table_schema = current_schema() AND table_name = $1 AND table_type = 'BASE TABLE'`
	}
	var n int
	if err := q.QueryRowContext(ctx, query, table).Scan(&n); err != nil {
		return false, err
	}
	return n > 0, nil
}

// Join is the keyword of a join the engine reads in the order it is written, the
// table on its left the outer loop and the table on its right fetched once per row
// of it. SQLite's planner will otherwise choose, and it has chosen to walk every
// document a workspace holds and probe the matches for each; its CROSS JOIN is the
// instruction not to. PostgreSQL has no such instruction (its CROSS JOIN takes no
// ON), plans from its statistics, and is given a plain JOIN.
func (d Dialect) Join() string {
	if d.postgres {
		return `JOIN`
	}
	return `CROSS JOIN`
}

// Analyze refreshes the planner's statistics for the tables after a bulk write, in
// the transaction that made it. PostgreSQL plans from them, and a table filled in
// one statement has none until autovacuum looks, which can be a minute: in that
// minute a join of a range of it to its documents is planned as a nested loop that
// rescans the documents for every match (20,000 documents took 18 seconds to ask
// one word of). SQLite is left to the plans it was tuned with, which a collected
// sqlite_stat1 would change, so there it is nothing.
func (d Dialect) Analyze(ctx context.Context, tx Executor, tables ...string) error {
	if !d.postgres {
		return nil
	}
	for _, t := range tables {
		if !named.MatchString(t) {
			return fmt.Errorf("dialect: %q is not a plain identifier", t)
		}
		if _, err := tx.ExecContext(ctx, `ANALYZE "`+t+`"`); err != nil {
			return err
		}
	}
	return nil
}

// Executor is the one write a *sql.DB and a *sql.Tx both answer.
type Executor interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}
