package tenure

// field_sql.go — the legacy path: rows written before a column was sealed.
//
// A SQLite file from before a column was sealed holds plaintext in it. The file is
// SQLCipher, so the plaintext was ciphertext on disk, and the store must still read it. It
// does so by sealing those values in place at open, before the first read, rather than by
// teaching Open to pass plaintext through:
//
//   - A reader that passes plaintext through also accepts plaintext someone WROTE: a
//     role with UPDATE (an injection in a neighbouring store shares the role) could set
//     a column to a value of its choosing and have it read as the store's own. Row.Open
//     refuses what is not sealed, so a sealed column authenticates or it fails.
//   - The same file is what cmd/sqlmove copies to hanzo-sql. Sealed in place, its rows
//     cross as the bytes they are, and no plaintext reaches Postgres on the way; the
//     format does not depend on the engine, which is why sealing runs on SQLite too and
//     there is one code path to read.
//
// Upgrade is for SQLite files only: hanzo-sql tables are born sealed, so there is nothing
// to repair there, and a scan of every row at every pod's start would be a cost with no
// return. On hanzo-sql it does nothing. Plaintext found there is a defect and Row.Open
// reports it.
//
// THE UPGRADE IS A SEQUENCE OF SMALL TRANSACTIONS, not one. A book of half a million rows
// is sealed in a few hundred batches, each of which commits on its own, so progress is
// durable: a pod killed half way, or a batch that fails, leaves the rows already sealed
// sealed, and the next open finds the rest by the same test. It runs after the store's
// migration has committed and before the store is handed to a reader, and is bounded by
// progress (each batch has a limit) and not by a wall clock over the whole: a clock over
// the whole would roll back everything it had done and fail again in the same place on
// every boot, for a book that is only large. The store does not open while it runs,
// because Row.Open refuses the plaintext the rest of the book still holds.

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/hanzoai/cloud/sdk/dialect"
)

// upgradeRows is how many rows one transaction seals. Rows are read whole before any is
// written, so the connection is free for the updates (SQLite has one).
const upgradeRows = 1000

// upgradeStall is how long one batch may take. A batch that has not finished by then is
// not slow but stuck (a lock never released, a disk gone), and the open fails rather than
// wait for it.
const upgradeStall = time.Minute

var sqlIdent = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// Upgrade seals, in place, every non-empty value of columns that is not already sealed,
// in the table whose natural key is key (column names, in the order Fields.Row lists them),
// and returns how many values it sealed. It is idempotent: a sealed value is never
// touched, so a second pass seals nothing and rewrites nothing.
//
// It walks the table in rowid order, upgradeBatch rows that need sealing at a time, each
// batch in a transaction of its own that starts after the last rowid of the one before.
// Every batch therefore reads each row once and the whole is linear in the table, and
// each row is found and written by its rowid, which is the table itself and not an index
// someone must have remembered to make: a key that is not unique, or has no index (a
// ledger line is keyed by its voucher and account, and a voucher may touch an account
// twice), costs nothing and misses no row. The key is only what the value is bound to.
// The columns being sealed must not be in it, since sealing one would change what its row
// is bound to.
//
// Names are SQL identifiers and are checked as such, because they are written into the
// statement; they are constants of the store, never input.
func (f *Fields) Upgrade(ctx context.Context, db *sql.DB, table string, key, columns []string) (int, error) {
	if err := upgradeCheck(table, key, columns); err != nil {
		return 0, err
	}
	if dialect.Of(db).Postgres() {
		return 0, nil
	}
	total := 0
	var after []any // the rowid the walk reached; none at the start
	for {
		read, sealed, last, err := f.upgradeBatch(ctx, db, table, key, columns, after)
		total += sealed
		if err != nil {
			return total, err
		}
		if read < upgradeRows {
			return total, nil // the walk reached the end of the table
		}
		after = []any{last}
	}
}

// UpgradeTx is Upgrade in a transaction the caller holds, for a table whose guards the
// migration lifts around the seal and puts back before it commits (a trigger that keeps a
// record final refuses the write that seals it): the seal must happen where they are down.
// It commits nothing and is bounded by the caller's context and transaction, so it is for a
// table that is small, and the caller states the engine, since a transaction cannot: it is
// for SQLite files only.
func (f *Fields) UpgradeTx(ctx context.Context, tx *sql.Tx, table string, key, columns []string) (int, error) {
	if err := upgradeCheck(table, key, columns); err != nil {
		return 0, err
	}
	total := 0
	var after []any
	for {
		read, sealed, last, err := f.upgradeStep(ctx, tx, table, key, columns, after)
		total += sealed
		if err != nil {
			return total, err
		}
		if read < upgradeRows {
			return total, nil
		}
		after = []any{last}
	}
}

// upgradeCheck refuses what Upgrade must not write into a statement or seal.
func upgradeCheck(table string, key, columns []string) error {
	for _, name := range append(append([]string{table}, key...), columns...) {
		if !sqlIdent.MatchString(name) {
			return fmt.Errorf("org: %q is not a plain SQL identifier", name)
		}
	}
	if len(key) == 0 || len(columns) == 0 {
		return ErrFieldRow
	}
	for _, c := range columns {
		if slices.Contains(key, c) {
			return fmt.Errorf("org: %s is both the key of %s and a column to seal: sealing it would change what its row is bound to", c, table)
		}
	}
	return nil
}

// upgradeQuery is the read of one batch: the rowid and the key and the columns of the rows,
// in rowid order, that have a value to seal, upgradeRows of them, and when after the rows
// past a rowid ($1).
//
// A value needs sealing when it is not empty and does not begin with the prefix. The
// comparison is on the first characters, which are ASCII, so it is case-sensitive.
func upgradeQuery(table string, key, columns []string, after bool) string {
	var need []string
	for _, c := range columns {
		need = append(need, fmt.Sprintf("(%s <> '' AND substr(%s, 1, %d) <> '%s')", c, c, len(fieldPrefix), fieldPrefix))
	}
	where := "(" + strings.Join(need, " OR ") + ")"
	if after {
		where = "rowid > $1 AND " + where
	}
	return fmt.Sprintf("SELECT rowid, %s FROM %s WHERE %s ORDER BY rowid LIMIT %d",
		strings.Join(append(append([]string{}, key...), columns...), ", "), table, where, upgradeRows)
}

// upgradeBatch seals one batch in a transaction of its own.
func (f *Fields) upgradeBatch(ctx context.Context, db *sql.DB, table string, key, columns []string, after []any) (read, sealed int, last int64, err error) {
	ctx, cancel := context.WithTimeout(ctx, upgradeStall)
	defer cancel()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("org: seal %s: %w", table, err)
	}
	defer func() { _ = tx.Rollback() }()
	read, sealed, last, err = f.upgradeStep(ctx, tx, table, key, columns, after)
	if err != nil {
		return 0, 0, 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, 0, fmt.Errorf("org: seal %s: %w", table, err)
	}
	return read, sealed, last, nil
}

// upgradeStep seals the next batch in tx and answers how many rows it read, how many values
// it sealed, and the rowid of the last row it read.
func (f *Fields) upgradeStep(ctx context.Context, tx *sql.Tx, table string, key, columns []string, after []any) (read, sealed int, last int64, err error) {
	rows, err := tx.QueryContext(ctx, upgradeQuery(table, key, columns, after != nil), after...)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("org: read %s: %w", table, err)
	}
	type row struct {
		rowid int64
		key   []string
		vals  []sql.NullString
	}
	var found []row
	for rows.Next() {
		r := row{key: make([]string, len(key)), vals: make([]sql.NullString, len(columns))}
		dest := []any{&r.rowid}
		for i := range r.key {
			dest = append(dest, &r.key[i])
		}
		for i := range r.vals {
			dest = append(dest, &r.vals[i])
		}
		if err := rows.Scan(dest...); err != nil {
			_ = rows.Close()
			return 0, 0, 0, fmt.Errorf("org: read %s: %w", table, err)
		}
		found = append(found, r)
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return 0, 0, 0, fmt.Errorf("org: read %s: %w", table, err)
	}

	for _, r := range found {
		at := f.Row(table, r.key...)
		var args []any
		var sets []string
		for i, c := range columns {
			v := r.vals[i].String
			if v == "" || strings.HasPrefix(v, fieldPrefix) {
				continue
			}
			args = append(args, at.Seal(c, v))
			sets = append(sets, fmt.Sprintf("%s = $%d", c, len(args)))
		}
		if err := at.Err(); err != nil {
			return 0, 0, 0, err
		}
		if len(sets) == 0 {
			continue
		}
		args = append(args, r.rowid)
		res, err := tx.ExecContext(ctx, fmt.Sprintf("UPDATE %s SET %s WHERE rowid = $%d", table, strings.Join(sets, ", "), len(args)), args...)
		if err != nil {
			return 0, 0, 0, fmt.Errorf("org: write %s: %w", table, err)
		}
		if n, err := res.RowsAffected(); err == nil && n == 0 {
			continue // the row is gone
		}
		sealed += len(sets)
	}
	if len(found) > 0 {
		last = found[len(found)-1].rowid
	}
	return len(found), sealed, last, nil
}
