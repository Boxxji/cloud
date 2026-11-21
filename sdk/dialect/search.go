package dialect

// search.go — full-text search, where the two engines share nothing.
//
// SQLite searches with FTS5, a virtual table beside the table it indexes. PostgreSQL
// has no such table: a searchable text is a column of the row (tsvector), indexed in
// place (GIN), and a substring is found through the pg_trgm extension. The two
// shapes differ in their DDL, in what a query looks like and in how a match is
// ranked, so a store asks for one of these and writes none of it:
//
//   - Words finds rows by the words in some of their columns, a caller's words
//     matching as the beginnings of words (`depl` finds `deploy`). SQLite: FTS5
//     unicode61 over the table's own content. PostgreSQL: a tsvector column the row
//     generates, with a GIN index.
//   - Grams finds rows by a substring of a text the caller supplies, however small
//     a part of a word (`seErr` finds `parseError`). SQLite: FTS5 trigram. PostgreSQL:
//     a table of the texts with a pg_trgm GIN index.
//
// Both answer a query as Hits: a subquery of `hit`, the key of a matching row, and
// `score`, which sorts ascending with the best match first. Callers join it to
// their own table and add every other narrowing there, so a search is one term of
// a read and not a read of its own.
//
// WHAT THE ENGINES AGREE ON, and tests hold them to: the same rows come back for the
// same query. A word is the run of letters and digits between anything else, so
// `acme/svc/api` is the words acme, svc and api and `go1.25` is go1 and 25; a term is
// one or more of them, adjacent and in order, and the last may be a beginning; case
// does not matter. WHAT THEY DO NOT: the order of equal-looking matches (bm25 on
// SQLite, ts_rank on PostgreSQL, which has no notion of a word's rarity), and
// SQLite folds diacritics (`cafe` finds `café`) where PostgreSQL's simple dictionary
// does not.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Words is a full-text index over text columns of one table, read by word.
type Words struct {
	d     Dialect
	table string
	key   string
	cols  []string
}

// Words names the index over columns of table, whose integer primary key is key.
// The index is a column of the table on PostgreSQL named fts, so a table has one
// and none of its columns is called that; the table and column names are plain
// lowercase identifiers, which are written into DDL.
func (d Dialect) Words(table, key string, columns ...string) (Words, error) {
	names := append([]string{table, key}, columns...)
	if len(columns) == 0 {
		return Words{}, errors.New("dialect: an index over no columns")
	}
	for _, n := range names {
		if !identifier.MatchString(n) {
			return Words{}, fmt.Errorf("dialect: %q is not a plain identifier", n)
		}
	}
	for _, c := range columns {
		if c == "fts" {
			return Words{}, errors.New("dialect: a column called fts is the index's own")
		}
	}
	return Words{d: d, table: table, key: key, cols: columns}, nil
}

// Create makes the index, once, inside the store's migration (tx is the one Migrate
// hands its func), and fills it from the rows the table already holds. It is
// idempotent: an index that exists is left as it is.
//
// SQLite keeps the index in a virtual table of EXTERNAL CONTENT, <table>_fts: it
// holds the terms and the key to find a row by, never a copy of the text, so a read
// still comes from the table and the two cannot disagree. Triggers keep it current
// through insert, delete and an update of an indexed column. A file that predates the
// index has it built from the rows it holds the one time the table is made, because
// a trigger only sees what arrives after it. PostgreSQL generates the vector in the
// row, so there is nothing to keep current and nothing to build.
func (w Words) Create(ctx context.Context, tx *sql.Tx) error {
	if w.d.postgres {
		list := make([]string, len(w.cols))
		for i, c := range w.cols {
			list[i] = `coalesce(` + c + `, '')`
		}
		// Punctuation is made a space before the text is parsed: PostgreSQL's parser
		// reads `acme/svc/api` as one file path and `core-api` as three words, where
		// the words of a key are what a caller searches by.
		doc := `to_tsvector('simple', translate(` + strings.Join(list, ` || ' ' || `) + `, '` + strings.ReplaceAll(punctuation, `'`, `''`) + `', '` + strings.Repeat(" ", len(punctuation)) + `'))`
		// Each is asked for before it is made: ALTER TABLE takes an exclusive lock on
		// the table and CREATE INDEX one that stops its writers, even to find the
		// thing already there, and a store is opened again and again.
		has, err := w.d.HasColumn(ctx, tx, w.table, "fts")
		if err != nil {
			return err
		}
		if !has {
			if _, err := tx.ExecContext(ctx, `ALTER TABLE `+w.table+` ADD COLUMN fts tsvector GENERATED ALWAYS AS (`+doc+`) STORED`); err != nil {
				return err
			}
		}
		return createIndex(ctx, tx, w.table+"_fts", `CREATE INDEX `+w.table+`_fts ON `+w.table+` USING GIN (fts)`)
	}
	fts := w.table + "_fts"
	built, err := w.d.HasTable(ctx, tx, fts)
	if err != nil {
		return err
	}
	cols := strings.Join(w.cols, ", ")
	fresh := "new." + strings.Join(w.cols, ", new.")
	stale := "old." + strings.Join(w.cols, ", old.")
	if _, err := tx.ExecContext(ctx, `
CREATE VIRTUAL TABLE IF NOT EXISTS `+fts+` USING fts5(
	`+cols+`,
	content='`+w.table+`', content_rowid='`+w.key+`', tokenize='unicode61'
);
CREATE TRIGGER IF NOT EXISTS `+w.table+`_ai AFTER INSERT ON `+w.table+` BEGIN
	INSERT INTO `+fts+`(rowid, `+cols+`) VALUES (new.`+w.key+`, `+fresh+`);
END;
CREATE TRIGGER IF NOT EXISTS `+w.table+`_ad AFTER DELETE ON `+w.table+` BEGIN
	INSERT INTO `+fts+`(`+fts+`, rowid, `+cols+`) VALUES ('delete', old.`+w.key+`, `+stale+`);
END;
CREATE TRIGGER IF NOT EXISTS `+w.table+`_au AFTER UPDATE OF `+cols+` ON `+w.table+` BEGIN
	INSERT INTO `+fts+`(`+fts+`, rowid, `+cols+`) VALUES ('delete', old.`+w.key+`, `+stale+`);
	INSERT INTO `+fts+`(rowid, `+cols+`) VALUES (new.`+w.key+`, `+fresh+`);
END`); err != nil {
		return err
	}
	if built {
		return nil
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO `+fts+`(`+fts+`) VALUES ('rebuild')`)
	return err
}

// Hits is the rows whose text matches, as a subquery of `hit` (the row's key) and
// `score` (ascending is best), and the one value to bind at $first, which the
// subquery may read more than once. Every term is one or more words, adjacent and in
// order, the last of them a beginning of a word. All requires every term, else any
// one will do. A term with no word in it (`"`) matches nothing, so under all the
// query does; the caller refuses a query with no term at all.
//
//	hits, args := words.Hits(1, terms, true)
//	q := `SELECT ` + cols + ` FROM t JOIN (` + hits + `) h ON h.hit = id WHERE ... ORDER BY h.score, id`
func (w Words) Hits(first int, terms []string, all bool) (string, []any) {
	n := strconv.Itoa(first)
	if w.d.postgres {
		query := `to_tsquery('simple', $` + n + `)`
		return `SELECT ` + w.key + ` AS hit, -ts_rank(fts, ` + query + `, 2) AS score FROM ` + w.table + ` WHERE fts @@ ` + query,
			[]any{tsquery(terms, all)}
	}
	fts := w.table + "_fts"
	phrases := make([]string, len(terms))
	for i, t := range terms {
		phrases[i] = `"` + strings.ReplaceAll(clean(t), `"`, `""`) + `"*`
	}
	return `SELECT rowid AS hit, bm25(` + fts + `) AS score FROM ` + fts + ` WHERE ` + fts + ` MATCH $` + n,
		[]any{strings.Join(phrases, joiner(all))}
}

// punctuation is every ASCII punctuation mark: what Create makes a space.
const punctuation = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"

func joiner(all bool) string {
	if all {
		return " AND "
	}
	return " OR "
}

// clean is s without what no engine may be asked: a NUL, and bytes that are not UTF-8.
func clean(s string) string {
	return strings.ToValidUTF8(strings.ReplaceAll(s, "\x00", ""), "")
}

// words is the words of s: runs of letters and digits.
func words(s string) []string {
	return strings.FieldsFunc(clean(s), func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsNumber(r) })
}

// tsquery is the terms as the text to_tsquery reads: each term's words in order,
// adjacent (<->), the last a prefix (:*), the terms joined by & or |. A term with no
// word is an operand to_tsquery would drop, which would make a conjunction of what
// was left, so it is the whole query's failure: nothing matches.
func tsquery(terms []string, all bool) string {
	var parts []string
	for _, t := range terms {
		ws := words(t)
		if len(ws) == 0 {
			if all {
				return ""
			}
			continue
		}
		for i, w := range ws {
			ws[i] = `'` + w + `'`
		}
		parts = append(parts, strings.Join(ws, ` <-> `)+`:*`)
	}
	if all {
		return strings.Join(parts, ` & `)
	}
	return strings.Join(parts, ` | `)
}

// Grams is a substring index over texts the caller supplies, one per key: the
// table of that name, and the keys are integers the caller assigns (a chunk's id).
type Grams struct {
	d     Dialect
	table string
}

// Grams names the index table. The name is a plain lowercase identifier, written
// into DDL.
func (d Dialect) Grams(table string) (Grams, error) {
	if !identifier.MatchString(table) {
		return Grams{}, fmt.Errorf("dialect: %q is not a plain identifier", table)
	}
	return Grams{d: d, table: table}, nil
}

// Create makes the table, once, inside the store's migration. SQLite: an FTS5
// virtual table with the trigram tokenizer, which finds any substring of three
// characters or more, ignoring case. PostgreSQL: a table of the texts with a GIN
// index on the pg_trgm operator class, which makes LIKE '%part%' an index read; the
// extension is installed in the database if no one has (a trusted extension, which
// a role that may create objects in the database may install) and its schema is
// found rather than assumed, because a store's search_path is its own schema.
func (g Grams) Create(ctx context.Context, tx *sql.Tx) error {
	if !g.d.postgres {
		_, err := tx.ExecContext(ctx, `CREATE VIRTUAL TABLE IF NOT EXISTS `+g.table+` USING fts5(body, tokenize='trigram')`)
		return err
	}
	// Two stores opening at once each hold their own migration lock, and CREATE
	// EXTENSION IF NOT EXISTS is not safe against itself, so this one is the
	// database's.
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('pg_trgm', 0))`); err != nil {
		return err
	}
	// Found before it is made, so a role that may not install extensions opens a
	// database where an administrator has.
	const where = `SELECT n.nspname FROM pg_extension e JOIN pg_namespace n ON n.oid = e.extnamespace WHERE e.extname = 'pg_trgm'`
	var schema string
	err := tx.QueryRowContext(ctx, where).Scan(&schema)
	if errors.Is(err, sql.ErrNoRows) {
		if _, err := tx.ExecContext(ctx, `CREATE EXTENSION pg_trgm SCHEMA public`); err != nil {
			return fmt.Errorf("pg_trgm is needed for substring search, and an administrator of the database installs it with CREATE EXTENSION pg_trgm SCHEMA public: %w", err)
		}
		err = tx.QueryRowContext(ctx, where).Scan(&schema)
	}
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS `+g.table+` (
	id   BIGINT PRIMARY KEY,
	body TEXT NOT NULL
)`); err != nil {
		return err
	}
	return createIndex(ctx, tx, g.table+"_body", `CREATE INDEX `+g.table+`_body ON `+g.table+` USING GIN (body "`+strings.ReplaceAll(schema, `"`, `""`)+`".gin_trgm_ops)`)
}

// createIndex runs a CREATE INDEX statement unless the schema already has an index of
// that name, which it asks first: CREATE INDEX IF NOT EXISTS locks out the table's
// writers before it finds the index there.
func createIndex(ctx context.Context, tx *sql.Tx, name, create string) error {
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM pg_indexes WHERE schemaname = current_schema() AND indexname = $1`, name).Scan(&n); err != nil || n > 0 {
		return err
	}
	_, err := tx.ExecContext(ctx, create)
	return err
}

// Put indexes body under id, which must not already be indexed (Delete it first).
func (g Grams) Put(ctx context.Context, tx *sql.Tx, id int64, body string) error {
	if g.d.postgres {
		// Matched lowered, as FTS5's trigram ignores case.
		_, err := tx.ExecContext(ctx, `INSERT INTO `+g.table+` (id, body) VALUES ($1, $2)`, id, strings.ToLower(body))
		return err
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO `+g.table+` (rowid, body) VALUES ($1, $2)`, id, body)
	return err
}

// Delete forgets id. An id that is not indexed is not an error.
func (g Grams) Delete(ctx context.Context, tx *sql.Tx, id int64) error {
	key := "id"
	if !g.d.postgres {
		key = "rowid"
	}
	_, err := tx.ExecContext(ctx, `DELETE FROM `+g.table+` WHERE `+key+` = $1`, id)
	return err
}

// Gram is the fewest characters a substring can be searched by: the trigram.
const Gram = 3

// Hits is the keys whose text holds the terms, as a subquery of `hit` and `score`
// (ascending is best) and the values to bind from $first, in the shape Words.Hits
// has. Every term is a substring, ignoring case; all requires every term, else any
// one will do. A term shorter than Gram characters finds nothing, on SQLite because
// no trigram is as short, so here too: under all the query finds nothing, under any
// the term is left out. The score is how many terms the text holds.
func (g Grams) Hits(first int, terms []string, all bool) (string, []any) {
	if !g.d.postgres {
		phrases := make([]string, len(terms))
		for i, t := range terms {
			phrases[i] = `"` + strings.ReplaceAll(clean(t), `"`, `""`) + `"`
		}
		return `SELECT rowid AS hit, bm25(` + g.table + `) AS score FROM ` + g.table + ` WHERE ` + g.table + ` MATCH $` + strconv.Itoa(first),
			[]any{strings.Join(phrases, joiner(all))}
	}
	var args []any
	var holds, counts []string
	for _, t := range terms {
		t = strings.ToLower(clean(t))
		if utf8.RuneCountInString(t) < Gram {
			if all {
				return `SELECT id AS hit, 0 AS score FROM ` + g.table + ` WHERE FALSE`, nil
			}
			continue
		}
		args = append(args, `%`+strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(t)+`%`)
		like := `body LIKE $` + strconv.Itoa(first+len(args)-1)
		holds = append(holds, like)
		counts = append(counts, `(`+like+`)::int`)
	}
	if len(holds) == 0 {
		return `SELECT id AS hit, 0 AS score FROM ` + g.table + ` WHERE FALSE`, nil
	}
	join := ` OR `
	if all {
		join = ` AND `
	}
	return `SELECT id AS hit, -(` + strings.Join(counts, ` + `) + `) AS score FROM ` + g.table + ` WHERE ` + strings.Join(holds, join), args
}
