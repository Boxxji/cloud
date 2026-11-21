// SPDX-License-Identifier: Apache-2.0 OR MIT

package template

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// errConflict is returned when the caller's org already owns that slug.
var errConflict = errors.New("templates: slug taken")

// Store holds every org's PRIVATE templates — ONE database, whichever the host
// opens (a SQLite file or a schema on a server database), whose isolation key is
// the org column. Its SQL is the dialect both kinds share: positional $n
// parameters and ON CONFLICT.
//
// The PUBLIC catalog is deliberately NOT in this table: it stays the embedded
// catalog.json, which has no write route at all. So a private row has no path
// into the public gallery by CONSTRUCTION, not by a filter someone has to
// remember to write — the two live in different containers, and every read of
// this one binds org.
//
// The whole StarterKit is one JSON `doc`: it is already the exact shape the API
// serves, so a row can never drift from it as fields are added, and (org, slug)
// — the only two things ever queried on — stay real columns.
type Store struct{ db *sql.DB }

// schema is the one table, written to be valid on SQLite and on a server database.
func schema(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS org_templates (
  org        TEXT NOT NULL,
  slug       TEXT NOT NULL,
  doc        TEXT NOT NULL,
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL,
  PRIMARY KEY (org, slug)
);`)
	return err
}

// openStore opens the database through the host, which applies schema to it under
// its own migration discipline before returning it.
func openStore(ctx context.Context, open func(context.Context, func(context.Context, *sql.Tx) error) (*sql.DB, error)) (*Store, error) {
	db, err := open(ctx, schema)
	if err != nil {
		return nil, fmt.Errorf("templates: open store: %w", err)
	}
	return &Store{db: db}, nil
}

// errText is returned for a value the two kinds of database disagree about.
var errText = errors.New("templates: value is not valid text")

// text refuses, before it is stored, a value a server database would refuse: a NUL
// byte or bytes that are not UTF-8. SQLite keeps either, so checking here makes a
// value that fits on one engine the same error on both, and never carries the
// value, which may be a secret.
func text(values ...string) error {
	for _, v := range values {
		if strings.IndexByte(v, 0) >= 0 || !utf8.ValidString(v) {
			return errText
		}
	}
	return nil
}

// Close closes the underlying database.
func (s *Store) Close() error { return s.db.Close() }

// Put writes t for its own org. create=true inserts and reports errConflict if
// the org already holds that slug; create=false replaces an existing row and
// reports sql.ErrNoRows if there is none — so "publish" can never silently
// clobber and "edit" can never silently create.
func (s *Store) Put(ctx context.Context, t StarterKit, create bool, now int64) error {
	doc, err := json.Marshal(t)
	if err != nil {
		return fmt.Errorf("templates: encode %q: %w", t.Slug, err)
	}
	if err := text(t.Org, t.Slug, string(doc)); err != nil {
		return fmt.Errorf("templates: %q: %w", t.Slug, err)
	}
	if !create {
		res, err := s.db.ExecContext(ctx,
			`UPDATE org_templates SET doc=$1, updated_at=$2 WHERE org=$3 AND slug=$4`, string(doc), now, t.Org, t.Slug)
		if err != nil {
			return fmt.Errorf("templates: update %q: %w", t.Slug, err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return sql.ErrNoRows
		}
		return nil
	}
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO org_templates (org,slug,doc,created_at,updated_at) VALUES ($1,$2,$3,$4,$5)
		 ON CONFLICT (org, slug) DO NOTHING`,
		t.Org, t.Slug, string(doc), now, now)
	if err != nil {
		return fmt.Errorf("templates: insert %q: %w", t.Slug, err)
	}
	// A row already held under that slug is the conflict: the insert said nothing.
	if n, _ := res.RowsAffected(); n == 0 {
		return errConflict
	}
	return nil
}

// Get returns org's own template at slug. found=false (nil error) when absent —
// including when the row belongs to ANOTHER org, because the WHERE binds org.
func (s *Store) Get(ctx context.Context, org, slug string) (StarterKit, bool, error) {
	var doc []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT doc FROM org_templates WHERE org=$1 AND slug=$2`, org, slug).Scan(&doc)
	if errors.Is(err, sql.ErrNoRows) {
		return StarterKit{}, false, nil
	}
	if err != nil {
		return StarterKit{}, false, fmt.Errorf("templates: get %q: %w", slug, err)
	}
	t, err := decode(doc, org)
	return t, err == nil, err
}

// List returns org's own templates (tenant-scoped read; there is no all-orgs
// counterpart, because nothing in this subsystem legitimately wants one).
func (s *Store) List(ctx context.Context, org string) ([]StarterKit, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT doc FROM org_templates WHERE org=$1 ORDER BY slug`, org)
	if err != nil {
		return nil, fmt.Errorf("templates: list: %w", err)
	}
	defer rows.Close()
	out := []StarterKit{}
	for rows.Next() {
		var doc []byte
		if err := rows.Scan(&doc); err != nil {
			return nil, fmt.Errorf("templates: list scan: %w", err)
		}
		t, err := decode(doc, org)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// Delete removes org's own template at slug, reporting whether a row went.
func (s *Store) Delete(ctx context.Context, org, slug string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM org_templates WHERE org=$1 AND slug=$2`, org, slug)
	if err != nil {
		return false, fmt.Errorf("templates: delete %q: %w", slug, err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// decode restores a stored StarterKit and re-stamps Org from the ROW's key, so the
// served owner is the column the query isolated on and never whatever a stale
// doc happens to carry.
func decode(doc []byte, org string) (StarterKit, error) {
	var t StarterKit
	if err := json.Unmarshal(doc, &t); err != nil {
		return StarterKit{}, fmt.Errorf("templates: decode %q: %w", org, err)
	}
	t.Org = org
	if t.Features == nil {
		t.Features = []string{}
	}
	return t, nil
}
