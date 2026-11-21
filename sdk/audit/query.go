package audit

// The read paths: filtered Query (for /v1/admin/audit) and Verify (the
// tamper-evidence walk for /v1/admin/audit/verify). Both are read-only — they
// issue SELECT only, never mutate — so exposing them can never weaken the
// append-only property.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/hanzoai/cloud/sdk/dialect"
)

// Filter narrows a Query. Zero-value fields are ignored (no constraint), so an
// empty Filter returns the most-recent Limit records. Time bounds are inclusive
// and compared against the RFC3339Nano ts column lexicographically (RFC3339 is
// order-preserving as text, so a string range is a correct time range).
type Filter struct {
	Org  string // actor_org exact match (the org acted IN)
	Sub  string // actor_sub exact match (a specific user)
	Home string // actor_home exact match — the org the actor came FROM.
	// Impersonated restricts to the actions a platform admin took inside a tenant
	// that was not their own: an org switch (actor_home <> '') or a support session
	// signed in as one of its people (act_sub <> ''). That is the question this
	// control exists to answer; without it an auditor would have to scan the whole
	// trail to find the events that matter most.
	Impersonated bool
	Action       string // action exact match
	// Actions matches any ONE of several action names — the question "show me
	// the rows that evidence this control", where a control is evidenced by a
	// SET of actions. One query rather than one per name, because the caller
	// needs them interleaved in time and bounded by one Limit; N queries would
	// have to merge and re-sort them, and would page each name separately.
	// Empty means unrestricted. Composes with Action as an AND, so naming both
	// is a contradiction rather than a widening.
	Actions    []string
	Resource   string    // res_type exact match
	ResourceID string    // res_id exact match (a specific resource instance)
	Result     string    // outcome result: success|deny|error
	Since      time.Time // ts >= Since (UTC)
	Until      time.Time // ts <= Until (UTC)
	Limit      int       // max rows (default 100, cap 1000)
	Offset     int       // pagination offset
	// Q matches action, actor, resource and org as a case-insensitive substring.
	Q string
	// Before starts the page at the records older than this chain position (seq <
	// Before): a keyset, so a page deep in the trail costs what the first does. It
	// narrows the page and never the count.
	Before uint64
}

// Query returns records matching f, newest first, and the total count matching
// the same predicate (ignoring Limit/Offset) for pagination. All predicates are
// parameterized — never string-interpolated — so a filter value can never inject
// SQL. Column names in the WHERE come from a fixed allowlist below, not caller
// input.
func (r *Recorder) Query(ctx context.Context, f Filter) (rows []Record, total int, err error) {
	if r.owner != nil {
		return r.owner.Query(ctx, f)
	}
	var a dialect.Args
	where := f.build(&a)
	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	offset := max(f.Offset, 0)
	read, _ := r.view()

	// The whole chain's count is its head: positions are gapless from 0 and never
	// removed, so nothing needs counting. COUNT(*) over it was a scan of every
	// record — 16 million and minutes — for the one number the head already holds.
	if where == "" {
		c, _, err := r.chainHead(ctx)
		if err != nil {
			return nil, 0, err
		}
		total = int(c)
	} else {
		countQ := `SELECT COUNT(*) FROM audit_log` + where
		if err = read.QueryRowContext(ctx, countQ, a.Values()...).Scan(&total); err != nil {
			return nil, 0, fmt.Errorf("audit: count: %w", err)
		}
	}

	listWhere := where
	if f.Before > 0 {
		if listWhere == "" {
			listWhere = " WHERE seq < " + a.Mark(int64(f.Before))
		} else {
			listWhere += " AND seq < " + a.Mark(int64(f.Before))
		}
	}
	listQ := `SELECT ` + selectCols + ` FROM audit_log` + listWhere +
		` ORDER BY seq DESC LIMIT ` + a.Mark(limit) + ` OFFSET ` + a.Mark(offset)
	rs, err := read.QueryContext(ctx, listQ, a.Values()...)
	if err != nil {
		return nil, 0, fmt.Errorf("audit: query: %w", err)
	}
	defer func() { _ = rs.Close() }()
	for rs.Next() {
		rec, scanErr := scanRecord(rs)
		if scanErr != nil {
			return nil, 0, fmt.Errorf("audit: scan: %w", scanErr)
		}
		rows = append(rows, rec)
	}
	return rows, total, rs.Err()
}

// build assembles the parameterized WHERE clause from the non-zero filter
// fields, marking each value into a as it is written. Each fragment uses a fixed
// column name and a numbered placeholder, so no caller value ever reaches the SQL
// text.
func (f Filter) build(a *dialect.Args) string {
	var conds []string
	if f.Org != "" {
		conds = append(conds, "actor_org = "+a.Mark(f.Org))
	}
	if f.Sub != "" {
		conds = append(conds, "actor_sub = "+a.Mark(f.Sub))
	}
	if f.Home != "" {
		conds = append(conds, "actor_home = "+a.Mark(f.Home))
	}
	if f.Impersonated {
		// No bound value — a fixed predicate, not caller input, so it stays
		// consistent with "no caller value ever reaches the SQL text".
		conds = append(conds, "(actor_home <> '' OR act_sub <> '')")
	}
	if f.Action != "" {
		conds = append(conds, "action = "+a.Mark(f.Action))
	}
	if len(f.Actions) > 0 {
		// The placeholder list is built from the marks of the values, never from the
		// values, so nothing a caller supplies reaches the SQL text — the same rule
		// every predicate above follows.
		marks := make([]string, len(f.Actions))
		for i, action := range f.Actions {
			marks[i] = a.Mark(action)
		}
		conds = append(conds, "action IN ("+strings.Join(marks, ",")+")")
	}
	if f.Resource != "" {
		conds = append(conds, "res_type = "+a.Mark(f.Resource))
	}
	if f.ResourceID != "" {
		conds = append(conds, "res_id = "+a.Mark(f.ResourceID))
	}
	if f.Result != "" {
		conds = append(conds, "result = "+a.Mark(f.Result))
	}
	if !f.Since.IsZero() {
		conds = append(conds, "ts >= "+a.Mark(f.Since.UTC().Format(time.RFC3339Nano)))
	}
	if !f.Until.IsZero() {
		conds = append(conds, "ts <= "+a.Mark(f.Until.UTC().Format(time.RFC3339Nano)))
	}
	if q := strings.TrimSpace(f.Q); q != "" {
		like := a.Mark("%" + strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(strings.ToLower(q)) + "%")
		var parts []string
		for _, col := range []string{"action", "actor_sub", "actor_email", "res_type", "res_id", "actor_org"} {
			parts = append(parts, "lower("+col+") LIKE "+like+` ESCAPE '\'`)
		}
		conds = append(conds, "("+strings.Join(parts, " OR ")+")")
	}
	if len(conds) == 0 {
		return ""
	}
	return " WHERE " + strings.Join(conds, " AND ")
}

const selectCols = `seq, ts, actor_org, actor_sub, actor_email, actor_home, action, res_type, res_id,
  auth_method, is_admin, result, status, reason, source_ip, user_agent,
  request_id, method, path, before, after, prev_hash, hash,
  act_sub, act_owner, act_name, actor_agent`

// scanRecord reconstructs a Record from a row of selectCols.
func scanRecord(sc interface{ Scan(...any) error }) (Record, error) {
	var (
		rec           Record
		ts            string
		isAdmin       int
		before, after string
	)
	if err := sc.Scan(
		&rec.Seq, &ts, &rec.Actor.Org, &rec.Actor.Sub, &rec.Actor.Email, &rec.Actor.Home,
		&rec.Action, &rec.Resource.Type, &rec.Resource.ID,
		&rec.Auth.Method, &isAdmin, &rec.Outcome.Result, &rec.Outcome.Status, &rec.Outcome.Reason,
		&rec.SourceIP, &rec.UserAgent, &rec.RequestID, &rec.Method, &rec.Path,
		&before, &after, &rec.PrevHash, &rec.Hash,
		&rec.Actor.Act.Sub, &rec.Actor.Act.Owner, &rec.Actor.Act.Name, &rec.Actor.Agent,
	); err != nil {
		return Record{}, err
	}
	if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
		rec.Time = t
	}
	rec.Auth.IsAdmin = isAdmin != 0
	if before != "" {
		rec.Before = json.RawMessage(before)
	}
	if after != "" {
		rec.After = json.RawMessage(after)
	}
	return rec, nil
}

// Verdict is what a chain walk concluded. THREE states, not two: a chain that
// could not be READ is not a chain that passed, and a boolean has nowhere to put
// the difference. That distinction is the whole reason this is not a bool — an
// outage and a clean bill of health must never render the same.
type Verdict string

const (
	// Intact: every record's stored hash equals the recomputed hash AND the chain
	// links are continuous (each PrevHash == the prior record's Hash, seqs gapless
	// from 0).
	Intact Verdict = "intact"
	// Broken: the walk reached BrokenAt, and Reason says how the chain fails there.
	Broken Verdict = "broken"
	// Unread: the chain could not be walked at all, and Reason says why. Nothing is
	// known about its contents — it is neither a pass nor a break.
	Unread Verdict = "unread"
)

// Integrity is ONE chain's verification — the AU-9 evidence that THAT chain has
// not been tampered with. One chain, never the trail: the live chain sits beside the
// history chains processes wrote before it had one holder (see Name), and the whole
// family verified is a Trail.
type Integrity struct {
	// Name is the chain this verdict is about, e.g. "audit" or "audit-iam". It is
	// carried because a verdict with no chain on it reads as the whole trail's,
	// which is what a reader of a 128-chain deployment did.
	Name string `json:"name"`
	// Verdict is intact, broken or unread.
	Verdict Verdict `json:"verdict"`
	// Count is the number of records walked. Zero on an unread chain, where it
	// means "nothing was read", not "the chain is empty".
	Count uint64 `json:"count"`
	// Head is the hash of the last record (or the genesis anchor for an empty
	// chain). Pin this externally over time to detect tail-truncation.
	Head string `json:"head"`
	// BrokenAt is the seq of the FIRST record that failed verification, and -1
	// whenever the walk found no break (including an unread chain, where no seq
	// was reached).
	BrokenAt int64 `json:"brokenAt"`
	// Reason says HOW the chain fails at BrokenAt — a recomputed-hash mismatch, a
	// prev-hash discontinuity, or a seq gap — or, on an unread chain, why it could
	// not be walked at all. Absent on an intact chain, which is the only verdict
	// with nothing to explain.
	Reason string `json:"reason,omitempty"`
	// At is when the walk finished, RFC 3339 in UTC. A verdict is about the chain as
	// it stood then; absent on an unread chain, which no walk finished.
	At string `json:"at,omitempty"`
}

// Verify walks THIS recorder's chain and reports its integrity. The whole family
// a deployment keeps is the package-level Verify.
func (r *Recorder) Verify(ctx context.Context) (Integrity, error) {
	if r.owner != nil {
		return Integrity{}, r.held()
	}
	read, _ := r.view()
	return walk(ctx, read, r.name)
}

// Fresh is how old the verdict Latest serves may grow before a reader starts the
// next walk.
const Fresh = time.Minute

// latest is the newest full walk of a recorder's chain, kept for Latest.
type latest struct {
	mu      sync.Mutex
	iv      *Integrity
	at      time.Time
	running bool
}

// Latest answers the newest FULL walk of this chain, which its At names, and starts
// the next one in the background once that verdict is older than Fresh. It is what a
// listing badges itself with: a walk is O(n) over a chain every request lengthens,
// so a read that answers in milliseconds cannot hold one. Nil until a first walk
// finishes (no verdict, never a pass), and on a Remote recorder. Verify still walks
// the whole chain on the spot.
func (r *Recorder) Latest() *Integrity {
	if r.owner != nil {
		return nil
	}
	r.last.mu.Lock()
	defer r.last.mu.Unlock()
	if !r.last.running && (r.last.iv == nil || time.Since(r.last.at) > Fresh) {
		r.last.running = true
		go func() {
			iv, err := r.Verify(context.Background())
			r.last.mu.Lock()
			defer r.last.mu.Unlock()
			r.last.running = false
			if err == nil {
				r.last.iv, r.last.at = &iv, time.Now()
			}
		}()
	}
	if r.last.iv == nil {
		return nil
	}
	iv := *r.last.iv
	return &iv
}

// walkPage is how many records one read of a walk holds. The store has ONE
// connection (locus.Single), and every Append needs it; the walk gives it back
// between pages, so an append waits for one page at most, never for the chain.
const walkPage = 1000

// walk is the ONE chain walk, shared by the Recorder's own Verify and by the
// trail reader, so a chain cannot be judged by two different rules depending on
// whether the process that wrote it is the process asking.
//
// It reads the chain in seq order, recomputing each record's hash from its
// content + the running prev-hash and checking continuity. It is the
// tamper-detector: any modification (a changed field re-hashes differently), any
// deletion or reordering (a seq gap or a broken prev-hash link), or a forged row
// (its recomputed hash won't match unless the attacker also recomputed the entire
// suffix — which they cannot do without re-inserting every subsequent record) is
// reported with the exact seq where the chain first breaks.
//
// A returned ERROR means the chain could not be read; it is never a verdict about
// its contents, and a caller must not render one as the other. Cancelling ctx
// stops the walk at the next page, so a 1.7 GB family does not outlive the client
// that asked about it.
//
// Complexity is O(n) over the records, read walkPage at a time (see there), so the
// walk never holds more than one page and never holds the connection between pages.
func walk(ctx context.Context, db *sql.DB, name string) (Integrity, error) {
	prevHash := genesisPrevHash
	var expectSeq uint64
	var count uint64
	headHash := genesisPrevHash
	now := func() string { return time.Now().UTC().Format(time.RFC3339) }

	broke := func(seq uint64, reason string) Integrity {
		return Integrity{
			Name: name, Verdict: Broken, Count: count, Head: headHash,
			BrokenAt: int64(seq), Reason: reason, At: now(),
		}
	}

	for {
		// A page starts at the seq the chain owes next, so a missing record shows as
		// the gap the first returned row makes.
		recs, err := page(ctx, db, expectSeq)
		if err != nil {
			return Integrity{}, err
		}
		for _, rec := range recs {
			// Gapless, 0-based ordering.
			if rec.Seq != expectSeq {
				return broke(rec.Seq, fmt.Sprintf("seq gap: expected %d, got %d", expectSeq, rec.Seq)), nil
			}
			// Link continuity: this record must chain to the previous record's hash.
			if rec.PrevHash != prevHash {
				return broke(rec.Seq, "prev_hash discontinuity (a record was deleted, reordered, or altered)"), nil
			}
			// Content integrity: recompute the hash from the record's own fields.
			want, hErr := computeHash(rec, rec.PrevHash)
			if hErr != nil {
				return Integrity{}, fmt.Errorf("audit: verify hash: %w", hErr)
			}
			if want != rec.Hash {
				return broke(rec.Seq, "hash mismatch (record content was modified after it was written)"), nil
			}
			prevHash = rec.Hash
			headHash = rec.Hash
			expectSeq = rec.Seq + 1
			count++
		}
		if len(recs) < walkPage {
			return Integrity{Name: name, Verdict: Intact, Count: count, Head: headHash, BrokenAt: -1, At: now()}, nil
		}
	}
}

// page reads up to walkPage records from seq from, in order, and gives the connection
// back before it returns.
func page(ctx context.Context, db *sql.DB, from uint64) ([]Record, error) {
	rs, err := db.QueryContext(ctx,
		`SELECT `+selectCols+` FROM audit_log WHERE seq >= $1 ORDER BY seq ASC LIMIT $2`, int64(from), walkPage)
	if err != nil {
		return nil, fmt.Errorf("audit: verify query: %w", err)
	}
	defer func() { _ = rs.Close() }()
	recs := make([]Record, 0, walkPage)
	for rs.Next() {
		rec, err := scanRecord(rs)
		if err != nil {
			return nil, fmt.Errorf("audit: verify scan: %w", err)
		}
		recs = append(recs, rec)
	}
	if err := rs.Err(); err != nil {
		return nil, fmt.Errorf("audit: verify rows: %w", err)
	}
	return recs, nil
}
