// Copyright 2025 Hanzo AI Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package tenure

// durable.go packages the single-writer + durability discipline (proven in
// handoff_test.go with the raw primitives) into ONE reusable value a per-org SQLite
// store wires at its open/write/close client. It composes the three orthogonal lanes,
// each kept in its own package:
//
//	WHO writes   — ha election via CASFencer: HRW names the owner, the lease binds
//	               it to a monotone Round. (github.com/hanzoai/ha)
//	HOW it ships  — replica.FencedStore over the S3 conditional store: a ship at a
//	               round below the recorded one is rejected (ErrStaleRound), and a
//	               takeover carries the latest durable bytes forward before sealing,
//	               so no acknowledged write is lost. (github.com/hanzoai/vfs/replica)
//	AT REST       — the durable object is sealed under the database's own cek key
//	               (Cipher), the SAME key the local file was opened with.
//
// # Snapshot is a raw file copy, not VACUUM/logical export
//
// The local file is opened through cek, which stores it as ciphertext under a key
// DERIVED from this deployment's master and the namespace that owns it. A snapshot
// therefore copies the ACTUAL local bytes (checkpoint the WAL, read the file) and
// ships those, entire. A successor writes them back and opens through cek exactly as
// the origin did — the derivation gives it the same key from the same name, so there
// is no key material in the payload to lose. No logical export, no SQLCipher-specific
// SQL, and an existing on-disk store needs no migration.
//
// # The wire-the-gate contract a store follows
//
//	open  : Hydrate() BEFORE opening the local handle — acquire the lease and
//	        reconcile the local file with the latest durable snapshot (or, for a
//	        non-owner, reconcile read-only). Then open the handle and Bind() it so
//	        Sync can fold the WAL on the same single connection.
//	write : after the write transaction COMMITS, Sync() — snapshot the local file and
//	        ship it fenced at the lease round. A ship rejected as ErrStaleRound means
//	        this replica was deposed: the write is NOT acknowledged and the caller
//	        retries on the new owner. Call Sync outside any open transaction.
//	close : best-effort final Sync, then release (the live *sql.DB is the store's).
//
// # The local file is never discarded
//
// The durable object is a COPY of a local file as it was when it shipped. The local
// file, and the -wal beside it that SQLite replays when the database opens, can hold
// committed writes the object does not: everything since the last ship. So hydrate
// RECONCILES rather than restores (reconcile). The local file stays whenever it
// descends from the object. It is replaced only when another writer has shipped
// since this file was last reconciled, and then it is set aside under a name SQLite
// never opens — never removed. What the file was last reconciled with is recorded
// beside it (mark).

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/hanzoai/ha"
	"github.com/hanzoai/namespace"
	"github.com/hanzoai/vfs/replica"
)

// Durability is the per-deployment, org-agnostic durable-store factory: the shared
// election+fence over ONE object store, plus the optional at-rest envelope. It holds
// no per-org state — For() mints a Durable per org DB. nil ⇒ durability disabled
// (local-only single-node/dev), the caller's default open path unchanged.
type Durability struct {
	fencer *CASFencer
	fenced *replica.FencedStore
	cipher *Cipher
	codec  snapshotCodec // how the durable payload is produced/applied (swappable ship)
	reader opener        // opens a snapshot's own read-only handle; nil ⇒ none available
	solo   bool          // the deployment declares one writer: nobody can depose it
	live   func() bool   // this pod's own heartbeat is fresh in the live set; nil ⇒ always
	lister Lister        // names the store's objects; nil ⇒ the disk is all a store knows
}

// Lister names an object store's keys under a prefix. A pod whose disk holds none
// of a deployment's stores — a new one, on an emptyDir — asks it which exist, so a
// read is not answered "nothing here" while the store holds the org's data, and a
// sweep still visits every org that has a store.
type Lister interface {
	List(ctx context.Context, prefix string) ([]string, error)
}

// ErrNoLister is what Keys and Holds answer on a Durability built without one.
var ErrNoLister = errors.New("org: the durable store cannot list its keys")

// Keys is every object key under prefix, in key order.
func (dy *Durability) Keys(ctx context.Context, prefix string) ([]string, error) {
	if dy.lister == nil {
		return nil, ErrNoLister
	}
	return dy.lister.List(ctx, prefix)
}

// Holds reports whether key names an object: a store this disk lacks but the
// deployment has.
func (dy *Durability) Holds(ctx context.Context, key string) (bool, error) {
	keys, err := dy.Keys(ctx, key)
	if err != nil {
		return false, err
	}
	return slices.Contains(keys, key), nil
}

// opener opens a second, READ-ONLY handle on the database a Durable names. A snapshot
// holds a read transaction on it while it copies the file, which is what lets the store
// keep its own connection (see pin). It answers (nil, nil) on a backend that has no
// second handle to give — the on-disk file is then not a database another handle could
// open, and the snapshot copies it unpinned, as it always did.
//
// It is a FUNCTION and not a handle because the snapshot opens one per ship and closes
// it again: nothing else may hold it, nothing has to close it on a promotion or an
// eviction, and a store that never ships never opens one.
type opener func(ns namespace.Namespace, subsystem, path string) (*sql.DB, error)

// NewDurability builds the factory over an atomic-CAS object store (the S3
// If-Match ConditionalStore), the live membership view (election input), and an
// optional per-org envelope Cipher (nil ⇒ the durable object is stored in the clear;
// pure-Go dev only). The SAME cond backs both the lease and the data ships, so they
// share one linearizable register.
//
// The cond is an INTERFACE by design (replica.ConditionalStore): a read-through/
// write-through cache tier (KV in front of S3) wraps it with a one-line decorator at the
// buildDurability construction site, with no change here — the fence reads and CASes
// through whatever store it is handed. The ship mechanism is likewise swappable: the
// default wholeFile codec can be replaced by a WAL-frame delta codec behind snapshotCodec
// without touching the fence or round. WithSeal injects the envelope's re-encrypting
// Checkpoint (crypto client); WithReader injects the opener a snapshot pins its file with.
func NewDurability(cond replica.ConditionalStore, view ownerView, cipher *Cipher, opts ...DurabilityOption) *Durability {
	var o durabilityOpts
	for _, fn := range opts {
		fn(&o)
	}
	return &Durability{
		fencer: NewCASFencer(cond, view),
		fenced: replica.NewFencedStore(cond),
		cipher: cipher,
		codec:  wholeFile{seal: o.seal},
		reader: o.reader,
		solo:   o.writers == 1,
		live:   o.live,
		lister: o.lister,
	}
}

// DurabilityOption configures a Durability.
type DurabilityOption func(*durabilityOpts)

type durabilityOpts struct {
	seal    func(*sql.DB) error
	reader  opener
	writers int
	live    func() bool
	lister  Lister
}

// WithLister supplies what names the store's keys (the S3 store itself; the CAS
// wrapper in front of it answers only Get and PutIfVersion).
func WithLister(l Lister) DurabilityOption {
	return func(o *durabilityOpts) { o.lister = l }
}

// WithWriters states how many writers the deployment declares. One is a deployment
// nothing else can depose a replica of, so Owned asks the object store nothing
// there; any other count (or none stated) asks it.
func WithWriters(n int) DurabilityOption {
	return func(o *durabilityOpts) { o.writers = max(n, 1) }
}

// WithLive supplies whether this pod's own heartbeat is fresh in the deployment's
// live set. A replica trusts what the object store last told it only while it is:
// a pod its peers have dropped can have been replaced, and it will not hear so from
// a store it cannot reach.
func WithLive(live func() bool) DurabilityOption {
	return func(o *durabilityOpts) { o.live = live }
}

// WithSeal injects the operation that makes the on-disk file hold every committed write
// on a backend that defers encryption. The pure-Go ENVELOPE keeps its plaintext on tmpfs
// and re-encrypts to the real path only when asked, so without this a ship would read the
// last-sealed ciphertext — a lost acked write on takeover. On the SQLCipher page-level and
// plaintext backends, which encrypt as they write, it is a successful no-op. Folding the
// WAL is NOT its job and never was a backend's choice: the codec does that itself, once,
// on every backend, and the fold is also where the file is pinned for the copy.
func WithSeal(fn func(*sql.DB) error) DurabilityOption {
	return func(o *durabilityOpts) { o.seal = fn }
}

// WithReader injects the opener a snapshot pins its file with — a second, read-only handle
// on the same database. Without it every ship copies the file while writers are free to
// move it; with it the copy reads what the fold left. The composition root supplies it
// where a second handle is safe (see opener).
func WithReader(open opener) DurabilityOption {
	return func(o *durabilityOpts) { o.reader = open }
}

// For mints the Durable binding for one org DB. It takes the NAME — the same
// (ns, subsystem) the local file was opened under — rather than the parts a name
// is made of, so the snapshot cannot be keyed for one database and shipped as
// another: the election key is ns.ID() (the ENTITY, so every one of an org's
// project-scoped files has one elected writer) and the snapshot key is cek's over
// (ns, subsystem). dbKey is the durable object location (replica.DBPath). dbPath
// is the local SQLite file.
func (dy *Durability) For(ns namespace.Namespace, subsystem, dbKey, dbPath string) *Durable {
	return &Durable{dy: dy, ns: ns, subsystem: subsystem, dbKey: dbKey, dbPath: dbPath}
}

// Durable binds one org's local SQLite file to its fenced durable object slot,
// gated by the org's single-writer lease. It never opens or closes the local handle
// (the store owns that) — Bind lends it the handle so Sync can checkpoint on the
// same single connection the store writes through.
type Durable struct {
	dy        *Durability
	ns        namespace.Namespace // the database's name — HRW key (ns.ID()) + snapshot key
	subsystem string              // which database of that entity — bound into the snapshot key
	dbKey     string              // durable object key (replica.DBPath)
	dbPath    string              // local SQLite file path

	mu       sync.Mutex
	owned    bool      // true iff we hold the lease as the elected writer
	held     bool      // the object store's last answer to whether the lease is still ours
	heldAt   time.Time // when it gave that answer; zero until it has been asked
	failedAt time.Time // when it last failed to answer; zero once it answers again
	replaced time.Time // when it said another replica holds the lease
	rival    string    // the replica it named then; "" when it could not be read
	lease    ha.Lease  // the monotone round every ship is fenced at
	db       *sql.DB   // live handle (set by Bind) — checkpoint runs on its sole conn
	aside    string    // where the last hydrate set a diverged local file aside, "" if it did not

	// shipping serializes Sync: two ships of one file (the ship loop and a close)
	// would otherwise interleave their marks.
	shipping sync.Mutex
}

// Hydrate acquires the writer lease and reconciles the local file with the latest
// durable snapshot, BEFORE the store opens its handle. As the elected owner it
// CarryForward-seals the durable object to the lease round while reconciling (safe
// takeover: no acknowledged write lost, and no local write discarded — see
// reconcile). A non-owner reconciles read-only. Any other
// condition (store unreachable, empty membership, lost race) degrades to read-only
// on the local file and is returned for the caller to log — it NEVER makes the store
// unopenable, so a store is always available for reads; writes fail closed until a
// later open re-acquires.
//
// RECOVERY from a degraded open (M3): a pod that could not acquire at open stays
// read-only until this replica becomes the org's elected owner (a membership change),
// at which point the OrgStore promotes the store IN PLACE — PendingPromotion gates it,
// TryClaim proves the lease is claimable, then a quiesce-close-reopen swaps in a writer
// handle and CarryForward-restores the latest snapshot under the FRESH handle (never
// under the live one — the swap is why the reopen is required). No process restart.
func (d *Durable) Hydrate(ctx context.Context) error {
	lease, err := d.dy.fencer.Acquire(ctx, d.ns.ID())
	if err != nil {
		// Not the elected writer, or no safe owner / unreachable store: serve reads
		// off the freshest local copy we can get, writes fail closed via Sync.
		d.restoreLatestReadOnly(ctx)
		if errors.Is(err, ErrNotOwner) || errors.Is(err, ErrNoMembership) {
			return nil
		}
		return fmt.Errorf("org: durable acquire %s: %w", d.ns, err)
	}
	if err := d.dy.fenced.CarryForward(ctx, d.dbKey, uint64(lease.Round), d.reconcile); err != nil {
		if errors.Is(err, replica.ErrStaleRound) {
			return nil // a newer owner already advanced past us — serve read-only
		}
		return fmt.Errorf("org: durable hydrate %s: %w", d.dbKey, err)
	}
	d.mu.Lock()
	d.lease, d.owned, d.held, d.heldAt, d.failedAt = lease, true, true, time.Time{}, time.Time{}
	d.mu.Unlock()
	return nil
}

// Bind lends Durable the store's live handle so Sync folds the WAL on the SAME single
// connection the store writes through. Call after the store opens the local file.
func (d *Durable) Bind(db *sql.DB) {
	d.mu.Lock()
	d.db = db
	d.mu.Unlock()
}

// Owned reports whether this replica holds the writer lease AND is still the org's
// elected owner. A store may gate a write on it, but the authoritative gate is
// Sync's fenced ship.
//
// BOTH HALVES, because the lease alone is a memory. `owned` is written once, at
// Hydrate, and cleared in exactly one place: a ship refused as a stale round. So a
// replica the fleet has re-elected away goes on answering true until it happens to
// attempt a ship — and the acts that most need this gate are the ones that never
// ship. Ending a lease stops a KUBERNETES POD before any ship is attempted, and
// ending a row that is not `holding` charges nothing and so ships nothing at all;
// neither would ever have learned the belief was stale. A deposed pod went on
// deleting the new owner's pods with no mechanism anywhere to stop it.
//
// The election half is the same cheap question PendingPromotion already asks in the
// other direction — one lock and an HRW over the live member snapshot, no I/O — so
// this closes within one membership refresh rather than never.
//
// THE LEASE HALF IS ASKED OF THE OBJECT STORE where another replica could have
// taken it. The live set is the deployment's view of who is alive, and a view can be
// wrong in the one direction that matters here: two pods that each see only
// themselves each elect themselves for every org. The lease object is the store's
// answer, and a replica it no longer names at its round has been deposed, so it
// acts on nothing — however it reads the live set. It is deposed exactly as a
// refused ship deposes it, and, while the replica that took it may still be live,
// waits out replacedBackoff before PendingPromotion lets it claim the org again, so
// two divergent views do not trade the org back and forth, each trade a full
// re-hydrate.
//
// The cost is bounded. A deployment that declares one writer has no one to be
// deposed by and asks nothing. Otherwise an answer is reused for answerFor (one
// refresh of the live set), and a store that failed to answer is not asked again
// for answerFor either: an act it gates waits at most ownedReach, once.
//
// A store that cannot be reached does not move ownership — the last answer it gave
// stands — but only while this pod's own heartbeat is fresh in the live set. A pod
// its peers have dropped can have been replaced by one of them, and from a store it
// cannot reach it would never hear so. What a replica that holds the lease must not
// do during an outage is call the resulting debit durable, and that is Sync's
// answer, not this one.
func (d *Durable) Owned() bool {
	d.mu.Lock()
	owned, lease := d.owned, d.lease
	d.mu.Unlock()
	if !owned || !d.dy.fencer.ElectsSelf(d.ns.ID()) {
		return false
	}
	if d.dy.solo {
		return true
	}
	now := time.Now()
	live := d.dy.live == nil || d.dy.live()
	d.mu.Lock()
	switch {
	case live && !d.heldAt.IsZero() && now.Sub(d.heldAt) < answerFor:
		held := d.held
		d.mu.Unlock()
		return held
	case !d.failedAt.IsZero() && now.Sub(d.failedAt) < answerFor:
		held := d.held && live
		d.mu.Unlock()
		return held
	}
	d.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), ownedReach)
	defer cancel()
	holder, round, err := d.dy.fencer.Holder(ctx, d.ns.ID())
	d.mu.Lock()
	defer d.mu.Unlock()
	if err != nil {
		d.failedAt = time.Now()
		return d.held && live
	}
	ok := holder == d.dy.fencer.view.Self() && round == lease.Round
	d.held, d.heldAt, d.failedAt = ok, time.Now(), time.Time{}
	if !ok {
		d.owned, d.replaced, d.rival = false, time.Now(), holder
	}
	return ok
}

// ownedReach bounds Owned's read of the lease: an act it gates waits no longer than
// this on a store that does not answer, and then goes on the last answer.
const ownedReach = 2 * time.Second

// answerFor is how long one answer about the lease — or one failure to get one —
// stands: one refresh of the live set, the time in which the view it depends on
// could have changed.
var answerFor = 2 * time.Second

// replacedBackoff is how long a replica the store said was replaced waits before it
// claims the org back from a holder that may still be live, however it reads the
// live set: long enough for divergent views to converge (a heartbeat's lifetime), so
// they do not trade the org.
var replacedBackoff = 10 * time.Second

// PendingPromotion reports whether this store opened degraded (does not hold the lease)
// yet this replica is NOW the org's elected owner — a membership change made it the
// writer, so the store must be promoted (re-acquire + hydrate + reopen) to serve writes.
// Cheap and I/O-free: a lock plus one HRW over the live member snapshot, evaluated only
// when the store is not already owned. It is the per-request gate the OrgStore checks on
// a cache hit; the actual promotion runs (rarely) only when this returns true.
//
// It is false within replacedBackoff of the object store saying another replica took
// the org, unless the live set has since dropped that replica (Membership.Gone): an
// org that returns to the pod it left once its holder is gone, as on every rolling
// restart and every scale-in, is claimed back at once, and a holder this pod never
// saw leave may be live in a set this pod cannot read. A lease that names this
// replica at a newer round is no contest either: another of the org's databases
// claimed it, and the claim renews it.
func (d *Durable) PendingPromotion() bool {
	d.mu.Lock()
	owned, replaced, rival := d.owned, d.replaced, d.rival
	d.mu.Unlock()
	if owned {
		return false
	}
	if !replaced.IsZero() && time.Since(replaced) < replacedBackoff &&
		rival != d.dy.fencer.view.Self() && !d.dy.fencer.Gone(rival) {
		return false
	}
	return d.dy.fencer.ElectsSelf(d.ns.ID())
}

// TryClaim probes whether this replica can hold the org's writer lease right now and, if
// so, claims it — the promotion gate. It performs ONLY the lease CAS (via the fencer), no
// local-file I/O, so a failed probe (not the elected owner, or the store unreachable)
// costs nothing and leaves any live handle untouched. On success the lease object names
// this replica at a fresh round (fencing any prior owner); the caller then quiesces and
// reopens, whose Hydrate renews THIS same lease and CarryForward-restores the latest
// snapshot under the fresh handle. Returns (false, nil) when not the elected owner,
// (false, err) on a store error, (true, nil) when claimed.
func (d *Durable) TryClaim(ctx context.Context) (bool, error) {
	_, err := d.dy.fencer.Acquire(ctx, d.ns.ID())
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, ErrNotOwner), errors.Is(err, ErrNoMembership):
		return false, nil
	default:
		return false, err
	}
}

// Sync snapshots the local file and ships it to the durable object fenced at the
// lease round — the ship-before-ack step. acked is true only if the fenced store
// admitted our round. A ship rejected as ErrStaleRound returns (false, nil): this
// replica was deposed, so it drops ownership and does NOT acknowledge — the caller
// retries on the new owner. A non-owner returns (false, ErrNotOwner). Call AFTER the
// write transaction commits and OUTSIDE any open transaction (Sync takes the sole
// connection for the two statements that fold the WAL and pin the file).
func (d *Durable) Sync(ctx context.Context) (acked bool, err error) {
	d.shipping.Lock()
	defer d.shipping.Unlock()
	d.mu.Lock()
	owned, lease := d.owned, d.lease
	d.mu.Unlock()
	if !owned {
		return false, ErrNotOwner
	}
	snap, err := d.snapshot(ctx)
	if err != nil {
		return false, err
	}
	payload := snap
	if d.dy.cipher != nil {
		sealed, err := d.dy.cipher.Seal(d.ns, d.subsystem, snap)
		if err != nil {
			return false, fmt.Errorf("org: durable seal %s: %w", d.dbKey, err)
		}
		payload = sealed
	}
	// The mark is written on both sides of the put so a crash between the two leaves
	// the object matching one of the digests it names: hydrate keeps the file either
	// way, and never reads its own ship as another writer's.
	sum := digest(payload)
	m, _ := d.readMark()
	if err := d.writeMark(mark{Current: m.Current, Pending: sum, Main: dirtyShape}); err != nil {
		return false, err
	}
	if err := d.dy.fenced.Put(ctx, d.dbKey, payload, uint64(lease.Round)); err != nil {
		if errors.Is(err, replica.ErrStaleRound) {
			holder, _, _ := d.dy.fencer.Holder(ctx, d.ns.ID()) // who, for PendingPromotion; "" if unread
			d.mu.Lock()
			d.owned, d.replaced, d.rival = false, time.Now(), holder
			d.mu.Unlock()
			return false, nil // deposed: not acknowledged
		}
		return false, fmt.Errorf("org: durable ship %s: %w", d.dbKey, err)
	}
	if err := d.writeMark(d.cleanMark(sum)); err != nil {
		return false, err
	}
	return true, nil
}

// Dirty reports whether the local file may hold writes the durable object does not:
// it has changed since it was last reconciled with the object, or it was kept ahead
// of the object at hydrate. A store with no mark is dirty, because nothing proves
// otherwise.
func (d *Durable) Dirty() bool {
	m, ok := d.readMark()
	return !ok || d.changedSince(m)
}

// SetAside names where the last hydrate moved a diverged local file, or "" when it
// moved nothing. The file and its -wal/-shm sit there under a name SQLite never
// opens, for an operator to merge.
func (d *Durable) SetAside() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.aside
}

// reconcile is the hydrate callback. It receives the latest durable payload and
// decides what the local file becomes:
//
//	no local file                         restore the payload: it is the only copy
//	empty payload (nothing ever shipped)  keep the local file
//	no mark beside the local file         keep it: nothing shows another writer shipped
//	payload is the one the mark names     keep it: the file descends from the payload
//	payload is one the mark never saw     another writer shipped since — set the local
//	                                      file aside (when it changed since it was last
//	                                      reconciled) and restore the payload
//
// A kept file is marked dirty until a ship carries it, so the store ships it. It may
// run more than once under CarryForward's retry, and is idempotent: a second call
// sees the mark the first one wrote.
func (d *Durable) reconcile(payload []byte) error {
	sum := digest(payload)
	if shapeOf(d.dbPath).Size < 0 {
		if len(payload) > 0 && shapeOf(d.dbPath+"-wal").Size > 0 {
			// A -wal with no database beside it still holds frames; restoring would
			// remove it.
			if err := d.keepAside(); err != nil {
				return err
			}
		}
		if err := d.restore(payload); err != nil {
			return err
		}
		return d.writeMark(d.cleanMark(sum))
	}
	m, ok := d.readMark()
	if len(payload) == 0 || !ok || sum == m.Current || sum == m.Pending {
		if ok && (sum == m.Current || sum == m.Pending) && !d.changedSince(m) {
			return d.writeMark(mark{Current: sum, Main: m.Main, WAL: m.WAL})
		}
		return d.writeMark(mark{Current: sum, Main: dirtyShape})
	}
	plain, err := d.open(payload)
	if err != nil {
		return err
	}
	if d.changedSince(m) {
		if err := d.keepAside(); err != nil {
			return err
		}
	}
	if err := d.dy.codec.apply(d.dbPath, plain); err != nil {
		return err
	}
	return d.writeMark(d.cleanMark(sum))
}

// keepAside moves the local database and its sidecars to <path>.aside-<unixnano>,
// <path>.aside-<unixnano>-wal and -shm, and records where for SetAside. Renames,
// never removes: a diverged file holds writes only an operator can merge.
func (d *Durable) keepAside() error {
	at := fmt.Sprintf("%s.aside-%d", d.dbPath, time.Now().UnixNano())
	for _, side := range []string{"", "-wal", "-shm"} {
		if err := os.Rename(d.dbPath+side, at+side); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("org: set aside %s%s: %w", d.dbPath, side, err)
		}
	}
	d.mu.Lock()
	d.aside = at
	d.mu.Unlock()
	return nil
}

// mark is what this replica last knew about its local file relative to the durable
// object: the digest of the payload it last restored or shipped (Current), the digest
// of a ship in flight (Pending), and the file's shape at that moment.
type mark struct {
	Current string `json:"current"`
	Pending string `json:"pending,omitempty"`
	Main    shape  `json:"main"`
	WAL     shape  `json:"wal"`
}

// shape is a file's size and modification time; Size -1 means absent.
type shape struct {
	Size  int64 `json:"size"`
	Mtime int64 `json:"mtime"`
}

// dirtyShape marks a local file as holding writes the object may not: no file has a
// negative size other than -1, so it never equals a shape read off the disk.
var dirtyShape = shape{Size: -2}

func shapeOf(path string) shape {
	fi, err := os.Stat(path)
	if err != nil {
		return shape{Size: -1}
	}
	return shape{Size: fi.Size(), Mtime: fi.ModTime().UnixNano()}
}

// cleanMark records that the local file, as it is now, holds exactly the payload
// whose digest is sum — unless frames have already reached the -wal, which are
// writes past it.
func (d *Durable) cleanMark(sum string) mark {
	main, wal := shapeOf(d.dbPath), shapeOf(d.dbPath+"-wal")
	if wal.Size > 0 {
		main = dirtyShape
	}
	return mark{Current: sum, Main: main, WAL: wal}
}

// changedSince reports whether the local file may have changed since m was written.
// SQLite writes the main file only at a checkpoint and appends every commit to the
// -wal, so an unchanged main file beside an empty -wal holds what it held then.
func (d *Durable) changedSince(m mark) bool {
	if m.Main == dirtyShape {
		return true
	}
	return shapeOf(d.dbPath) != m.Main || shapeOf(d.dbPath+"-wal").Size > 0
}

func (d *Durable) markPath() string { return d.dbPath + ".durable" }

func (d *Durable) readMark() (mark, bool) {
	b, err := os.ReadFile(d.markPath())
	if err != nil {
		return mark{}, false
	}
	var m mark
	if json.Unmarshal(b, &m) != nil || m.Current == "" && m.Pending == "" {
		return mark{}, false
	}
	return m, true
}

// writeMark replaces the mark atomically, so a crash leaves the old one or the new.
func (d *Durable) writeMark(m mark) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	// Hydrate runs before the store opens, so a first open reaches here before
	// anything has created the namespace's directory.
	if err := os.MkdirAll(filepath.Dir(d.markPath()), 0o700); err != nil {
		return fmt.Errorf("org: write mark %s: %w", d.markPath(), err)
	}
	tmp := d.markPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("org: write mark %s: %w", d.markPath(), err)
	}
	if err := os.Rename(tmp, d.markPath()); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("org: write mark %s: %w", d.markPath(), err)
	}
	return nil
}

// digest names a durable payload. The empty payload has a digest too, so a file
// reconciled with an object that held nothing is told apart from one never reconciled.
func digest(payload []byte) string {
	s := sha256.Sum256(payload)
	return hex.EncodeToString(s[:])
}

// Close best-effort ships any final state under the caller's (time-bounded) ctx —
// ship-before-ack already covers every acknowledged write, so this is
// belt-and-suspenders — and releases. It does NOT close the live *sql.DB; that is the
// store handle the caller owns.
func (d *Durable) Close(ctx context.Context) error {
	d.mu.Lock()
	owned, bound := d.owned, d.db != nil
	d.mu.Unlock()
	if owned && bound {
		_, _ = d.Sync(ctx)
	}
	return nil
}

// snapshot produces the durable payload for the bound local database via the swappable
// codec (default wholeFile: fold the WAL, pin the file, copy it).
//
// It opens the snapshot's own read-only handle for the length of this call and closes it
// again. One handle per ship costs an open on a file that is about to be read whole and
// sent to an object store, and it buys a lifetime nothing else has to manage: no handle
// survives a promotion, an eviction or a shutdown, because none outlives the ship that
// made it.
func (d *Durable) snapshot(ctx context.Context) (payload []byte, err error) {
	d.mu.Lock()
	db := d.db
	d.mu.Unlock()
	if db == nil {
		return nil, fmt.Errorf("org: durable %s not bound to a db", d.dbKey)
	}
	var reader *sql.DB
	if d.dy.reader != nil {
		// A reader that cannot be opened fails the ship rather than falling back to an
		// unpinned copy: the write is not acknowledged and the caller retries, where a
		// fallback would ship a file writers were free to move under it.
		if reader, err = d.dy.reader(d.ns, d.subsystem, d.dbPath); err != nil {
			return nil, fmt.Errorf("org: durable reader %s: %w", d.dbKey, err)
		}
		if reader != nil {
			defer reader.Close()
		}
	}
	return d.dy.codec.produce(ctx, db, reader, d.dbPath)
}

// restore opens the sealed durable payload and hands the plaintext to the codec to
// apply onto the local file. An empty payload (nothing shipped yet) keeps whatever
// the local file already holds. Only reconcile calls it, and only where no local
// file exists.
func (d *Durable) restore(sealed []byte) error {
	plain, err := d.open(sealed)
	if err != nil {
		return err
	}
	return d.dy.codec.apply(d.dbPath, plain)
}

// open removes the at-rest envelope from a durable payload (envelope decryption is
// orthogonal, done HERE around the codec).
func (d *Durable) open(sealed []byte) ([]byte, error) {
	if len(sealed) == 0 || d.dy.cipher == nil {
		return sealed, nil
	}
	pt, err := d.dy.cipher.Open(d.ns, d.subsystem, sealed)
	if err != nil {
		return nil, fmt.Errorf("org: durable open %s: %w", d.dbKey, err)
	}
	return pt, nil
}

// restoreLatestReadOnly reconciles the local file with the durable object without a
// lease — the non-owner / degraded path. Best-effort: an absent or unreachable
// object leaves the local file as-is (serve whatever is on disk), never an error.
func (d *Durable) restoreLatestReadOnly(ctx context.Context) {
	payload, _, err := d.dy.fenced.Get(ctx, d.dbKey)
	if err != nil {
		return
	}
	_ = d.reconcile(payload)
}
