package coord

import (
	"cmp"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hanzoai/cloud/sdk/brand"
	"github.com/hanzoai/cloud/sdk/env"
	luxlog "github.com/luxfi/log"
)

// Member is one live pod: its stable id and the address its peers dial. It is the
// same pair org and ha elect over (org.Member(m) converts it), declared here so the
// light host, which links this package for presence, links no election.
type Member struct {
	ID   string
	Addr string
}

// Store is the linearizable register every loop's lease is a compare-and-set on:
// the deployment's object store, as replica.ConditionalStore states it. Get answers
// a key's bytes and its version, or an error wrapping ErrMissing when there is none;
// PutIfVersion writes only while the version is still expect ("" for an absent key)
// and answers an error wrapping ErrConflict when it is not. The caller maps its
// store's own errors onto these, so this package links no store.
type Store interface {
	Get(ctx context.Context, key string) (data []byte, version string, err error)
	PutIfVersion(ctx context.Context, key string, data []byte, expect string) (version string, err error)
}

var (
	// ErrMissing is a Store's answer for a key that holds nothing.
	ErrMissing = errors.New("coord: no such object")
	// ErrConflict is a Store's answer when a conditional write lost a race.
	ErrConflict = errors.New("coord: the object changed under a conditional write")
	// ErrDuplicate is the refusal when another live pod already holds this pod's
	// id. Two pods answering to one id would each believe they own the same orgs.
	ErrDuplicate = errors.New("coord: another live pod holds this pod id")
	// ErrUnavailable is the answer while the KV is not answering: a question that
	// must be asked of every pod cannot be answered by this one alone.
	ErrUnavailable = errors.New("coord: the deployment's KV is not answering")
	// ErrNotHeld is a loop's refusal: this process may not act for it now.
	ErrNotHeld = errors.New("coord: this process does not hold the loop")
)

// PeerListenEnv names the address a pod's root listens on for its peers (mutual
// TLS, see peer.go), and so the port every member's address carries.
const PeerListenEnv = "CLOUD_PEER_LISTEN"

// DefaultPeerListen is the peer listener when PeerListenEnv names none.
const DefaultPeerListen = ":8443"

// Config is one process's place in its deployment.
type Config struct {
	// URL is KV_URL; empty means this process answers alone.
	URL string
	// Deployment names the deployment, so two that share one KV (a testnet and
	// production) never answer for each other.
	Deployment string
	// BusURL is the shared pubsub cluster the bus (Publish, Subscribe, Serve, Call)
	// rides on, as nats://user:password@host:4222. Empty keeps it on the KV. It is
	// read only where the KV is shared: a bus no other pod can reach is not a bus.
	BusURL string
	// Self is this pod: its id and the address its peers dial.
	Self Member
	// Instance tells two pods under one id apart.
	Instance string
	// Secret is the deployment's master key. Every pod holds it, and the live set
	// is signed and the peer certificates issued under keys derived from it, so a
	// member or a peer nobody holding it made is refused.
	Secret []byte
	// Root is true for the pod's root process, which alone joins and leaves the live
	// set. The processes it spawns read the set; a process that comes and goes (an
	// app reaped when idle) must not take the pod with it.
	Root bool
	// Declared is the number of writers the deployment may run: the larger of the
	// replica count it declares (CLOUD_REPLICAS) and the pods CLOUD_PEERS names.
	Declared int
	// Periods is how long this process waits for each thing it waits for. A zero
	// field is production's.
	Periods Periods
	Log     luxlog.Logger
}

// Periods is every length of time a Coord keeps. Production states none of them
// and gets the length named beside each; a test of a lease changing hands, or of a
// pod leaving the live set, states short ones and sees the same thing sooner.
type Periods struct {
	// A loop's lease (lead.go).
	Term    time.Duration // 15s: how long a confirmed lease is held, from the write that confirmed it
	Effect  time.Duration // 5s: how much of the term must remain for an effect to be admitted
	Confirm time.Duration // 3s: how often a holder renews, and anyone else looks
	Watch   time.Duration // 1s: how often a running pass looks for its right having ended early

	// The live set (members.go). Presence is how long a pod stays in it after its
	// last heartbeat. The root renews every third of it, so one missed heartbeat
	// never drops a live pod, and a dead one is gone within it. An entry the KV says
	// lives longer than this was not written by a pod, and is ignored.
	Presence time.Duration // 10s
	Skew     time.Duration // 5s: how far two pods' clocks may disagree before a signed member reads as stale
	Refresh  time.Duration // 2s: how often each process re-reads the live set

	// Open is how long the KV's breaker stays open after the KV fails to answer (internal/driver/kv).
	Open time.Duration // 5s
}

// set is p with production's length wherever p states none.
func (p Periods) set() Periods {
	return Periods{
		Term:     cmp.Or(p.Term, 15*time.Second),
		Effect:   cmp.Or(p.Effect, 5*time.Second),
		Confirm:  cmp.Or(p.Confirm, 3*time.Second),
		Watch:    cmp.Or(p.Watch, time.Second),
		Presence: cmp.Or(p.Presence, 10*time.Second),
		Skew:     cmp.Or(p.Skew, 5*time.Second),
		Refresh:  cmp.Or(p.Refresh, 2*time.Second),
		Open:     cmp.Or(p.Open, 5*time.Second),
	}
}

// Env is this process's place in its deployment as the environment states it: the
// one reading the pod's root and every process it spawns make, so they all name the
// pod alike. Root is false; the root says so itself.
func Env() Config {
	id := cmp.Or(env.Or("CLOUD_POD_NAME", ""), env.Or("POD_NAME", ""), Hostname("cloud-0"))
	addr := net.JoinHostPort(podHost(), portOf(env.Or(PeerListenEnv, DefaultPeerListen)))
	declared := 0
	for p := range strings.SplitSeq(env.Or("CLOUD_PEERS", ""), ",") {
		if strings.TrimSpace(p) != "" {
			declared++
		}
	}
	if n, err := strconv.Atoi(strings.TrimSpace(env.Or("CLOUD_REPLICAS", ""))); err == nil {
		declared = max(declared, n)
	}
	var secret []byte
	if k, err := base64.StdEncoding.DecodeString(strings.TrimSpace(os.Getenv("CLOUD_KMS_MASTER_KEY_REF"))); err == nil && len(k) == 32 {
		secret = k
	}
	return Config{
		URL:        env.Or("KV_URL", ""),
		BusURL:     env.Or("CLOUD_PUBSUB_URL", ""),
		Deployment: Deployment(),
		Self:       Member{ID: id, Addr: addr},
		Instance:   Hostname("") + "|" + addr,
		Secret:     secret,
		Declared:   declared,
	}
}

// Deployment names the deployment a pod belongs to: its namespace, brand and
// environment. Two deployments that share a KV share no key.
func Deployment() string {
	parts := []string{env.Or("POD_NAMESPACE", "local"), env.Or("CLOUD_BRAND", brand.Default)}
	if env := env.Or("CLOUD_ENV", ""); env != "" {
		parts = append(parts, env)
	}
	return strings.Join(parts, ":")
}

// Hostname is the OS hostname, or def.
func Hostname(def string) string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return def
}

// podHost is the address this pod's peers reach it on: POD_IP, else the first
// non-loopback IPv4 address, else the hostname.
func podHost() string {
	if ip := strings.TrimSpace(os.Getenv("POD_IP")); ip != "" {
		return ip
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && !n.IP.IsLoopback() && !n.IP.IsLinkLocalUnicast() && n.IP.To4() != nil {
				return n.IP.String()
			}
		}
	}
	return Hostname("localhost")
}

func portOf(listen string) string {
	if i := strings.LastIndex(listen, ":"); i >= 0 {
		return listen[i+1:]
	}
	return listen
}

// Backend is what a Coord asks. kv answers across pods, mem across this process.
type Backend interface {
	// join writes r into the live set and answers nil, or, when another instance
	// holds r's id and force is false, writes nothing and answers what it holds.
	Join(ctx context.Context, set string, r Record, ttl time.Duration, force bool) (*Record, error)
	Leave(ctx context.Context, set, id, instance string) error
	Members(ctx context.Context, set string, ttl time.Duration) ([]Record, error)
	Spend(ctx context.Context, keys []string, scales []int, limit int, period time.Duration) (int, time.Time, error)
	Take(ctx context.Context, key string, perMin int) (bool, error)
	Once(ctx context.Context, key string, ttl time.Duration) (bool, error)
	// commit holds cents under id in the total at key, and answers the total of every
	// live hold at key, this one included; uncommit gives a hold back.
	Commit(ctx context.Context, key, id string, cents int64, ttl time.Duration) (int64, error)
	Uncommit(ctx context.Context, key, id string, cents int64) error
	Committed(ctx context.Context, key string) (int64, error)
	Quota(ctx context.Context, keys []string, limits []int, ttls []time.Duration) ([]int, []time.Duration, bool, error)
	Counted(ctx context.Context, keys []string) ([]int, error)
	Unquota(ctx context.Context, keys []string) error
	// span answers the start of the span under key running at now (unix seconds),
	// one lasting length seconds, or 0 when none runs; open opens one at now then.
	Span(ctx context.Context, key string, now, length int64, open bool) (int64, error)
}

// Coord answers for one process of one deployment.
type Coord struct {
	b        Backend
	local    *mem // the count a Spend or Take falls back to when the KV cannot be asked
	shared   bool
	prefix   string
	self     Member
	instance string
	owner    string // this process, as a loop lease names it: the pod and a nonce
	key      []byte // signs the live set
	secret   []byte // issues the peer certificates
	root     bool
	declared int
	p        Periods // every one set
	log      *quiet

	view     atomic.Pointer[snapshot]
	draining atomic.Bool
	closed   atomic.Bool

	mu       sync.Mutex
	err      error // why this process may not serve as part of the deployment
	presence *presence
	leaders  map[string]*Leader
	store    Store
	passes   sync.WaitGroup
	started  bool
	stop     chan struct{}
	peer     *peerTLS
	bus      Bus   // where the bus rides when it is not the KV: the shared pubsub cluster
	wire     *wire // what this pod says to the others and hears from them (bus.go)
}

// snapshot is the live set as last read: the verified members, and when.
type snapshot struct {
	members []Member
	at      time.Time // zero: never read
	self    time.Time // when this pod's own Record says it was written; zero: not seen
	dropped bool      // peers' records were live and this pod's was not
}

// New returns the Coord for one process. A KV_URL that cannot be parsed is an
// error, and so is a shared KV with no master key to sign the live set by: a live
// set nobody can verify is one anybody can write.
func New(cfg Config) (*Coord, error) {
	local := newMem()
	var b Backend = local
	shared := false
	drv := registered()
	if url := strings.TrimSpace(cfg.URL); url != "" {
		if len(cfg.Secret) == 0 {
			return nil, errors.New("coord: KV_URL is set but this process holds no master key to sign the live set with")
		}
		if drv.Backend == nil {
			return nil, ErrNoDriver
		}
		kb, err := drv.Backend(url, cfg.Periods)
		if err != nil {
			return nil, err
		}
		b, shared = kb, true
	}
	co := over(b, local, shared, cfg)
	if shared && strings.TrimSpace(cfg.BusURL) != "" {
		if drv.Bus == nil {
			return nil, ErrNoDriver
		}
		nb, err := drv.Bus(strings.TrimSpace(cfg.BusURL), "coord-"+co.owner)
		if err != nil {
			// The error is not shown: the URL carries the client's password and a
			// parse error quotes it.
			return nil, errors.New("coord: CLOUD_PUBSUB_URL cannot be used")
		}
		co.bus = nb
	}
	return co, nil
}

// over builds a Coord on backend b, with local as the fallback count.
func over(b Backend, local *mem, shared bool, cfg Config) *Coord {
	log := cfg.Log
	if log == nil {
		log = luxlog.Default()
	}
	nonce := make([]byte, 6)
	_, _ = rand.Read(nonce)
	c := &Coord{
		b: b, local: local, shared: shared,
		prefix:   "coord:" + strings.Trim(cfg.Deployment, ":") + ":",
		self:     cfg.Self,
		instance: cfg.Instance,
		owner:    cfg.Self.ID + "#" + hex.EncodeToString(nonce),
		key:      derive(cfg.Secret, "hanzo cloud coord member v1"),
		secret:   cfg.Secret,
		root:     cfg.Root,
		declared: cfg.Declared,
		p:        cfg.Periods.set(),
		log:      &quiet{log: log},
		leaders:  map[string]*Leader{},
		stop:     make(chan struct{}),
	}
	c.view.Store(&snapshot{})
	return c
}

// derive is a key for one purpose from the deployment's master.
func derive(secret []byte, purpose string) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(purpose))
	return mac.Sum(nil)
}

// OnBackend returns a Coord over b, which its pods share as they would a KV: a
// host or a test that holds a Backend already needs no URL to name one.
func OnBackend(b Backend, cfg Config) *Coord {
	return over(b, newMem(), true, cfg)
}

// Alone returns a Coord that answers for its own caller only: nothing else shares
// its counts, and its live set is this process.
func Alone() *Coord {
	return over(newMem(), newMem(), false, Config{Deployment: "local", Self: Member{ID: "local"}})
}

// Broken returns a Coord that answers for this process alone and reports err from
// Err, for a deployment whose KV cannot be used: the process must not serve
// believing it is alone when it may not be.
func Broken(err error) *Coord {
	c := Alone()
	c.err = err
	return c
}

var (
	defMu sync.Mutex
	def   *Coord
)

// SetDefault names this process's Coord.
func SetDefault(c *Coord) {
	defMu.Lock()
	def = c
	defMu.Unlock()
}

// Default is this process's Coord: the one SetDefault named, else one that answers
// for this process alone.
func Default() *Coord {
	defMu.Lock()
	defer defMu.Unlock()
	if def == nil {
		def = Alone()
	}
	return def
}

// Shared reports whether the answers hold across pods.
func (c *Coord) Shared() bool { return c.shared }

// Err is why this process may not serve as part of the deployment: its KV could not
// be used, or another live pod holds its id. nil when it may.
func (c *Coord) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

func (c *Coord) fail(err error) {
	c.mu.Lock()
	c.err = err
	c.mu.Unlock()
}

// SetStore names the deployment's object store, which every loop's lease lives in.
// Without one a loop runs only while this process is the deployment's one writer.
func (c *Coord) SetStore(s Store) {
	c.mu.Lock()
	c.store = s
	c.mu.Unlock()
}

func (c *Coord) storeOf() Store {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.store
}

func (c *Coord) Key(kind, name string) string { return c.prefix + kind + ":" + name }

// Spend charges one request to each of keys under the window named name, narrowest
// first, each held to limit times its scale per period, and answers what the
// tightest key has left (negative once over) and when the caller may next be
// admitted. A KV that cannot be asked is not a reason to admit everyone: the count
// falls back to this process's, and on a deployment of several writers each pod
// admits its share of the limit — rounded up, so no limit falls to zero — and the
// pods together admit about the limit, not the limit once per pod.
func (c *Coord) Spend(ctx context.Context, name string, keys []string, scales []int, limit int, period time.Duration) (int, time.Time) {
	full := make([]string, len(keys))
	for i, k := range keys {
		full[i] = c.Key("win:"+name, k)
	}
	left, reset, err := c.b.Spend(ctx, full, scales, limit, period)
	if err == nil {
		return left, reset
	}
	c.log.warn("spend", "coord: the shared count is not answering; this pod admits its share", "window", name, "err", err)
	if c.shared && c.Peered() {
		limit = (limit + c.declared - 1) / c.declared
	}
	left, reset, _ = c.local.Spend(ctx, full, scales, limit, period)
	return left, reset
}

// Take spends one token of key's bucket under name: perMin a minute, refilled
// continuously, as many as perMin at once. It falls back to this process's bucket
// when the KV cannot be asked.
func (c *Coord) Take(ctx context.Context, name, key string, perMin int) bool {
	full := c.Key("bucket:"+name, key)
	ok, err := c.b.Take(ctx, full, perMin)
	if err == nil {
		return ok
	}
	c.log.warn("take", "coord: the shared bucket is not answering; counting in this process", "bucket", name, "err", err)
	ok, _ = c.local.Take(ctx, full, perMin)
	return ok
}

// Once reports whether token under name is redeemed for the first time, and records
// it for ttl. A KV that cannot answer is ErrUnavailable on a deployment with more
// than one writer: a single-use token that cannot be proven unused is not used.
// A deployment of one writer is this process, so it counts here.
func (c *Coord) Once(ctx context.Context, name, token string, ttl time.Duration) (bool, error) {
	key := c.Key("once:"+name, token)
	first, err := c.b.Once(ctx, key, ttl)
	if err == nil {
		return first, nil
	}
	if !c.Peered() {
		c.log.warn("once", "coord: the KV is not answering; single-use tokens are counted in this process", "name", name, "err", err)
		return c.local.Once(ctx, key, ttl)
	}
	c.log.warn("once", "coord: a single-use token cannot be checked", "name", name, "err", err)
	return false, ErrUnavailable
}

// Commit holds cents against key under name, as hold id, for at most ttl, and answers the
// total held against key by every pod, this hold included. It is the sum a caller weighs
// its balance against, so that calls in flight on three pods each see the others' and
// not only their own: the holds are the deployment's, in the KV every pod shares, and a
// hold a pod never gives back (it died) lapses after ttl instead of locking the key until
// something restarts. A KV that cannot be asked leaves each pod the total of its own
// holds, as a pod always had.
func (c *Coord) Commit(ctx context.Context, name, key, id string, cents int64, ttl time.Duration) int64 {
	full := c.Key("hold:"+name, key)
	total, err := c.b.Commit(ctx, full, id, cents, ttl)
	if err == nil {
		return total
	}
	c.log.warn("commit", "coord: the shared holds are not answering; counting this pod's", "holds", name, "err", err)
	total, _ = c.local.Commit(ctx, full, id, cents, ttl)
	return total
}

// Uncommit gives back the hold id under key, committed with the same cents. A hold
// already given back, or lapsed, is not an error. Both the shared holds and this
// pod's own are cleared, as a hold may have been made in either while the KV
// was and was not answering.
func (c *Coord) Uncommit(ctx context.Context, name, key, id string, cents int64) {
	full := c.Key("hold:"+name, key)
	if err := c.b.Uncommit(ctx, full, id, cents); err != nil {
		c.log.warn("uncommit", "coord: the shared holds are not answering; the hold lapses instead", "holds", name, "err", err)
	}
	if c.shared {
		_ = c.local.Uncommit(ctx, full, id, cents)
	}
}

// Committed is the total held against key under name, read without holding anything.
func (c *Coord) Committed(ctx context.Context, name, key string) int64 {
	full := c.Key("hold:"+name, key)
	total, err := c.b.Committed(ctx, full)
	if err != nil {
		total, _ = c.local.Committed(ctx, full)
	}
	return total
}

// quiet logs each kind of trouble at most once a period, so a KV that is down does
// not write a line per request.
type quiet struct {
	log  luxlog.Logger
	mu   sync.Mutex
	last map[string]time.Time
}

const quietPeriod = 30 * time.Second

func (q *quiet) warn(kind, msg string, kv ...any) {
	q.mu.Lock()
	if q.last == nil {
		q.last = map[string]time.Time{}
	}
	now := time.Now()
	if now.Sub(q.last[kind]) < quietPeriod {
		q.mu.Unlock()
		return
	}
	q.last[kind] = now
	q.mu.Unlock()
	q.log.Warn(msg, kv...)
}
