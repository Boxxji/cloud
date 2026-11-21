package object

import (
	"context"
	"errors"
	"io"
	"iter"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/hanzoai/cloud/sdk/env"
)

// Driver is what a deployment's object store registers into this package. The host
// and each plugin main link it; the SDK links none.
type Driver struct {
	// Name names the driver in the one log line that says which store a process
	// opened.
	Name string
	// Open builds the store from the environment, or reports false when the
	// environment does not configure it (the process then uses local disk, or
	// refuses where local disk is not allowed).
	Open func() (Store, bool, error)
}

var (
	driverMu sync.Mutex
	driver   *Driver
)

// Register installs d. A second driver is a programming error and panics, as
// sql.Register does.
func Register(d Driver) {
	driverMu.Lock()
	defer driverMu.Unlock()
	if driver != nil {
		panic("object: a store driver is already registered")
	}
	driver = &d
}

// ConfigEnv is the variable that says a deployment keeps its objects in the object
// store: the shared admin access key. A process that has it and links no driver
// refuses (ErrNoDriver) rather than answer from an empty disk.
const ConfigEnv = "S3_ADMIN_ACCESS_KEY"

// LocalEnv set to "local" declares that this deployment keeps its files on its own
// volume, which is how a single-pod deployment runs where Production is true.
const LocalEnv = "CLOUD_OBJECT_STORE"

var (
	// ErrNoDriver is Open's refusal when the environment configures an object store
	// and no driver for it is linked into this binary.
	ErrNoDriver = errors.New("object: " + ConfigEnv + " is set but no object store driver is linked into this binary")
	// ErrNotConfigured is Open's refusal in a production deployment that configures
	// no object store. Its data may already live in one; an empty local disk would
	// answer "no such object" for all of it, and the next write would bury it.
	ErrNotConfigured = errors.New("object: this is a production deployment with no object store configured; set " + ConfigEnv + " (and the S3_ADMIN_* settings), or " + LocalEnv + "=local to keep files on this volume")
)

// Production reports whether this process belongs to a deployment: CLOUD_ENV
// names one (every deployment states it; the hanzo-sql driver refuses to open a
// store without it). Being in a Kubernetes pod is not the test — a CI runner is a
// pod too, and a production binary must not link package testing to tell them apart.
func Production() bool {
	switch env.Or("CLOUD_ENV", "") {
	case "", "test", "dev", "local":
		return false
	}
	return true
}

// Open resolves the store a process uses: the registered driver when the
// environment configures it, else local when allowed. local is the engine to fall
// back to; its Dir is the data directory.
//
//	driver configured              -> the driver
//	ConfigEnv set, no driver       -> ErrNoDriver
//	nothing configured, Production -> ErrNotConfigured, unless LocalEnv=local
//	otherwise                      -> local
func Open(local *Local) (Store, error) {
	driverMu.Lock()
	d := driver
	driverMu.Unlock()
	if d != nil {
		s, ok, err := d.Open()
		if err != nil {
			return nil, err
		}
		if ok {
			return s, nil
		}
	}
	if env.Or(ConfigEnv, "") != "" {
		return nil, ErrNoDriver
	}
	if Production() && env.Or(LocalEnv, "") != "local" {
		return nil, ErrNotConfigured
	}
	return local, nil
}

var shared = &lazy{}

// PublicEnv names the URL a local link points at, e.g. http://localhost:8080 on a
// laptop. Without it a deployment's links use https://<CLOUD_DOMAIN>, and with
// neither there is no address a browser could follow, so Share and Form refuse
// (ErrNoPresign) rather than sign one.
const PublicEnv = "CLOUD_PUBLIC_URL"

func publicBase() string {
	if u := env.Or(PublicEnv, ""); u != "" {
		return strings.TrimRight(u, "/")
	}
	if d := env.Or("CLOUD_DOMAIN", ""); d != "" {
		return "https://" + d
	}
	return ""
}

// Default is the process-wide store, opened on first use so a package-level
// variable can hold it before the host has said anything. An open that fails (no
// driver, not configured) fails every call with the same error, and is retried on
// the next one.
func Default() Store { return shared }

// Handler serves the links the process-wide store signs. It answers 404 when the
// store is not the local one, whose links point at the object store itself.
func Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, err := shared.get()
		if l, ok := s.(*Local); err == nil && ok {
			l.Handler().ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
	})
}

type lazy struct {
	mu   sync.Mutex
	s    Store
	made string // the environment s was opened under
}

// stance is what Open decides from: the environment that picks an engine. A deployment
// never changes it, so the store opens once; a process that does change it (a test
// moving from a laptop to a production posture) is answered afresh rather than from
// an engine chosen under the old one.
func stance() string {
	return strings.Join([]string{env.Or(ConfigEnv, ""), env.Or(LocalEnv, ""), env.Or("CLOUD_ENV", ""), os.Getenv("KUBERNETES_SERVICE_HOST"), env.DataDir()}, "\x00")
}

func (z *lazy) get() (Store, error) {
	z.mu.Lock()
	defer z.mu.Unlock()
	now := stance()
	if z.s != nil && z.made == now {
		return z.s, nil
	}
	z.s = nil
	s, err := Open(&Local{Dir: env.DataDir(), Base: publicBase})
	if err != nil {
		return nil, err
	}
	z.s, z.made = s, now
	return s, nil
}

// Usable reports why s cannot be used, or nil. For the process-wide store it is Check
// (the open can refuse); any other store is taken to work until it fails.
func Usable(s Store) error {
	if z, ok := s.(*lazy); ok {
		_, err := z.get()
		return err
	}
	return nil
}

// ConfiguredShared reports whether the environment names a shared object store
// (ConfigEnv is set), whether or not a driver for it is linked. A process that keeps
// its stores in one must not mint a key of its own over an empty disk.
func ConfiguredShared() bool { return env.Or(ConfigEnv, "") != "" }

// Check opens the process-wide store and reports why it cannot (ErrNoDriver,
// ErrNotConfigured, or the driver's own refusal). A caller that must not run
// without the store the deployment promised asks at boot, not at the first write.
func Check() error {
	_, err := shared.get()
	return err
}

// Delegation is the address and key pair of the object store itself, for a process
// that writes into it with a client of its own. It is the whole store's key, not a
// scoped one (the store issues none), so whoever takes one holds every bucket.
type Delegation struct {
	URL       string // with the scheme
	Region    string
	AccessKey string
	Secret    string
	// PathStyle addresses a bucket as the first path segment.
	PathStyle bool
}

// Delegator is a store that can hand its credential to another process. The local
// engine cannot: there is no server for the process to write to.
type Delegator interface {
	Delegate() (Delegation, bool)
}

// Delegate returns the process-wide store's credential, and false when it has
// none to give.
func Delegate() (Delegation, bool) {
	s, err := shared.get()
	if err != nil {
		return Delegation{}, false
	}
	d, ok := s.(Delegator)
	if !ok {
		return Delegation{}, false
	}
	return d.Delegate()
}

// IsLocal reports the process-wide store as the local engine, and false when it is
// anything else or cannot be opened.
func IsLocal() bool {
	s, err := shared.get()
	_, ok := s.(*Local)
	return err == nil && ok
}

func (z *lazy) Ensure(ctx context.Context, b string) error {
	s, err := z.get()
	if err != nil {
		return err
	}
	return s.Ensure(ctx, b)
}
func (z *lazy) Has(ctx context.Context, b string) (bool, error) {
	s, err := z.get()
	if err != nil {
		return false, err
	}
	return s.Has(ctx, b)
}
func (z *lazy) Buckets(ctx context.Context) ([]Bucket, error) {
	s, err := z.get()
	if err != nil {
		return nil, err
	}
	return s.Buckets(ctx)
}
func (z *lazy) Drop(ctx context.Context, b string) error {
	s, err := z.get()
	if err != nil {
		return err
	}
	return s.Drop(ctx, b)
}
func (z *lazy) Put(ctx context.Context, b, k string, r io.Reader, n int64, o Put) (Info, error) {
	s, err := z.get()
	if err != nil {
		return Info{}, err
	}
	return s.Put(ctx, b, k, r, n, o)
}
func (z *lazy) Open(ctx context.Context, b, k string, o Get) (*Body, error) {
	s, err := z.get()
	if err != nil {
		return nil, err
	}
	return s.Open(ctx, b, k, o)
}
func (z *lazy) Stat(ctx context.Context, b, k string) (Info, error) {
	s, err := z.get()
	if err != nil {
		return Info{}, err
	}
	return s.Stat(ctx, b, k)
}
func (z *lazy) Remove(ctx context.Context, b, k string) error {
	s, err := z.get()
	if err != nil {
		return err
	}
	return s.Remove(ctx, b, k)
}
func (z *lazy) RemoveMany(ctx context.Context, b string, keys []string) error {
	s, err := z.get()
	if err != nil {
		return err
	}
	return s.RemoveMany(ctx, b, keys)
}
func (z *lazy) List(ctx context.Context, b string, o List) iter.Seq2[Info, error] {
	s, err := z.get()
	if err != nil {
		return func(yield func(Info, error) bool) { yield(Info{}, err) }
	}
	return s.List(ctx, b, o)
}
func (z *lazy) Copy(ctx context.Context, dst, src Ref, o Copy) (Info, error) {
	s, err := z.get()
	if err != nil {
		return Info{}, err
	}
	return s.Copy(ctx, dst, src, o)
}
func (z *lazy) Share(ctx context.Context, sh Share) (Link, error) {
	s, err := z.get()
	if err != nil {
		return Link{}, err
	}
	return s.Share(ctx, sh)
}
func (z *lazy) Form(ctx context.Context, f Form) (Link, error) {
	s, err := z.get()
	if err != nil {
		return Link{}, err
	}
	return s.Form(ctx, f)
}
func (z *lazy) Begin(ctx context.Context, b, k string, o Put) (string, error) {
	s, err := z.get()
	if err != nil {
		return "", err
	}
	return s.Begin(ctx, b, k, o)
}
func (z *lazy) Parts(ctx context.Context, b, k, id string) ([]Part, error) {
	s, err := z.get()
	if err != nil {
		return nil, err
	}
	return s.Parts(ctx, b, k, id)
}
func (z *lazy) Join(ctx context.Context, b, k, id string, p []Part) (Info, error) {
	s, err := z.get()
	if err != nil {
		return Info{}, err
	}
	return s.Join(ctx, b, k, id, p)
}
func (z *lazy) Abort(ctx context.Context, b, k, id string) error {
	s, err := z.get()
	if err != nil {
		return err
	}
	return s.Abort(ctx, b, k, id)
}
