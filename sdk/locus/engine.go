package locus

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"sync/atomic"
	"time"

	"github.com/hanzoai/orm/tenant"
	luxlog "github.com/luxfi/log"

	"github.com/hanzoai/namespace"
)

// Engine is a server a store can live on instead of its SQLite file. The SDK runs
// every store on its own embedded SQLite; a deployment that names a server in the
// environment (Env) links the driver for it, and the driver registers itself here.
// An app never names an engine: it opens a store through [Open] or [Use], and the
// engine, when there is one, decides where the store lives and moves it off its
// file when the policy ([MoveMode]) says to.
//
// With no server named, no method of an Engine is ever called. With one named and
// no driver linked, every open fails: a store must never quietly fall back to a
// file the deployment did not mean it to have.
type Engine interface {
	// Ported reports whether the subsystem's stores run on the server at all. A
	// subsystem that is not ported keeps its file even where the server is
	// configured. The driver answers it because the list is production wiring.
	Ported(subsystem string) bool
	// Where says where the store lives now.
	Where(ns namespace.Namespace, subsystem, dir string) (Place, error)
	// WhereAt is Where for a store whose file is at a path the caller names: an
	// engine that keeps its own files and so is not under the namespace's path.
	WhereAt(ns namespace.Namespace, subsystem, path string) (Place, error)
	// Open opens the store on the server. It is the handle's owner's to close.
	Open(ns namespace.Namespace, subsystem string) (*sql.DB, error)
	// Guard refuses a file for a store the server holds, which would split it.
	Guard(ns namespace.Namespace, subsystem string) error
	// Settle moves the store from its file to the server when the policy says to,
	// once, the first time a process opens it. open is the store's own open over a
	// handle, migration included. A move that fails is not an error: the store
	// stays its file. One in progress elsewhere is ErrMoving.
	Settle(ctx context.Context, log luxlog.Logger, ns namespace.Namespace, subsystem, dir string, open func(*sql.DB) (io.Closer, error)) error
	// Move moves the store from its file under dir to the server, or says why not.
	Move(ctx context.Context, log luxlog.Logger, ns namespace.Namespace, subsystem, dir string, open func(*sql.DB) (io.Closer, error)) (Report, error)
	// MoveOnline moves a live append-only store while its writer keeps appending.
	MoveOnline(ctx context.Context, log luxlog.Logger, ns namespace.Namespace, subsystem, dir string, open func(*sql.DB) (io.Closer, error), on Online) (Report, error)
	// MoveFile moves a store whose engine opens its own file and its own pool.
	MoveFile(ctx context.Context, log luxlog.Logger, ns namespace.Namespace, subsystem string, f Files) (Report, error)
	// Revert puts a moved store back on its file.
	Revert(ctx context.Context, ns namespace.Namespace, subsystem string) error
	// Stores lists the namespaces, as text, that have a store for subsystem on the server.
	Stores(subsystem string) ([]string, error)
	// Subsystems lists the subsystems ns has a store for on the server.
	Subsystems(ns namespace.Namespace) ([]string, error)
	// Exists reports whether the store has been made on the server, without making it.
	Exists(ns namespace.Namespace, subsystem string) (bool, error)
	// Lease claims or renews holder's lease on a store, so one replica acts for it at a time.
	Lease(ns namespace.Namespace, subsystem, holder string, ttl time.Duration) (held bool, retry time.Duration, err error)
	// Unlease gives up every lease holder has.
	Unlease(holder string) error
	// Slot is the one place in the deployment a background move runs from.
	Slot(ctx context.Context) (release func(), err error)
	// Locks is the pool for advisory locks that have no store of their own.
	Locks() (*sql.DB, error)
	// Described opens the store for an engine that opens its own pools and changes its own tables.
	Described(ns namespace.Namespace, subsystem string) (*sql.DB, error)
	// Placed answers the pools of a store a module opens itself.
	Placed(ctx context.Context, log luxlog.Logger, ns namespace.Namespace, subsystem, dir, legacy string, prepare func() error, open func(Host) (io.Closer, error)) (Host, error)
	// Scratch makes a schema nobody else uses, and the function that drops it.
	Scratch(ctx context.Context) (Host, func(), error)
	// Tenants opens a shared store on the server, or says ok=false when the
	// deployment keeps shared stores in SQLite. A server named without its
	// administrator is an error.
	Tenants(ctx context.Context, t Tenancy) (db *tenant.DB, closeDB func() error, ok bool, err error)
}

var driver atomic.Pointer[Engine]

// Register installs the server engine. A driver calls it once, from its init;
// the host links the driver, the SDK never does.
func Register(e Engine) { driver.Store(&e) }

// ErrNoServer is what a store answers when the environment names a server and no
// driver for it is linked.
var ErrNoServer = errors.New("locus: " + Env + " names a server and no server driver is linked into this binary")

// server is the engine the deployment asked for: nil when it asked for none.
func server() (Engine, error) {
	if DSN() == "" {
		return nil, nil
	}
	p := driver.Load()
	if p == nil {
		return nil, ErrNoServer
	}
	return *p, nil
}

// Ported reports whether the subsystem's stores run on the configured server:
// false with no server, and false for a subsystem the server does not hold.
func Ported(subsystem string) bool {
	e, err := server()
	return err == nil && e != nil && e.Ported(subsystem)
}

// need is server for a call that has no meaning without one.
func need(what string) (Engine, error) {
	e, err := server()
	if err != nil {
		return nil, err
	}
	if e == nil {
		return nil, fmt.Errorf("locus: %s: %s is not set, so no server holds the stores", what, Env)
	}
	return e, nil
}

// Where says where the store lives now. Without a server every store is a file.
func Where(ns namespace.Namespace, subsystem, dir string) (Place, error) {
	e, err := server()
	if e == nil {
		return OnFile, err
	}
	return e.Where(ns, subsystem, dir)
}

// WhereAt is [Where] for a store whose file is at a path the caller names.
func WhereAt(ns namespace.Namespace, subsystem, path string) (Place, error) {
	e, err := server()
	if e == nil {
		return OnFile, err
	}
	return e.WhereAt(ns, subsystem, path)
}

// Stores lists the namespaces, as text, that have a store for subsystem on the server.
func Stores(subsystem string) ([]string, error) {
	e, err := need("list the stores")
	if err != nil {
		return nil, err
	}
	return e.Stores(subsystem)
}

// Subsystems lists the subsystems ns has a store for on the server.
func Subsystems(ns namespace.Namespace) ([]string, error) {
	e, err := need("list the subsystems")
	if err != nil {
		return nil, err
	}
	return e.Subsystems(ns)
}

// Exists reports whether the store has been made on the server.
func Exists(ns namespace.Namespace, subsystem string) (bool, error) {
	e, err := need("ask whether a store exists")
	if err != nil {
		return false, err
	}
	return e.Exists(ns, subsystem)
}

// Lease claims, or renews, holder's lease on the store for ttl.
func Lease(ns namespace.Namespace, subsystem, holder string, ttl time.Duration) (bool, time.Duration, error) {
	e, err := need("lease a store")
	if err != nil {
		return false, 0, err
	}
	return e.Lease(ns, subsystem, holder, ttl)
}

// Unlease gives up every lease holder has. Without a server it holds none.
func Unlease(holder string) error {
	e, err := server()
	if e == nil {
		return err
	}
	return e.Unlease(holder)
}

// Slot takes the one place a background move runs from.
func Slot(ctx context.Context) (func(), error) {
	e, err := need("take the move slot")
	if err != nil {
		return nil, err
	}
	return e.Slot(ctx)
}

// Locks is the pool a lock is held on when its caller has no store of its own. With
// no server there is one process, a lock is its mutex, and Locks answers nil.
func Locks() (*sql.DB, error) {
	e, err := server()
	if e == nil {
		return nil, err
	}
	return e.Locks()
}

// Move moves the store from its file under dir to the server.
func Move(ctx context.Context, log luxlog.Logger, ns namespace.Namespace, subsystem, dir string, open func(*sql.DB) (io.Closer, error)) (Report, error) {
	e, err := need("move a store")
	if err != nil {
		return Report{}, err
	}
	return e.Move(ctx, log, ns, subsystem, dir, open)
}

// MoveOnline moves a live append-only store while its writer keeps appending.
func MoveOnline(ctx context.Context, log luxlog.Logger, ns namespace.Namespace, subsystem, dir string, open func(*sql.DB) (io.Closer, error), on Online) (Report, error) {
	e, err := need("move a live store")
	if err != nil {
		return Report{}, err
	}
	return e.MoveOnline(ctx, log, ns, subsystem, dir, open, on)
}

// MoveFile moves a store whose engine opens its own file and its own pool.
func MoveFile(ctx context.Context, log luxlog.Logger, ns namespace.Namespace, subsystem string, f Files) (Report, error) {
	e, err := need("move a file")
	if err != nil {
		return Report{}, err
	}
	return e.MoveFile(ctx, log, ns, subsystem, f)
}

// Revert puts a moved store back on its file. Without a server it never left.
func Revert(ctx context.Context, ns namespace.Namespace, subsystem string) error {
	e, err := server()
	if e == nil {
		return err
	}
	return e.Revert(ctx, ns, subsystem)
}

// Described opens the store for an engine that opens its own pools.
func Described(ns namespace.Namespace, subsystem string) (*sql.DB, error) {
	e, err := need("open a described pool")
	if err != nil {
		return nil, err
	}
	return e.Described(ns, subsystem)
}

// Placed answers the pools of a store a module opens itself, or nil when the store
// stays on its file.
func Placed(ctx context.Context, log luxlog.Logger, ns namespace.Namespace, subsystem, dir, legacy string, prepare func() error, open func(Host) (io.Closer, error)) (Host, error) {
	e, err := server()
	if e == nil {
		return nil, err
	}
	return e.Placed(ctx, log, ns, subsystem, dir, legacy, prepare, open)
}

// Scratch makes a schema nobody else uses.
func Scratch(ctx context.Context) (Host, func(), error) {
	e, err := need("make a scratch schema")
	if err != nil {
		return nil, nil, err
	}
	return e.Scratch(ctx)
}
