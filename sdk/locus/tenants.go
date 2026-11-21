package locus

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/hanzoai/orm/tenant"
)

// AdminEnv names the server administrator's URL. A deployment that names it keeps
// its shared stores (see [Tenants]) on the server; the driver reads it.
const AdminEnv = "CLOUD_SQL_ADMIN_DSN"

// Tenancy is a store whose rows many organizations share: one database, tenancy a
// column, through hanzoai/orm/tenant.
type Tenancy struct {
	// Name is the app's: the server login, database and schema, or the SQLite file in
	// the system namespace. A lowercase identifier.
	Name string
	// DataDir holds the SQLite file when no server is named.
	DataDir string
	// Tables are the store's tenant tables.
	Tables []tenant.Table
	// Tenant answers the org a statement's context acts for, and nothing a caller sent.
	Tenant func(context.Context) (string, bool)
	// Audit records every entry into the platform (cross-org) scope.
	Audit func(ctx context.Context, why string)
}

// Tenants opens a shared store and migrates its tables; the returned func closes
// it. It is the relational counterpart of [Open]: a per-org file isolates tenants
// physically, a shared table isolates them twice over (every statement is scoped to
// the org its context names, and on a server row-level security is forced on every
// table).
//
// With the administrator named (AdminEnv) the engine opens it on the server. Without
// it the store is the app's encrypted SQLite file, and orm/tenant runs the same
// statements there. A deployment that names a server and not its administrator does
// not get that file, which would be a copy of rows every replica must share, private
// to one pod: it refuses.
func Tenants(ctx context.Context, t Tenancy) (*tenant.DB, func() error, error) {
	if t.Name == "" || strings.Trim(t.Name, "abcdefghijklmnopqrstuvwxyz0123456789_") != "" {
		return nil, nil, fmt.Errorf("locus: store name %q is not a lowercase identifier", t.Name)
	}
	if p := driver.Load(); p != nil {
		if db, closeDB, ok, err := (*p).Tenants(ctx, t); ok || err != nil {
			return db, closeDB, err
		}
	}
	if _, err := server(); err != nil {
		return nil, nil, err
	}
	db, err := System(t.Name, t.DataDir)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: open the store: %w", t.Name, err)
	}
	st, err := tenant.Open(ctx, tenant.Config{Driver: "sqlite", DB: db, Tables: t.Tables, Tenant: t.Tenant, Audit: t.Audit})
	if err != nil {
		_ = db.Close()
		return nil, nil, err
	}
	return st, db.Close, nil
}

var master atomic.Pointer[func() []byte]

// SetMaster tells the SDK where the deployment's data-plane master is held, for a
// driver that derives a credential from it. The host calls it once.
func SetMaster(f func() []byte) { master.Store(&f) }

// Master is the data-plane master, nil where none is held.
func Master() []byte {
	if p := master.Load(); p != nil {
		return (*p)()
	}
	return nil
}
