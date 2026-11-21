package cloud

import (
	"database/sql"
	"testing"

	"github.com/hanzoai/cloud/sdk/principal"
	"github.com/hanzoai/namespace"
)

// An open func made with NewOrgStoreAt is handed the namespace its database is for, once
// per store and not per visit: that is what lets a store whose rows carry no org seal a
// column bound to the org.
func TestNewOrgStoreAtHandsTheOpenerItsNamespace(t *testing.T) {
	var opened []namespace.Namespace
	store := NewOrgStoreAt(Base{DataDir: t.TempDir()}, "widget", func(ns namespace.Namespace, db *sql.DB) (*sql.DB, error) {
		opened = append(opened, ns)
		return openRows(db)
	})
	t.Cleanup(func() { _ = store.CloseAll() })

	acme, globex := principal.MustOrgNamespace("acme", ""), principal.MustOrgNamespace("globex", "")
	for _, ns := range []namespace.Namespace{acme, globex, acme} {
		if _, err := store.For(ns); err != nil {
			t.Fatalf("For(%s): %v", ns, err)
		}
	}
	if len(opened) != 2 || opened[0] != acme || opened[1] != globex {
		t.Fatalf("the opener was handed %v, want [%v %v]", opened, acme, globex)
	}
}
