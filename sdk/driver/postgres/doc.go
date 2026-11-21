// Package postgres is the hanzo-sql engine of the SDK's locus package: a schema on the one
// shared PostgreSQL per store, a connection budget for the process, the registry, the
// leases, and the mover that carries a store from its file to the server. It registers
// itself into locus.Engine from init (engine.go).
//
// For a file it is one sentence — one connection — and it is a package so that the
// sentence has somewhere to be true: a store that opens a database does not restate
// it, nor the driver's own PRAGMA defaults, so there is one copy of the fact to keep.
//
// The PRAGMAs are gone because hanzoai/sqlite already applies them, on every
// connection, on every backend — see sdk/locus pragma_test.go, which asserts exactly that
// and fails if it ever stops being true. What is NOT already applied everywhere
// is the pool cap, so that is what remains here.
package postgres
