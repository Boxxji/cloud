// Package audit is the unified cloud binary's compliance-grade audit trail —
// tamper-evident, append-only, and complete over the security-relevant request
// surface (FedRAMP AU-* / SOC 2 CC-* controls).
//
// THE CONTROL, IN ONE SENTENCE. Every security-relevant action against this
// binary is captured as a structured Record, hash-chained to its predecessor so
// any later deletion or modification is detectable, and written INLINE (never
// dropped) to an append-only store the application can only INSERT into.
//
// THREE PIECES, EACH IN ITS LANE (orthogonal, per the Zen of Hanzo):
//   - record.go  — the event model + the hash-chain math (what a record IS and
//     how it links to the one before it). Pure, no I/O.
//   - store.go   — the append-only sink (SQLite primary, INSERT-only; a
//     best-effort OLAP mirror) and the serialized Recorder that
//     owns the chain head. All persistence.
//   - redact.go  — the secret-stripping allowlist/denylist for any structured
//     before/after an explicit emit point supplies. No secret ever
//     reaches a record.
//
// The HTTP middleware (Middleware, in the cloud package) and the query/verify
// endpoints (in clients/admin) are thin callers of this package. This package
// holds the security logic; it has zero knowledge of routes.
package audit
