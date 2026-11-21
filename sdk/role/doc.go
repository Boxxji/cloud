// Package role resolves the HA role of a Hanzo Cloud process: the single
// authoritative WRITER (owns the RWO data dir — the ZapDB KMS store, the SQLite
// audit chain, the durable task store, and per-tenant SQLite) or a stateless
// READER (no RWO PVC, no exclusive store lock; hydrates read-only replicas from
// the S3/vfs replication stream and serves read paths).
//
// INVARIANT — exactly one process may open the RWO stores for WRITE at a time.
// The writer is a StatefulSet with replicas:1 + Recreate; readers are a
// RollingUpdate Deployment with no RWO mount. This package makes the role an
// explicit, first-class value instead of an implicit "there is only one pod"
// assumption, so readers can be added without ever risking a second writer.
//
// DEFAULT — an unset CLOUD_ROLE resolves to Writer, so a deployment that does
// not set the variable behaves EXACTLY as cloud does today (one writer pod).
// This package has zero effect until something reads it: it imports nothing from
// cloud and mutates no global state.
package role
