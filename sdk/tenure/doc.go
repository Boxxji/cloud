// Package org is the high-availability layer under the per-org SQLite stores:
// writer membership and fencing decide who writes an org, the snapshot codec and
// conditional store ship its state to the object store, and the cipher and field
// seals keep that state and sensitive columns encrypted at rest.
package tenure
