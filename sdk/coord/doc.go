// Package coord is what cloud's pods agree on: which pods are alive (Members), which
// one runs each loop (Lead), how much a caller has spent across every pod (Spend,
// Take, Quota), when a caller's session window opened (Span), and which single-use
// tokens have been redeemed (Once).
//
// With the deployment's KV (KV_URL, Hanzo KV) the answers hold across pods. With no
// KV they hold across this process, which is the whole deployment when it is one
// pod. That is a backend, not a mode: every caller asks the same questions of the
// same type either way.
//
// This package links no KV and no message cluster. A host registers them (Register)
// before it calls New: internal/driver/kv for the KV and internal/driver/pubsub for
// the cross-pod bus. A KV_URL or CLOUD_PUBSUB_URL with nothing registered is refused
// (ErrNoDriver) rather than answered alone, because pods that each think they are
// alone each spend a whole limit and each run every loop. A driver implements
// Backend, and Bus when it carries messages; the in-process answers (Memory) are the
// reference for what each method must do.
//
// The KV is never the fence. Who runs a loop is decided by a lease in the
// deployment's object store, taken by compare-and-set exactly as an org's writer is
// (sdk/tenure), renewed by its holder's writes, and taken from a holder only once
// it has gone a full term unrenewed (lead.go); nothing about a loop asks the KV.
// The KV says who is alive, and only what this deployment signed within a heartbeat
// counts as an answer, so a value planted in it names nobody and takes no pod down.
package coord
