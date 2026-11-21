// Package coordtest stands up pods that share a deployment in this process: shared
// counts (Memory) and loops fenced by a store (Replicas). Pods over a real KV, a
// Valkey server or miniredis, are internal/driver/kv/kvtest's.
package coordtest
