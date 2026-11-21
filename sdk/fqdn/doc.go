// Package fqdn is the ONE place a public hostname is normalized, validated, and
// proven to be under a caller's control.
//
// Two subsystems bind customer hostnames — /v1/platform apps (clients/platform)
// and PaaS sites (clients/projects) — and both must answer the same three
// questions: what is the canonical form of this name, is it syntactically a
// hostname at all, and does the caller actually control it. Each carried its own
// copy of the answer, and the copies had already drifted: both compiled the same
// hostname regexp independently, and only the apps path stripped a trailing root
// dot before matching, so `example.com.` normalized on one endpoint and was
// rejected as malformed on the other. One concept, one implementation, here.
//
// Ownership proof is the DNS-01 model: the claimant publishes a per-claim token
// as a TXT record at `_hanzo-challenge.<host>`. Only someone who controls that
// zone's DNS can, so a matching token proves control. This is the boundary that
// stops a tenant claiming a host it does not own, so the check is deliberately
// small enough to read in one sitting.
//
// Everything here is pure except Verify (one DNS read) and Token (one rng read):
// no store, no HTTP, no service state. That is what lets both callers share it.
package fqdn
