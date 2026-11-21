package spec

// A GET THAT CHANGES SOMETHING, declared, because the method cannot say it.
//
// Every reader of a published document takes GET to mean "reads": the client
// catalog marks such an operation read-only (plugin/gen-client-catalog), and the
// fleet's MCP server publishes a subsystem whose every operation reads with
// readOnlyHint, the annotation a client trusts to skip the confirmation a write
// deserves. A link a person follows out of an email is a GET because a mail
// client can only follow a link, and it can still record something: the click it
// counts, the opt-out it files. [Writes] is how its subsystem says so, beside the
// route, exactly as [Open] says an operation needs no credential.

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
)

var (
	writesMu  sync.Mutex
	writesOps = map[opKey]bool{}
)

// Writes declares that one GET operation changes state, keyed by its address and
// method exactly as [Open] is. It renders as `x-writes: true`, and a reader of
// the document stops calling that operation read-only.
//
// ONE operation per call and GET only: any other method already says it writes.
// A duplicate is a programming error at init time and panics, as [Open] does.
func Writes(path, method string) {
	if strings.ContainsAny(path, "*+") {
		panic(fmt.Sprintf("openapi: Writes(%q) names operations, never a wildcard", path))
	}
	m := strings.ToUpper(method)
	if m != http.MethodGet {
		panic(fmt.Sprintf("openapi: Writes(%q, %q) — only a GET can look like a read", path, method))
	}
	at, _ := Translate(path)
	key := opKey{method: m, path: at}
	writesMu.Lock()
	defer writesMu.Unlock()
	if writesOps[key] {
		panic(fmt.Sprintf("openapi: duplicate Writes for %s %s", key.method, key.path))
	}
	writesOps[key] = true
}

// writes marks the declared operations on a finished document. It runs where
// [secure] runs, on the same finished set of addresses, for the same reason.
func writes(d *Document) {
	writesMu.Lock()
	defer writesMu.Unlock()
	for path, item := range d.Paths {
		for method, op := range item {
			if writesOps[opKey{method: strings.ToUpper(method), path: path}] {
				op.Writes = true
			}
		}
	}
}
