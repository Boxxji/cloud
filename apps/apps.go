// Package apps is the composition root for the OSS Hanzo Cloud core: the single,
// explicit list of which subsystems are linked into the binary AND the order they
// mount in.
//
// Wire() returns []cloud.MountSpec in mount order (slice position == order). There
// is no init()-registry and no order-int: adding, removing, or reordering a
// subsystem is a one-line edit to Wire(), read top-to-bottom. cmd/cloud calls
// Wire() and threads the slice into cloud.Serve — the set is defined ONCE, here.
//
// This is the local dev server: every subsystem here runs on one machine with a
// data directory as its only dependency.
//
// (This package must NOT live in package cloud: the subsystems import cloud for
// Deps + Typed, so a root-package bundle would form an import cycle. As a sibling
// subpackage it composes them without one.)
package apps

import (
	"context"
	"fmt"

	luxlog "github.com/luxfi/log"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/cloud"
	"github.com/hanzoai/cloud/apps/blueprint"

	// In-repo subsystem packages (clients/*). Each exports a Mount (and, where it
	// owns process-lifetime resources, a Shutdown); Wire references them directly.
	"github.com/hanzoai/cloud/clients/auditlog"
	"github.com/hanzoai/cloud/clients/base"
	"github.com/hanzoai/cloud/clients/code"
	"github.com/hanzoai/cloud/clients/dns"
	"github.com/hanzoai/cloud/clients/exec"
	"github.com/hanzoai/cloud/clients/flags"
	"github.com/hanzoai/cloud/clients/functions"
	"github.com/hanzoai/cloud/clients/gateway"
	"github.com/hanzoai/cloud/clients/ingress"
	"github.com/hanzoai/cloud/clients/kms"
	"github.com/hanzoai/cloud/clients/kv"
	"github.com/hanzoai/cloud/clients/plugin"
	"github.com/hanzoai/cloud/clients/security"
	"github.com/hanzoai/cloud/clients/session"
	"github.com/hanzoai/cloud/clients/storage"
	"github.com/hanzoai/cloud/clients/tasks"
)

// Wire returns every linked subsystem as a cloud.MountSpec, in mount order. The
// slice position IS the order: cloud.MountAll iterates it as-given, registering
// each subsystem's teardown as a zip shutdown hook so teardown runs in reverse
// (LIFO). Enablement is a separate axis: cloud.Serve mounts only the specs
// cfg.Enabled(name) admits, so a STAGED subsystem is linked but inert until named.
func Wire() []cloud.MountSpec {
	return []cloud.MountSpec{
		// Insights feature-flag evaluation seam (no routes; a hot value plane).
		{Name: "flags", Mount: flags.Mount, Shutdown: flags.Shutdown, OwnsHealth: true, Description: "Feature flags: ship it dark, then turn it on for who you pick."},
		// Embedded KMS secrets plane /v1/kms/*. OwnsHealth: serves its own
		// fail-closed /v1/kms/health. Fails closed until CLOUD_KMS_MASTER_KEY_REF.
		{Name: "kms", Mount: kms.Mount, OwnsHealth: true, Description: "Secret custody: your org's secrets sealed at rest."},
		// Embedded runtime edge (/v1/ingress/*). STAGED — edge listeners stay off
		// unless the operator names "ingress" in CLOUD_ENABLE.
		{Name: "ingress", Mount: ingress.Mount, Shutdown: ingress.Shutdown, Description: "Your edge: automatic TLS certificates and hostname routing."},
		// /v1/s3/buckets/* + /v1/s3/health. OwnsHealth (real fail-closed probe).
		{Name: "storage", Mount: storage.Mount, OwnsHealth: true, Prefix: "/v1/s3", Description: "Object storage: your buckets and the files in them."},
		// The /v1/dns forward head: relays the console DNS dashboard to the DNS
		// control plane under the caller's own validated bearer.
		{Name: "dns", Mount: dns.Mount, Description: "Your DNS records, relayed to the DNS control plane under your own bearer."},
		{Name: "code", Mount: code.Mount, Shutdown: code.Shutdown, Description: "Search and symbols across your repos, for you and your agents."},
		{Name: "session", Mount: session.Mount, Shutdown: ctxShutdown(session.Shutdown), Prefix: "/v1/code/sessions", Description: "Live coding-agent runs: list them, watch them, steer them."},
		{Name: "security", Mount: security.Mount, Shutdown: ctxShutdown(security.Shutdown), OwnsHealth: true, Description: "Secret scanning for your code: submit sources, get findings."},
		{Name: "exec", Mount: exec.Mount, Description: "The code interpreter: run a snippet in a sandbox and move files."},
		{Name: "gateway", Mount: gateway.Mount, Description: "Live control of the edge policy your API applies to every request."},
		{Name: "audit", Mount: auditlog.Mount, Description: "Your org's tamper-evident audit trail."},

		// The local apps. Each is a REAL implementation over the embedded store,
		// not a relay to a cluster: the dev edition is meant to be a working
		// product on a laptop with no network, and an app that only forwards
		// somewhere else would make it a client for a thing you do not have.
		//
		// Every route in these is a typed op, which is why they need no
		// per-app integration work: one declaration is simultaneously the REST
		// route, the OpenAPI schema, the MCP tool and the generated SDK method.
		{Name: "base", Mount: base.Mount, Shutdown: base.Shutdown, Description: "A document store per org: collections of JSON records."},
		{Name: "kv", Mount: kv.Mount, Shutdown: kv.Shutdown, Description: "Your key-value store: versioned values your apps read and write."},
		{Name: "tasks", Mount: tasks.Mount, Shutdown: tasks.Shutdown, Description: "Durable work: a lease and acknowledge queue."},
		// STAGED (see stagedSubsystems): functions RUNS CODE, so it is linked in
		// every build but mounts only when an operator names it.
		{Name: "functions", Mount: functions.Mount, Shutdown: functions.Shutdown, Description: "Serverless code: publish it and call it over HTTP."},

		// Apps that import zip and nothing of their host: the same package mounts in
		// any host that hands it a router and the few things it reads. Each takes
		// only what it names, so an entry here is an adapter from cloud.Deps to
		// that and nothing more.
		{Name: "blueprint", Mount: logged("blueprint", blueprint.Mount), OwnsHealth: true, Description: "What a template costs to run: its bill of images and a compute-cost estimate."},

		// Runtime wasm/proxy plugins — mounts dead last.
		{Name: "plugins", Mount: plugin.Mount, Description: "Runtime plugins, wasm and proxy, mounted under /v1/plugins."},
	}
}

// ServeSingle is the ONE way to run a single app standalone: validate `name`
// against Wire(), then serve exactly it (cloud.Serve with a one-name enable list).
// Returns an error for an unknown name rather than booting a no-op.
func ServeSingle(name string) error {
	if name == "" {
		return fmt.Errorf("ServeSingle: empty app name")
	}
	for _, spec := range Wire() {
		if spec.Name == name {
			return cloud.Serve(Wire(), []string{name})
		}
	}
	return fmt.Errorf("ServeSingle: unknown app %q", name)
}

// logged adapts an app that asks its host for a router and a logger to the mount
// contract: the logger is scoped to the app's name, as cloud.Mount scopes it.
func logged(name string, mount func(*zip.App, luxlog.Logger) error) cloud.MountFunc {
	return func(app *zip.App, deps cloud.Deps) error {
		return mount(app, deps.Logger.New("subsystem", name))
	}
}

// ctxShutdown adapts a subsystem's zero-arg Shutdown() error to the
// cloud.ShutdownFunc(ctx) signature. Several subsystems expose the simpler form
// (their teardown ignores the deadline); this bridges the impedance mismatch in
// ONE place so the Wire entries stay declarative — no inline closures.
func ctxShutdown(f func() error) cloud.ShutdownFunc {
	return func(context.Context) error { return f() }
}
