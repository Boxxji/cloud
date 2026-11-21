package cloud

import (
	"context"
	"fmt"

	luxlog "github.com/luxfi/log"
	"github.com/zap-proto/zip"
)

// UseFunc is a subsystem's mount contract: register your routes on app, using
// deps for everything shared. Every subsystem in the fleet exports exactly this
// signature, so Wire references each one directly and the compiler checks it.
//
// app is the subsystem's grant: a group at each prefix it declared and nothing
// above them, so what it registers and what it gates are the same subtrees. A
// subsystem that must cover every route declares [Plugin.Root].
//
// THIS IS THE CONTRACT'S ONLY ENFORCEMENT, AND IT IS THE COMPILER. There is no
// second entry-point field to launder a divergent shape through, so an app whose
// Mount takes *zip.App, or a differently-aliased Router, cannot be assigned here
// and cannot reach a composition root. A doc comment stating the signature is
// what let five apps diverge from it unnoticed; a type is what checks it.
//
// A subsystem whose routes are registered by a module that spells its own whole
// addresses declares them on a definition and composes it with [Router.Use],
// which refuses any address outside the grant.
type UseFunc func(app Router, deps Deps) error

// ShutdownFunc releases a subsystem's process-lifetime resources (background
// goroutines, open DB handles) on graceful shutdown. It must be idempotent and
// bounded — Serve calls it within the shutdown deadline. ctx carries that
// deadline so a slow teardown is cut off rather than hanging SIGTERM.
type ShutdownFunc func(ctx context.Context) error

// CtxShutdown adapts a subsystem's zero-arg Shutdown() error to ShutdownFunc.
// Several subsystems expose the simpler form (their teardown ignores the
// deadline); this bridges the impedance mismatch in ONE place so the Wire
// entries stay declarative — no inline closures.
//
// It lives beside ShutdownFunc rather than in package apps because a Wire entry
// is copied verbatim into plugin/<app>/main.go by plugin/gen-app-cmds: an apps-local
// helper is unreachable from a standalone main, so that app falls back to the
// fat stub that links EVERY subsystem. Package-qualified here, it is nameable
// from anywhere and the per-app binary stays lean.
func CtxShutdown(f func() error) ShutdownFunc {
	return func(context.Context) error { return f() }
}

// App describes one subsystem to mount. There is NO Order field: the slice
// position in apps.Wire() IS the mount order — the composition root lists
// subsystems in the exact sequence they mount (and, reversed, tear down), so order
// is data read top-to-bottom in one file, not ints scattered across the tree.
type Plugin struct {
	Name     string
	Use      UseFunc
	Shutdown ShutdownFunc // optional; nil means the subsystem has nothing to tear down.

	// Price is what ONE request to this subsystem's surface costs at the edge gate —
	// Free, Metered, or a positive number of cents (see price.go). It is REQUIRED:
	// the zero value is Undeclared, and TestPriceDeclared fails on it, so a new
	// subsystem cannot reach main until someone writes down what it costs. This is
	// the ONE place a surface's price is declared; DefaultPrice reads it and holds no
	// table of its own.
	Price Price

	// Shared opens this process's plane socket to every user on the host. The
	// socket stops being the boundary and the app's ops attest each peer from
	// what the kernel says about it instead; only an app whose every plane op
	// does so may set it, and today that is kms.
	Shared bool

	// OwnsHealth marks a subsystem that serves its OWN GET /v1/<name>/health
	// (a real, fail-closed probe). Serve's generic liveness loop skips these so
	// its always-ok route never shadows the subsystem's real probe.
	OwnsHealth bool

	// Prefixes are the route subtrees this subsystem holds. Empty means the
	// convention it already follows — /v1/<Name>, the same subtree Serve's generic
	// liveness route assumes — so only a subsystem serving somewhere else has to
	// name it. It is the whole of what the subsystem may register and gate: UseAll
	// hands it a group at each of these and nothing above them, which is the same
	// bound the light host applies when it routes a child's declared prefixes.
	Prefixes []string

	// Root mounts on the app instead of a group, for a subsystem whose
	// middleware must cover every route. Set Use or Root, never both.
	Root func(*zip.App, Deps) error

	// Offer is this subsystem's PER-CALLER contribution to the MCP server: the tools
	// that exist because of who is asking, which the build-time projection cannot
	// hold. Nil — every subsystem but one — leaves the MCP server exactly the typed
	// ops.
	//
	// It is stated HERE, at the composition root, for the reason Price and
	// Prefixes are: what a binary serves is a property of the binary, declared
	// where the binary is assembled, not installed from inside a Mount that runs
	// after the MCP server is configured.
	Offer zip.Source
}

// Offer is the ONE per-caller tool source of a binary. Two subsystems each
// claiming one would be two answers to "what else can this caller call", so the
// second is a composition error and not a merge.
func Offer(plugins []Plugin) (zip.Source, error) {
	var src zip.Source
	var held string
	for _, p := range plugins {
		if p.Offer == nil {
			continue
		}
		if src != nil {
			return nil, fmt.Errorf("%s and %s both declare an Offer — a binary has one per-caller tool source", held, p.Name)
		}
		src, held = p.Offer, p.Name
	}
	return src, nil
}

// UseAll mounts every ENABLED subsystem in specs, in slice order — the order is
// the composition root's (apps.Wire()); UseAll does NOT sort.
//
// app is the concrete *zip.App from Serve. A Root spec receives it. Everyone
// else receives a group at each prefix it declared and nothing above them, so
// what it registers and what it gates are the same subtrees, whatever its slice
// position. A subsystem that asks for a prefix it does not hold fails the mount
// — the binary refuses to boot rather than serve one subsystem's route under
// another's gate. It is the bound the light host already applies from the other
// side, where a child is routed its declared prefixes and nothing else.
//
// Every spec goes through spec.Use, whatever the grant: the Router it receives
// is the only difference, which is what makes [UseFunc] the fleet's ONE mount
// signature and lets the compiler check it at all 123 composition roots.
//
// Teardown is wired HERE, at mount time: right after a subsystem mounts, its
// ShutdownFunc (if any) is registered via app.OnShutdown. zip drains those hooks
// LIFO — AFTER the listeners stop accepting and in-flight requests drain — so
// registration-at-mount yields reverse-mount teardown (a dependency mounted before
// its dependents is torn down after them) with no subsystem torn down while a
// request still uses it. Only ENABLED specs mount, so only they register a hook;
// teardown needs no separate enablement gate.
func UseAll(app *zip.App, specs []Plugin, cfg *Config, deps Deps) error {
	logger := luxlog.Default()
	// Declare the composition root BEFORE anything mounts: TracingMiddleware resolves
	// hanzo.subsystem off this, DefaultPrice resolves each surface's declared price off
	// it, and the inventory (including what is switched OFF) is what
	// /v1/admin/subsystems reports. Built once, read lock-free per request.
	Declare(specs, cfg)
	for _, spec := range specs {
		if !cfg.Enabled(spec.Name) {
			logger.Debug("subsystem disabled", "name", spec.Name)
			continue
		}
		if spec.Use == nil && spec.Root == nil {
			return fmt.Errorf("use %s: no Use — a subsystem that registers nothing is not composed, it is absent", spec.Name)
		}
		if spec.Use != nil && spec.Root != nil {
			return fmt.Errorf("use %s: set Use or Root, not both", spec.Name)
		}
		// The grant decides WHICH Router, never which signature. Global is handed
		// the host as well as its group; everyone else gets the group alone, and
		// that is the confinement — zip composes a chain over the definition it
		// was declared on, so what a subsystem installs reaches the routes it
		// registered and nothing else. One call, one shape, either way.
		switch {
		case spec.Root != nil:
			if err := spec.Root(app, deps); err != nil {
				return fmt.Errorf("mount %s: %w", spec.Name, err)
			}
		default:
			def := zip.New(zip.Config{AppName: spec.Name, Logger: luxlog.Default(), DisableStartupMessage: true})
			if err := spec.Use(def, deps); err != nil {
				return fmt.Errorf("mount %s: %w", spec.Name, err)
			}
			if err := held(def, UsePrefixes(spec.Name, spec.Prefixes)); err != nil {
				return fmt.Errorf("mount %s: %w", spec.Name, err)
			}
			app.Use(def)
		}
		// Register teardown as a zip shutdown hook. zip runs hooks LIFO after the
		// drain (zip.App.Shutdown), so this reproduces the reverse-mount order the
		// hand-rolled reverse-loop gave — without the teardown-before-drain race.
		if spec.Shutdown != nil {
			app.OnShutdown(spec.Shutdown)
		}
		logger.Info("composed subsystem", "name", spec.Name)
	}
	return nil
}
