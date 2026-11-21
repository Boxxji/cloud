// Copyright 2025 Hanzo AI Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cloud

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"

	luxlog "github.com/luxfi/log"

	"github.com/zap-proto/zip"

	"github.com/hanzoai/cloud/sdk/coord"
	"github.com/hanzoai/cloud/sdk/locus"
	"github.com/hanzoai/namespace"
	tasksauth "github.com/hanzoai/tasks/pkg/auth"
	tasksclient "github.com/hanzoai/tasks/pkg/sdk/client"
	tasksengine "github.com/hanzoai/tasks/pkg/tasks"
)

// durableGatedZAPPort is the CLUSTER-reachable, identity-gated ZAP port the embedded
// engine exposes via Embedded.ServeGated (published on cloud's Service in universe).
// Unlike the loopback socket (ungated, ai-ingest only), every request here must
// carry a valid IAM auth_token — the same trust anchor as HTTP SanitizeIdentity —
// org-scoped to the token owner. 9999 mirrors the port the retired tasksd exposed, so
// a consumer repoint changes only the host (the old service host → this one).
const durableGatedZAPPort = 9999

// gatedAddr is the cluster-reachable tasks listener. It defaults to the port
// the retired tasksd exposed, so existing consumers keep their address, and
// CLOUD_TASKS_GATED_PORT moves it.
//
// It needs to move because "two instances can never coexist on one host" stopped
// being acceptable: apps are separate processes now, and a developer running a
// second stack — or a second agent on a shared box — has no way to bring one up
// while another holds the port. A fixed number is right for a deployment and wrong
// for a workstation.
// gatedAddr is where the CLUSTER-reachable, identity-gated listener binds. This
// one is a TCP address and must stay one: consumers in other pods dial it, and a
// unix socket does not leave the host. The engine's own loopback listener is a
// socket (see InstallDurableIngest) precisely because nothing off-host dials THAT.
func gatedAddr() string {
	if v := strings.TrimSpace(os.Getenv("CLOUD_TASKS_GATED_PORT")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return ":" + strconv.Itoa(n)
		}
	}
	return ":" + strconv.Itoa(durableGatedZAPPort)
}

// embeddedTasks keeps the in-process engine alive for the process (a package ref the GC
// won't collect) and lets Serve stop it on shutdown. It is atomic because a
// subsystem may wait for it from a goroutine Use started, before Serve installs it.
var embeddedTasks atomic.Pointer[tasksengine.Embedded]

// EmbeddedTasks returns the ONE in-process tasks engine, or nil until
// InstallDurableIngest has run (or if it failed to start). The Tasks HTTP/UI surface
// (apps/tasks, mounted at /v1/tasks/*) serves on THIS shared engine — there is
// exactly one engine per process, shared by ai's durable ingest AND the Tasks
// product surface, never a second Embed. The surface resolves it lazily (per
// request) because subsystem Mount runs during UseAll, before InstallDurableIngest.
func EmbeddedTasks() *tasksengine.Embedded { return embeddedTasks.Load() }

// InstallDurableIngest embeds the ONE hanzoai/tasks engine IN-PROCESS — the unified durable
// queue (there is no second async system; tasks/CONTRACT) — and injects a per-org
// loopback ZAP dialer into ai's ingest. A long ingest (github/crawl/s3) then runs as a
// durable workflow in the OWNER's namespace (CONTRACT §6: namespace maps 1:1 to org),
// tracked in the ONE Tasks product. In-process ZAP = mega fast, low latency/memory, no
// HTTP. Fail-soft by construction: any embed error leaves ai's dialer unset →
// EnqueueIngest returns ErrTasksNotConfigured → the handler runs ingest inline (always
// works). Called once, after UseAll (ai is mounted), in its own goroutine beside
// Listen: until it stores the engine, EmbeddedTasks is nil and every consumer
// takes its not-yet path.
func InstallDurableIngest(ctx context.Context, deps Deps, app string) {
	// A stable data dir the engine owns. Cloud's container is distroless (no /tmp), so
	// Embed's default os.MkdirTemp("") fallback fails — pin it to cloud's data root.
	// PER PROCESS, both of them. Apps are their own binaries now, so a fixed port
	// and a shared directory are two processes' worth of contention over one
	// resource: seven of eight children lost the bind on one fixed port and ran with
	// NO durable engine at all — marketing's drip queue among them, which is how a
	// campaign resolved its audience and then mailed nobody. A shared store would be
	// the same collision one layer down, since the engine's SQLite has one writer.
	//
	// It is a UNIX SOCKET, not a port. A path per app needs no allocation and
	// cannot collide, which is what the internal plane does everywhere else — and
	// it is why the collision above cannot recur: two processes cannot want the
	// same free port when neither wants a port at all.
	//
	// ON HANZO-SQL the directory is only where the engine's old files are, if it
	// has any: the engine's state is a schema, and every replica is one engine (see
	// durableDatabase). A pod then needs no volume for it.
	dataDir := filepath.Join(cmp.Or(DataDir(), "/data"), "tasks", cmp.Or(app, "cloud"))
	db, err := durableDatabase(ctx, app, dataDir)
	if err != nil {
		luxlog.Default().Error("durable ingest: the engine's database is unavailable; ingest runs inline", "app", app, "err", err)
		return
	}
	if db == nil {
		if err := os.MkdirAll(dataDir, 0o755); err != nil {
			luxlog.Default().Warn("durable ingest: data dir unavailable; ingest runs inline", "err", err)
			return
		}
	}
	sock := zip.SocketPath("tasks-" + cmp.Or(app, "cloud"))
	var relay func(tasksengine.Event)
	var hear func(*tasksengine.Embedded) func()
	if db != nil {
		relay, hear = relayEvents(coord.Default(), app)
	}
	emb, err := tasksengine.Embed(ctx, durableConfig(sock, dataDir, db, durableNode(app), relay))
	if err != nil {
		if db != nil {
			_ = db.Close()
		}
		luxlog.Default().Warn("durable ingest: tasks embed failed; ingest runs inline", "err", err)
		return
	}
	embeddedTasks.Store(emb)
	embeddedTasksDB.Store(db)
	if hear != nil {
		stop := hear(emb)
		embeddedTasksFeed.Store(&stop)
	}
	addr := emb.Address()
	ingestDialer = func(org string) (tasksclient.Client, error) {
		return tasksclient.Dial(tasksclient.Options{Address: addr, Namespace: "default"})
	}
	luxlog.Default().Info("durable ingest wired: in-process tasks engine", "app", app, "addr", addr, "dataDir", dataDir, "shared", db != nil)

	// Expose the SAME engine on a cluster-reachable, IDENTITY-GATED ZAP listener so the
	// standalone tasksd's consumers (auto, hanzo-playground, platform) run their durable
	// work here. RequireIdentity: every request must carry an IAM auth_token, validated
	// against {IAMIssuer}/v1/iam/.well-known/jwks (HIP-0111) and org-scoped to its owner —
	// the SAME trust anchor as the HTTP SanitizeIdentity boundary. The loopback dialer above
	// stays ungated (in-process ai-ingest shares cloud's trust boundary). Fail-soft: a
	// missing issuer or a bind failure logs and leaves the gated surface down without
	// touching ai-ingest.
	// The GATED listener is a cluster-reachable port, so exactly one process may own
	// it — and the one that should is the app that serves the Tasks product. Every
	// process trying meant seven of eight logging "address already in use" for a
	// listener they had no business exposing.
	if app != "tasks" && app != "cloud" {
		return
	}
	if deps.IAMIssuer == "" {
		luxlog.Default().Warn("durable tasks: no IAM issuer; gated cluster ZAP listener NOT exposed", "addr", gatedAddr())
		return
	}
	validator := tasksauth.NewValidator(tasksauth.JWTConfig{
		Issuer:  deps.IAMIssuer,
		JWKSURL: JWKSURLFor(deps.IAMIssuer),
	})
	if err := emb.ServeGated(ctx, gatedAddr(), validator); err != nil {
		luxlog.Default().Error("durable tasks: gated cluster ZAP listener failed to start", "err", err, "addr", gatedAddr())
		return
	}
	luxlog.Default().Info("durable tasks: gated cluster ZAP listener up", "addr", gatedAddr(), "issuer", deps.IAMIssuer)
}

// durableConfig is how every embedded engine is configured: the one place.
//
// RequireIdentity defaults false: the engine is loopback-only and shares cloud's trust
// boundary. Data isolation is enforced in the workflow INPUT (IngestSource is
// owner-scoped), so ingest enqueues into the engine's always-registered `default`
// namespace rather than a per-org namespace. The embedded engine only registers
// `default` at boot and does NOT lazily create namespaces on ExecuteWorkflow — dialing
// an unregistered per-org namespace makes the worker poll a namespace that doesn't
// exist and BLOCK, which silently forced ingest to fall back inline.
func durableConfig(sock, dataDir string, db *sql.DB, node string, relay func(tasksengine.Event)) tasksengine.EmbedConfig {
	return tasksengine.EmbedConfig{
		Address:      sock,
		DataDir:      dataDir,
		Database:     db,
		Relay:        relay,
		NodeID:       node,
		KeepFinished: keepFinishedRuns,
	}
}

// keepFinishedRuns is whether the engine keeps finished runs for ever. It does, and the
// period a namespace keeps its history for is set by a human, not by cloud: deleting
// workflow history is their decision, and nobody has made it. The engine enforces a
// namespace's WorkflowExecutionRetentionTtl (720h unless the row says otherwise) since
// hanzoai/tasks v1.53.6; cloud ran v1.53.5, which purged nothing. Until a period is
// chosen the purge does not run, and a namespace's period is a field on its row that
// nothing acts on. This is the only place it is stated.
const keepFinishedRuns = true

// embeddedTasksFeed ends this process's hearing of the other pods' events.
var embeddedTasksFeed atomic.Pointer[func()]

// relayEvents carries an engine's live feed between the pods of a deployment, on the
// bus the pods already share (coord.Publish): what a pod's engine emits, the other
// pods' engines hear into their own feeds, so a browser on /v1/workflow/events sees the
// deployment's events and not those of the pod the edge happened to choose. Nothing is
// stored, and the feed is a view: an event sent while a pod was reconnecting is missed,
// and a client that needs state reads it.
func relayEvents(bus *coord.Coord, app string) (relay func(tasksengine.Event), hear func(*tasksengine.Embedded) (stop func())) {
	subject := "tasks.events." + cmp.Or(app, "cloud")
	relay = func(ev tasksengine.Event) {
		if body, err := json.Marshal(ev); err == nil {
			_ = bus.Publish(subject, body) // a full queue (ErrBusy) drops the event, as the feed does anywhere
		}
	}
	hear = func(emb *tasksengine.Embedded) (stop func()) {
		return bus.Subscribe(subject, func(_ string, payload []byte) {
			var ev tasksengine.Event
			if json.Unmarshal(payload, &ev) == nil {
				emb.Hear(ev)
			}
		}, nil)
	}
	return relay, hear
}

// embeddedTasksDB is the hanzo-sql schema the engine runs on, or nil when it keeps
// files. The engine does not close it; StopDurable does, after the engine has left.
var embeddedTasksDB atomic.Pointer[sql.DB]

// StopDurable ends the in-process engine. On hanzo-sql it LEAVES: its membership is
// given up now and not at the end of its term, so the replicas that remain take up
// what it owed within a beat, which is what makes a rolling update lose nothing.
func StopDurable(ctx context.Context) {
	if stop := embeddedTasksFeed.Swap(nil); stop != nil {
		(*stop)()
	}
	if emb := embeddedTasks.Swap(nil); emb != nil {
		if err := emb.Stop(ctx); err != nil {
			luxlog.Default().Warn("durable tasks: the engine did not stop cleanly", "err", err)
		}
	}
	if db := embeddedTasksDB.Swap(nil); db != nil {
		_ = db.Close()
	}
}

// durableNode names this replica's engine: the pod, and the app whose engine it is.
// The engine adds what tells two incarnations of one pod apart.
func durableNode(app string) string {
	return coord.Env().Self.ID + "-" + cmp.Or(app, "cloud")
}

// durableDatabase is where app's engine keeps its state: the hanzo-sql schema
// "tasks-<app>" when the deployment has one (CLOUD_SQL_DSN) and the app is one that
// runs an engine there (manifest.SQLStores), nil when the engine keeps shard files.
//
// WHERE AN ENGINE LIVES IS A FACT ABOUT ITS ROWS, not about the deployment, as it is for
// every store (locus.Where). Setting the DSN moves nothing: an engine whose files hold
// rows that have not been moved stays on them (one replica, as before) until
// CLOUD_SQL_MOVE says to move them, and then it moves them once, here, before it opens, so
// no second process has the files while they are copied. An engine with no files, or
// whose files have been moved, is born or stays on the schema, and every replica that
// opens it is the same engine.
//
// The engine's files are a tree of shards and not one SQLite file, so locus.Move, which
// copies a file's tables by name, is not what moves them: tasksengine.MoveFiles is, under
// the same policy (locus.MoveMode) and, for a sweep, the same one-at-a-time slot. A move
// that fails leaves the engine on its files, and the next start tries again.
func durableDatabase(ctx context.Context, app, dataDir string) (*sql.DB, error) {
	if locus.DSN() == "" {
		return nil, nil
	}
	subsystem := "tasks-" + cmp.Or(app, "cloud")
	if !onSQL(subsystem) {
		// An app that is not declared to run an engine on hanzo-sql keeps the one it
		// always had, on the pod's own disk.
		return nil, nil
	}
	mode, err := locus.MoveMode()
	if err != nil {
		return nil, err
	}
	// No data directory: the schema is where this engine's state is, and the engine's
	// files are the tree below dataDir, not a file the seam would name.
	db, err := locus.Open(namespace.System(), subsystem, "")
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*sql.DB, error) {
		_ = db.Close()
		return nil, err
	}
	moved, err := tasksengine.Moved(ctx, db)
	if err != nil {
		return fail(err)
	}
	if moved {
		return db, nil
	}
	if moving, err := tasksengine.Moving(ctx, db); err != nil {
		return fail(err)
	} else if moving {
		return fail(fmt.Errorf("another process is moving %s's files to hanzo-sql, or one stopped halfway and will be tried again; this engine does not open beside it", app))
	}
	if !tasksengine.FilesIn(dataDir) {
		return db, nil // born here
	}
	if mode == locus.Never {
		luxlog.Default().Warn("durable tasks: this engine's rows are still in files and stay there; set "+locus.MoveEnv+" to move them to hanzo-sql",
			"app", app, "dir", dataDir)
		_ = db.Close()
		return nil, nil
	}
	if mode == locus.Sweep {
		release, err := locus.Slot(ctx)
		if err != nil {
			return fail(err)
		}
		defer release()
	}
	rep, err := tasksengine.MoveFiles(ctx, db, dataDir, nil)
	if err != nil {
		luxlog.Default().Error("durable tasks: the engine's files could not be moved to hanzo-sql; it stays on them and the move is tried again at the next start",
			"app", app, "dir", dataDir, "err", err)
		_ = db.Close()
		return nil, nil
	}
	luxlog.Default().Info("durable tasks: engine moved from files to hanzo-sql", "app", app,
		"tenants", rep.Tenants, "shards", rep.Shards, "rows", rep.Rows, "bytes", rep.Bytes, "took", rep.Took, "already", rep.Already)
	return db, nil
}
