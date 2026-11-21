package cloud

import (
	"context"
	"github.com/hanzoai/cloud/sdk/secret"
	"os"
	"strings"

	"github.com/hanzoai/cloud/sdk/meter"
	"github.com/hanzoai/ha"
	luxlog "github.com/luxfi/log"

	"github.com/hanzoai/cloud/sdk/audit"
	"github.com/hanzoai/cloud/sdk/infer"
	"github.com/hanzoai/cloud/sdk/tenure"
)

// Deps is the shared dependency surface passed to every subsystem's
// Use(app, deps) function. Subsystems consume only what they need.
//
// In-process: each Client below resolves to a direct Go method-call
// implementation. Out-of-process (legacy split deploys): the same Client
// resolves to a ZAP-RPC implementation. Subsystem code does not branch
// on which mode; the interface is the contract.
// Secret resolves a KMS-sealed secret by reference, for a subsystem that must not
// import the KMS client type to read one. A nil KMS yields a resolver that errors,
// so a caller needing a sealed key fails closed rather than reading a zero value.
//
// It lives on Deps because Deps is what HAS the KMS. It was written twice — byte
// for byte, in apps/company and apps/compliance — which is how a helper with no
// home ends up with two, free to drift apart while both look canonical.
//
// The return type is the bare signature, not any subsystem's named alias, so this
// package stays ignorant of who consumes it and the consumers keep their own names
// for it.
func (d Deps) Secret() func(ctx context.Context, ref string) ([]byte, error) {
	return func(ctx context.Context, ref string) ([]byte, error) { return secret.Get(ctx, d.KMS, ref) }
}

// SecretFromEnv resolves the KMS reference held in the environment variable
// `name`. Only the reference travels through the environment; the value stays
// sealed until this call and never appears in a manifest, a pod spec or a log.
//
// This is the layer above Secret, and it had gone the same way: loadMPCKey and
// loadSafeJWTSecret in apps/wallet are the same eight lines twice, which is what
// the note above predicts of a helper with no home. Every env-held ref wants the
// same three decisions and they are worth making once.
//
// An unset variable is "not configured" and yields nil quietly. A variable that
// names a ref which does not resolve — no secret store in this process, a ref the
// store does not hold, a store that cannot answer — also yields nil, and the
// caller fails closed; that is deliberate, since these are read at construction,
// where the choice is between running without a capability and not running at
// all. But it is LOUD: it is logged as an error, here, once, naming the variable
// and why. A process that was told to hold a key and silently does not is how a
// signing key reads as empty.
func (d Deps) SecretFromEnv(ctx context.Context, name string) []byte {
	return secretFromEnv(ctx, d.KMS, name)
}

// SecretFromEnv is the same on Base, because Base is what a mounted subsystem
// holds — Use derives one from Deps — and a helper reachable only from the
// construction side is a helper the handlers cannot call.
func (b Base) SecretFromEnv(ctx context.Context, name string) []byte {
	return secretFromEnv(ctx, b.KMS, name)
}

func secretFromEnv(ctx context.Context, kms secret.Store, name string) []byte {
	if strings.TrimSpace(os.Getenv(name)) == "" {
		return nil
	}
	value, err := secret.Resolve(ctx, kms, name)
	if err != nil {
		luxlog.Default().Error("a configured secret did not resolve; the capability it keys is off", "env", name, "err", err)
		return nil
	}
	return value
}

type Deps struct {
	// Logger is not here. The process default is (luxlog.Default, installed by
	// BuildDeps before anything can log), so a subsystem derives its scoped child
	// from the library rather than from a field it had to be handed. Carrying it
	// meant every mount checked it for nil — a field can be nil, a package-level
	// default cannot.

	// Brand, Env, Domain and DataDir are not here. They are deployment FACTS: a
	// subsystem cannot fail to connect to a brand name, it reads the string and
	// stamps it, which is what separated them from the clients below. Carrying them
	// meant every mount took a struct of twenty things to read one string, and a
	// field can be empty where a resolver cannot. They are cloud.Brand(), cloud.Env(),
	// cloud.Domain() and cloud.DataDir() in config.go — the same move the logger, the
	// process id and the model names made before them.

	// Version is the API contract/build version emitted as the X-Api-Version
	// response header (see middleware.ProductionHeaders wiring in serve.go).
	Version string

	// Self is not here. It was — THIS process's stable id, the StatefulSet ordinal
	// or the OS hostname — with a doc comment describing how a subsystem would
	// name the replica a status came from. No subsystem ever did: it had ZERO
	// readers. The id itself is real and still resolved by selfID(cfg), which the
	// durability membership elects on; what was dead was the copy on Deps. A field
	// whose justification is written entirely in the future tense is a plan, not a
	// dependency.

	// IAMIssuer is the canonical OIDC issuer (JWKS source) for this brand,
	// resolved from Brand via the white-label registry unless pinned by the
	// operator. Subsystems validate JWT `iss` + signatures against
	// {IAMIssuer}/v1/iam/.well-known/jwks (HIP-0111). One issuer per deployment.
	IAMIssuer string

	// MasterKey is the 32-byte at-rest KEK (decoded CLOUD_KMS_MASTER_KEY_REF), for
	// subsystems that encrypt their own stores and would otherwise each need a key
	// provisioned separately. One process, one key. nil ⇒ unset/invalid, and each
	// subsystem falls back to whatever it did before.
	MasterKey []byte

	// Durable is the per-deployment HA-durability factory every OrgStore routes
	// through: the shared ha election + vfs FencedStore over the S3
	// gateway + per-org envelope Cipher. nil ⇒ local-only (no object store creds,
	// dev/single-node), and every OrgStore is exactly the pre-durability cache.
	Durable *tenure.Durability

	// Peers says this deployment DECLARES more than one writer: the replica count
	// its Deployment states (CLOUD_REPLICAS) or the static peer list, never who is
	// live. It exists for the one question the fence cannot answer when there is
	// no fence: on the local-only path, may this process acknowledge an org's
	// write? See [OrgStore.Sync].
	//
	// It is stated in the POSITIVE — "there are others" — so the zero value is the
	// single-writer deployment, which owns everything it holds. A process that
	// builds its own Base (a test, a subsystem with its own composition root) is
	// then an owner by default, which is what a lone process IS; the dangerous
	// arrangement is the one that has to say so.
	Peers bool

	// LiveMembers reads the CURRENT live writer set (the SAME ha.Membership snapshot the
	// durability fencer elects over). Non-nil ONLY when the durable plane is active — the
	// shard router then routes on the live set, so a draining/dead pod's orgs go to the
	// ready successor that hydrates them (M3), not to the gone pod. nil ⇒ the router falls
	// back to the static CLOUD_PEERS set: without the durable plane a peer cannot serve
	// another pod's local-only files, so ownership must stay pinned to the ordinal (which
	// reattaches its PVC across a restart). One field gates the whole live-routing path.
	LiveMembers func() []ha.Member

	// The default and failover MODELS are not here. They were, as
	// AIDefaultModel/AIFallbackModel sourced from CLOUD_AI_DEFAULT_MODEL /
	// CLOUD_AI_FALLBACK_MODEL, and they were not dependencies: a subsystem cannot
	// fail to connect to a model name. They are a routing and pricing DECISION,
	// and the eight subsystems that read them did the identical thing — copy the
	// string onto their own state, never branching on it — which is a constant
	// wearing a struct field's clothes. They are aimodel.DefaultModel and
	// aimodel.FallbackModel in model.go now, one literal each.

	// Subsystem clients — populated by BuildDeps based on enabled subsystems.
	// Each is an interface with both in-process and ZAP-RPC implementations.
	KMS      secret.Store
	Commerce CommerceClient
	// AI runs CHAT COMPLETIONS (a WRITE endpoint): agents, guide, crm, content,
	// sitegen, code /ask. It authenticates with the binary's IAM M2M identity — a
	// completions-capable credential — NEVER the read-only publishable (pk-) embed
	// key, which the gateway 403s on any write endpoint.
	AI infer.Client
	// Embed runs EMBEDDINGS (a READ-ONLY endpoint): code-index + KB knowledge. This
	// is the ONLY consumer of the read-only publishable (pk-) key (CLOUD_AI_API_KEY),
	// the correct least-privilege credential for a read-only call. Split from AI so a
	// pk- embed key can never leak onto the completions path (the intermittent-403
	// bug). Falls back to the AI (M2M) resolution when no static embed key is set.
	Embed infer.Client
	// O11y is not here. It WAS — a Counter/Timing/Span client for the o11y
	// subsystem, with a disabled stub and exactly one call site — and build.go
	// never assigned it, so the field was nil in every deployment and that one
	// call site was dead. What made it dead is what makes it wrong: this process
	// already has an instrument API, the OTel meter the composition root installs
	// (telemetry.go), collected into the process registry and pushed to the
	// telemetry store in-process by apps/o11y. A second one could only ever be the
	// unwired one. Measurements go on the meter — see metrics_http.go,
	// metrics_plane.go and metrics_usage.go.

	// Metering is the canonical commerce billing client used by the
	// request-edge BillingGate. It speaks net/http to commerce's billing API
	// (separate from the ZAP Commerce client above, which is for typed
	// inter-subsystem calls). Nil or not-Enabled() makes the gate a no-op.
	Metering *meter.Client

	// Audit is the tamper-evident, append-only audit trail Recorder (FedRAMP AU-*
	// / SOC 2 CC-*). Serve constructs it once, wires the AuditTrail middleware to
	// it, and hands it here so the /v1/admin/audit query + /v1/admin/audit/verify
	// endpoints read the SAME store the middleware writes. Nil makes the audit
	// middleware a no-op and the query endpoint fall back to the IAM proxy (an
	// unconfigured deployment is never blocked). See audit/ and audit_middleware.go.
	Audit *audit.Recorder
}
