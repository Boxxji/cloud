package cloud

import (
	"cmp"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hanzoai/cloud/sdk/brand"
	"github.com/hanzoai/cloud/sdk/edge"
	"github.com/hanzoai/cloud/sdk/env"
	"github.com/hanzoai/cloud/sdk/iam"
	"github.com/hanzoai/cloud/sdk/role"
)

// Config is the cloud binary's startup configuration. Drives which
// subsystems mount, what brand surface to serve, and where data lives.
type Config struct {
	// Enable lists subsystems to mount this run. Empty = all enabled.
	// Example: --enable=iam,base,kms,commerce,ai,gateway,o11y
	Enable []string

	// Replicas is the app-tier replica count the operator injects (CLOUD_REPLICAS,
	// mirroring the Deployment's spec.replicas). 0 = unset/unmanaged. It is the
	// left-hand side of ONE contract, whose right-hand side is IAMStore below.
	Replicas int

	// OpenStores is CLOUD_OPEN_STORES as written: how many per-entity stores ONE
	// OrgStore keeps open (see OpenStores and MaxOpenPerStore, the value when it is
	// unset). It is kept raw so Validate can refuse a value that is not a positive
	// integer and name it, rather than a typo quietly running the deployment on the
	// default — which is exactly the bound a deployment sets this to leave.
	OpenStores string

	// IAMStore names the backend holding embedded IAM's identity records, read
	// from IAMStoreEnv. Empty or "sqlite" is the per-pod file at
	// {DataDir}/iam/iam.db; any other name is a server every replica reaches
	// alike (see apps/iam.openStore, which opens whichever this names).
	//
	// It is here, beside Replicas, because the two are one contract and this is
	// where that contract is checked. IAMStoreShared is the predicate; Validate
	// is the only caller that pairs it with a replica count.
	IAMStore string

	// Brand is the white-label brand identifier.
	Brand string

	// Version is the API contract/build version emitted as the X-Api-Version
	// response header, resolved by sdk/env: CLOUD_VERSION — which the
	// host publishes to every child and an operator can override — else
	// HANZO_VERSION, else the tag linked into the host, else "dev".
	Version string

	// Env is the deployment environment (mainnet|testnet|devnet) per the 3-env
	// split. Billing fires in EVERY env — test/dev meter against their own
	// sandbox commerce/Square, never free — so Env is an attribution label, not
	// a gate. Empty when the operator has not set CLOUD_ENV.
	Env string

	// Domain is the deployment's primary public domain.
	Domain string

	// IAMIssuer is the public identity host of this deployment, which the IAM base URL
	// and sign-in links derive from. It does NOT decide whose tokens are trusted: that
	// is Discovery. It should equal the `iss` IAM actually stamps: hanzo.id for hanzo, and each brand's own .id
	// otherwise (sdk/brand/brand.go is the registry and the reasoning).
	//
	// Not iam.hanzo.ai. That host answers discovery and reports
	// issuer=https://hanzo.id — it is a routing alias rather than an issuer, so
	// pinning it here fails the issuer check on every real token and anonymizes
	// every principal. Left unset, issuerFor derives it from the brand, which is
	// the path to prefer.
	IAMIssuer string

	// Discovery is the OIDC discovery URL of the provider that signs this
	// deployment's tokens, https://<host>/.well-known/openid-configuration. It is
	// the ONE input for who is trusted: the issuer a token must name and the JWKS it
	// is checked against both come from the document it names (discovery.go).
	// Defaults to the brand's own (brand.Info.Discovery); override with
	// CLOUD_OIDC_DISCOVERY for a deployment whose provider is not a registered brand.
	Discovery string

	// DiscoveryClient is the HTTP client discovery documents are fetched with, for
	// a deployment that reaches its provider through an egress proxy. Nil is a
	// default client with a 10 s timeout.
	DiscoveryClient *http.Client

	// KMSMasterKeyRef is the base64-encoded 32-byte KMS master key (KEK) the
	// embedded luxfi/kms store seals every secret's DEK under, and the ONE
	// credential a deployment provisions. The operator injects it from a K8s
	// Secret as CLOUD_KMS_MASTER_KEY_REF; it is never read from the store it
	// hosts (the bootstrap chicken-and-egg) and never logged. Empty ⇒ the KMS
	// subsystem runs fail-closed (health-only).
	//
	// BootMaster resolves it at process start and holds it; see rootKeyRef.
	KMSMasterKeyRef string

	// KMSMPCAddr / KMSMPCVaultID configure the MPC threshold-signing backend for
	// KMS Sign. Both empty (the default) ⇒ Sign fails closed with a clear error;
	// signing is never fabricated. Set via CLOUD_KMS_MPC_ADDR / CLOUD_KMS_MPC_VAULT_ID.
	KMSMPCAddr    string
	KMSMPCVaultID string

	// DataDir is the on-disk data root.
	DataDir string

	// Role is the HA role of this process (CLOUD_ROLE): the single Writer that
	// owns the RWO stores (default) or a read-only Reader replica. Resolved and
	// validated in Serve; defaults to Writer so an unset variable is byte-identical
	// to today's single-pod deployment.
	Role role.Role

	// WriterURL is the base URL of the single writer (CLOUD_WRITER_URL, e.g.
	// http://cloud-writer.hanzo.svc:8000). A Reader forwards EVERY request here —
	// it opens no stores and is a transparent, always-ready edge that absorbs the
	// writer's rollout gap (see reader_proxy.go). Required when Role==Reader;
	// ignored by a Writer.
	WriterURL string

	// ReaderRetryBudget bounds how long a Reader retries a request the writer
	// could not yet accept (connection refused / no ready endpoint) during a
	// writer roll, before returning 502. Dial-only retry (the request never
	// reached the writer) keeps a non-idempotent POST safe. CLOUD_READER_RETRY_BUDGET
	// (Go duration, default 25s).
	ReaderRetryBudget time.Duration

	// The writer lease is NOT a field here. CLOUD_WRITER_LEASE has exactly one
	// reader — internal/writerlease — because the answer depends on something a
	// Config cannot see: this process's position in the pod's process tree. A
	// bool parsed here would be true in every one of a pod's processes alike,
	// which is precisely the reading that must never be available.

	// ShardPeers is the CLOUD_PEERS membership list ("id@addr,id2@addr2") of the
	// horizontal-scale StatefulSet: the full, STABLE set of writer pods (each a
	// cloud-N ordinal at its headless per-pod DNS cloud-N.<svc>:8000). Every org is
	// pinned to exactly one owner pod by rendezvous hashing (ha.Owner over this set),
	// so each org's per-org SQLite files are written by ONE pod only; a request whose
	// org this pod does not own is forwarded to the owner (shardrouter.go). Empty or a
	// single entry ⇒ sharding OFF, byte-identical to the single-pod deployment. The
	// set is identical on every pod (static env), so all pods agree on every org's
	// owner — no split-brain dual-writer, no routing loop.
	ShardPeers string

	// ShardSelf is THIS pod's stable id — the StatefulSet ordinal name cloud-N, from
	// CLOUD_POD_NAME (or the downward-API POD_NAME). When sharding is on it MUST be one
	// of ShardPeers' ids (Validate refuses otherwise, so a misconfigured ordinal cannot
	// black-hole every request by forwarding it away with no shard of its own).
	ShardSelf string

	// KVURL is the deployment's shared Hanzo KV (KV_URL). With it, every pod joins
	// one live set, each once-per-cluster loop runs on one pod, and rate windows and
	// single-use tokens hold across pods (sdk/coord). Without it the process
	// answers alone, which is the whole deployment when it is one pod.
	KVURL string

	// ListenAddr is the public HTTP listener (default :8080).
	ListenAddr string

	// ZAPListenAddr is the ZAP-RPC listener (default :9653).
	ZAPListenAddr string

	// ZAPWebOrigins is the WebSocket Origin allowlist for the browser-facing
	// /zap ZAP plane (the SPA hosts that may open a ZAP-over-WS connection).
	// Empty == same-origin only. Set via CLOUD_ZAP_WEB_ORIGINS (comma-sep).
	ZAPWebOrigins []string

	// MarkdownDefaultPrefixes lists path prefixes whose successful JSON
	// responses default to markdown (zap-proto/md) when the caller expresses no
	// format preference — the agent-facing endpoints (e.g. /v1/code/, /v1/agent/).
	// A caller always keeps the override: ?format=json or Accept: application/json
	// forces JSON even here, and JSON stays the default everywhere else. Empty ==
	// JSON everywhere unless explicitly negotiated. Env CLOUD_MARKDOWN_DEFAULT_PREFIXES
	// (comma-separated). See middleware_markdown.go.
	MarkdownDefaultPrefixes []string

	// Edge policy (middleware_edge.go) — the "gateway role" cloud absorbs when it
	// serves the public api.hanzo.ai edge directly, no KrakenD hop.
	//
	// CORSOrigins is the browser-CORS allowlist for the /v1 edge. Each entry is an
	// exact origin ("https://hanzo.ai"), a bare host ("hanzo.ai"), or a host
	// wildcard ("*.hanzo.ai" = apex + any subdomain). It ADDS to the origins cloud
	// derives itself (every brand site, brand.Owned, and every verified site_hosts
	// binding), which need no entry; an origin listed here is first-party and gets
	// credentials. Cloud is the only layer that answers CORS. Read from
	// CLOUD_CORS_ORIGINS — one name, so a deployment cannot half-configure the
	// allowlist under a second spelling.
	CORSOrigins []string

	// IdentityHosts are the hosts a person signs in ON — the identity origins:
	// hanzo.id, lux.id, zoolabs.id, pars.id, osage.id, the id. and iam. hosts. An
	// IAM route that sets the session or spends it answers a credentialed
	// cross-origin request only from a page on one of these (middleware_edge.go).
	// Every other origin CORSOrigins admits is an app, and an app sends people to
	// one of these to sign in rather than taking a credential on its own page.
	//
	// Derived, not configured: every registered brand's (brand.IdentityHosts),
	// plus each host the operator pinned in IAM_ISSUER_MAP — the hosts the
	// embedded IAM mints tokens under, so a host that issues sign-ins and a host
	// trusted to run one cannot drift apart. Read here, at load, from the
	// process environment: the iam subsystem later fills an UNSET IAM_ISSUER_MAP
	// with a derived default that names bare brand domains and customer-content
	// hosts (hanzo.app), and none of those is a place people sign in.
	IdentityHosts []string

	// EdgeRateEnabled turns on the per-client-IP edge flood cap that runs BEFORE
	// identity (CLOUD_EDGE_RATELIMIT, default true — the gateway enforced this, so
	// dropping it silently would drop a protection). EdgeRatePerIP requests per
	// EdgeRateWindowSec seconds are allowed per public client IP (leftmost
	// X-Forwarded-For); in-cluster direct callers carry no XFF and are exempt.
	// Defaults 100/1s mirror the gateway service-tier client_max_rate (strategy:ip).
	EdgeRateEnabled   bool
	EdgeRatePerIP     int
	EdgeRateWindowSec int

	// HealthListenAddr is the health/metrics listener (default :9090).
	HealthListenAddr string

	// AdminListenAddr is the admin endpoint (default :8081, gated by IAM admin).
	AdminListenAddr string

	// ReadBufferSize is the fasthttp per-conn request-read buffer for the public
	// HTTP edge (zip/fiber), in bytes. fasthttp caps total request-header size at
	// this value and returns 431 (Request Header Fields Too Large) above it. The
	// framework default is 4 KiB — too small once a multi-domain SSO session (an
	// admin-guard Domain=.hanzo.ai cookie set on EVERY subdomain) pushes a
	// browser's request headers past ~4 KiB, 431-ing legitimate requests. This
	// raises the edge ceiling to a sane 32 KiB (nginx large_client_header_buffers
	// parity). Env GATEWAY_READ_BUFFER_SIZE (shared with the gateway edge so both
	// trust boundaries agree on ONE value); tunable down if the per-conn memory
	// budget (SCALE_STANDARD §8) demands it. Internal zip services keep the 4 KiB
	// framework default — only the browser-facing edge opts up.
	ReadBufferSize int

	// BodyLimit is the maximum request body the public HTTP edge (zip/fiber)
	// accepts, in bytes. The framework default is 4 MiB — which silently caps the
	// CONTEXT WINDOW: a chat request carries its whole prompt in the body, and at
	// ~4.3 bytes/token a 1M-token prompt is ~4.3 MB. So the 1M-context models we
	// route to (deepseek-v4-pro; anything glm-5.2 overflows into past its 262,144
	// cap) could not actually be reached — fasthttp refused the body before any
	// handler ran, with the opaque 400 "Error when parsing request" that reads
	// like a malformed payload rather than a size cap. 16 MiB gives 1M tokens
	// real headroom (~3.7x) without inviting a memory-exhaustion vector: the edge
	// is authenticated + rate-limited, and fasthttp streams rather than buffering
	// per-conn. Env GATEWAY_BODY_LIMIT.
	BodyLimit int

	// The site-edge configuration (apex, reserved labels, self domains, first-party
	// sites) is NOT here: it is resolved by sites.ConfigFromEnv, in the package that
	// owns the type. Both processes that mount the edge — this one and the light
	// router that owns the public port — read that one function, so the env keys and
	// their defaults cannot drift apart again. Domain (above) is the only field of
	// this struct that feeds it.

	// Billing gate (commerce metering) — the request-edge balance gate.
	//
	// CommerceHTTPURL is the commerce service base over HTTP (the metering
	// client speaks net/http, not ZAP). Empty, the gate asks the process that
	// owns the ledger over the plane. Either way a call the ledger cannot weigh
	// is refused: there is no switch that serves it.
	CommerceHTTPURL string

	// The spend gate (middleware_spend.go) is deliberately NOT configured here. It reads
	// the `paywall_enforced` platform switch and nothing else, so the admin cockpit is
	// its single source of truth and the kill switch can always disarm it. A
	// PAYWALL_ENFORCED field here ORed with the switch, which meant an env var could arm
	// a gate the cockpit could not turn off — the one failure mode a kill switch exists
	// to prevent. One reader, one answer.

	// AI inference gateway (see build.go pickCompletionsClient / pickEmbedClient):
	//   - CHAT COMPLETIONS (deps.AI, a WRITE endpoint) — agents/guide/crm/content/
	//     sitegen/code-ask. NEVER a read-only publishable (pk-) key.
	//   - EMBEDDINGS and RERANKS (deps.Embed, READ endpoints) — code-index, knowledge,
	//     search. A pk- key may serve them.
	// Both take the IAM M2M identity below wherever the binary has one, crossing the
	// plane for the org a call is for; AIAPIKey serves only where it has none.
	//
	// AIBaseURL is the gateway /v1 root (CLOUD_AI_BASE_URL, default
	// https://api.hanzo.ai/v1); the client appends /chat/completions or /embeddings.
	//
	// AIAPIKey is the KMS-injected static gateway key (CLOUD_AI_API_KEY ←
	// cloud-ai-embed-key). It is a SECRET — never logged, printed, or read from disk
	// here. It drives deps.Embed, and deps.AI completions, only where the binary has
	// no IAM identity below — completions never as a read-only publishable (pk-) key,
	// which the gateway would 403 ("Publishable keys can only access read-only
	// endpoints").
	//
	// The default and failover MODELS are NOT configured here. CLOUD_AI_DEFAULT_MODEL
	// and CLOUD_AI_FALLBACK_MODEL are gone; the values are aimodel.DefaultModel and
	// aimodel.FallbackModel (model.go), one literal each. A model name is a routing
	// and pricing decision, not an address — there is nothing to connect to and
	// nothing to fail — and holding it in two places (a constant AND the
	// deployment's env) is what let production run a value the constant disagreed
	// with, undetected, until someone read both. The failover value is worse than
	// redundant: `best` is a SKU in the GATEWAY's catalog with its own server-side
	// route and fallback chain, so a knob here could only disagree with the thing
	// that actually decides. No deployment ever set it.
	AIBaseURL string
	AIAPIKey  string

	// AIAuthClientID / AIAuthClientSecret are the binary's OWN IAM service
	// identity (IAM_CLIENT_ID / IAM_CLIENT_SECRET). The completions client (deps.AI)
	// authenticates to the gateway with a client-credentials (M2M) token minted from
	// this identity and auto-refreshed — the durable no-static-key path, and the ONLY
	// completions credential when AIAPIKey is the read-only pk- embed key. On the
	// Hanzo deployment the identity resolves to admin/hanzo-cloud (gateway-balance-
	// exempt), so cloud's per-org Meter remains the single debit. The token
	// endpoint is derived from IAMIssuer ({issuer}/v1/iam/oauth/token). The secret is
	// KMS-injected and never logged.
	AIAuthClientID     string
	AIAuthClientSecret string
}

// flagsOnce guards the ONE registration of the CLI overrides on the process-global
// flag.CommandLine. LoadConfig runs once in production (main) but many times across a
// test binary (body_limit_test, brand_test, …); a second flag.StringVar of the same
// name panics ("flag redefined: enable"). Flags are a command-line concern orthogonal
// to the env resolution every call performs, so bind + parse them exactly once.
var flagsOnce sync.Once

// LoadConfig reads flags + env into a Config. Flags override env.
func LoadConfig() *Config {
	cfg := &Config{
		ListenAddr: env.Or("CLOUD_LISTEN", ":8080"),
		// LOOPBACK BY DEFAULT, and the reason is what sits behind these two ports.
		// The ZAP listener serves the IDENTICAL route surface as HTTP over plaintext
		// TCP — including /v1/function/{name}/invoke, which is arbitrary process
		// execution. A bare ":9653" binds every interface, so on a laptop that port
		// is open to the LAN with no credential; it has been reached that way, from
		// another host on the same subnet, unauthenticated.
		//
		// A cluster has a NetworkPolicy and a mesh in front and now SAYS so —
		// universe sets CLOUD_ZAP_LISTEN=:9653 on the cloud deployments, which is
		// why this default can move without cutting the transport superbase dials
		// (zap://cloud.hanzo.svc.cluster.local:9653, a real Service port). A
		// developer has neither guard and sets nothing, so the unattended case is
		// the one the default has to be safe for.
		//
		// CLOUD_LISTEN was already honoured for HTTP while these two were not, which
		// is how binding the HTTP listener to 127.0.0.1 still left two ports open.
		ZAPListenAddr:           env.Or("CLOUD_ZAP_LISTEN", "127.0.0.1:9653"),
		HealthListenAddr:        env.Or("CLOUD_HEALTH_LISTEN", "127.0.0.1:9090"),
		AdminListenAddr:         env.Or("CLOUD_ADMIN_LISTEN", ":8081"),
		ReadBufferSize:          edge.ReadBufferSize(),
		BodyLimit:               edge.BodyLimit(),
		MarkdownDefaultPrefixes: splitTrim(env.Or("CLOUD_MARKDOWN_DEFAULT_PREFIXES", "")),
		Brand:                   env.Or("CLOUD_BRAND", brand.Default),
		Version:                 env.Version(),
		Env:                     env.Or("CLOUD_ENV", ""),
		Role:                    role.Writer, // safe default; Serve refines + validates from CLOUD_ROLE

		Replicas:   getenvInt("CLOUD_REPLICAS", 0),
		OpenStores: env.Or("CLOUD_OPEN_STORES", ""),
		IAMStore:   env.Or(IAMStoreEnv, ""),
		// Domain left empty here; derived from Brand below unless pinned — the
		// literal "api.hanzo.ai" default used to live here, which meant a lux
		// deployment that pinned nothing answered with Hanzo's host in every URL
		// it built about itself.
		Domain: env.Or("CLOUD_DOMAIN", ""),
		// IAMIssuer left empty here; resolved from Brand below unless pinned.
		IAMIssuer:         env.Or("CLOUD_IAM_ISSUER", ""),
		Discovery:         env.Or("CLOUD_OIDC_DISCOVERY", ""),
		KMSMasterKeyRef:   rootKeyRef(),
		KMSMPCAddr:        env.Or("CLOUD_KMS_MPC_ADDR", ""),
		KMSMPCVaultID:     env.Or("CLOUD_KMS_MPC_VAULT_ID", ""),
		DataDir:           DataDir(),
		WriterURL:         strings.TrimRight(env.Or("CLOUD_WRITER_URL", ""), "/"),
		ReaderRetryBudget: getenvDuration("CLOUD_READER_RETRY_BUDGET", 25*time.Second),
		ShardPeers:        env.Or("CLOUD_PEERS", ""),
		ShardSelf:         cmp.Or(env.Or("CLOUD_POD_NAME", ""), env.Or("POD_NAME", "")),
		KVURL:             env.Or("KV_URL", ""),
		// Billing gate.
		CommerceHTTPURL: env.Or("CLOUD_COMMERCE_HTTP_URL", ""),
		// AI inference gateway. CLOUD_AI_API_KEY (KMS-backed) is an optional static
		// override; absent it, the AI client authenticates via M2M using the
		// binary's own IAM identity (IAM_CLIENT_ID / IAM_CLIENT_SECRET) — no static
		// key, no expiry cliff. Never plaintext.
		AIBaseURL:          env.Or("CLOUD_AI_BASE_URL", "https://api.hanzo.ai/v1"),
		AIAPIKey:           env.Or("CLOUD_AI_API_KEY", ""),
		AIAuthClientID:     env.Or("IAM_CLIENT_ID", ""),
		AIAuthClientSecret: env.Or("IAM_CLIENT_SECRET", ""),
	}

	// THE BINARY KNOWS WHICH APP IT IS; a deployment does not restate it.
	//
	// cfg.Enable is set by Listen from the app the plugin was built as — one
	// process per app, and plugin/<app>/main.go names it. CLOUD_ENABLE/--enable
	// used to state the same set a SECOND time, from the values file, and the
	// only thing a second source of truth can add is disagreement: the list named
	// an app that does not exist and omitted one every child needs. Neither is
	// representable now. Empty still means all, which is what production has
	// always run.
	flagsOnce.Do(func() {
		flag.StringVar(&cfg.Brand, "brand", cfg.Brand, "white-label brand")
		flag.StringVar(&cfg.Domain, "domain", cfg.Domain, "primary domain")
		flag.StringVar(&cfg.IAMIssuer, "iam-issuer", cfg.IAMIssuer, "JWKS issuer")
		// The master key is NOT offered as a flag. Its value is what would become
		// flag.DefValue, and usage prints defaults — on -h and on any parse error —
		// so registering it puts the key on stderr, which is the pod log. Offering
		// it would also invite it onto a command line, where /proc and ps keep it.
		// The environment is the one way in, and it is what the chart sets.
		flag.StringVar(&cfg.DataDir, "data-dir", cfg.DataDir, "data root")
		flag.StringVar(&cfg.ListenAddr, "listen", cfg.ListenAddr, "HTTP listener")
		flag.Parse()
	})

	// White-label by brand (HIP-0111): when the operator does not pin
	// CLOUD_IAM_ISSUER / --iam-issuer, derive the canonical OIDC issuer from the
	// brand so a lux deployment validates against lux.id, zoo against zoolabs.id,
	// etc. — never silently defaulting every brand to iam.hanzo.ai.
	//
	// issuerFor is THE resolution, shared with the package-level IAMIssuer()
	// (iamurl.go). That function used to read CLOUD_IAM_ISSUER raw and stop, so on
	// any deployment that let the brand supply the issuer — the documented happy
	// path — this field held "https://lux.id" while IAMIssuer() held "". The two
	// cannot differ now because there is one function.
	cfg.IAMIssuer = iam.IssuerFor(cfg.IAMIssuer, cfg.Brand)

	// The deployment's own public API host, by the same rule and for the same
	// reason: api.<the brand's apex>. The brand registry already states each
	// brand's apex (brand.Info.Domain) and already says base URLs derive from it
	// — every brand but hanzo simply never got the derivation, so an unpinned lux
	// or zoo deployment presented api.hanzo.ai as its own host.
	cfg.Domain = domainFor(cfg.Domain, cfg.Brand)

	// The provider that signs this deployment's tokens, by its discovery document:
	// the brand's own unless the operator names another.
	if cfg.Discovery == "" {
		cfg.Discovery = brand.DiscoveryFor(cfg.Brand)
	}

	// Browser ZAP-over-WS Origin allowlist. Default to the console SPA hosts so
	// the console can connect cross-origin; override with CLOUD_ZAP_WEB_ORIGINS.
	zapOrigins := env.Or("CLOUD_ZAP_WEB_ORIGINS",
		"console.hanzo.ai,cloud.hanzo.ai,localhost:4000")
	for o := range strings.SplitSeq(zapOrigins, ",") {
		if s := strings.TrimSpace(o); s != "" {
			cfg.ZAPWebOrigins = append(cfg.ZAPWebOrigins, s)
		}
	}

	// Edge policy (middleware_edge.go). CORS origins are derived (Config.CORSOrigins
	// only adds); the per-IP flood cap default
	// ON at gateway-parity 100/1s so a protection is never dropped silently.
	cfg.CORSOrigins = splitTrim(env.Or("CLOUD_CORS_ORIGINS", ""))
	cfg.IdentityHosts = identityHosts(env.Or("IAM_ISSUER_MAP", ""))
	cfg.EdgeRateEnabled = getenvBoolDefault("CLOUD_EDGE_RATELIMIT", true)
	cfg.EdgeRatePerIP = getenvInt("CLOUD_EDGE_RATELIMIT_PER_IP", 100)
	cfg.EdgeRateWindowSec = getenvInt("CLOUD_EDGE_RATELIMIT_WINDOW_SEC", 1)
	return cfg
}

// Enabled reports whether subsystem `name` is enabled in this config.
// An empty Enable list mounts everything; a non-empty one mounts exactly what it
// names. There is no third case.
func (c *Config) Enabled(name string) bool {
	if len(c.Enable) == 0 {
		return true
	}
	return slices.Contains(c.Enable, name)
}

// DefaultDataDir is the on-disk data root when CLOUD_DATA_DIR is unset.
const DefaultDataDir = env.DataDirDefault

// DataDir resolves the data root from the environment. It is exported and split
// out of LoadConfig because BootMaster must find the same directory BEFORE
// LoadConfig runs — the credential broker's socket lives there, and the
// credentials have to be installed before anything reads config or opens a store.
//
// The rule itself lives in sdk/env because the ROUTER needs it too, and
// the router cannot link this package. It takes the pod's writer lease on a file
// under this root before it spawns the children that open stores under it, so
// the two must resolve the same directory or the lock guards nothing.
func DataDir() string { return env.DataDir() }

// Brand, Env and Domain are this deployment's own facts, resolved the same way
// LoadConfig resolves them and reachable without being handed over.
//
// THEY ARE FACTS, NOT DEPENDENCIES. A subsystem cannot fail to connect to a brand
// name — it reads the string and stamps it — which is what separates these from
// the clients on Deps. As fields there, every mount took a struct of twenty things
// to read one string, and a field can be empty where a resolver cannot. That is
// the same reason the logger, the process id and the model names left Deps before
// them; see the notes on the struct. Version is already one (version.go), and
// DataDir above was the first.
//
// A caller holding a Config keeps reading cfg.Brand: it is the same value by
// construction. These exist for the callers that have no Config in hand.
func Brand() string { return env.Or("CLOUD_BRAND", brand.Default) }

// Env is the deployment environment (mainnet|testnet|devnet), empty when unset. It
// is stamped for per-env attribution and never gates billing — every env bills
// against its own commerce ledger.
func Env() string { return env.Or("CLOUD_ENV", "") }

// Domain is the deployment's OWN public API host (api.hanzo.ai, api.lux.network),
// for building absolute URLs back to itself.
//
// It is the HOST and never the apex; a sibling host (git.hanzo.ai) comes from
// brand.Sibling and a trust root from brand.Apex. Reading one for the other is what
// made every native build fail once, and those two are the one derivation of it.
func Domain() string { return domainFor(env.Or("CLOUD_DOMAIN", ""), Brand()) }

// ZTBase is the Zero Trust controller's public address — scheme and host, no
// trailing slash, no API path — from ZT_CONTROLLER_URL, else Hanzo's. Its
// management API (apps/network) and its client API (fleet) both hang off it.
func ZTBase() string {
	return strings.TrimRight(env.Or("ZT_CONTROLLER_URL", "https://zt-api.hanzo.ai"), "/")
}

// rootKeyRef resolves the data-plane master. BootMaster holds it in memory once
// resolved, which covers the dev-key case where the environment carries nothing;
// the raw variable is the fallback for a process that never Booted — a test
// building a Config directly — and is the same value one step earlier.
func rootKeyRef() string {
	if b64 := MasterB64(); b64 != "" {
		return b64
	}
	return env.Or(MasterEnv, "")
}

// domainFor is THE resolution of the deployment's own public API host: an
// explicit pin wins, else api.<the brand's apex> from the registry. It is the
// exact shape of issuerFor, for the exact same reason — one decision, one
// function, no second place to hold a different answer.
//
// The old default was the bare literal "api.hanzo.ai", applied whatever the
// brand. IAMIssuer derived from the brand and Domain did not, so an unpinned lux
// deployment resolved issuer=https://lux.id alongside domain=api.hanzo.ai and
// went on to build every self-referential URL — OAuth redirect_uri, avatar URL,
// git clone URL — pointing at another brand's host. brand.Info.Domain already
// carried each brand's apex and its own doc already said base URLs derive from
// it; only hanzo ever got the derivation.
func domainFor(pinned, brandID string) string {
	if p := strings.TrimSpace(pinned); p != "" {
		return p
	}
	return brand.APIHost(brandID)
}

// identityHosts is Config.IdentityHosts: the registry's identity hosts plus the
// keys of the operator's IAM_ISSUER_MAP. A map that does not parse adds nothing —
// the set narrows to the registry, which can only withhold a credentialed answer,
// never grant one.
func identityHosts(pinned string) []string {
	hosts := brand.IdentityHosts()
	var byHost map[string]string
	if json.Unmarshal([]byte(pinned), &byHost) == nil {
		for h := range byHost {
			hosts = append(hosts, h)
		}
	}
	slices.Sort(hosts)
	return slices.Compact(hosts)
}

// splitTrim splits a comma-separated list, trimming and dropping empties.
func splitTrim(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// getenvBoolDefault reads a boolean env var with an explicit default: dflt when
// unset/blank, else true for true/1/yes and false for false/0/no (matching
// the truthy set of a plain flag). Lets a protection default ON while staying operator-
// disableable (CLOUD_EDGE_RATELIMIT=false), which a default-false flag can't.
func getenvBoolDefault(key string, dflt bool) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "":
		return dflt
	case "true", "1", "yes":
		return true
	default:
		return false
	}
}

// getenvDuration reads key as a Go duration (e.g. "25s", "1m"), returning dflt
// when unset, blank, or unparseable (a malformed override can never silently
// zero a timeout).
func getenvDuration(key string, dflt time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return dflt
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return dflt
	}
	return d
}

// Stores is CLOUD_OPEN_STORES read as a bound: MaxOpenPerStore when it is unset,
// and an error naming the value when it is not a positive integer. Validate asks
// it, so a typo refuses boot instead of running on the bound it meant to leave.
func (c *Config) Stores() (int, error) { return openStores(c.OpenStores) }

// OpenStores is the open bound every OrgStore in this process runs at:
// CLOUD_OPEN_STORES, or MaxOpenPerStore when it is unset.
//
// The bound has to cover the namespaces a store is asked for within StoreIdleAfter,
// because reclaim only takes a store that has gone that long untouched. A deployment
// whose sweeps visit more orgs than the bound in that window evicts each store just
// before the sweep reaches it again — a fenced ship and a re-hydrate per org per
// pass — so the number is the deployment's to state. A malformed value never reaches
// here in a serving process: Validate refused it at boot.
func OpenStores() int {
	n, err := openStores(env.Or("CLOUD_OPEN_STORES", ""))
	if err != nil {
		return MaxOpenPerStore
	}
	return n
}

func openStores(raw string) (int, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return MaxOpenPerStore, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("CLOUD_OPEN_STORES=%q: want a positive integer, the most per-entity stores one subsystem keeps open", raw)
	}
	return n, nil
}

// getenvInt reads key as a base-10 int, returning dflt when unset, blank, or
// unparseable (a malformed override can never silently zero a scale knob).
func getenvInt(key string, dflt int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return dflt
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return dflt
	}
	return n
}

// IAMStoreEnv names the backend that holds embedded IAM's identity records —
// users, organizations, applications, the signing certs, and the session rows.
// apps/iam.openStore reads it to decide what to open; Config carries it so the
// contract below can be checked at boot, before anything serves.
const IAMStoreEnv = "IAM_STORE_BACKEND"

// IAMStoreShared reports whether backend names an identity store every replica
// reaches alike, rather than a file private to one pod.
//
// Empty and "sqlite" are the embedded file: real, encrypted, and LOCAL — two
// pods holding it hold two different databases that never converge. Every other
// name is a server (hanzoai/sql over ZAP, the datastore fork), reached over the
// network, identical from anywhere. That is the whole distinction, and it is one
// function so the chart's guard, the boot check, and the opener cannot each form
// their own opinion of what "shared" means.
func IAMStoreShared(backend string) bool {
	b := strings.TrimSpace(backend)
	return b != "" && b != "sqlite"
}

// Validate returns an error if the config is missing required values.
func (c *Config) Validate() error {
	if c.Brand == "" {
		return fmt.Errorf("brand is required")
	}
	if c.Domain == "" {
		return fmt.Errorf("domain is required")
	}
	if c.DataDir == "" {
		return fmt.Errorf("data-dir is required")
	}
	if _, err := c.Stores(); err != nil {
		return err
	}
	// WHAT EMBEDDED IAM ACTUALLY NEEDS ABOVE ONE REPLICA: a shared identity store.
	// Not one replica.
	//
	// The rule here read "iam enabled ⇒ replicas must be 1", justified by a memory
	// session store. There is no memory session store. Sessions in hanzoai/iam are a
	// signed stateless cookie whose MAC key is derived from the platform signing cert
	// — chosen deterministically from the REFERENCED cert set precisely so it is the
	// same on every replica — plus a revocation row that lives in the same orm.DB as
	// every other identity record. So sessions are already replica-correct, and what
	// is not shared is the DATABASE: {DataDir}/iam/iam.db is a file on one pod's
	// volume, and two pods holding it hold two identity stores that never converge.
	//
	// So the check is the real condition. Name a shared backend and any replica
	// count is sound; leave it at the per-pod file and more than one replica is two
	// divergent identity stores, which is refused here rather than discovered when a
	// user created on one pod cannot log in on the next.
	//
	// CLOUD_REPLICAS=0 (unset) is the unmanaged/dev case and never refuses.
	if c.Enabled("iam") && c.Replicas > 1 && !IAMStoreShared(c.IAMStore) {
		return fmt.Errorf("iam is enabled at CLOUD_REPLICAS=%d but %s=%q keeps its identity store in the per-pod file %s/iam/iam.db: %d replicas would hold %d divergent identity stores (set %s to a shared backend, or run one replica)",
			c.Replicas, IAMStoreEnv, c.IAMStore, c.DataDir, c.Replicas, c.Replicas, IAMStoreEnv)
	}
	// MORE THAN ONE WRITER NEEDS A KV. The pods agree through it on who is alive,
	// which one runs each loop, what a caller has spent and which single-use tokens
	// are spent; a deployment that declares several (CLOUD_REPLICAS, CLOUD_PEERS)
	// with none would have each pod refuse every token it cannot check and fence
	// every loop on the object store alone. It is refused here rather than found out
	// one refused link at a time.
	if n := declared(c); n > 1 && strings.TrimSpace(c.KVURL) == "" {
		return fmt.Errorf("this deployment declares %d writers (CLOUD_REPLICAS / CLOUD_PEERS) and names no KV: set KV_URL, from the KMS secret holding the KV's ACL user, or run one writer", n)
	}
	// Horizontal shard routing (CLOUD_PEERS names >1 pod). Two fail-closed guards:
	//   1. THIS pod must be one of the peers, else it owns no shard and would forward
	//      every request away (a silent black-hole) — refuse to boot.
	//   2. Embedded IAM on the per-pod FILE store cannot be sharded: that store is local
	//      to each pod, so a login/authorize step served on one pod is unreachable on
	//      the owner pod a later request routes to. A shared backend has no such
	//      locality and shards fine — same condition as the replica check above, so it
	//      is the same predicate and not a second opinion about IAM.
	// Both are boot errors, never guesses — a wrong shard topology must fail loud.
	if peers := peerCount(c.ShardPeers); peers >= 2 {
		if c.ShardSelf == "" {
			return fmt.Errorf("CLOUD_PEERS names %d pods but POD_NAME/CLOUD_POD_NAME is empty: a shard member must know its own ordinal id", peers)
		}
		if !peerHas(c.ShardPeers, c.ShardSelf) {
			return fmt.Errorf("shard self %q is not in CLOUD_PEERS %q: this pod is not a member of its own ring (it would forward every request away and own no shard)", c.ShardSelf, c.ShardPeers)
		}
		if c.Enabled("iam") && !IAMStoreShared(c.IAMStore) {
			return fmt.Errorf("iam is enabled with CLOUD_PEERS shard routing but %s=%q keeps its identity store in the per-pod file: a login served on one pod is unreachable on the pod a later request routes to (set %s to a shared backend, or name one pod in CLOUD_PEERS)", IAMStoreEnv, c.IAMStore, IAMStoreEnv)
		}
	}
	return nil
}
