# LLM.md — hanzoai/cloud

**What**: Open-source Hanzo Cloud local dev & self-hosted server (`cmd/cloud` -> `./cloud`).
One Go binary that mounts every subsystem from a single composition root (`apps.Wire()`):
Base (`/v1/base` document/KV/SQLite store), Tasks (`/v1/tasks` durable lease/ack queue),
Functions (`/v1/functions` staged runner), KMS (`/v1/kms` embedded `luxfi/kms`), S3, Search,
Edge, Feature Flags, Audit, Plugin runtime (`/v1/plugins`), OpenAPI (`/v1/openapi.json`),
and MCP (`/mcp` JSON-RPC 2.0). `GET /v1` is the capability index: the subsystems this process mounted, each
with its address and a sentence on what it is for (`MountSpec.Description`).

**Canonical AI instructions**: `LLM.md` is the canonical instruction file in this repository.
`AGENTS.md`, `CLAUDE.md`, and `GEMINI.md` are tracked symlinks to `LLM.md`.

## Build, Run & Test

The stack is Go 1.27.1 and `github.com/zap-proto/zip` v1.37.45 (the version the private build runs). A route is a typed op (`app.Get[In, Out](path, fn)`) or, where a handler owns its whole response, a raw one (`app.Raw(method, path, handler)`).

```bash
make dev      # CGO_ENABLED=0 go build ./cmd/cloud, mints .dev/master.key (0600), serves 127.0.0.1:8080
make build    # CGO_ENABLED=0 go build -o cloud ./cmd/cloud
make test     # CGO_ENABLED=0 go test ./...
make vet      # CGO_ENABLED=0 go vet ./...
make hooks    # git config core.hooksPath .githooks (public-only pre-push guard)
```

- **Public module path**: a build with no credentials and no `GOPRIVATE` resolves every module from the Go proxy and checks it against `go.sum` (the first step of the `check` job runs exactly that). Pin only versions the proxy serves: `curl -s -o /dev/null -w '%{http_code}' https://proxy.golang.org/<module>/@v/<version>.zip` answers 200.
- **Pure-Go SQLCipher Encryption at Rest (`CGO_ENABLED=0`)**:
  - `Makefile` and `Dockerfile` build with `CGO_ENABLED=0` so the pure-Go SQLite backend (`cek/`) encrypts all SQLite stores under `CLOUD_KMS_MASTER_KEY_REF` (32 random bytes, base64-encoded) with zero C toolchain dependencies.
  - A default `CGO_ENABLED=1` build links unencrypted C SQLite and refuses to start with a master key unless built with `-tags libsqlite3` against `libsqlcipher` (or run explicitly with `CLOUD_DEV_UNENCRYPTED=1`).
- **Optional Rust Flag Evaluator**:
  - `make native` builds `native/flags/Cargo.toml`; linking it requires `CGO_ENABLED=1 make build TAGS=flags_native` (plus `libsqlite3` linked against `libsqlcipher` if encryption is required).

## Listeners & Ports

| Env / Flag | Default | Purpose |
|---|---|---|
| `CLOUD_LISTEN` / `-listen` / `PORT` | `:8080` (`make dev`: `127.0.0.1:8080`) | HTTP API (`/v1/*`), MCP (`/mcp`), embedded console |
| `CLOUD_HEALTH_LISTEN` | `127.0.0.1:9090` | `/healthz`, `/readyz`, `/metrics` |
| `CLOUD_ZAP_LISTEN` | `127.0.0.1:9653` | Binary ZAP transport exposing the same typed ops |

## OCI Container Image & `hanzo up`

- [`Dockerfile`](Dockerfile) builds a multi-arch (`linux/amd64`, `linux/arm64`) static `CGO_ENABLED=0` `/cloud` binary on `gcr.io/distroless/static-debian12:nonroot` (`USER 65532:65532`, `VOLUME ["/var/lib/cloud"]`).
- [`.github/workflows/image.yml`](.github/workflows/image.yml) publishes public **`ghcr.io/hanzoai/cloud-oss:main`** (and `:v*` release tags), which `hanzo up` (`github.com/hanzoai/cli`) pulls anonymously into its measured local k3s microVM (`127.0.0.1:3690` -> container `:8080`).

## Architecture Invariants

1. **Typed Operations Only**: Declare operations as typed ops so a single registration projects simultaneously into REST routes, `/v1/openapi.json`, `/mcp` JSON-RPC tools, CLI commands, and SDKs. Never add untyped ad-hoc HTTP handlers for API operations.
2. **Namespace Isolation**: Authenticated requests (JWTs verified against `{CLOUD_IAM_ISSUER}/v1/iam/.well-known/jwks`) run inside the token's `owner` org namespace; unauthenticated requests operate in the local namespace (`""`), which is why `make dev` binds `127.0.0.1`.
3. **Staged Subsystems**: Subsystems that execute arbitrary code or alter ingress (`functions`, `iam`, `ingress`) only mount when explicitly listed in `CLOUD_ENABLE_STAGED`.
4. **Fail-Closed External Integrations**: Optional sibling services (`S3_*`, `HANZO_DNS_URL`, `CODE_EXEC_UPSTREAM`, `CLOUD_AI_ZAP_ADDR`) report 503 clearly when unconfigured rather than faking success.
5. **Public-Only Repository Guard**: `.githooks/pre-push` enforces that `github.com/hanzoai/cloud` carries zero commits from non-public remotes and zero non-public Go module imports (`Apache-2.0 OR MIT`).

## Apps: one source each

An app under `apps/<name>` imports zip, the standard library and public modules, and nothing of its host: not `github.com/hanzoai/cloud` itself and not another of this repo's packages (`apps/imports_test.go` fails the build on one). It exports `Mount(app *zip.App, ...) error`, taking the router and exactly what it reads from its host, and `apps.Wire()` adapts `cloud.Deps` to that. An app written this way mounts unchanged in any host that hands it those values, which is how the private build runs the same source.

An app is private only when its job is one of:

- **M** moving money or keeping its ledger: billing, commerce, wallets, treasury, tax, payouts, plans and prices, balances. The mechanism is OSS wherever it separates from our price data. Payment protocols (x402 and the other agentic-commerce protocols) are OSS for everyone; only our price data and wallet configuration stay private.
- **A** operating the platform as SuperAdmin: fleet, host and platform-wide control.
- **P** our production estate: our cluster's build and deploy plane, our data tier, our forge.
- **H** one private program: a runtime or a network's onboarding that is not a product anyone else runs.

Everything else is OSS. Where an OSS app meets billing, it asks through an interface the private build fills with its billing; this edition's implementation is real, and local mode genuinely has no billing. That interface is the seam, and cutting it is the work, not the verdict.

Moved here so far: `blueprint`, `template`. The private build deletes its copy as each one lands and imports this module's.

| app | class | reason |
|---|---|---|
| account | OSS | API keys and org onboarding; the billing-subject pin is a seam |
| ad | OSS | paid-ad campaigns over the org's own connected accounts |
| admin | PRIVATE | A: the SuperAdmin operator console |
| admission | PRIVATE | A: operator launch control and waitlist for our hosted services |
| affiliate | PRIVATE | M: partner commission payouts |
| agents | OSS | autonomous agents for an org |
| ai | OSS | the model API; vendor keys, plan caps and spend gates come in through a seam |
| allowance | PRIVATE | M: plan caps and spend metering |
| amqp | OSS | AMQP 0-9-1 adapter on the message bus |
| answer | OSS | researched answers with sources |
| ask | OSS | plain-language questions answered over an org's own numbers |
| auditlog | OSS | tamper-evident audit trail (a local twin already ships) |
| author | OSS | royalty for open-source work; the payout is a seam |
| auto | OSS | workflows on a schedule or a webhook |
| base | OSS | managed Base (a local twin already ships) |
| benchmark | OSS | model benchmark scores |
| billing | PRIVATE | M: balances, spend and cards |
| blueprint | OSS | MOVED: template compute-cost estimate and bill of images |
| books | OSS | double-entry ledger; postings come in through a seam |
| bot | OSS | a bot doing work on a desktop |
| campaign | OSS | go-to-market campaigns across paid, organic and email |
| captable | OSS | cap table |
| catalog | OSS | one place to browse projects, apps and sites |
| ci | PRIVATE | P: CI dashboard over our forge's estate namespaces |
| cloudflare | OSS | the org's own Cloudflare account, managed |
| cms | OSS | CMS content model fixtures |
| code | OSS | code search and symbols (a local twin already ships) |
| coding | OSS | autonomous coding runs |
| commerce | PRIVATE | M: checkout, subscriptions and invoices |
| company | OSS | incorporation end to end; partner accounts and payment are seams |
| compliance | OSS | KYC/KYB records and accreditation; the vendor adapter is a seam |
| compute | OSS | machines, GPUs and clusters through a configured Visor |
| content | OSS | marketing content from draft to published |
| crawl | OSS | a web page as clean markdown |
| crm | OSS | sales and hiring model |
| dataroom | OSS | secure document room |
| dataset | OSS | per-org datasets for the risk model plane |
| deploy | PRIVATE | A: SuperAdmin control of our CD (sync, roll back) |
| destination | OSS | events forwarded to ad and analytics tools |
| dns | OSS | DNS records (a local relay already ships) |
| domain | OSS | domain search and purchase; the registrar account and payment are seams |
| email | OSS | commercial mail through the org's own provider |
| engine | OSS | serving-runtime management plane |
| entitlement | OSS | what the plan grants; the plan lookup is a seam |
| environment | OSS | what a codebase is before its agent starts |
| erp | OSS | ERP business model fixtures |
| esign | OSS | documents out for signature |
| eval | OSS | scoring a model on your own data |
| event | OSS | product analytics |
| exec | OSS | code interpreter (a local twin already ships) |
| experiment | OSS | A/B testing |
| explorer | OSS | block indexer status |
| flags | OSS | feature flags (a local twin already ships) |
| flow | OSS | agent workflow canvas |
| form | OSS | forms |
| framework | OSS | document types you define |
| functions | OSS | serverless functions (a local twin already ships) |
| gateway | OSS | live edge policy (a local twin already ships) |
| git | OSS | Git hosting for an org |
| graph | OSS | an org's entities and relations |
| guide | OSS | guided company building |
| help | OSS | support desk |
| iam | OSS | identity provider mount |
| index | OSS | full-text search over an org's data |
| ingress | OSS | edge TLS and hostname routing (a local twin already ships) |
| kafka | OSS | Kafka adapter on the message bus |
| kms | OSS | secret custody (a local twin already ships) |
| knowledge | OSS | team wiki and agent memory |
| kv | OSS | key-value store (a local twin already ships) |
| label | OSS | ground-truth labels for the risk model plane |
| leaderboard | OSS | who uses AI most, opt-in |
| legal | OSS | company paperwork drafted, signed, filed |
| library | OSS | everything a person made, in one place |
| link | OSS | AI login manager registry |
| lsp | OSS | live code intelligence |
| market | OSS | what trades on each chain |
| marketing | OSS | lifecycle email drips |
| marketplace | OSS | the market between orgs; settlement is a seam |
| meet | OSS | virtual office rooms |
| ml | OSS | model serving |
| mq | OSS | queue and stream admin |
| network | OSS | networking surface |
| node | OSS | an org's machines |
| notify | OSS | transactional email and SMS through the org's own provider |
| o11y | OSS | logs, metrics and traces; in-cluster defaults become config |
| patent | OSS | who conceived what, and when the machine was asked |
| patrol | OSS | estate watch: sites, tours, incidents |
| plan | PRIVATE | M: the plan catalog and its prices (the mechanism is OSS once it parts from our price data) |
| platform | PRIVATE | P: PaaS build and deploy on our cluster and runner pool |
| plugin | PRIVATE | A: SuperAdmin control of what each host runs |
| pref | OSS | per-person settings |
| pricing | PRIVATE | M: our price list and vendor costs (the mechanism is OSS once it parts from our price data) |
| principals | OSS | an org as payer or payee, with screening; payment facts are seams |
| projects | OSS | where sites live: create, deploy, roll back |
| prompt | OSS | versioned prompt library |
| provider | OSS | connect third-party accounts; vendor client ids become config |
| provisioning | PRIVATE | P: one-click add-ons on our production data tier |
| pubsub | OSS | message bus |
| reference | OSS | lookup data for the risk model plane |
| referral | PRIVATE | M: attribution that feeds affiliate payables |
| registry | OSS | container and package registry management |
| research | OSS | every experiment kept and comparable |
| reward | PRIVATE | M: points that convert to money |
| risk | OSS | per-org scoring models |
| s3 | OSS | object storage buckets (a local twin already ships) |
| sandbox | OSS | the sandbox compute primitive |
| sbom | OSS | components inside a container image |
| search | OSS | one ranked result set over an org's data |
| security | OSS | secret scanning (a local twin already ships) |
| seo | OSS | search visibility as data; the vendor account and metering are seams |
| settings | OSS | per-product org settings |
| share | OSS | a public URL for a service on your own machine |
| sites | OSS | published sites |
| skills | OSS | the skill catalogue an AI client reads |
| social | OSS | posting to every social account |
| space | OSS | drives, folders and files |
| standing | OSS | the cost of keeping a company; prices are data behind a seam |
| studio | OSS | Studio workflow backend |
| sync | OSS | data sync between endpoints |
| task | OSS | boards and work items |
| tax | PRIVATE | M: payee tax forms for payouts |
| taxonomy | OSS | the product catalogue's categories and tags |
| team | OSS | shared documents and files |
| tel | OSS | numbers, calls and messages; the carrier account and metering are seams |
| template | OSS | MOVED: starter-kit gallery |
| tools | OSS | everything an org can call, in one list |
| train | OSS | training jobs and their executor; per-second billing windows come in through a seam |
| translate | OSS | text translation |
| transport | OSS | one inbox for the chat apps you connect |
| treasury | PRIVATE | M: the reserve fund behind payouts |
| trust | OSS | trust centre |
| usage | OSS | what an org ran and what it cost; the ledger is a seam |
| validator | PRIVATE | H: one network's validator onboarding program |
| wallet | PRIVATE | M: key custody for value |
| web3 | OSS | chain-access surface |
| webhook | OSS | webhook endpoints and delivery |
| websearch | OSS | web search and page fetch for agents |
| workflow | OSS | durable workflows |
| world | OSS | live news feed filtered to a project |
| worlds | PRIVATE | H: relay to a private runtime |
| x402 | OSS | pay-per-request payments over HTTP 402; our prices and wallet config stay private behind a seam |
| zen | OSS | model-serving layer; billing comes in through a seam |

Three more apps have a plugin and no source directory in the private build, because each is an external module: `authz` and `metrics` are OSS modules, `licensing` is private.
