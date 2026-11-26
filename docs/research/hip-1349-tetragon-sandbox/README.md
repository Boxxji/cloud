# HIP-1349 Research Dossier: eBPF Runtime Enforcement for Agent Sandboxes (Tetragon)

- **Tracking Issue**: [`hanzoai/cloud#33`](https://github.com/hanzoai/cloud/issues/33) (`p2, bounty, research, hip-1349, test, visor`)
- **Canonical Owning Repository**: `hanzoai/cloud` (`apps/sandboxpolicy`, `cmd/sandboxpolicy-bench`, `apps/apps.go`)
- **Disposition Target**: `MERGE` (bounded clean-room Apache-2.0 implementation, zero new external dependencies, full race/security/regression verification, raw benchmark receipts in [`results.json`](./results.json))

---

## 1. Primary Reference, Architecture Summary & License Audit

### Primary Reference
- **Cilium Tetragon — eBPF-based Security Observability and Runtime Enforcement**
  - Primary repository: <https://github.com/cilium/tetragon>
  - **Core architectural insight**: Post-hoc container log scraping and userspace ptrace monitors detect escapes *after* kernel state has already been mutated and incur high context-switch overhead. Tetragon enforces declarative `TracingPolicy` specifications synchronously at kernel boundaries (syscalls, `execve` / credentials, and socket connect/bind), supporting three graduated enforcement modes (`AuditOnly` telemetry, synchronous `Override`/`EPERM` denial, and synchronous `Sigkill` termination) while emitting structured process-lineage audit events over bounded ring buffers.
  - **Visor Agent Sandbox Adaptation**: Autonomous coding agents running inside Visor sandboxes legitimately execute compilers (`go test`, `go build`), VCS (`git`), package managers (`npm`), ephemeral loopback test servers (`httptest`), and public HTTPS/DNS API calls — while untrusted prompts, dependencies, or tool invocations may attempt container breakouts (`ptrace`, `mount`, `bpf`, `open_by_handle_at`, `setns`, `clone(CLONE_NEWUSER)`), symlink/path-traversal exec escapes, capability/UID privilege escalation, or cloud metadata SSRF (`169.254.169.254`, `::ffff:169.254.169.254`, `fd00:ec2::254`, host loopback Docker/Kubernetes sockets).

### Clean-Room License & Dependency Audit

| Reference / Dependency | Upstream License | Imported Code? | Audit Result |
|---|---|---|---|
| Cilium Tetragon (`github.com/cilium/tetragon`) | Apache-2.0 (userspace) / GPL-2.0-only or Dual BSD/GPL (kernel BPF C) | **None** — 100% clean-room Go design & implementation (zero GPL or Tetragon code copied) | **Clear** |
| Linux seccomp-BPF UAPI constants (`struct sock_filter`, `seccomp_data`) | Public kernel ABI specification | Clean-room Go structs & cBPF VM in `apps/sandboxpolicy/bpf.go` | **Clear** |
| `apps/sandboxpolicy` & `cmd/sandboxpolicy-bench` | Apache-2.0 | Go stdlib + existing `github.com/zap-proto/zip` & `github.com/luxfi/log` | **Zero new `go.mod` / `go.sum` entries** |

No upstream Cilium Tetragon Go or eBPF C code was copied or vendored, avoiding any GPL-2.0 kernel-code contamination. `go.mod` and `go.sum` remain 100% untouched. Published Tetragon benchmarks are **not** claimed; every measurement in Section 6 was reproduced locally by [`cmd/sandboxpolicy-bench`](../../../cmd/sandboxpolicy-bench/main.go).

---

## 2. Reproducible Baseline & Real-Repo Evaluation Corpus

To comply with `PR_CONVERGENCE.md` (public reproducibility on real data rather than synthetic-only claims), [`cmd/sandboxpolicy-bench`](../../../cmd/sandboxpolicy-bench/main.go) anchors its benign agent workload directly to **48 real source files** sampled deterministically from `hanzoai/cloud` (corpus SHA-256 `27ca30e4cec806561d39f44997773441cd9f2f9cc709ce9fb323ae0f5b68f46c`, anchored to git commit `0f3125493818da9f324b83c6ae62dea2297be530`) and exercises authentic Go (`go test`, `GOTMPDIR=/tmp/go-build` test binaries), `git status`, `npm test`, `rg`, `cat`, public HTTPS/DNS egress, and ephemeral loopback `httptest` operations alongside 20 concrete sandbox escape scenarios.

### Exact Reproduction Command
```bash
go run ./cmd/sandboxpolicy-bench \
  -repo . \
  -seed 1349 \
  -out docs/research/hip-1349-tetragon-sandbox/results.json
```

- **Host environment**: `linux/amd64`, 2 vCPUs, `go1.27.1`, `runtime.LockOSThread()` pinned wall-clock timing, deterministic seed `1349`.
- **Baselines evaluated identically**:
  1. Unmonitored no-op dispatch baseline (`0` policy evaluation).
  2. `AuditOnly` vs `EnforceDeny` (`EPERM`) vs `EnforceSigkill` (`SIGKILL`) over the identical 20-case escape regression matrix.
  3. Indexed O(1) syscall / root-bucketed process prefix / bitmask-indexed CIDR engine vs unindexed linear-scan baseline across `10`, `100`, and `1,000` active rules.
  4. Userspace audit-all emission vs in-kernel seccomp-BPF allowlist fast-path filtering under a `50,000 events/sec` benign syscall loop.

---

## 3. Falsifiable Hypothesis, Metrics & Expected Failure Modes

### Hypothesis
> **H1**: A clean-room Tetragon-inspired `TracingPolicy` engine (`apps/sandboxpolicy`) enforcing canonicalized syscall (compiled to classic seccomp-BPF bytecode), process execution, and network CIDR rules (a) blocks **`100.00%`** (`20/20`) of unauthorized syscall, path-traversal/symlink/privilege-escalation, and IMDS/RFC1918/IPv4-mapped-IPv6 network escape attempts under `EnforceDeny` and `EnforceSigkill` while maintaining **`100.00%`** hash-chained audit visibility and **`100.00%`** seccomp-BPF VM parity, (b) incurs **`0.00%`** (`0/240`) false-positive blocks on real benign coding-agent workloads under `EnforceSigkill`, (c) maintains constant O(1)/O(k) median evaluation latency (`< 1 µs`) across `10` to `1,000` active rules (beating unindexed linear scanning by `>5×` at `1,000` rules), and (d) avoids ring-buffer telemetry drops (`0.00%` vs `>60%` drops under `50k/s` tight syscall loops) when benign allowlisted syscalls resolve on the in-kernel seccomp-BPF fast path.

### Falsification Criteria
H1 is falsified if:
1. Any of the 20 escape cases bypasses `EnforceDeny` or `EnforceSigkill`, or any syscall verdict diverges from the compiled seccomp-BPF bytecode executed in `EvalBPF`.
2. Any of the 240 benign agent operations is blocked under `EnforceSigkill` (`>0` false positives).
3. Indexed engine median latency fails to stay flat or fails to outperform unindexed scanning by `>2×` at `1,000` active rules.
4. Any cross-tenant policy, sandbox binding, or audit event leaks across org boundaries, or any audit hash-chain fails tamper verification.

### Expected Failure Modes (Explicit Negative Regimes)
1. **Negative Regime 1 — Over-broad / Unindexed Rule Explosion**:
   - *Unindexed scaling*: Naive linear rule scanning degrades linearly (`O(N)`), exploding from `693 ns` at `10` rules to `5,833 ns` p50 (`29,171 ns` p99) at `1,000` rules (`7.63×` slower than indexed O(1)/bitmask-CIDR tables).
   - *Over-broad policy authoring*: Naive unanchored regexes (`(?i)(test|status|silent|workspace)`) combined with IPv4-only egress rules produce a **`33.75%`** (`81/240`) false-positive failure rate on legitimate agent builds.
2. **Negative Regime 2 — High-Frequency Tight Syscall Loop / Audit-Ring Backpressure**:
   - Streaming every benign `read`/`newfstatat` call to a userspace hash-chained audit ring at `50,000 events/sec` against a `4,096`-slot ring drained at `12,000 events/sec` triggers **`68.29%` ring drops (`34,144 / 50,000` dropped)** and **`14.44×` worse p99 latency** (`7,016 ns` vs `486 ns`). High-frequency benign syscalls **must** be filtered in-kernel (`SECCOMP_RET_ALLOW`) with only policy alerts/denials escalating to userspace rings.

---

## 4. Bounded Implementation (`apps/sandboxpolicy`, `apps/apps.go`, `cmd/sandboxpolicy-bench`)

The clean-room implementation lives in [`apps/sandboxpolicy/`](../../../apps/sandboxpolicy/) and mounts declaratively in [`apps/apps.go`](../../../apps/apps.go) (`Wire()`) with **zero host imports** (verified by `apps.TestAppsImportNothingOfTheirHost`):

- [`apps/sandboxpolicy/policy.go`](../../../apps/sandboxpolicy/policy.go): Declarative `TracingPolicy` specification, `EnforcementMode` (`audit_only`, `enforce_deny`, `enforce_sigkill`), canonical POSIX path normalization (`NormalizeCanonicalPath`, strict directory-boundary `PathMatchesPrefix`), canonical IP/CIDR normalization (`NormalizeIP`/`NormalizeCIDR` unmapping IPv4-mapped IPv6 addresses via `addr.Unmap()`), deterministic priority ordering, same-priority conflict detection (`ErrPolicyConflict`), and `DefaultVisorSandboxPolicy`.
- [`apps/sandboxpolicy/bpf.go`](../../../apps/sandboxpolicy/bpf.go): Real kernel-ready Linux classic BPF (`struct sock_filter`) seccomp-BPF filter compiler (`CompileSeccompBPF`) enforcing `AUDIT_ARCH_X86_64` / `AUDIT_ARCH_AARCH64` at instruction 0, 64-bit lo/hi argument filter predicates (`eq`, `ne`, `mask_any`, `mask_all`, `ge`, `le`), `BPF_MAXINSNS` (4096) enforcement, deterministic SHA-256 program digest, and a clean-room cBPF VM interpreter (`EvalBPF`) for cross-platform CI parity verification.
- [`apps/sandboxpolicy/audit.go`](../../../apps/sandboxpolicy/audit.go): Strictly per-tenant bounded circular ring buffer (`TenantAuditRing`) with SHA-256 hash-chaining (`"hanzo-sandboxpolicy-audit-v1"`, `VerifyAuditChain`) and configurable `RingOverwriteOldest` / `RingDropNewest` overflow telemetry.
- [`apps/sandboxpolicy/engine.go`](../../../apps/sandboxpolicy/engine.go): Concurrency-safe `Engine` with O(1) syscall maps, O(1) exact-path + root-segment-bucketed process prefix maps, bitmask-indexed IPv4/IPv6 CIDR tables, symlink target validation, Linux capability / UID / GID / `setuid` / `no_new_privs` privilege-escalation refusal, and fail-closed defaults on unbound sandboxes or malformed events.
- [`apps/sandboxpolicy/http.go`](../../../apps/sandboxpolicy/http.go) + [`apps/sandboxpolicy/zipdoc_gen.go`](../../../apps/sandboxpolicy/zipdoc_gen.go): 8 typed `zip.App` routes mounted under `/v1/sandboxpolicy` (`GET /health`, `POST /policies`, `GET /policies`, `GET /policies/:id`, `POST /sandboxes/:id/bind`, `POST /evaluate`, `GET /audit`, `GET /metrics`) with zero `http.NewServeMux()`, server-stamped IAM org isolation via `principal.Acting`, `url:"-"` query-hijack protection on every POST body field, and full `zipdoc` OpenAPI/MCP descriptions.
- [`cmd/sandboxpolicy-bench/main.go`](../../../cmd/sandboxpolicy-bench/main.go) + [`cmd/sandboxpolicy-bench/main_test.go`](../../../cmd/sandboxpolicy-bench/main_test.go): Reproducible benchmark & policy-regression harness and automated CI gate.

---

## 5. Correctness, Concurrency, Security & Regression Evidence

### Verification Commands Executed
- `gofmt -l apps/sandboxpolicy cmd/sandboxpolicy-bench apps/apps.go` -> clean (`0` unformatted files).
- `go vet ./apps/sandboxpolicy/... ./cmd/sandboxpolicy-bench/... ./apps/...` -> pass (`0` warnings).
- `go test -race -count=1 -v ./apps/sandboxpolicy/... ./cmd/sandboxpolicy-bench/...` -> **all 10 top-level tests (13 test cases including subtests) pass with 0 data races**:
  - `TestSeccompBPFCompilationAndVMParity` (`audit_only`, `enforce_deny`, `enforce_sigkill`): verifies wrong-architecture `SECCOMP_RET_KILL_PROCESS`, all six 64-bit argument operators (including upper 32-bit words), and `100%` parity between `EvalBPF` and `Engine.Evaluate`.
  - `TestPathNormalizationSymlinkAndPrivEscRefusal`: verifies path traversal, NUL byte, relative path, `/usr/bin2` & `/tmp/go-build-evil` boundary spoofing, symlink target escape, and all 6 privilege-escalation vectors (`Setuid`, `NewUID`, `NewGID`, `CapabilitiesAdded`, `EffectiveCaps`, `NoNewPrivs=false`).
  - `TestNetworkCIDRAndIPv4MappedIPv6Normalization`: verifies IPv4/IPv6 IMDS blocking, `::ffff:169.254.169.254` / `::ffff:10.96.0.1` / `::ffff:127.0.0.1:2375` unmapping, reverse-shell refusal, and allowed public HTTPS + ephemeral loopback binds.
  - `TestPolicyConflictAndFailClosedDefaults`: verifies unbound sandbox fail-closed refusal and atomic preservation of v1 policy when conflicting v2 compilation fails.
  - `TestAuditRingBoundedMemoryHashChainAndTamperDetection`: verifies bounded ring eviction, wrapped-window hash-chain validity, cryptographic tamper detection, and `RingDropNewest` backpressure/drain accounting.
  - `TestIndexedEqualsUnindexedEquivalence`: proves indexed lookup equals unindexed linear scan across all 3 domains.
  - `TestStrictTenantIsolationAndConcurrencyRaceFree`: 8 concurrent workers across 4 tenants under `-race` with zero cross-tenant audit leaks.
  - `TestEveryOperationAndFieldIsDescribed`: verifies all 8 `/v1/sandboxpolicy` routes and every published schema field carry non-empty `zipdoc` descriptions.
  - `TestHTTPWireSecurityIsolationAndQueryHijackImmunity`: end-to-end `zip.App` wire tests verifying `401` unauthenticated refusals, `url:"-"` query-hijack immunity on `POST /policies`, `POST /sandboxes/:id/bind`, and `POST /evaluate`, `404` on cross-org policy reads/binds, and `0` cross-org audit leaks.
  - `TestRunBenchmarksRegressionAndNegativeRegimes`: end-to-end automated gate validating Matrix 1, Matrix 2, Matrix 3, and Negative Regimes 1 & 2.
- `CGO_ENABLED=0 go test ./apps/...` -> pass (including `TestAppsImportNothingOfTheirHost`).
- `CGO_ENABLED=0 go build ./cmd/cloud` -> pass.

### Security Review Posture (`PR_CONVERGENCE.md`)
- **Strict Tenant Isolation**: Every policy, sandbox binding, evaluation counter, and SHA-256 hash-chained audit ring is partitioned strictly by server-stamped `principal.Acting(ctx)`. Cross-org policy reads/binds return `404`; unbound sandboxes fail closed (`fail_closed_no_policy`). Public `GET /v1/sandboxpolicy/health` exposes only aggregate numeric counters — zero tenant IDs or rule payloads.
- **Canonicalization Before Matching**: Binary paths and resolved symlink targets are normalized via `NormalizeCanonicalPath` with strict directory-boundary matching prior to allow/deny evaluation. Network IPs and CIDRs are unmapped via `netip.Addr.Unmap()` prior to CIDR lookup, eliminating `::ffff:169.254.169.254` dual-stack bypasses.
- **Query-Hijack Defense & Memory Bounds**: All POST body fields carry `url:"-"`. Hard caps enforce `MaxPolicyRules (4096)`, `BPFMaxInsns (4096)`, `MaxArgFiltersPerRule (6)`, `DefaultMaxTenants (4096)`, `DefaultMaxPoliciesPerTenant (256)`, `DefaultMaxSandboxesPerTenant (4096)`, and `MaxAuditRingCapacity (65536)`.

---

## 6. Before/After Measurements, Negative Regimes & HIP-1349 Recommendation

All measurements below are verbatim from [`docs/research/hip-1349-tetragon-sandbox/results.json`](./results.json) (`seed=1349`, `go1.27.1`, `linux/amd64`, commit `0f3125493818da9f324b83c6ae62dea2297be530`).

### 6.1 Matrix 1: Boundary-Enforcement Regression (20 Escape Cases: 8 Syscall, 6 Process, 6 Network)

| Enforcement Mode | Blocked | Block Rate | `AUDIT_ALERT` | `DENY` (`EPERM`) | `SIGKILL` | Audit Visibility | Hash-Chain Valid | Seccomp-BPF VM Parity (8/8) |
|---|---:|---:|---:|---:|---:|---:|---|---|
| `audit_only` (baseline) | 0 / 20 | **0.00%** | 20 | 0 | 0 | **100.00%** | **Pass** | **100.00%** |
| `enforce_deny` (`EPERM`) | **20 / 20** | **100.00%** | 0 | 20 | 0 | **100.00%** | **Pass** | **100.00%** |
| `enforce_sigkill` | **20 / 20** | **100.00%** | 0 | 2 | 18 | **100.00%** | **Pass** | **100.00%** |

*(Under `enforce_sigkill`, 18 critical escapes terminate via `SIGKILL` while `socket(AF_PACKET)` and internal RFC1918 `10.96.0.1:443` respect their rule-level `enforce_deny` `EPERM` override — achieving `100.00%` refusal across all 20 escape vectors.)*

### 6.2 Matrix 2: Benign Agent Workload False-Positive Matrix (240 Real Operations under `enforce_sigkill`)

| Domain | Operations Tested | Allowed | False-Positive Blocks | False-Positive Rate | Seccomp-BPF Parity |
|---|---:|---:|---:|---:|---:|
| Syscall (`go`, `git`, `npm`, file I/O, thread `clone`, `AF_INET`) | 120 | 120 | **0** | **0.00%** | **100.00%** |
| Process (`go test`, `git status`, `npm test`, `rg`, `cat`, `GOTMPDIR` test bins) | 72 | 72 | **0** | **0.00%** | — |
| Network (public IPv4/IPv6 HTTPS `:443`, DNS `:53`, ephemeral loopback `httptest`) | 48 | 48 | **0** | **0.00%** | — |
| **Total** | **240** | **240** | **0** | **0.00%** | **100.00%** |

### 6.3 Matrix 3 & Negative Regime 1: Rule Scaling (`10` / `100` / `1,000` Rules) & Unindexed Explosion

- **Unmonitored Baseline**: `p50 = 31 ns`, `p95 = 33 ns`, `p99 = 50 ns`, `mean = 31.73 ns`, `10,364,493 events/sec`.

| Active Rules | Compiled BPF Insns | Indexed p50 (ns) | Indexed p99 (ns) | Indexed Throughput (ev/s) | BPF VM p50 (ns) | Unindexed p50 (ns) | Unindexed p99 (ns) | Unindexed p50 Slowdown |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 10 | 13 | 785 | 9,161 | 562,398 | 57 | 693 | 5,470 | 0.88× |
| 100 | 73 | 738 | 20,282 | 583,734 | 172 | 1,471 | 7,755 | 1.99× |
| **1,000** | **673** | **764** | **6,416** | **504,397** | **1,244** | **5,833** | **29,171** | **7.63×** |

- **Negative Regime 1A Finding (Unindexed Rule Explosion)**: Indexed O(1)/bitmask-CIDR enforcement remains flat (`785 -> 738 -> 764 ns` p50, `>500k events/sec`) across a `100×` increase in rule count. Unindexed linear scanning scales linearly to **`5,833 ns` p50 (`7.63×` slower)** and **`29,171 ns` p99 (`4.55×` slower)** at `1,000` rules, slashing throughput `3.54×` (`142,617` vs `504,397 events/sec`).
- **Negative Regime 1B Finding (Over-Broad Policy False-Positive Explosion)**: Adding an unanchored regex rule `(?i)(test|status|silent|workspace)` and dropping IPv6/ephemeral-loopback network allowances causes **`81 / 240` (`33.75%`) false-positive blocks** on legitimate agent tasks — demonstrating that runtime enforcement requires canonical path prefixes, scoped `GOTMPDIR=/tmp/go-build`, and dual-stack/ephemeral-loopback allowances rather than ad-hoc regex blocklists.

### 6.4 Negative Regime 2: High-Frequency Tight Syscall Loop (`50,000 events/sec`) & Audit-Ring Backpressure

| Configuration (`50,000` benign `read`/`newfstatat`, ring cap `4,096`, drain `12k/s`) | Emitted to Ring | Dropped | Drop Rate | p50 (ns) | p99 (ns) | Mean (ns) | Throughput (ev/s) |
|---|---:|---:|---:|---:|---:|---:|---:|
| **Userspace Audit-All (`AuditAllowEvents=true`)** | 50,000 | **34,144** | **68.29%** | 590 | 7,016 | 1,573.04 | 605,371 |
| **In-Kernel Seccomp-BPF Fast-Path (`AuditAllowEvents=false`)** | **0** | **0** | **0.00%** | **430** | **486** | **460.09** | **1,908,349** |

- **Negative Regime 2 Conclusion**: Streaming high-frequency benign syscalls (`read`, `newfstatat`) into userspace audit rings loses **`68.29%`** of events under backpressure and inflates p99 latency **`14.44×`** (`7,016 ns` vs `486 ns`) — creating a denial-of-visibility hazard where benign I/O floods evict or drop genuine escape alerts. Resolving benign allowlisted syscalls via compiled in-kernel seccomp-BPF (`SECCOMP_RET_ALLOW`) eliminates ring drops completely (**`0.00%`**) and raises throughput **`3.15×`** (`1.91M` vs `605k events/sec`).

### 6.5 HIP-1349 Integration Recommendation, Rollout & Rollback Plan
- **Canonical Architecture Alignment**: Preserves `vfs -> Hanzo S3 -> Visor, Cloud owns lifecycle and billing, Enso routes models, Zen generates, Kai decides`. `apps/sandboxpolicy` lives in `hanzoai/cloud` as the control-plane policy compiler, seccomp-BPF bytecode emitter, and tenant-isolated hash-chained audit store mounted at `/v1/sandboxpolicy`. Visor sandbox launchers fetch the compiled `BPFProgram` (`GET /v1/sandboxpolicy/policies/:id`) to install `SECCOMP_MODE_FILTER` via `prctl(PR_SET_SECCOMP)` at container spawn (with `GOTMPDIR=/tmp/go-build` and `PR_SET_NO_NEW_PRIVS=1`), and stream process/network/violation hooks to `/v1/sandboxpolicy/evaluate` & `/v1/sandboxpolicy/audit` — or optionally attach Cilium Tetragon `TracingPolicy` CRDs in Kubernetes clusters using the identical three-domain schema.
- **Next-Phase Production Hardening**: Add a Linux-only `seccomp_linux.go` attachment helper in Visor that passes `CompiledPolicy.BPF.Insns` directly to `SYS_SECCOMP(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC)` before `execve`, and stream Tetragon eBPF ringbuf violation alerts on Linux 5.15+ nodes into `TenantAuditRing` while keeping benign syscall allowlists strictly in-kernel.
- **Rollout & Rollback**: Mounted declaratively in `apps.Wire()` with zero database migrations, zero changes to existing routes, and zero `go.mod` / `go.sum` edits. Rollout starts per-tenant in `mode=audit_only` to verify `0.00%` false positives on real workloads, graduates to `enforce_deny`, and then `enforce_sigkill`. Rollback is a single-line removal of the `sandboxpolicy` entry in `apps.Wire()` with zero impact on any other subsystem.
