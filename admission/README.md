# Adaptive Concurrency Admission Control (`admission` - HIP-1348 / HIP-1349)

Implements windowed Gradient2 adaptive concurrency admission control paired with explicit `budget_exhausted` (`layer`) error attribution for overloaded Hanzo Cloud inference and storage endpoints (`hanzoai/cloud#38`, `hanzoai/cloud#31`).

## 1. Primary Reference and License Audit

- **Primary reference**: Netflix `concurrency-limits` (`Gradient2Limit` + `WindowedLimit`, TCP Vegas queueing-gradient control), `https://github.com/Netflix/concurrency-limits` (`Apache-2.0` license, no patent grants restricting independent implementation).
- **Clean-room audit**: 100% clean-room Go (`SPDX-License-Identifier: Apache-2.0 OR MIT`) implemented inside `admission/` using Go standard library primitives and `github.com/zap-proto/zip`. Zero external Go modules added (`go.mod` and `go.sum` untouched) and zero non-public module imports.

## 2. Canonical Stack Boundaries and `budget_exhausted` Taxonomy

Canonical Hanzo stack boundaries remain intact (`vfs -> hanzoai/s3 -> visor`, Cloud owning lifecycle, edge admission, and billing, Enso routing models, Zen generating outputs, Kai returning structured decisions).

Every shed request returns a structured `BudgetExhaustedError` (`code: "budget_exhausted"`) with an explicit `HIP-1348` section 1 `layer` and `Retry-After` header:

| Layer | HTTP Status | Trigger |
|---|---|---|
| `tenant_ledger` | `429` | Pre-execution tenant spend ceiling exhausted before endpoint concurrency is touched |
| `ai_gateway` | `503` / `429` | Global adaptive concurrency limit (`503`) or per-tenant share cap (`429`) at AI gateway |
| `worker` | `503` / `429` | Staged worker or storage execution pool concurrency saturation |
| `durable_object` | `503` / `429` | Single-writer durable state coordinator saturation |
| `upstream_provider` | `503` / `429` | Downstream model or S3 storage provider overload / slow dependency |

Live endpoint telemetry is projected strictly via a typed `zip.Get[SnapshotIn, SnapshotOut]` operation (`GET /v1/gateway/admission`, `operationId: gateway_admission_snapshot`) in accordance with `LLM.md` Architecture Invariant #1.

## 3. Falsifiable Hypothesis and Failure Modes

- **Hypothesis**: Across a 3-phase workload (`steady_pre_spike` with 24 upstream workers -> `overload_and_slow_dependency` 4x arrival spike with upstream degradation to 8 workers at 2.2x base latency -> `post_spike_recovery` back to 24 workers), windowed `GradientLimiter` achieves strictly higher SLO-compliant goodput than both an under-provisioned static semaphore (`limit=8`) and an over-provisioned static semaphore (`limit=64`), while cutting p99 tail latency by `>3x` relative to `static_64` and protecting non-flooding tenants via `MaxTenantShare`.
- **Documented failure modes and mitigations**:
  1. *Multi-request single-RTT over-contraction*: updating `limit` on every in-flight completion compounds $N$ multiplicative decreases within a single RTT spike. Mitigated by aggregating RTT and overload counts per RTT window (`max(4, limit/2)` completions).
  2. *Baseline RTT lock-in after permanent routing shifts*: if upstream base latency rises permanently, a pinned historical `longRTT` causes persistent contraction toward `MinLimit`. Mitigated by exponential upward `LongRTTDecay` (`0.99` per non-overload window).
  3. *Client `4xx` baseline pollution*: fast validation rejections (`<1 ms`) would artificially depress `longRTT`. Mitigated by `OutcomeIgnore` classification on HTTP `400..499` (excluding `429`).

## 4. Reproducible Matched-Baseline Measurements

Reproduce with:

```bash
CGO_ENABLED=0 go test -v -run TestMatchedBaselineEvaluationBenchmark ./admission/...
go test -race ./admission/...
```

Measured results (`seed = 20261118`, `4,000` total requests across 3 phases):

| Controller | Admitted | Rejected | SLO Goodput | Goodput Ratio | p50 (ms) | p95 (ms) | p99 (ms) | Normal-Tenant Goodput | Final Limit |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `static_semaphore_64` | 449 | 3551 | 291 | 0.0728 | 11.08 | 1622.93 | 1626.03 | 0.0888 | 64 |
| `static_semaphore_8` | 1136 | 2864 | 1136 | 0.2840 | 10.23 | 22.95 | 24.72 | 0.3149 | 8 |
| `gradient2_adaptive` | 1617 | 2383 | 1452 | 0.3630 | 10.35 | 172.74 | 387.60 | 0.4502 | 14 |

- **Goodput**: `gradient2_adaptive` delivers `1,452` SLO-compliant completions (`+399.0%` vs `static_semaphore_64` and `+27.8%` vs `static_semaphore_8`).
- **Tail latency**: `gradient2_adaptive` reduces p99 latency from `1626.03 ms` (`static_64`) to `387.60 ms` (`4.20x` reduction).
- **Multi-tenant isolation**: Non-flooding tenant goodput rises from `8.88%` (`static_64`) and `31.49%` (`static_8`) to `45.02%` under a 75% noisy-neighbor flood.
