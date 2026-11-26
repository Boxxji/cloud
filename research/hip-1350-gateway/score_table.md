# HIP-1350 Five-Dimension Score Table — Permissionless Enso Gateway (`hanzoai/cloud#15`)

- **Generated**: `2026-11-26T09:36:33Z` (`go1.27.1`, `linux/amd64`, `2` vCPU)
- **Protocol**: `enso-gateway/v1` (`VerificationClass: cryptographic_signed_commitment_sha256`)
- **Raw Artifact**: [`raw_results.json`](./raw_results.json)

## Summary Across All 5 HIP-1350 Dimensions

| Dimension | Metric | Measured Result | Target / Invariant |
| --- | --- | --- | --- |
| **1. Cost** | Hanzo Convenience Gateway (25 bps) | **$0.280723 / 1M useful tokens** (base `$0.280` + fee `$0.000700` + verify `$0.000023`) | Open fee competition (0–25 bps) |
| **1. Cost** | Independent Community Gateway (10 bps) | **$0.280303 / 1M useful tokens** (base `$0.280` + fee `$0.000280` + verify `$0.000023`) | Open fee competition (0–25 bps) |
| **1. Cost** | Self-Hosted / Forked Community Gateway (0 bps) | **$0.280023 / 1M useful tokens** (base `$0.280` + fee `$0.000000` + verify `$0.000023`) | Open fee competition (0–25 bps) |
| **2. Performance** | Sequential loopback HTTP (`N = 120`) | **TTFT p50 0.107 ms (p99 0.442 ms)** · **E2E p50 2.076 ms / p95 6.176 ms / p99 9.475 ms** · **323.3 req/s** (`43966 tok/s`) · **100.0% completion** | Sub-10ms local gateway overhead, 100% completion |
| **2. Performance** | Concurrent `16`-client loopback load (`N = 112`) | **230.7 req/s** (`31376 tok/s`) · **p50 45.177 ms / p95 76.501 ms / p99 88.106 ms** · `112/112` completed | Race-free stateless concurrency |
| **2. Performance** | Mid-flight provider crash failover (`20` drills) | **100.0% completion** (`20/20`) · **p50 2.120 ms / p95 3.956 ms / p99 7.149 ms** | Automatic peer failover recovery |
| **3. Trust** | Adversarial forged/tampered quote & receipt matrix | **7 / 7 detected fail-closed (100.0%)** | 100% fail-closed under declared threat model |
| **4. Decentralization** | Workload with EVERY Hanzo gateway disabled (`N = 60`) | **100.0% independent completion** (`60/60`), **`HanzoClientCalls = 0`**, **`HanzoServerCalls = 0`** | 100% workload with 0 Hanzo gateways |
| **5. Sovereignty** | Stateless export, offline verify & third-party fork | **3601 B signed bundle**, verified in **442.3 µs**, forked in **861.8 µs**, **100.0% completion** (`0` Hanzo calls, `0 bps` fee) | Full config/directory export & permissionless forkability |

## Stateless Strategy Comparison

| Strategy | Primary Provider Selected | Effective Price ($/1M tok) | Latency p50 (ms) | Latency p95 (ms) | Completion |
| --- | --- | ---: | ---: | ---: | ---: |
| `lowest_cost` | `worker-alpha-lowcost` | $0.280280 | 4.322 | 10.248 | 100.0% |
| `lowest_ttft` | `worker-beta-lowttft` | $0.440440 | 2.109 | 6.626 | 100.0% |
| `weighted_slo_score` | `worker-alpha-lowcost` | $0.280280 | 2.451 | 4.430 | 100.0% |
| `failover_resilient` | `worker-gamma-balanced` | $0.340340 | 2.409 | 8.402 | 100.0% |

## Three Honest Negative & Boundary Regimes

| Regime | Category | Trials | Observed | Control | Validated |
| --- | --- | ---: | ---: | ---: | :---: |
| `unverified_receipt_negative` | `negative_control` | 40 | 100.0% | 100.0% | `true` |
| `single_provider_no_failover_negative` | `negative_control` | 40 | 70.0% | 100.0% | `true` |
| `stale_quote_storm_boundary` | `boundary_regime` | 40 | 0.0% | 70.0% | `true` |
