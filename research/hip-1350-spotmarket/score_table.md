# HIP-1350 Score Table — Open GPU Spot Market & Capacity Auctions

Generated deterministically from `go run ./cmd/spotmarket-bench -seed 1350 -providers 100 -epochs 24 -write-dossier research/hip-1350-spotmarket`.
Every figure below matches `raw_results.json` to the exact decimal.

## 1. Five-Dimension Regime Comparison

| Regime | Realized Cost ($/1M useful tok) | Savings vs Baseline | Ledger Drift (uUSD) | TTFT p50 / p95 / p99 (ms) | Mean Throughput (tok/s) | Completion Rate | Adversarial Detected | Hanzo Calls | Completion w/o Hanzo |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `fixed_price_baseline` | $0.8292 | 0.00% | 0 | 185.16 / 369.07 / 397.38 | 98.77 | 98.63% | n/a | 293 | 0.00% |
| `hip1350_decentralized_spot_100p` | $0.3027 | 63.50% | 0 | 99.91 / 145.37 / 157.72 | 111.40 | 100.00% | 674/674 (100.00%) | 0 | 100.00% |
| `neg_unverified_no_slashing_control` | $0.3202 | 61.38% | 0 | 100.76 / 147.39 / 166.44 | 108.24 | 100.00% | 24/672 (3.57%) | 0 | 100.00% |
| `neg_fleet_capacity_saturation` | $0.5238 | 36.83% | 0 | 104.35 / 150.68 / 161.21 | 105.22 | 99.02% | 4285/4285 (100.00%) | 0 | 100.00% |
| `neg_ultra_short_ttl_churn` | $0.3233 | 61.01% | 0 | 100.71 / 154.67 / 162.62 | 109.87 | 99.32% | 684/684 (100.00%) | 0 | 100.00% |

## 2. Cost Decomposition (Primary Spot vs Fixed Baseline)

| Metric | Fixed-Price Baseline | Primary HIP-1350 Spot (100 Providers) |
|---|---:|---:|
| Useful Tokens Delivered | 168895109 | 170402285 |
| Gross Compute Spend (uUSD) | 140048576 | 51533316 |
| Cryptographic Verification Overhead (uUSD) | 0 | 38706 |
| Settlement Ledger Overhead (uUSD) | 0 | 3033 |
| Buyer Slashing Compensation Received (uUSD) | 0 | 919330 |
| Realized Cost (incl. Verify + Settle, $/1M useful tok) | $0.8292 | $0.3027 |
| Net Cost After Slash Compensation ($/1M useful tok) | $0.8292 | $0.2973 |
| Realized Savings vs Baseline | 0.00% | 63.50% |
| Ledger Conservation Drift (uUSD) | 0 | 0 |

## 3. Adversarial Trust Breakdown by Verification Class (Primary Spot)

| Attack Vector | Verification Class | Injected | Detected | Detection Rate |
|---|---|---:|---:|---:|
| `forged_signature` | `crypto_signature` | 96 | 96 | 100.00% |
| `high_s_malleated` | `crypto_signature` | 96 | 96 | 100.00% |
| `expired_offer_or_bid` | `crypto_signature` | 24 | 24 | 100.00% |
| `replay_nonce` | `crypto_signature` | 67 | 67 | 100.00% |
| `sybil_spam_bids` | `crypto_signature` | 318 | 318 | 100.00% |
| `stale_capacity_overclaim` | `crypto_signature` | 69 | 69 | 100.00% |
| `bait_and_switch_non_delivery` | `economic_stake_slashing` | 4 | 4 | 100.00% |
| **Total Adversarial Events** | `crypto_signature` + `economic_stake_slashing` | **674** | **674** | **100.00%** |
| Hardware TEE Attestation (`hardware_attestation`) | `hardware_attestation` | 100 providers | 0 attested | **not claimed (0.00%)** |

## 4. Decentralization & Sovereignty Measurements

| Metric | Measured Value |
|---|---:|
| Hanzo Control-Plane Calls (`HanzoCalls`) | 0 |
| Completion Without Hanzo Infrastructure | 100.00% |
| Zero-Hanzo-Preference Parity Verified | true |
| Active Winning Providers (out of 100) | 41 |
| Provider Share Concentration (HHI, lower = more decentralized) | 0.0671 |
| Signed Export Bundle Size | 494625 bytes |
| Exported State Objects (Offers / Leases / Receipts / Peers) | 95 / 337 / 337 / 95 |
| Export / Verify / Cold-Start Import Latency | 11.19 ms / 23.26 ms / 22.07 ms (total 56.52 ms) |
| Post-Fork Conservation Drift (uUSD) | 0 |
| Post-Fork Independent Order Clear & Settle OK | true (HanzoCalls=0) |
