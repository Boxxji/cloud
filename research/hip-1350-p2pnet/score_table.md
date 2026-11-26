# HIP-1350 Score Table — Decentralized Peer Discovery & Routing (`p2pnet`)

Generated directly from `go run ./cmd/p2pnet-bench -seed 1350 -nodes 20 -requests 80 -write-dossier research/hip-1350-p2pnet`.
Every number below matches [`raw_results.json`](./raw_results.json) to the exact decimal.

## 1. Five-Dimension Regime Comparison

| Regime | Realized Cost ($/1M useful tok) | Convergence (ms) | Route Latency p50/p95/p99 (ms) | Throughput (req/s \| tok/s) | Pre-Kill / Post-Kill Completion | Hijacked | Adversarial Detected | Hanzo Calls | Completion w/o Hanzo |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `centralized_registry_baseline` | $0.3044 | 8.08 | 3.75 / 7.34 / 7.56 | 277.01 \| 709137.85 | 100.00% / n/a | 0 (0.00%) | n/a | 100 | 0.00% |
| `hip1350_decentralized_p2p_20n` | $0.2676 | 878.72 | 2.83 / 7.14 / 9.71 | 322.71 \| 826133.80 | 100.00% / 100.00% | 0 (0.00%) | 100/100 (100.00%) | 0 | 100.00% |
| `neg_unverified_advertisements_control` | n/a (0 useful tok) | 1657.15 | 2.95 / 6.37 / 8.15 | 0.00 \| 0.00 | 0.00% / n/a | 80 (100.00%) | 0/100 (0.00%) | 0 | 0.00% |
| `neg_central_registry_kill_negative` | n/a (0 useful tok) | 2.49 | 0.00 / 0.00 / 0.00 | 0.00 \| 0.00 | n/a / 0.00% | 0 (0.00%) | n/a | 18 | 0.00% |
| `neg_total_partition_eclipse_boundary` | n/a (0 useful tok) | 0.00 | 0.00 / 0.48 / 2.29 | 0.00 \| 0.00 | n/a / 0.00% | 0 (0.00%) | 100/100 (100.00%) | 0 | 0.00% |

## 2. Cost Decomposition (Centralized Baseline vs Primary Decentralized 20-Node DHT)

| Metric | Centralized Registry Baseline | Primary HIP-1350 P2P (20 Nodes) |
|---|---:|---:|
| Useful Tokens Delivered | 204800 | 204800 |
| Compute Spend (uUSD) | 53608 | 54106 |
| Cryptographic Verification Overhead (uUSD) | 54 | 60 |
| DHT / Gossip / Relay Bandwidth Overhead (uUSD) | 15 | 644 |
| Central Registry Control-Plane Overhead (uUSD) | 8668 | 0 |
| Total Realized Cost (uUSD) | 62345 | 54810 |
| Realized Cost ($/1M useful tokens) | $0.3044 | $0.2676 |
| Realized Savings vs Centralized Baseline | 0.00% | 12.09% |

## 3. Adversarial Trust Breakdown by Verification Class (Primary 20-Node P2P)

| Attack Vector | Verification Class | Injected | Detected | Detection Rate |
|---|---|---:|---:|---:|
| `forged_signature` | `crypto_peer_signature` | 12 | 12 | 100.00% |
| `tampered_capability_fields` | `crypto_peer_signature` | 12 | 12 | 100.00% |
| `expired_ttl` | `crypto_peer_signature` | 12 | 12 | 100.00% |
| `sequence_rollback` | `crypto_peer_signature` | 12 | 12 | 100.00% |
| `replay_nonce` | `crypto_peer_signature` | 12 | 12 | 100.00% |
| `peer_id_mismatch` | `crypto_peer_signature` | 12 | 12 | 100.00% |
| `clock_skew_future` | `crypto_peer_signature` | 12 | 12 | 100.00% |
| `sybil_flood` | `network_liveness_probe` | 16 | 16 | 100.00% |
| **Total Adversarial Events** | `crypto_peer_signature` + `network_liveness_probe` | **100** | **100** | **100.00%** |
| Hardware TEE Attestation | `hardware_attestation` | 20 nodes | 0 attested | **not claimed (0.00%)** |

## 4. Decentralization, NAT Traversal & Sovereignty Measurements

| Metric | Measured Value |
|---|---:|
| Hanzo Control-Plane Calls (`HanzoCalls`) | 0 |
| Hanzo Registry Disabled (`HanzoRegistryDisabled`) | true |
| Nodes Killed Mid-Run (ALL 3 Bootstraps + 2 Relays) | 5 / 20 |
| Post-Kill End-to-End Request Completion | 40/40 (100.00%) |
| NAT-Relayed Circuit-Forwarded Inference Completions | 23 (Relay Forwards: 85) |
| Mean Discovered Peers per Node (20-Node Mesh) | 19.00 |
| Signed UDP/QUIC-Ready Probe Mean RTT | 0.11 ms |
| Active Serving Providers / Provider HHI | 12 / 0.1013 |
| Signed `MeshExportBundle` Size | 37142 bytes |
| Exported State (Peers / Bootstraps / Announcements) | 20 / 19 / 20 |
| Export / Verify / Cold-Start Fork Latency | 0.43 ms / 2.69 ms / 6.91 ms (total 10.03 ms) |
| Bundle Tamper Detection | true |
| Post-Fork Independent Routing OK | true (HanzoCalls=0) |
