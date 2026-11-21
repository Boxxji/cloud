// SPDX-License-Identifier: Apache-2.0 OR MIT

package gradient

import (
	"context"
	"math"
	"math/rand"
	"sort"
	"time"
)

// PhaseSpec describes one deterministic traffic phase in the overload and
// slow-dependency evaluation benchmark.
type PhaseSpec struct {
	Name               string
	Requests           int
	ArrivalConcurrency int
	UpstreamWorkers    int
	BaseLatencyMs      float64
	QueuePenaltyMs     float64 // Extra queueing delay per request above UpstreamWorkers.
	SLOMs              float64 // Goodput latency ceiling: requests exceeding SLOMs count against goodput.
	NoisyTenantShare   float64 // Fraction of requests originating from a single flood tenant.
}

// EvalSummary captures matched-baseline metrics across a benchmark run.
type EvalSummary struct {
	Controller         string  `json:"controller"`
	TotalRequests      int     `json:"total_requests"`
	Admitted           int     `json:"admitted"`
	Rejected           int     `json:"rejected"`
	GoodputCount       int     `json:"goodput_count"`
	GoodputRatio       float64 `json:"goodput_ratio"`
	P50LatencyMs       float64 `json:"p50_latency_ms"`
	P95LatencyMs       float64 `json:"p95_latency_ms"`
	P99LatencyMs       float64 `json:"p99_latency_ms"`
	RecoveryP99Ms      float64 `json:"recovery_p99_ms"`
	NormalTenantGoodOk float64 `json:"normal_tenant_goodput_ratio"`
	FinalLimit         int     `json:"final_limit"`
}

type simEvent struct {
	releaseAtMs float64
	releaseFn   ReleaseFunc
	rtt         time.Duration
	outcome     Outcome
}

// DefaultThreePhaseWorkload returns the canonical 3-phase workload used to
// evaluate normal operation, a 4x load + slow-dependency spike, and recovery.
func DefaultThreePhaseWorkload() []PhaseSpec {
	return []PhaseSpec{
		{
			Name:               "steady_pre_spike",
			Requests:           1200,
			ArrivalConcurrency: 22,
			UpstreamWorkers:    24,
			BaseLatencyMs:      10.0,
			QueuePenaltyMs:     4.5,
			SLOMs:              45.0,
			NoisyTenantShare:   0.25,
		},
		{
			Name:               "overload_and_slow_dependency",
			Requests:           1200,
			ArrivalConcurrency: 64,
			UpstreamWorkers:    8,
			BaseLatencyMs:      22.0,
			QueuePenaltyMs:     9.0,
			SLOMs:              85.0,
			NoisyTenantShare:   0.75,
		},
		{
			Name:               "post_spike_recovery",
			Requests:           1600,
			ArrivalConcurrency: 22,
			UpstreamWorkers:    24,
			BaseLatencyMs:      10.0,
			QueuePenaltyMs:     4.5,
			SLOMs:              45.0,
			NoisyTenantShare:   0.25,
		},
	}
}

// RunDiscreteEvaluation replays an identical seeded multi-phase workload
// against lim, modeling M/G/C-style upstream queueing contention and timeout
// collapse when admitted concurrency exceeds upstream worker capacity.
func RunDiscreteEvaluation(name string, lim Limiter, phases []PhaseSpec, seed int64) EvalSummary {
	rng := rand.New(rand.NewSource(seed))
	ctx := context.Background()

	var (
		nowMs             float64
		active            []simEvent
		allLatencies      []float64
		recoveryLatencies []float64
		totalReqs         int
		admitted          int
		rejected          int
		goodput           int
		normalTotal       int
		normalGood        int
	)

	drainCompleted := func(upToMs float64) {
		remaining := active[:0]
		for _, ev := range active {
			if ev.releaseAtMs <= upToMs {
				ev.releaseFn(ev.rtt, ev.outcome)
			} else {
				remaining = append(remaining, ev)
			}
		}
		active = remaining
	}

	for pIdx, phase := range phases {
		stepMs := phase.BaseLatencyMs / float64(maxInt(1, phase.ArrivalConcurrency))
		for i := 0; i < phase.Requests; i++ {
			nowMs += stepMs
			drainCompleted(nowMs)

			tenant := "org-normal"
			isNormal := true
			if rng.Float64() < phase.NoisyTenantShare {
				tenant = "org-flood"
				isNormal = false
			} else if rng.Float64() < 0.5 {
				tenant = "org-partner"
			}
			if isNormal {
				normalTotal++
			}
			totalReqs++

			rel, rej := lim.Acquire(ctx, tenant)
			if rej != nil {
				rejected++
				continue
			}
			admitted++

			// Upstream queueing physics: once active inflight exceeds upstream
			// workers, queueing latency grows super-linearly with queue depth.
			upstreamInflight := len(active) + 1
			jitter := 0.85 + 0.30*rng.Float64()
			latMs := phase.BaseLatencyMs * jitter
			if over := upstreamInflight - phase.UpstreamWorkers; over > 0 {
				latMs += float64(over)*phase.QueuePenaltyMs + 0.35*float64(over*over)
			}

			outcome := OutcomeSuccess
			if latMs > phase.SLOMs*2.5 {
				outcome = OutcomeOverload
			}

			rtt := time.Duration(latMs * float64(time.Millisecond))
			active = append(active, simEvent{
				releaseAtMs: nowMs + latMs,
				releaseFn:   rel,
				rtt:         rtt,
				outcome:     outcome,
			})

			allLatencies = append(allLatencies, latMs)
			if pIdx == len(phases)-1 {
				recoveryLatencies = append(recoveryLatencies, latMs)
			}
			if outcome == OutcomeSuccess && latMs <= phase.SLOMs {
				goodput++
				if isNormal {
					normalGood++
				}
			}
		}
	}

	drainCompleted(math.MaxFloat64)
	snap := lim.Snapshot()

	var normalGoodRatio float64
	if normalTotal > 0 {
		normalGoodRatio = float64(normalGood) / float64(normalTotal)
	}
	var goodputRatio float64
	if totalReqs > 0 {
		goodputRatio = float64(goodput) / float64(totalReqs)
	}

	return EvalSummary{
		Controller:         name,
		TotalRequests:      totalReqs,
		Admitted:           admitted,
		Rejected:           rejected,
		GoodputCount:       goodput,
		GoodputRatio:       round4(goodputRatio),
		P50LatencyMs:       round2(percentile(allLatencies, 0.50)),
		P95LatencyMs:       round2(percentile(allLatencies, 0.95)),
		P99LatencyMs:       round2(percentile(allLatencies, 0.99)),
		RecoveryP99Ms:      round2(percentile(recoveryLatencies, 0.99)),
		NormalTenantGoodOk: round4(normalGoodRatio),
		FinalLimit:         snap.Limit,
	}
}

func percentile(xs []float64, q float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	cp := make([]float64, len(xs))
	copy(cp, xs)
	sort.Float64s(cp)
	idx := int(math.Ceil(q*float64(len(cp)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(cp) {
		idx = len(cp) - 1
	}
	return cp[idx]
}

func round2(v float64) float64 {
	return math.Round(v*100) / 100
}

func round4(v float64) float64 {
	return math.Round(v*10000) / 10000
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
