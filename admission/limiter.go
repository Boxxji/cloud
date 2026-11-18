// SPDX-License-Identifier: Apache-2.0 OR MIT

// Package admission implements gradient-based adaptive concurrency admission
// control (HIP-1348 Bounty #48 / HIP-1349 #31) paired with explicit
// budget_exhausted layer attribution across Hanzo Cloud inference and storage
// endpoints.
//
// Primary reference: Netflix concurrency-limits (Gradient2 + WindowedLimit
// Vegas congestion control, Apache-2.0,
// https://github.com/Netflix/concurrency-limits). This package is a 100%
// clean-room Go implementation with zero external module additions.
package admission

import (
	"context"
	"math"
	"sync"
	"time"
)

// Layer identifies the canonical HIP-1348 section 1 spend-limit or overload
// enforcement boundary that rejected a request.
type Layer string

const (
	LayerTenantLedger     Layer = "tenant_ledger"
	LayerAIGateway        Layer = "ai_gateway"
	LayerWorker           Layer = "worker"
	LayerDurableObject    Layer = "durable_object"
	LayerUpstreamProvider Layer = "upstream_provider"
)

// Valid reports whether l is one of the five canonical HIP-1348 layers.
func (l Layer) Valid() bool {
	switch l {
	case LayerTenantLedger, LayerAIGateway, LayerWorker, LayerDurableObject, LayerUpstreamProvider:
		return true
	default:
		return false
	}
}

// BudgetExhaustedError is the structured rejection returned when pre-execution
// tenant budget checks or adaptive concurrency admission shed a request.
type BudgetExhaustedError struct {
	Code         string `json:"code"`
	Layer        Layer  `json:"layer"`
	Reason       string `json:"reason"`
	Tenant       string `json:"tenant,omitempty"`
	Limit        int    `json:"limit"`
	Inflight     int    `json:"inflight"`
	RetryAfterMs int64  `json:"retry_after_ms"`
	HTTPStatus   int    `json:"-"`
}

func (e *BudgetExhaustedError) Error() string {
	if e == nil {
		return ""
	}
	return e.Code + ":" + string(e.Layer) + ":" + e.Reason
}

// Outcome classifies a completed request so the adaptive controller only
// updates latency baselines on meaningful upstream work.
type Outcome int

const (
	// OutcomeSuccess records a normal completed request sample.
	OutcomeSuccess Outcome = iota
	// OutcomeOverload signals an explicit upstream 429/503 or timeout, driving a
	// multiplicative backoff bounded to at most once per RTT window.
	OutcomeOverload
	// OutcomeIgnore excludes fast client errors (4xx) or cancelled requests so
	// rejected inputs never depress the no-load RTT estimate.
	OutcomeIgnore
)

// ReleaseFunc must be called exactly once when an admitted request finishes.
type ReleaseFunc func(rtt time.Duration, outcome Outcome)

// TenantBudgetChecker enforces pre-execution tenant spend ceilings before
// consuming endpoint concurrency capacity.
type TenantBudgetChecker func(ctx context.Context, tenant string) (allowed bool, retryAfter time.Duration, reason string)

// Stats exposes an atomic point-in-time snapshot of limiter state.
type Stats struct {
	Algorithm      string  `json:"algorithm"`
	Layer          Layer   `json:"layer"`
	Limit          int     `json:"limit"`
	FloatingLimit  float64 `json:"floating_limit"`
	Inflight       int     `json:"inflight"`
	ShortRTTMs     float64 `json:"short_rtt_ms"`
	LongRTTMs      float64 `json:"long_rtt_ms"`
	LastGradient   float64 `json:"last_gradient"`
	AdmittedTotal  uint64  `json:"admitted_total"`
	RejectedBudget uint64  `json:"rejected_budget_total"`
	RejectedLimit  uint64  `json:"rejected_limit_total"`
	RejectedTenant uint64  `json:"rejected_tenant_share_total"`
	OverloadEvents uint64  `json:"overload_events_total"`
}

// Limiter is implemented by both GradientLimiter and StaticSemaphoreLimiter so
// production middleware and matched-baseline benchmarks share one interface.
type Limiter interface {
	Acquire(ctx context.Context, tenant string) (ReleaseFunc, *BudgetExhaustedError)
	Snapshot() Stats
}

// GradientConfig parameterizes the windowed Gradient2 adaptive controller.
type GradientConfig struct {
	Layer          Layer
	InitialLimit   int
	MinLimit       int
	MaxLimit       int
	Tolerance      float64 // Permitted shortRTT / longRTT ratio before shedding (default 1.5).
	Smoothing      float64 // Per-RTT-window smoothing factor in (0, 1] (default 0.2).
	LongWindow     int     // Exponential window length in RTT epochs for baseline RTT (default 100).
	LongRTTDecay   float64 // Gentle upward drift when windowRTT > longRTT so stale baselines heal (default 0.99).
	MaxTenantShare float64 // Per-tenant share cap in (0, 1] when contended (default 0.6).
	BudgetCheck    TenantBudgetChecker
}

func (c GradientConfig) withDefaults() GradientConfig {
	if !c.Layer.Valid() {
		c.Layer = LayerAIGateway
	}
	if c.MinLimit <= 0 {
		c.MinLimit = 2
	}
	if c.MaxLimit < c.MinLimit {
		c.MaxLimit = 64
	}
	if c.InitialLimit <= 0 {
		c.InitialLimit = 16
	}
	if c.InitialLimit < c.MinLimit {
		c.InitialLimit = c.MinLimit
	}
	if c.InitialLimit > c.MaxLimit {
		c.InitialLimit = c.MaxLimit
	}
	if c.Tolerance <= 1.0 {
		c.Tolerance = 1.25
	}
	if c.Smoothing <= 0 || c.Smoothing > 1.0 {
		c.Smoothing = 0.2
	}
	if c.LongWindow <= 0 {
		c.LongWindow = 100
	}
	if c.LongRTTDecay <= 0 || c.LongRTTDecay >= 1.0 {
		c.LongRTTDecay = 0.99
	}
	if c.MaxTenantShare <= 0 || c.MaxTenantShare > 1.0 {
		c.MaxTenantShare = 0.6
	}
	return c
}

// GradientLimiter adapts concurrency limits once per RTT window (matching
// Netflix WindowedLimit + Gradient2Limit) so concurrent in-flight requests
// experiencing one shared queue spike adjust the window proportionally rather
// than compounding N multiplicative contractions in a single RTT.
type GradientLimiter struct {
	cfg GradientConfig

	mu              sync.Mutex
	limit           float64
	intLimit        int
	inflight        int
	byTenant        map[string]int
	shortRTTNs      float64
	longRTTNs       float64
	lastGradient    float64
	windowSamples   int
	windowSumRTTNs  float64
	windowMaxInflt  int
	windowOverloads int
	admittedTotal   uint64
	rejectedBudget  uint64
	rejectedLimit   uint64
	rejectedTenant  uint64
	overloadEvents  uint64
}

// NewGradientLimiter constructs a clean-room windowed Gradient2 limiter.
func NewGradientLimiter(cfg GradientConfig) *GradientLimiter {
	cfg = cfg.withDefaults()
	return &GradientLimiter{
		cfg:          cfg,
		limit:        float64(cfg.InitialLimit),
		intLimit:     cfg.InitialLimit,
		byTenant:     make(map[string]int),
		lastGradient: 1.0,
	}
}

// Acquire checks pre-execution tenant budget isolation first, then global and
// per-tenant concurrency limits.
func (g *GradientLimiter) Acquire(ctx context.Context, tenant string) (ReleaseFunc, *BudgetExhaustedError) {
	if g.cfg.BudgetCheck != nil && tenant != "" {
		allowed, retryAfter, reason := g.cfg.BudgetCheck(ctx, tenant)
		if !allowed {
			if reason == "" {
				reason = "tenant pre-execution spend ceiling reached"
			}
			retryMs := retryAfter.Milliseconds()
			if retryMs <= 0 {
				retryMs = 1000
			}
			g.mu.Lock()
			g.rejectedBudget++
			lim := g.intLimit
			inf := g.inflight
			g.mu.Unlock()
			return nil, &BudgetExhaustedError{
				Code:         "budget_exhausted",
				Layer:        LayerTenantLedger,
				Reason:       reason,
				Tenant:       tenant,
				Limit:        lim,
				Inflight:     inf,
				RetryAfterMs: retryMs,
				HTTPStatus:   429,
			}
		}
	}

	g.mu.Lock()
	if g.inflight >= g.intLimit {
		g.rejectedLimit++
		lim := g.intLimit
		inf := g.inflight
		retryMs := g.estimatedRetryMsLocked()
		g.mu.Unlock()
		return nil, &BudgetExhaustedError{
			Code:         "budget_exhausted",
			Layer:        g.cfg.Layer,
			Reason:       "adaptive concurrency limit reached",
			Tenant:       tenant,
			Limit:        lim,
			Inflight:     inf,
			RetryAfterMs: retryMs,
			HTTPStatus:   503,
		}
	}

	if tenant != "" && g.cfg.MaxTenantShare < 1.0 && g.inflight*2 >= g.intLimit {
		tenantCap := int(math.Ceil(float64(g.intLimit) * g.cfg.MaxTenantShare))
		if tenantCap < 1 {
			tenantCap = 1
		}
		if g.byTenant[tenant] >= tenantCap {
			g.rejectedTenant++
			lim := g.intLimit
			inf := g.inflight
			retryMs := g.estimatedRetryMsLocked()
			g.mu.Unlock()
			return nil, &BudgetExhaustedError{
				Code:         "budget_exhausted",
				Layer:        g.cfg.Layer,
				Reason:       "per-tenant concurrency share cap reached",
				Tenant:       tenant,
				Limit:        lim,
				Inflight:     inf,
				RetryAfterMs: retryMs,
				HTTPStatus:   429,
			}
		}
	}

	g.inflight++
	if tenant != "" {
		g.byTenant[tenant]++
	}
	inflightAtSample := g.inflight
	g.admittedTotal++
	g.mu.Unlock()

	var once sync.Once
	return func(rtt time.Duration, outcome Outcome) {
		once.Do(func() {
			g.onRelease(tenant, inflightAtSample, rtt, outcome)
		})
	}, nil
}

func (g *GradientLimiter) estimatedRetryMsLocked() int64 {
	if g.shortRTTNs <= 0 {
		return 25
	}
	ms := int64(g.shortRTTNs / 1e6)
	if ms < 5 {
		return 5
	}
	if ms > 5000 {
		return 5000
	}
	return ms
}

func (g *GradientLimiter) onRelease(tenant string, inflightSample int, rtt time.Duration, outcome Outcome) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.inflight > 0 {
		g.inflight--
	}
	if tenant != "" {
		if cur := g.byTenant[tenant]; cur <= 1 {
			delete(g.byTenant, tenant)
		} else {
			g.byTenant[tenant] = cur - 1
		}
	}

	if outcome == OutcomeIgnore {
		return
	}

	sampleNs := float64(rtt.Nanoseconds())
	if sampleNs <= 0 {
		sampleNs = 1e5
	}

	if outcome == OutcomeOverload {
		g.overloadEvents++
		g.windowOverloads++
	}
	g.windowSamples++
	g.windowSumRTTNs += sampleNs
	if inflightSample > g.windowMaxInflt {
		g.windowMaxInflt = inflightSample
	}

	// Flush one control epoch once roughly one window of in-flight work (at least
	// 4 samples, capped at intLimit) completes, matching Netflix WindowedLimit.
	windowTarget := max(4, g.intLimit/2)
	if g.windowSamples < windowTarget {
		return
	}

	avgRTTNs := g.windowSumRTTNs / float64(g.windowSamples)
	maxInflt := g.windowMaxInflt
	overloads := g.windowOverloads

	g.windowSamples = 0
	g.windowSumRTTNs = 0
	g.windowMaxInflt = 0
	g.windowOverloads = 0

	g.shortRTTNs = avgRTTNs
	if g.longRTTNs == 0 {
		g.longRTTNs = avgRTTNs
		return
	}

	longAlpha := 2.0 / (float64(g.cfg.LongWindow) + 1.0)
	if avgRTTNs < g.longRTTNs {
		g.longRTTNs += longAlpha * (avgRTTNs - g.longRTTNs)
	} else if overloads == 0 {
		g.longRTTNs = g.longRTTNs*g.cfg.LongRTTDecay + avgRTTNs*(1.0-g.cfg.LongRTTDecay)
	}

	if overloads > 0 {
		g.lastGradient = 0.5
		g.applyTargetLocked(g.limit * 0.75)
		return
	}

	ratio := g.cfg.Tolerance * (g.longRTTNs / g.shortRTTNs)
	gradient := math.Max(0.5, math.Min(1.0, ratio))
	g.lastGradient = gradient

	// Do not grow the concurrency ceiling when actual demand is well below half
	// the current limit (app-limited traffic).
	if gradient >= 1.0 && maxInflt*2 < g.intLimit {
		return
	}

	queueAllowance := 0.0
	if gradient >= 1.0 && g.shortRTTNs <= g.longRTTNs*1.10 {
		queueAllowance = math.Min(4.0, math.Max(1.0, math.Sqrt(g.limit)))
	}

	target := g.limit*gradient + queueAllowance
	smoothed := g.limit*(1.0-g.cfg.Smoothing) + target*g.cfg.Smoothing
	g.applyTargetLocked(smoothed)
}

func (g *GradientLimiter) applyTargetLocked(next float64) {
	if next < float64(g.cfg.MinLimit) {
		next = float64(g.cfg.MinLimit)
	}
	if next > float64(g.cfg.MaxLimit) {
		next = float64(g.cfg.MaxLimit)
	}
	g.limit = next
	rounded := int(math.Round(next))
	if rounded < g.cfg.MinLimit {
		rounded = g.cfg.MinLimit
	}
	if rounded > g.cfg.MaxLimit {
		rounded = g.cfg.MaxLimit
	}
	g.intLimit = rounded
}

// Snapshot returns an atomic copy of current limiter metrics.
func (g *GradientLimiter) Snapshot() Stats {
	g.mu.Lock()
	defer g.mu.Unlock()
	return Stats{
		Algorithm:      "gradient2",
		Layer:          g.cfg.Layer,
		Limit:          g.intLimit,
		FloatingLimit:  g.limit,
		Inflight:       g.inflight,
		ShortRTTMs:     g.shortRTTNs / 1e6,
		LongRTTMs:      g.longRTTNs / 1e6,
		LastGradient:   g.lastGradient,
		AdmittedTotal:  g.admittedTotal,
		RejectedBudget: g.rejectedBudget,
		RejectedLimit:  g.rejectedLimit,
		RejectedTenant: g.rejectedTenant,
		OverloadEvents: g.overloadEvents,
	}
}

// StaticConfig parameterizes the matched-baseline fixed semaphore limiter.
type StaticConfig struct {
	Layer       Layer
	Limit       int
	BudgetCheck TenantBudgetChecker
}

// StaticSemaphoreLimiter implements fixed-ceiling concurrency control as the
// matched baseline against GradientLimiter.
type StaticSemaphoreLimiter struct {
	layer       Layer
	limit       int
	budgetCheck TenantBudgetChecker

	mu             sync.Mutex
	inflight       int
	admittedTotal  uint64
	rejectedBudget uint64
	rejectedLimit  uint64
	overloadEvents uint64
}

// NewStaticSemaphoreLimiter constructs a fixed-capacity semaphore limiter.
func NewStaticSemaphoreLimiter(cfg StaticConfig) *StaticSemaphoreLimiter {
	layer := cfg.Layer
	if !layer.Valid() {
		layer = LayerAIGateway
	}
	limit := cfg.Limit
	if limit <= 0 {
		limit = 16
	}
	return &StaticSemaphoreLimiter{
		layer:       layer,
		limit:       limit,
		budgetCheck: cfg.BudgetCheck,
	}
}

// Acquire enforces fixed semaphore admission with identical budget_exhausted
// layer attribution for apples-to-apples evaluation.
func (s *StaticSemaphoreLimiter) Acquire(ctx context.Context, tenant string) (ReleaseFunc, *BudgetExhaustedError) {
	if s.budgetCheck != nil && tenant != "" {
		allowed, retryAfter, reason := s.budgetCheck(ctx, tenant)
		if !allowed {
			if reason == "" {
				reason = "tenant pre-execution spend ceiling reached"
			}
			retryMs := retryAfter.Milliseconds()
			if retryMs <= 0 {
				retryMs = 1000
			}
			s.mu.Lock()
			s.rejectedBudget++
			inf := s.inflight
			s.mu.Unlock()
			return nil, &BudgetExhaustedError{
				Code:         "budget_exhausted",
				Layer:        LayerTenantLedger,
				Reason:       reason,
				Tenant:       tenant,
				Limit:        s.limit,
				Inflight:     inf,
				RetryAfterMs: retryMs,
				HTTPStatus:   429,
			}
		}
	}

	s.mu.Lock()
	if s.inflight >= s.limit {
		s.rejectedLimit++
		inf := s.inflight
		s.mu.Unlock()
		return nil, &BudgetExhaustedError{
			Code:         "budget_exhausted",
			Layer:        s.layer,
			Reason:       "static concurrency limit reached",
			Tenant:       tenant,
			Limit:        s.limit,
			Inflight:     inf,
			RetryAfterMs: 50,
			HTTPStatus:   503,
		}
	}
	s.inflight++
	s.admittedTotal++
	s.mu.Unlock()

	var once sync.Once
	return func(_ time.Duration, outcome Outcome) {
		once.Do(func() {
			s.mu.Lock()
			if s.inflight > 0 {
				s.inflight--
			}
			if outcome == OutcomeOverload {
				s.overloadEvents++
			}
			s.mu.Unlock()
		})
	}, nil
}

// Snapshot returns current fixed-semaphore metrics.
func (s *StaticSemaphoreLimiter) Snapshot() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Stats{
		Algorithm:      "static_semaphore",
		Layer:          s.layer,
		Limit:          s.limit,
		FloatingLimit:  float64(s.limit),
		Inflight:       s.inflight,
		LastGradient:   1.0,
		AdmittedTotal:  s.admittedTotal,
		RejectedBudget: s.rejectedBudget,
		RejectedLimit:  s.rejectedLimit,
		OverloadEvents: s.overloadEvents,
	}
}
