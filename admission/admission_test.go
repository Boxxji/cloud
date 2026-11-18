// SPDX-License-Identifier: Apache-2.0 OR MIT

package admission

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zap-proto/zip"
)

func TestGradientLimiterContractsUnderOverloadAndRecovers(t *testing.T) {
	lim := NewGradientLimiter(GradientConfig{
		Layer:        LayerAIGateway,
		InitialLimit: 20,
		MinLimit:     4,
		MaxLimit:     48,
		Tolerance:    1.4,
		Smoothing:    0.25,
	})

	ctx := context.Background()

	// Seed baseline no-load RTT around 10ms with >50% pool utilization.
	for round := 0; round < 10; round++ {
		rels := make([]ReleaseFunc, 0, 12)
		for i := 0; i < 12; i++ {
			rel, rej := lim.Acquire(ctx, "org-alpha")
			if rej != nil {
				t.Fatalf("unexpected rejection during warmup: %v", rej)
			}
			rels = append(rels, rel)
		}
		for _, rel := range rels {
			rel(10*time.Millisecond, OutcomeSuccess)
		}
	}

	warmLimit := lim.Snapshot().Limit
	if warmLimit < 20 {
		t.Fatalf("expected steady/growing limit >= 20 under low RTT, got %d", warmLimit)
	}

	// Inject severe queueing delay (80ms vs 10ms baseline) + explicit overload.
	for round := 0; round < 15; round++ {
		curLim := lim.Snapshot().Limit
		rels := make([]ReleaseFunc, 0, curLim)
		for i := 0; i < curLim; i++ {
			rel, rej := lim.Acquire(ctx, "")
			if rej == nil {
				rels = append(rels, rel)
			}
		}
		for idx, rel := range rels {
			if idx%4 == 0 {
				rel(80*time.Millisecond, OutcomeOverload)
			} else {
				rel(80*time.Millisecond, OutcomeSuccess)
			}
		}
	}

	contracted := lim.Snapshot().Limit
	if contracted >= warmLimit {
		t.Fatalf("expected limit contraction under 8x RTT spike: warm=%d contracted=%d", warmLimit, contracted)
	}

	// Recover when RTT returns to 10ms under active utilization.
	for round := 0; round < 25; round++ {
		curLim := lim.Snapshot().Limit
		rels := make([]ReleaseFunc, 0, curLim)
		for i := 0; i < curLim; i++ {
			rel, rej := lim.Acquire(ctx, "")
			if rej == nil {
				rels = append(rels, rel)
			}
		}
		for _, rel := range rels {
			rel(10*time.Millisecond, OutcomeSuccess)
		}
	}

	recovered := lim.Snapshot().Limit
	if recovered <= contracted {
		t.Fatalf("expected post-spike limit recovery: contracted=%d recovered=%d", contracted, recovered)
	}
}

func TestBudgetExhaustedLayerAttributionAndTenantShare(t *testing.T) {
	lim := NewGradientLimiter(GradientConfig{
		Layer:          LayerUpstreamProvider,
		InitialLimit:   6,
		MinLimit:       2,
		MaxLimit:       12,
		MaxTenantShare: 0.5,
		BudgetCheck: func(_ context.Context, tenant string) (bool, time.Duration, string) {
			if tenant == "org-broke" {
				return false, 2500 * time.Millisecond, "monthly token budget exhausted"
			}
			return true, 0, ""
		},
	})

	ctx := context.Background()

	// 1. Pre-execution tenant ledger rejection must report layer=tenant_ledger and HTTP 429.
	_, rej := lim.Acquire(ctx, "org-broke")
	if rej == nil {
		t.Fatalf("expected budget_exhausted rejection for org-broke")
	}
	if rej.Code != "budget_exhausted" || rej.Layer != LayerTenantLedger || rej.HTTPStatus != 429 {
		t.Fatalf("unexpected budget error: %+v", rej)
	}
	if rej.RetryAfterMs != 2500 {
		t.Fatalf("RetryAfterMs = %d, want 2500", rej.RetryAfterMs)
	}

	// 2. Noisy tenant hits MaxTenantShare=0.5 (cap=3 of 6) once pool >=50% utilized,
	// leaving slots open for sibling tenant org-clean.
	var noisyRels []ReleaseFunc
	for i := 0; i < 3; i++ {
		rel, errRej := lim.Acquire(ctx, "org-noisy")
		if errRej != nil {
			t.Fatalf("slot %d for org-noisy rejected early: %v", i, errRej)
		}
		noisyRels = append(noisyRels, rel)
	}

	// 4th concurrent request from org-noisy is throttled by per-tenant share cap.
	_, shareRej := lim.Acquire(ctx, "org-noisy")
	if shareRej == nil || shareRej.HTTPStatus != 429 || shareRej.Layer != LayerUpstreamProvider {
		t.Fatalf("expected 429 tenant share cap on org-noisy, got %+v", shareRej)
	}

	// Sibling tenant org-clean still acquires remaining slots cleanly!
	var cleanRels []ReleaseFunc
	for i := 0; i < 3; i++ {
		rel, errRej := lim.Acquire(ctx, "org-clean")
		if errRej != nil {
			t.Fatalf("sibling org-clean starved at slot %d: %v", i, errRej)
		}
		cleanRels = append(cleanRels, rel)
	}

	// Pool is now 6/6 full -> global limit rejection returns HTTP 503 on configured layer.
	_, fullRej := lim.Acquire(ctx, "org-third")
	if fullRej == nil || fullRej.HTTPStatus != 503 || fullRej.Layer != LayerUpstreamProvider {
		t.Fatalf("expected 503 global limit rejection, got %+v", fullRej)
	}

	for _, r := range noisyRels {
		r(5*time.Millisecond, OutcomeIgnore) // Ignored 4xx must not initialize RTT baseline
	}
	for _, r := range cleanRels {
		r(12*time.Millisecond, OutcomeSuccess)
	}

	snap := lim.Snapshot()
	if snap.Inflight != 0 {
		t.Fatalf("inflight leak: %d", snap.Inflight)
	}
	if snap.RejectedBudget != 1 || snap.RejectedTenant != 1 || snap.RejectedLimit != 1 {
		t.Fatalf("unexpected rejection counters: %+v", snap)
	}
}

func TestZipMiddlewareAndTypedInspectionOp(t *testing.T) {
	app := zip.New(zip.Config{AppName: "admission-test", DisableStartupMessage: true})
	lim := NewGradientLimiter(GradientConfig{
		Layer:          LayerWorker,
		InitialLimit:   1,
		MinLimit:       1,
		MaxLimit:       4,
		MaxTenantShare: 1.0,
	})

	reg := NewRegistry()
	reg.Put("s3_put_object", lim)
	if err := RegisterOps(app, reg); err != nil {
		t.Fatalf("RegisterOps: %v", err)
	}

	entered := make(chan struct{})
	proceed := make(chan struct{})
	app.Group("/v1/work", Middleware(lim)).Post("/run", func(c *zip.Ctx) error {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-proceed
		return c.JSON(200, map[string]any{"ok": true})
	})

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		req := httptest.NewRequest(http.MethodPost, "/v1/work/run", nil)
		req.Header.Set("X-Org-Id", "acme")
		req.Header.Set("X-User-Id", "u@acme")
		res, err := app.Fiber().Test(req)
		if err != nil {
			t.Errorf("first request failed: %v", err)
			return
		}
		_ = res.Body.Close()
	}()

	<-entered

	// Second concurrent request must fail fast with 503 + structured budget_exhausted JSON.
	req2 := httptest.NewRequest(http.MethodPost, "/v1/work/run", nil)
	req2.Header.Set("X-Org-Id", "acme")
	req2.Header.Set("X-User-Id", "u@acme")
	res2, err := app.Fiber().Test(req2)
	if err != nil {
		t.Fatalf("second request transport error: %v", err)
	}
	body2, _ := io.ReadAll(res2.Body)
	_ = res2.Body.Close()

	if res2.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (%s)", res2.StatusCode, string(body2))
	}
	if res2.Header.Get("Retry-After") == "" {
		t.Fatalf("missing Retry-After header")
	}
	var payload BudgetExhaustedError
	if err := json.Unmarshal(body2, &payload); err != nil {
		t.Fatalf("unmarshal 503 JSON: %v", err)
	}
	if payload.Code != "budget_exhausted" || payload.Layer != LayerWorker {
		t.Fatalf("unexpected 503 payload: %+v", payload)
	}

	close(proceed)
	wg.Wait()

	// Inspect live state via typed op GET /v1/gateway/admission?endpoint=s3_put_object.
	snapReq := httptest.NewRequest(http.MethodGet, "/v1/gateway/admission?endpoint=s3_put_object", nil)
	snapRes, err := app.Fiber().Test(snapReq)
	if err != nil {
		t.Fatalf("snapshot op failed: %v", err)
	}
	snapBytes, _ := io.ReadAll(snapRes.Body)
	_ = snapRes.Body.Close()
	if snapRes.StatusCode != http.StatusOK {
		t.Fatalf("snapshot status = %d, body = %s", snapRes.StatusCode, string(snapBytes))
	}
	var out SnapshotOut
	if err := json.Unmarshal(snapBytes, &out); err != nil {
		t.Fatalf("unmarshal snapshot: %v", err)
	}
	if len(out.Endpoints) != 1 || out.Endpoints[0].Stats.AdmittedTotal != 1 || out.Endpoints[0].Stats.RejectedLimit != 1 {
		t.Fatalf("unexpected snapshot output: %+v", out)
	}
}

func TestConcurrentRaceSafety(t *testing.T) {
	lim := NewGradientLimiter(GradientConfig{
		Layer:          LayerAIGateway,
		InitialLimit:   12,
		MinLimit:       4,
		MaxLimit:       32,
		MaxTenantShare: 0.7,
	})

	ctx := context.Background()
	var wg sync.WaitGroup
	var admitted atomic.Int64

	for g := 0; g < 24; g++ {
		wg.Add(1)
		tenant := "tenant-a"
		if g%2 == 1 {
			tenant = "tenant-b"
		}
		go func(tn string) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				rel, rej := lim.Acquire(ctx, tn)
				if rej != nil {
					continue
				}
				admitted.Add(1)
				rel(time.Duration(5+(i%20))*time.Millisecond, OutcomeSuccess)
			}
		}(tenant)
	}
	wg.Wait()

	snap := lim.Snapshot()
	if snap.Inflight != 0 {
		t.Fatalf("expected 0 inflight after all goroutines exit, got %d", snap.Inflight)
	}
	if uint64(admitted.Load()) != snap.AdmittedTotal {
		t.Fatalf("admitted mismatch: atomic=%d snap=%d", admitted.Load(), snap.AdmittedTotal)
	}
}

func TestMatchedBaselineEvaluationBenchmark(t *testing.T) {
	phases := DefaultThreePhaseWorkload()
	const seed = 20261118

	staticOver := RunDiscreteEvaluation(
		"static_semaphore_64",
		NewStaticSemaphoreLimiter(StaticConfig{Layer: LayerAIGateway, Limit: 64}),
		phases,
		seed,
	)
	staticUnder := RunDiscreteEvaluation(
		"static_semaphore_8",
		NewStaticSemaphoreLimiter(StaticConfig{Layer: LayerAIGateway, Limit: 8}),
		phases,
		seed,
	)
	gradient := RunDiscreteEvaluation(
		"gradient2_adaptive",
		NewGradientLimiter(GradientConfig{
			Layer:          LayerAIGateway,
			InitialLimit:   16,
			MinLimit:       4,
			MaxLimit:       64,
			Tolerance:      1.25,
			Smoothing:      0.25,
			MaxTenantShare: 0.55,
		}),
		phases,
		seed,
	)

	t.Logf("EVAL static_64:  %+v", staticOver)
	t.Logf("EVAL static_8:   %+v", staticUnder)
	t.Logf("EVAL gradient2:  %+v", gradient)

	// Falsifiable hypothesis verification:
	// 1. Over-provisioned static_64 suffers severe queueing collapse (high p99, low goodput).
	if gradient.P99LatencyMs >= staticOver.P99LatencyMs {
		t.Fatalf("gradient p99 (%.2fms) did not beat over-provisioned static_64 p99 (%.2fms)", gradient.P99LatencyMs, staticOver.P99LatencyMs)
	}
	if gradient.GoodputCount <= staticOver.GoodputCount {
		t.Fatalf("gradient goodput (%d) did not beat static_64 goodput (%d)", gradient.GoodputCount, staticOver.GoodputCount)
	}
	// 2. Under-provisioned static_8 throttles steady-state recovery capacity; gradient achieves higher total goodput.
	if gradient.GoodputCount <= staticUnder.GoodputCount {
		t.Fatalf("gradient goodput (%d) did not beat under-provisioned static_8 goodput (%d)", gradient.GoodputCount, staticUnder.GoodputCount)
	}
	// 3. Multi-tenant share cap protects normal tenants during flood phase compared to static_64.
	if gradient.NormalTenantGoodOk <= staticOver.NormalTenantGoodOk {
		t.Fatalf("gradient normal-tenant goodput ratio (%.4f) did not beat static_64 (%.4f)", gradient.NormalTenantGoodOk, staticOver.NormalTenantGoodOk)
	}
}
