package cloud

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/hanzoai/account"
	"github.com/zap-proto/zip"
)

func resetTierCache(t *testing.T) {
	t.Helper()
	tiers.mu.Lock()
	clear(tiers.m)
	tiers.mu.Unlock()
	t.Cleanup(func() {
		tiers.mu.Lock()
		clear(tiers.m)
		tiers.mu.Unlock()
	})
}

func TestAnUnlimitedPayerIsKnownByItsPlanNotItsTier(t *testing.T) {
	resetTierCache(t)
	prev := peersOf()
	t.Cleanup(func() { SetPeers(prev) })

	plans := map[string]string{
		account.Org("rung-unlimited").Subject():  "unlimited",
		account.Org("rung-pro3x").Subject():      "pro-3x",
		account.Org("rung-enterprise").Subject(): "enterprise",
		account.Org("rung-free").Subject():       "free",
	}
	SetPeers(Peers{
		TierOf: func(_ context.Context, subject string) (string, error) {
			if plans[subject] == "free" {
				return "free", nil
			}
			return "pro", nil
		},
		PlanOf: func(_ context.Context, subject string) (string, error) {
			return plans[subject], nil
		},
	})

	ctx := context.Background()
	for org, want := range map[string]bool{
		"rung-unlimited":  true,
		"rung-pro3x":      false,
		"rung-enterprise": false,
		"rung-free":       false,
	} {
		if got := TierAllows(ctx, org, account.Org(org)); got != want {
			t.Errorf("TierAllows(%s) = %v, want %v", org, got, want)
		}
	}
	if tier, err := Tier(ctx, account.Org("rung-unlimited").Subject(), "rung-unlimited"); err != nil || tier != "pro" {
		t.Fatalf("the Unlimited payer's tier = %q, %v; want pro", tier, err)
	}
}

func TestTierAndPlanNormalizeCompositeOrg(t *testing.T) {
	resetTierCache(t)
	prev := peersOf()
	t.Cleanup(func() { SetPeers(prev) })

	var tierAsks, planAsks atomic.Int64
	SetPeers(Peers{
		TierOf: func(ctx context.Context, subject string) (string, error) {
			tierAsks.Add(1)
			if got := zip.CallerOf(ctx).Org; got != "hanzo" {
				return "free", nil
			}
			return "pro", nil
		},
		PlanOf: func(ctx context.Context, subject string) (string, error) {
			planAsks.Add(1)
			if got := zip.CallerOf(ctx).Org; got != "hanzo" {
				return "free", nil
			}
			return "unlimited", nil
		},
	})

	ctx := context.Background()
	if got, err := Tier(ctx, "hanzo/composite-u", "hanzo/composite-u"); err != nil || got != "pro" {
		t.Fatalf("Tier(hanzo/composite-u, hanzo/composite-u) = %q, %v; want pro", got, err)
	}
	// Plain org call hits the same cache entry.
	if got, err := Tier(ctx, "hanzo/composite-u", "hanzo"); err != nil || got != "pro" {
		t.Fatalf("Tier(hanzo/composite-u, hanzo) = %q, %v; want pro", got, err)
	}
	if n := tierAsks.Load(); n != 1 {
		t.Fatalf("TierOf asked %d times for normalized pair, want 1", n)
	}
	if got, err := Plan(ctx, "hanzo/composite-u", "hanzo/composite-u"); err != nil || got != "unlimited" {
		t.Fatalf("Plan(hanzo/composite-u, hanzo/composite-u) = %q, %v; want unlimited", got, err)
	}
	if got, err := Plan(ctx, "hanzo/composite-u", "hanzo"); err != nil || got != "unlimited" {
		t.Fatalf("Plan(hanzo/composite-u, hanzo) = %q, %v; want unlimited", got, err)
	}
	if n := planAsks.Load(); n != 1 {
		t.Fatalf("PlanOf asked %d times for normalized pair, want 1", n)
	}
}
