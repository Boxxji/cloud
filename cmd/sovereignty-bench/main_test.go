// SPDX-License-Identifier: Apache-2.0 OR MIT

package main

import "testing"

func TestBenchmarkSmoke(t *testing.T) {
	rep, err := runBenchmark(10, 2, 5)
	if err != nil {
		t.Fatalf("runBenchmark failed: %v", err)
	}
	if !rep.ZIPE2EPassed {
		t.Fatalf("expected ZIPE2EPassed=true")
	}
	if rep.Trust.Passed != rep.Trust.Total || rep.Trust.DetectionRate != 1.0 {
		t.Fatalf("expected 100%% trust detection, got %d/%d", rep.Trust.Passed, rep.Trust.Total)
	}
	if rep.Decentralization.IndependentShare != 1.0 || rep.Decentralization.HanzoCallsAfterKill != 0 {
		t.Fatalf("expected 100%% decentralization with 0 post-kill Hanzo calls, got share=%.4f calls=%d",
			rep.Decentralization.IndependentShare, rep.Decentralization.HanzoCallsAfterKill)
	}
	if !rep.Sovereignty.ForkBundleVerified || rep.Sovereignty.ConservationDrift != 0 {
		t.Fatalf("expected verified fork bundle and 0 drift, got %+v", rep.Sovereignty)
	}
	if len(rep.NegativeRegimes) != 3 {
		t.Fatalf("expected 3 negative/boundary regimes, got %d", len(rep.NegativeRegimes))
	}
	for _, r := range rep.NegativeRegimes {
		if !r.Validated {
			t.Errorf("negative regime %s failed validation: %+v", r.Name, r)
		}
	}
}
