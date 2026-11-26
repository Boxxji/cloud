// SPDX-License-Identifier: Apache-2.0 OR MIT

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestGatewayBenchmarkAndDossierGeneration(t *testing.T) {
	rep, err := runBenchmark(24, 15, 8)
	if err != nil {
		t.Fatalf("runBenchmark failed: %v", err)
	}
	if rep.Performance.CompletionRate != 1.0 {
		t.Fatalf("expected 100%% sequential completion, got %.4f", rep.Performance.CompletionRate)
	}
	if rep.Performance.FailoverCompletion != 1.0 {
		t.Fatalf("expected 100%% failover completion, got %.4f", rep.Performance.FailoverCompletion)
	}
	if rep.Trust.Passed != rep.Trust.Total || rep.Trust.DetectionRate != 1.0 {
		t.Fatalf("expected 100%% trust detection, got %d/%d", rep.Trust.Passed, rep.Trust.Total)
	}
	if !rep.Decentralization.DualGatewayOpenAIParity || !rep.Decentralization.ZIPDualGatewayParity {
		t.Fatalf("expected dual-gateway OpenAI and zip parity: %+v", rep.Decentralization)
	}
	if rep.Decentralization.IndependentWorkloadShare != 1.0 ||
		rep.Decentralization.HanzoClientCallsAfterKill != 0 ||
		rep.Decentralization.HanzoServerCallsAfterKill != 0 {
		t.Fatalf("expected 100%% kill-switch decentralization with 0 Hanzo calls, got %+v", rep.Decentralization)
	}
	if !rep.Sovereignty.TamperedBundleRejected || rep.Sovereignty.ForkedGatewayCompletion != 1.0 || rep.Sovereignty.ForkedGatewayHanzoCalls != 0 {
		t.Fatalf("sovereignty check failed: %+v", rep.Sovereignty)
	}
	if len(rep.NegativeRegimes) != 3 {
		t.Fatalf("expected 3 negative/boundary regimes, got %d", len(rep.NegativeRegimes))
	}
	for _, nr := range rep.NegativeRegimes {
		if !nr.Validated {
			t.Errorf("negative/boundary regime %s failed validation: %+v", nr.Name, nr)
		}
	}

	dir := t.TempDir()
	raw, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := writeDossier(dir, rep, raw); err != nil {
		t.Fatalf("writeDossier: %v", err)
	}
	for _, name := range []string{"raw_results.json", "score_table.md", "README.md"} {
		st, err := os.Stat(filepath.Join(dir, name))
		if err != nil || st.Size() == 0 {
			t.Fatalf("expected non-empty dossier artifact %s, err=%v", name, err)
		}
	}
}
