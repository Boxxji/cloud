// SPDX-License-Identifier: Apache-2.0 OR MIT

package sovereignty

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	luxlog "github.com/luxfi/log"
	"github.com/zap-proto/zip"
)

func TestFullNetworkExitUnderTotalHanzoBlackout(t *testing.T) {
	domain := DefaultDomain()
	report, fork, err := RunNetworkExitDrill(domain)
	if err != nil {
		t.Fatalf("RunNetworkExitDrill failed: %v", err)
	}
	if !report.AllStagesPassed {
		t.Fatalf("expected all 8 stages to pass, got report=%+v", report)
	}
	if len(report.Stages) != 8 {
		t.Fatalf("expected 8 stages, got %d", len(report.Stages))
	}
	for _, st := range report.Stages {
		if !st.Passed {
			t.Errorf("stage %d (%s) failed: %s", st.Stage, st.Name, st.Detail)
		}
		if st.Stage >= 3 && st.HanzoCallsDuringStep != 0 {
			t.Errorf("stage %d (%s) made %d Hanzo calls after Kill Switch", st.Stage, st.Name, st.HanzoCallsDuringStep)
		}
	}
	if report.GuardMetrics.HanzoCallsBeforeKill == 0 {
		t.Fatalf("expected baseline stage 1 to exercise Hanzo plane before Kill Switch")
	}
	if report.GuardMetrics.HanzoCallsAfterKill != 0 {
		t.Fatalf("INVARIANT VIOLATION: HanzoCallsAfterKill = %d, want 0", report.GuardMetrics.HanzoCallsAfterKill)
	}
	if report.GuardMetrics.CommunityCallsAfterKill == 0 {
		t.Fatalf("expected non-zero Community Plane B HTTP calls after Kill Switch")
	}
	if !report.HanzoBlackoutProbePass {
		t.Fatalf("expected api.hanzo.ai and Hanzo gateway blackout probe to fail closed")
	}
	if !report.UnauthorizedKeyBlocked {
		t.Fatalf("expected unauthorized third-party data key to be rejected")
	}
	if !report.GovernanceRatified {
		t.Fatalf("expected independent community governance proposal to ratify")
	}
	if !report.ForkBundleVerified || fork == nil {
		t.Fatalf("expected portable fork bundle to verify and hydrate Operator C")
	}
	if report.DecentralizationRatio != 1.0 {
		t.Fatalf("expected DecentralizationRatio=1.0, got %.4f", report.DecentralizationRatio)
	}
	if report.SovereigntyRatio != 1.0 {
		t.Fatalf("expected SovereigntyRatio=1.0, got %.4f", report.SovereigntyRatio)
	}
	if report.ConservationDrift != 0 {
		t.Fatalf("expected zero settlement conservation drift, got %d", report.ConservationDrift)
	}
	if err := VerifyForkBundleOffline(domain, *fork); err != nil {
		t.Fatalf("offline fork bundle verification failed: %v", err)
	}
}

func TestCentralizedNegativeControlFailsUnderBlackout(t *testing.T) {
	domain := DefaultDomain()
	regimes, err := RunNegativeAndBoundaryRegimes(domain, 20)
	if err != nil {
		t.Fatalf("RunNegativeAndBoundaryRegimes failed: %v", err)
	}
	if len(regimes) != 3 {
		t.Fatalf("expected 3 regimes, got %d", len(regimes))
	}
	for _, r := range regimes {
		if !r.Validated {
			t.Errorf("regime %s not validated: %+v", r.Name, r)
		}
		if r.CompletionRate != 0.0 {
			t.Errorf("regime %s expected 0.0 completion rate, got %.4f", r.Name, r.CompletionRate)
		}
		if r.FailedClosed != 20 {
			t.Errorf("regime %s expected 20 fail-closed trials, got %d", r.Name, r.FailedClosed)
		}
	}
	coupled := regimes[0]
	if coupled.Name != "centralized_hanzo_coupled_negative" {
		t.Fatalf("unexpected first regime: %s", coupled.Name)
	}
	if coupled.BlockedHanzoCalls != 20 {
		t.Fatalf("expected 20 blocked Hanzo calls on coupled negative control, got %d", coupled.BlockedHanzoCalls)
	}
}

func TestModelIntegrityAndUnauthorizedDataRecoveryRejected(t *testing.T) {
	domain := DefaultDomain()
	guard := NewHostBlocker()
	defer guard.CloseIdleConnections()
	guard.ActivateKillSwitch()
	client := guard.NewHTTPClient(5 * time.Second)

	community, err := NewCommunityControlPlane("community-integrity-test", domain, client, 2)
	if err != nil {
		t.Fatalf("NewCommunityControlPlane: %v", err)
	}
	defer community.Close()

	// 1. Tampered model weight blob MUST fail closed on SHA-256 verification.
	const modelID = "zen-integrity-test-v1"
	blob := DeterministicModelWeights(modelID, 8192)
	digest := SHA256Hex(blob)
	if err := UploadModelBlob(client, community.Mirror.URL(), digest, blob); err != nil {
		t.Fatalf("UploadModelBlob: %v", err)
	}
	community.Mirror.InjectTamperedBlob(digest, true)
	if _, err := DownloadAndVerifyModelBlob(client, community.Mirror.URL(), digest); !errors.Is(err, ErrModelDigestMismatch) {
		t.Fatalf("expected ErrModelDigestMismatch for tampered model blob, got %v", err)
	}
	community.Mirror.InjectTamperedBlob(digest, false)
	verifiedBlob, err := DownloadAndVerifyModelBlob(client, community.Mirror.URL(), digest)
	if err != nil || !bytes.Equal(verifiedBlob, blob) {
		t.Fatalf("expected clean download after clearing tamper toggle, err=%v", err)
	}

	// 2. Tampered inference execution receipt MUST fail offline verification.
	provKP, _ := GenerateKeyPair()
	tenantKP, _ := GenerateKeyPair()
	prov := NewProviderNodeServer("prov-dishonest", provKP, domain, client)
	defer prov.Close()
	if err := prov.FetchAndVerifyModel(community.Mirror.URL(), digest); err != nil {
		t.Fatalf("prov FetchAndVerifyModel: %v", err)
	}
	prov.SetTamperOutput(true)
	req := InferenceRequest{
		JobID:             "job-tamper-check",
		TenantAddress:     tenantKP.Address(),
		ModelID:           modelID,
		ModelDigestSHA256: digest,
		Prompt:            "detect tampered provider execution",
		Seed:              42,
		MaxTokens:         32,
		Nonce:             1,
		Timestamp:         time.Now().UTC().Unix(),
	}
	var badReceipt InferenceExecutionReceipt
	if _, err := doJSONRequest(client, http.MethodPost, prov.URL()+"/v1/infer", req, &badReceipt); err != nil {
		t.Fatalf("prov infer: %v", err)
	}
	if err := VerifyExecutionReceiptOffline(domain, req, verifiedBlob, badReceipt); !errors.Is(err, ErrInvalidReceipt) {
		t.Fatalf("expected ErrInvalidReceipt on tampered output, got %v", err)
	}

	// 3. Payment replay attack MUST be rejected with HTTP 409 / ErrReplayDetected.
	_, _ = doJSONRequest(client, http.MethodPost, community.Facilitator.URL()+"/v1/payments/mint", mintReq{
		Address: tenantKP.Address(),
		Amount:  10_000,
	}, nil)
	pay := PaymentAuthorization{
		PaymentID:    "pay-replay-001",
		JobID:        req.JobID,
		PayeeAddress: provKP.Address(),
		AmountAtomic: 1_000,
		Nonce:        1,
		ValidBefore:  time.Now().UTC().Add(5 * time.Minute).Unix(),
		ChainID:      domain.ChainID,
	}
	if err := SignPaymentAuthorization(domain, tenantKP, &pay); err != nil {
		t.Fatalf("SignPaymentAuthorization: %v", err)
	}
	if _, err := doJSONRequest(client, http.MethodPost, community.Facilitator.URL()+"/v1/payments/settle", pay, nil); err != nil {
		t.Fatalf("first settlement failed: %v", err)
	}
	status, err := doJSONRequest(client, http.MethodPost, community.Facilitator.URL()+"/v1/payments/settle", pay, nil)
	if err == nil || status != http.StatusConflict {
		t.Fatalf("expected HTTP 409 on payment replay, got status=%d err=%v", status, err)
	}

	// 4. Unauthorized key AND tampered ciphertext MUST fail closed on user data recovery.
	userKey, _ := GenerateUserDataKey()
	wrongKey, _ := GenerateUserDataKey()
	env, err := EncryptUserData(domain, tenantKP, userKey, "snap-auth-test", []byte("top-secret-user-state"), []string{community.Vault.URL()}, []string{community.OperatorID}, time.Now().UTC().Unix())
	if err != nil {
		t.Fatalf("EncryptUserData: %v", err)
	}
	if _, err := DecryptUserData(domain, wrongKey, env); !errors.Is(err, ErrUnauthorizedDataAccess) {
		t.Fatalf("expected ErrUnauthorizedDataAccess for wrong key, got %v", err)
	}
	if _, err := DecryptUserData(domain, nil, env); !errors.Is(err, ErrUnauthorizedDataAccess) {
		t.Fatalf("expected ErrUnauthorizedDataAccess for missing key, got %v", err)
	}
	tamperedEnv := env
	tamperedEnv.CiphertextHex = "00" + env.CiphertextHex[2:]
	if _, err := DecryptUserData(domain, userKey, tamperedEnv); !errors.Is(err, ErrUnauthorizedDataAccess) {
		t.Fatalf("expected ErrUnauthorizedDataAccess for tampered ciphertext, got %v", err)
	}
	if guard.Metrics().HanzoCallsAfterKill != 0 {
		t.Fatalf("expected 0 Hanzo calls, got %d", guard.Metrics().HanzoCallsAfterKill)
	}
}

func TestConcurrentMultiTenantBlackoutExitRace(t *testing.T) {
	domain := DefaultDomain()
	guard := NewHostBlocker()
	defer guard.CloseIdleConnections()
	client := guard.NewHTTPClient(15 * time.Second)

	// Bring up Hanzo plane and immediately kill it to enforce total blackout.
	hanzoPlane, err := NewHanzoControlPlane(domain, guard)
	if err != nil {
		t.Fatalf("NewHanzoControlPlane: %v", err)
	}
	KillHanzoControlPlane(hanzoPlane, guard)

	community, err := NewCommunityControlPlane("community-race-op", domain, client, 2)
	if err != nil {
		t.Fatalf("NewCommunityControlPlane: %v", err)
	}
	defer community.Close()

	publisherKP, _ := GenerateKeyPair()
	const modelID = "zen-race-model-v1"
	modelBlob := DeterministicModelWeights(modelID, 8192)
	modelDigest := SHA256Hex(modelBlob)

	if err := UploadModelBlob(client, community.Mirror.URL(), modelDigest, modelBlob); err != nil {
		t.Fatalf("UploadModelBlob: %v", err)
	}
	manifest := ModelManifest{
		ModelID:      modelID,
		Version:      "1.0.0",
		License:      "MIT",
		DigestSHA256: modelDigest,
		SizeBytes:    int64(len(modelBlob)),
		Mirrors:      []string{community.Mirror.URL()},
		IssuedAt:     time.Now().UTC().Unix(),
	}
	if err := SignModelManifest(domain, publisherKP, &manifest); err != nil {
		t.Fatalf("SignModelManifest: %v", err)
	}
	for _, b := range community.BootstrapNodes {
		if _, err := doJSONRequest(client, http.MethodPost, b.URL()+"/v1/models", manifest, nil); err != nil {
			t.Fatalf("register model: %v", err)
		}
	}

	// Spin up 2 post-blackout independent providers.
	providers := make([]*ProviderNodeServer, 2)
	for i := 0; i < 2; i++ {
		kp, _ := GenerateKeyPair()
		p := NewProviderNodeServer(fmt.Sprintf("prov-race-%d", i+1), kp, domain, client)
		defer p.Close()
		if err := p.FetchAndVerifyModel(community.Mirror.URL(), modelDigest); err != nil {
			t.Fatalf("provider %d fetch model: %v", i, err)
		}
		ad, err := p.BuildSignedAdvertisement([]string{modelID}, 250, 2000, time.Now().UTC())
		if err != nil {
			t.Fatalf("BuildSignedAdvertisement: %v", err)
		}
		for _, b := range community.BootstrapNodes {
			if _, err := doJSONRequest(client, http.MethodPost, b.URL()+"/v1/peers/register", ad, nil); err != nil {
				t.Fatalf("register provider: %v", err)
			}
		}
		providers[i] = p
	}

	const numTenants = 8
	var wg sync.WaitGroup
	errCh := make(chan error, numTenants)

	for i := 0; i < numTenants; i++ {
		wg.Add(1)
		go func(tenantIdx int) {
			defer wg.Done()
			tenantKP, err := GenerateKeyPair()
			if err != nil {
				errCh <- fmt.Errorf("tenant %d keygen: %w", tenantIdx, err)
				return
			}
			userKey, err := GenerateUserDataKey()
			if err != nil {
				errCh <- fmt.Errorf("tenant %d data key: %w", tenantIdx, err)
				return
			}
			// Mint balance on community facilitator.
			if _, err := doJSONRequest(client, http.MethodPost, community.Facilitator.URL()+"/v1/payments/mint", mintReq{
				Address: tenantKP.Address(),
				Amount:  100_000,
			}, nil); err != nil {
				errCh <- fmt.Errorf("tenant %d mint: %w", tenantIdx, err)
				return
			}
			// Discover peers & model manifest.
			peers, err := DiscoverPeersFromBootstraps(client, domain, community.BootstrapURLs(), modelID)
			if err != nil || len(peers) < 2 {
				errCh <- fmt.Errorf("tenant %d discover peers: len=%d err=%v", tenantIdx, len(peers), err)
				return
			}
			m, err := DiscoverModelManifest(client, domain, community.BootstrapURLs(), modelID)
			if err != nil {
				errCh <- fmt.Errorf("tenant %d discover model: %w", tenantIdx, err)
				return
			}
			blob, err := DownloadAndVerifyModelBlob(client, m.Mirrors[0], m.DigestSHA256)
			if err != nil {
				errCh <- fmt.Errorf("tenant %d download model: %w", tenantIdx, err)
				return
			}
			// Schedule inference via Community Scheduler B.
			req := InferenceRequest{
				JobID:             fmt.Sprintf("job-tenant-%d", tenantIdx),
				TenantAddress:     tenantKP.Address(),
				ModelID:           modelID,
				ModelDigestSHA256: m.DigestSHA256,
				Prompt:            fmt.Sprintf("concurrent sovereign exit prompt from tenant %d", tenantIdx),
				Seed:              uint64(1000 + tenantIdx),
				MaxTokens:         48,
				Nonce:             uint64(tenantIdx + 1),
				Timestamp:         time.Now().UTC().Unix(),
			}
			var receipt InferenceExecutionReceipt
			if _, err := doJSONRequest(client, http.MethodPost, community.Scheduler.URL()+"/v1/schedule", scheduleDispatchRequest{Request: req}, &receipt); err != nil {
				errCh <- fmt.Errorf("tenant %d schedule: %w", tenantIdx, err)
				return
			}
			if err := VerifyExecutionReceiptOffline(domain, req, blob, receipt); err != nil {
				errCh <- fmt.Errorf("tenant %d verify receipt: %w", tenantIdx, err)
				return
			}
			// Settle payment via Community Facilitator B.
			pay := PaymentAuthorization{
				PaymentID:    fmt.Sprintf("pay-tenant-%d", tenantIdx),
				JobID:        req.JobID,
				PayeeAddress: receipt.ProviderAddress,
				AmountAtomic: 250,
				Nonce:        uint64(tenantIdx + 1),
				ValidBefore:  time.Now().UTC().Add(5 * time.Minute).Unix(),
				ChainID:      domain.ChainID,
			}
			if err := SignPaymentAuthorization(domain, tenantKP, &pay); err != nil {
				errCh <- fmt.Errorf("tenant %d sign payment: %w", tenantIdx, err)
				return
			}
			var settle SettlementReceipt
			if _, err := doJSONRequest(client, http.MethodPost, community.Facilitator.URL()+"/v1/payments/settle", pay, &settle); err != nil {
				errCh <- fmt.Errorf("tenant %d settle: %w", tenantIdx, err)
				return
			}
			if err := VerifySettlementReceipt(domain, settle); err != nil {
				errCh <- fmt.Errorf("tenant %d verify settle: %w", tenantIdx, err)
				return
			}
			// Store & recover user-sovereign encrypted data.
			payload := []byte(fmt.Sprintf(`{"tenant":%d,"state":"sovereign-ok"}`, tenantIdx))
			snapID := fmt.Sprintf("snap-tenant-%d", tenantIdx)
			env, err := EncryptUserData(domain, tenantKP, userKey, snapID, payload, []string{community.Vault.URL()}, []string{community.OperatorID}, time.Now().UTC().Unix())
			if err != nil {
				errCh <- fmt.Errorf("tenant %d encrypt: %w", tenantIdx, err)
				return
			}
			if _, err := doJSONRequest(client, http.MethodPost, community.Vault.URL()+"/v1/vault/snapshots", env, nil); err != nil {
				errCh <- fmt.Errorf("tenant %d store vault: %w", tenantIdx, err)
				return
			}
			var fetched EncryptedDataEnvelope
			if _, err := doJSONRequest(client, http.MethodGet, community.Vault.URL()+"/v1/vault/snapshots/"+snapID, nil, &fetched); err != nil {
				errCh <- fmt.Errorf("tenant %d fetch vault: %w", tenantIdx, err)
				return
			}
			plain, err := DecryptUserData(domain, userKey, fetched)
			if err != nil || !bytes.Equal(plain, payload) {
				errCh <- fmt.Errorf("tenant %d decrypt mismatch: err=%v", tenantIdx, err)
				return
			}
		}(i)
	}
	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent tenant error: %v", err)
	}
	if drift := community.Facilitator.ConservationDrift(); drift != 0 {
		t.Fatalf("expected 0 conservation drift across 8 concurrent tenants, got %d", drift)
	}
	if gm := guard.Metrics(); gm.HanzoCallsAfterKill != 0 {
		t.Fatalf("expected 0 Hanzo calls after kill across 8 concurrent tenants, got %d", gm.HanzoCallsAfterKill)
	}
}

func TestZIPHTTPAndSovereignForkExport(t *testing.T) {
	app := zip.New(zip.Config{Logger: luxlog.New("sovereignty-test")})
	coord := NewCoordinator(DefaultDomain())
	if err := Mount(app, luxlog.New("sovereignty-test"), coord); err != nil {
		t.Fatalf("Mount: %v", err)
	}

	callZip := func(method, path string, body any) (int, []byte) {
		t.Helper()
		var r io.Reader
		if body != nil {
			raw, err := json.Marshal(body)
			if err != nil {
				t.Fatalf("marshal body: %v", err)
			}
			r = bytes.NewReader(raw)
		}
		req := httptest.NewRequest(method, path, r)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := app.Test(req, zip.TestConfig{Timeout: 30 * time.Second, FailOnTimeout: true})
		if err != nil {
			t.Fatalf("app.Test %s %s: %v", method, path, err)
		}
		defer resp.Body.Close()
		out, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, out
	}

	// 1. Health check before drill.
	status, raw := callZip(http.MethodGet, "/v1/sovereignty/health", nil)
	if status != http.StatusOK {
		t.Fatalf("health status=%d body=%s", status, raw)
	}
	var health HealthOut
	if err := json.Unmarshal(raw, &health); err != nil || health.Status != "ok" || health.ProtocolVersion != ProtocolVersion {
		t.Fatalf("unexpected health payload: %+v err=%v", health, err)
	}

	// 2. Latest drill returns 404 before first run.
	status, _ = callZip(http.MethodGet, "/v1/sovereignty/drill/latest", nil)
	if status != http.StatusNotFound {
		t.Fatalf("expected 404 before first drill, got %d", status)
	}

	// 3. Run full 8-stage blackout exit drill over /v1/sovereignty/drill/run.
	status, raw = callZip(http.MethodPost, "/v1/sovereignty/drill/run", nil)
	if status != http.StatusOK {
		t.Fatalf("drill/run status=%d body=%s", status, raw)
	}
	var report NetworkExitReport
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatalf("decode drill report: %v", err)
	}
	if !report.AllStagesPassed || report.GuardMetrics.HanzoCallsAfterKill != 0 {
		t.Fatalf("expected drill pass with 0 post-kill Hanzo calls, got %+v", report)
	}

	// 4. Latest drill now returns 200.
	status, _ = callZip(http.MethodGet, "/v1/sovereignty/drill/latest", nil)
	if status != http.StatusOK {
		t.Fatalf("expected 200 on drill/latest, got %d", status)
	}

	// 5. Run negative & boundary regimes over /v1/sovereignty/regimes/run.
	status, raw = callZip(http.MethodPost, "/v1/sovereignty/regimes/run", RegimesIn{Trials: 10})
	if status != http.StatusOK {
		t.Fatalf("regimes/run status=%d body=%s", status, raw)
	}
	var regOut RegimesOut
	if err := json.Unmarshal(raw, &regOut); err != nil || len(regOut.Regimes) != 3 {
		t.Fatalf("unexpected regimes output: %+v err=%v", regOut, err)
	}
	for _, r := range regOut.Regimes {
		if !r.Validated {
			t.Fatalf("regime %s failed validation via HTTP", r.Name)
		}
	}

	// 6. Export fork bundle & verify valid + tampered fork bundle detection.
	status, raw = callZip(http.MethodGet, "/v1/sovereignty/fork/export", nil)
	if status != http.StatusOK {
		t.Fatalf("fork/export status=%d body=%s", status, raw)
	}
	var fork NetworkForkBundle
	if err := json.Unmarshal(raw, &fork); err != nil {
		t.Fatalf("decode fork bundle: %v", err)
	}
	status, raw = callZip(http.MethodPost, "/v1/sovereignty/fork/verify", fork)
	if status != http.StatusOK {
		t.Fatalf("fork/verify status=%d body=%s", status, raw)
	}
	var verifyOut ForkVerifyOut
	if err := json.Unmarshal(raw, &verifyOut); err != nil || !verifyOut.Valid || verifyOut.ProviderCount == 0 {
		t.Fatalf("unexpected verifyOut: %+v err=%v", verifyOut, err)
	}

	// Tamper with fork bundle and assert fail-closed HTTP 422 rejection.
	tampered := fork
	tampered.OperatorID = "tampered-operator"
	status, _ = callZip(http.MethodPost, "/v1/sovereignty/fork/verify", tampered)
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("expected HTTP 422 on tampered fork bundle, got %d", status)
	}
}
