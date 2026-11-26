// SPDX-License-Identifier: Apache-2.0 OR MIT

package gateway

import (
	"bytes"
	"context"
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

type testTopology struct {
	domain        EIP712Domain
	hanzoDir      *DirectoryPeerServer
	communityDirA *DirectoryPeerServer
	communityDirB *DirectoryPeerServer
	workers       []*WorkerNode
	hanzoGW       *Gateway
	communityGW   *Gateway
	hanzoSrv      *httptest.Server
	communitySrv  *httptest.Server
}

func (top *testTopology) close() {
	if top.hanzoSrv != nil {
		top.hanzoSrv.Close()
	}
	if top.communitySrv != nil {
		top.communitySrv.Close()
	}
	for _, w := range top.workers {
		w.Close()
	}
	if top.hanzoDir != nil {
		top.hanzoDir.Close()
	}
	if top.communityDirA != nil {
		top.communityDirA.Close()
	}
	if top.communityDirB != nil {
		top.communityDirB.Close()
	}
}

func setupDualGatewayTopology(t *testing.T) *testTopology {
	t.Helper()
	domain := DefaultDomain()
	models := []ModelSpec{
		{
			ModelID:          "zen-7b-instruct",
			ModelDigest:      "sha256:" + SHA256Hex([]byte("zen-7b-instruct-open-weights-v1")),
			MaxContextTokens: 32768,
			License:          "Apache-2.0",
		},
		{
			ModelID:          "zen-32b-coder",
			ModelDigest:      "sha256:" + SHA256Hex([]byte("zen-32b-coder-open-weights-v1")),
			MaxContextTokens: 65536,
			License:          "Apache-2.0",
		},
	}

	hanzoDirKP, err := KeyPairFromSeed([]byte("test-hanzo-dir-peer"))
	if err != nil {
		t.Fatal(err)
	}
	commDirAKP, err := KeyPairFromSeed([]byte("test-comm-dir-peer-a"))
	if err != nil {
		t.Fatal(err)
	}
	commDirBKP, err := KeyPairFromSeed([]byte("test-comm-dir-peer-b"))
	if err != nil {
		t.Fatal(err)
	}

	hanzoDir, err := NewDirectoryPeerServer("dir-hanzo-convenience", "Hanzo Convenience Directory", domain, hanzoDirKP)
	if err != nil {
		t.Fatal(err)
	}
	commDirA, err := NewDirectoryPeerServer("dir-community-alpha", "Community Peer Alpha", domain, commDirAKP)
	if err != nil {
		t.Fatal(err)
	}
	commDirB, err := NewDirectoryPeerServer("dir-community-beta", "Community Peer Beta", domain, commDirBKP)
	if err != nil {
		t.Fatal(err)
	}

	workerSpecs := []struct {
		id     string
		region string
		price  uint64
		ttft   int64
	}{
		{"worker-alpha-lowcost", "us-east", 280_000, 35},
		{"worker-beta-lowttft", "eu-west", 440_000, 12},
		{"worker-gamma-balanced", "ap-northeast", 340_000, 18},
	}

	workers := make([]*WorkerNode, 0, len(workerSpecs))
	for _, spec := range workerSpecs {
		kp, err := KeyPairFromSeed([]byte("test-worker-" + spec.id))
		if err != nil {
			t.Fatal(err)
		}
		w, err := NewWorkerNode(WorkerConfig{
			ProviderID:         spec.id,
			Region:             spec.region,
			Models:             models,
			PriceMicroUSDPer1M: spec.price,
			AdvertisedTTFTMs:   spec.ttft,
			Domain:             domain,
			KeyPair:            kp,
		})
		if err != nil {
			t.Fatal(err)
		}
		workers = append(workers, w)
		rec, err := w.SignedRecord(time.Now().Unix(), 3600)
		if err != nil {
			t.Fatal(err)
		}
		// Workers publish directly to community peer A (not Hanzo-locked).
		if err := commDirA.RegisterWorker(rec); err != nil {
			t.Fatal(err)
		}
	}

	// Open gossip propagates worker records to Community Peer B and Hanzo Directory.
	ctx := context.Background()
	if err := commDirA.GossipToPeer(ctx, commDirB.URL(), nil); err != nil {
		t.Fatalf("gossip A->B: %v", err)
	}
	if err := commDirB.GossipToPeer(ctx, hanzoDir.URL(), nil); err != nil {
		t.Fatalf("gossip B->Hanzo: %v", err)
	}

	hanzoGWKP, err := KeyPairFromSeed([]byte("test-hanzo-gateway"))
	if err != nil {
		t.Fatal(err)
	}
	commGWKP, err := KeyPairFromSeed([]byte("test-community-gateway"))
	if err != nil {
		t.Fatal(err)
	}

	hanzoGW, err := NewGateway(GatewayConfig{
		GatewayID:       "hanzo-enso-gateway-1",
		OperatorName:    "Hanzo Convenience Gateway",
		OperatorType:    OperatorTypeHanzo,
		Strategy:        StrategyWeightedSLOScore,
		GatewayFeeBps:   25,
		Domain:          domain,
		KeyPair:         hanzoGWKP,
		DirectoryURLs:   []string{hanzoDir.URL(), commDirA.URL()},
		ProviderTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	commGW, err := NewGateway(GatewayConfig{
		GatewayID:       "community-enso-gateway-1",
		OperatorName:    "Independent Community Gateway",
		OperatorType:    OperatorTypeCommunity,
		Strategy:        StrategyWeightedSLOScore,
		GatewayFeeBps:   10,
		Domain:          domain,
		KeyPair:         commGWKP,
		DirectoryURLs:   []string{commDirA.URL(), commDirB.URL()},
		ProviderTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := hanzoGW.SyncDirectory(ctx); err != nil {
		t.Fatalf("sync hanzo gateway: %v", err)
	}
	if _, err := commGW.SyncDirectory(ctx); err != nil {
		t.Fatalf("sync community gateway: %v", err)
	}

	top := &testTopology{
		domain:        domain,
		hanzoDir:      hanzoDir,
		communityDirA: commDirA,
		communityDirB: commDirB,
		workers:       workers,
		hanzoGW:       hanzoGW,
		communityGW:   commGW,
		hanzoSrv:      StartLoopbackServer(hanzoGW),
		communitySrv:  StartLoopbackServer(commGW),
	}
	t.Cleanup(top.close)
	return top
}

func TestProtocolQuoteAndReceiptCrypto(t *testing.T) {
	domain := DefaultDomain()
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	req := ChatCompletionRequest{
		Model:     "zen-7b-instruct",
		Messages:  []ChatMessage{{Role: "user", Content: "Verify EIP-712 quote and receipt"}},
		MaxTokens: 64,
	}
	reqHash := CanonicalRequestHash(req)
	quote := InferenceQuote{
		QuoteID:            "qt-crypto-001",
		ProtocolVersion:    ProtocolVersion,
		ProviderID:         "worker-crypto",
		ModelID:            "zen-7b-instruct",
		ModelDigest:        "sha256:" + SHA256Hex([]byte("weights")),
		PriceMicroUSDPer1M: 320_000,
		MaxTTFTMs:          15,
		MaxTokens:          64,
		IssuedAt:           now,
		ExpiresAt:          now + 60,
		Nonce:              "nonce-crypto-001",
		RequestHash:        reqHash,
	}
	if err := SignQuote(domain, kp, &quote); err != nil {
		t.Fatalf("SignQuote: %v", err)
	}
	if err := VerifyQuote(domain, quote, now); err != nil {
		t.Fatalf("VerifyQuote valid quote failed: %v", err)
	}

	// Verify EIP-2 high-S malleated quote is rejected fail-closed.
	highSQuote := quote
	highSQuote.Signature, err = MalleateSignatureHighS(quote.Signature)
	if err != nil {
		t.Fatalf("MalleateSignatureHighS: %v", err)
	}
	if err := VerifyQuote(domain, highSQuote, now); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature for high-S quote, got %v", err)
	}

	// Sign and verify ExecutionReceipt offline.
	qh, err := QuoteHash(domain, quote)
	if err != nil {
		t.Fatal(err)
	}
	content := "deterministic verifiable inference output"
	rcpt := ExecutionReceipt{
		ReceiptID:         "rcpt-crypto-001",
		ProtocolVersion:   ProtocolVersion,
		VerificationClass: ReceiptVerificationClass,
		GatewayID:         "community-gw",
		GatewayOperator:   "Community Operator",
		ProviderID:        quote.ProviderID,
		ModelID:           quote.ModelID,
		ModelDigest:       quote.ModelDigest,
		QuoteID:           quote.QuoteID,
		QuoteHash:         qh,
		QuoteNonce:        quote.Nonce,
		RequestHash:       reqHash,
		OutputHash:        ComputeOutputHash(content),
		PromptTokens:      12,
		CompletionTokens:  24,
		TotalTokens:       36,
		TTFTMs:            11.5,
		TotalLatencyMs:    18.2,
		CompletedAt:       now,
	}
	if err := SignReceipt(domain, kp, &rcpt); err != nil {
		t.Fatalf("SignReceipt: %v", err)
	}
	if err := VerifyReceipt(domain, rcpt, &quote, reqHash, content); err != nil {
		t.Fatalf("VerifyReceipt valid receipt failed: %v", err)
	}
	if err := VerifyReceipt(domain, rcpt, &quote, reqHash, content+" tampered"); !errors.Is(err, ErrOutputHashMismatch) {
		t.Fatalf("expected ErrOutputHashMismatch on modified content, got %v", err)
	}
}

func TestTwoIndependentGatewaysIdenticalOpenAIRequests(t *testing.T) {
	top := setupDualGatewayTopology(t)
	ctx := context.Background()

	req := ChatCompletionRequest{
		Model:     "zen-7b-instruct",
		Messages:  []ChatMessage{{Role: "user", Content: "Compare Hanzo and Community Enso gateways"}},
		MaxTokens: 48,
	}
	reqHash := CanonicalRequestHash(req)

	// 1. Live TCP loopback HTTP via HanzoGateway and CommunityGateway.
	hanzoClient := NewMultiGatewayClient(top.domain, []GatewayEndpoint{
		{GatewayID: top.hanzoGW.GatewayID(), OperatorType: OperatorTypeHanzo, BaseURL: top.hanzoSrv.URL, Enabled: true},
	}, nil)
	commClient := NewMultiGatewayClient(top.domain, []GatewayEndpoint{
		{GatewayID: top.communityGW.GatewayID(), OperatorType: OperatorTypeCommunity, BaseURL: top.communitySrv.URL, Enabled: true},
	}, nil)

	hanzoModels, err := hanzoClient.ListModels(ctx)
	if err != nil {
		t.Fatalf("Hanzo /v1/models: %v", err)
	}
	commModels, err := commClient.ListModels(ctx)
	if err != nil {
		t.Fatalf("Community /v1/models: %v", err)
	}
	if len(hanzoModels.Data) != 2 || len(commModels.Data) != 2 {
		t.Fatalf("expected identical 2 models on both gateways, got hanzo=%d comm=%d", len(hanzoModels.Data), len(commModels.Data))
	}

	hanzoResp, err := hanzoClient.ChatCompletions(ctx, req)
	if err != nil {
		t.Fatalf("Hanzo /v1/chat/completions: %v", err)
	}
	commResp, err := commClient.ChatCompletions(ctx, req)
	if err != nil {
		t.Fatalf("Community /v1/chat/completions: %v", err)
	}

	if hanzoResp.Object != "chat.completion" || commResp.Object != "chat.completion" {
		t.Fatalf("unexpected OpenAI object type: hanzo=%q comm=%q", hanzoResp.Object, commResp.Object)
	}
	if hanzoResp.Choices[0].Message.Content != commResp.Choices[0].Message.Content {
		t.Fatalf("expected identical OpenAI completion content across independent gateways:\nhanzo=%q\ncomm =%q",
			hanzoResp.Choices[0].Message.Content, commResp.Choices[0].Message.Content)
	}
	if err := VerifyReceipt(top.domain, *hanzoResp.EnsoReceipt, hanzoResp.EnsoQuote, reqHash, hanzoResp.Choices[0].Message.Content); err != nil {
		t.Fatalf("Hanzo receipt offline verify failed: %v", err)
	}
	if err := VerifyReceipt(top.domain, *commResp.EnsoReceipt, commResp.EnsoQuote, reqHash, commResp.Choices[0].Message.Content); err != nil {
		t.Fatalf("Community receipt offline verify failed: %v", err)
	}
	if hanzoResp.EnsoRoute.GatewayID == commResp.EnsoRoute.GatewayID {
		t.Fatalf("expected two distinct gateway IDs, both were %q", hanzoResp.EnsoRoute.GatewayID)
	}
	// Community gateway competes on lower routing fee (10 bps vs 25 bps).
	if commResp.EnsoRoute.EffectivePriceMicroUSDPer1M >= hanzoResp.EnsoRoute.EffectivePriceMicroUSDPer1M {
		t.Fatalf("expected community gateway fee competition to yield lower effective price: comm=%d hanzo=%d",
			commResp.EnsoRoute.EffectivePriceMicroUSDPer1M, hanzoResp.EnsoRoute.EffectivePriceMicroUSDPer1M)
	}
}

func TestKillSwitchHanzoDisabledAcceptance(t *testing.T) {
	top := setupDualGatewayTopology(t)
	ctx := context.Background()

	client := NewMultiGatewayClient(top.domain, []GatewayEndpoint{
		{GatewayID: top.hanzoGW.GatewayID(), OperatorType: OperatorTypeHanzo, BaseURL: top.hanzoSrv.URL, Enabled: true},
		{GatewayID: top.communityGW.GatewayID(), OperatorType: OperatorTypeCommunity, BaseURL: top.communitySrv.URL, Enabled: true},
	}, nil)

	// Engage full Hanzo Kill Switch: disable AND close Hanzo gateway + Hanzo directory,
	// and disable all Hanzo endpoints in the client routing table.
	top.hanzoGW.Disable()
	top.hanzoSrv.Close()
	top.hanzoDir.Disable()
	top.hanzoDir.Close()
	top.hanzoGW.ResetCounters()
	client.DisableOperatorType(OperatorTypeHanzo)
	client.ResetCounters()

	const totalRequests = 25
	completed := 0
	for i := 0; i < totalRequests; i++ {
		req := ChatCompletionRequest{
			Model:     "zen-7b-instruct",
			Messages:  []ChatMessage{{Role: "user", Content: fmt.Sprintf("post-killswitch request %d", i)}},
			MaxTokens: 32,
		}
		resp, err := client.ChatCompletions(ctx, req)
		if err != nil {
			t.Fatalf("request %d failed with Hanzo disabled: %v", i, err)
		}
		if resp.EnsoRoute.OperatorType != OperatorTypeCommunity {
			t.Fatalf("expected community operator, got %q", resp.EnsoRoute.OperatorType)
		}
		if err := VerifyReceipt(top.domain, *resp.EnsoReceipt, resp.EnsoQuote, CanonicalRequestHash(req), resp.Choices[0].Message.Content); err != nil {
			t.Fatalf("offline receipt verification failed on request %d: %v", i, err)
		}
		completed++
	}

	if completed != totalRequests {
		t.Fatalf("expected 100%% completion (%d/%d), got %d", totalRequests, totalRequests, completed)
	}
	if client.HanzoCalls() != 0 {
		t.Fatalf("expected client HanzoGatewayCalls == 0, got %d", client.HanzoCalls())
	}
	if top.hanzoGW.Calls() != 0 {
		t.Fatalf("expected server HanzoGateway.Calls() == 0, got %d", top.hanzoGW.Calls())
	}
	if client.CommunityCalls() != totalRequests {
		t.Fatalf("expected %d community gateway calls, got %d", totalRequests, client.CommunityCalls())
	}
}

func TestSchedulerStrategiesAndProviderFailover(t *testing.T) {
	top := setupDualGatewayTopology(t)
	ctx := context.Background()

	// 1. lowest_cost picks worker-alpha-lowcost (280k microUSD/1M).
	respCost, err := top.communityGW.ChatCompletions(ctx, ChatCompletionRequest{
		Model:     "zen-7b-instruct",
		Messages:  []ChatMessage{{Role: "user", Content: "strategy lowest cost"}},
		MaxTokens: 32,
		Strategy:  string(StrategyLowestCost),
	})
	if err != nil {
		t.Fatalf("lowest_cost failed: %v", err)
	}
	if respCost.EnsoRoute.ProviderID != "worker-alpha-lowcost" {
		t.Fatalf("lowest_cost chose %q, want worker-alpha-lowcost", respCost.EnsoRoute.ProviderID)
	}

	// 2. lowest_ttft picks worker-beta-lowttft (12ms TTFT).
	respTTFT, err := top.communityGW.ChatCompletions(ctx, ChatCompletionRequest{
		Model:     "zen-7b-instruct",
		Messages:  []ChatMessage{{Role: "user", Content: "strategy lowest ttft"}},
		MaxTokens: 32,
		Strategy:  string(StrategyLowestTTFT),
	})
	if err != nil {
		t.Fatalf("lowest_ttft failed: %v", err)
	}
	if respTTFT.EnsoRoute.ProviderID != "worker-beta-lowttft" {
		t.Fatalf("lowest_ttft chose %q, want worker-beta-lowttft", respTTFT.EnsoRoute.ProviderID)
	}

	// 3. Mid-flight HTTP 500 crash on primary cheapest worker -> automatic failover to peer.
	top.workers[0].SetFaultMode(FaultCrash500)
	respCrashFailover, err := top.communityGW.ChatCompletions(ctx, ChatCompletionRequest{
		Model:     "zen-7b-instruct",
		Messages:  []ChatMessage{{Role: "user", Content: "midflight crash failover"}},
		MaxTokens: 32,
		Strategy:  string(StrategyLowestCost),
	})
	if err != nil {
		t.Fatalf("crash failover failed: %v", err)
	}
	if !respCrashFailover.EnsoRoute.FailoverOccurred || respCrashFailover.EnsoRoute.ProviderID == "worker-alpha-lowcost" {
		t.Fatalf("expected failover away from crashed worker-alpha-lowcost, got route=%+v", respCrashFailover.EnsoRoute)
	}

	// 4. Mid-flight timeout on primary lowest-TTFT worker -> automatic failover to peer.
	top.workers[1].SetFaultMode(FaultTimeout)
	top.workers[1].SetTimeoutDelay(400 * time.Millisecond)

	shortTimeoutGW, err := NewGateway(GatewayConfig{
		GatewayID:       "gw-timeout-failover",
		OperatorName:    "Timeout Failover Tester",
		OperatorType:    OperatorTypeCommunity,
		Strategy:        StrategyLowestTTFT,
		Domain:          top.domain,
		DirectoryURLs:   []string{top.communityDirA.URL()},
		ProviderTimeout: 80 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := shortTimeoutGW.SyncDirectory(ctx); err != nil {
		t.Fatal(err)
	}
	respTimeoutFailover, err := shortTimeoutGW.ChatCompletions(ctx, ChatCompletionRequest{
		Model:     "zen-7b-instruct",
		Messages:  []ChatMessage{{Role: "user", Content: "timeout failover"}},
		MaxTokens: 32,
		Strategy:  string(StrategyFailoverResilient),
	})
	if err != nil {
		t.Fatalf("timeout failover failed: %v", err)
	}
	if respTimeoutFailover.EnsoRoute.ProviderID != "worker-gamma-balanced" {
		t.Fatalf("expected failover to healthy worker-gamma-balanced, got %q", respTimeoutFailover.EnsoRoute.ProviderID)
	}
}

func TestAdversarialFailClosedSuite(t *testing.T) {
	domain := DefaultDomain()
	ctx := context.Background()

	newSingleWorkerGW := func(t *testing.T, id string, mode FaultMode) (*WorkerNode, *Gateway) {
		t.Helper()
		kp, err := KeyPairFromSeed([]byte("adv-" + id))
		if err != nil {
			t.Fatal(err)
		}
		w, err := NewWorkerNode(WorkerConfig{
			ProviderID:         id,
			Region:             "eu-central",
			Models:             defaultTestModels(),
			PriceMicroUSDPer1M: 300_000,
			AdvertisedTTFTMs:   10,
			Domain:             domain,
			KeyPair:            kp,
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(w.Close)
		w.SetFaultMode(mode)
		rec, err := w.SignedRecord(time.Now().Unix(), 3600)
		if err != nil {
			t.Fatal(err)
		}
		gw, err := NewGateway(GatewayConfig{
			GatewayID:       "gw-adv-" + id,
			OperatorName:    "Adversarial Verifier",
			OperatorType:    OperatorTypeCommunity,
			Strategy:        StrategyLowestCost,
			Domain:          domain,
			StaticWorkers:   []WorkerRecord{rec},
			FailoverEnabled: BoolPtr(false),
			VerifyReceipts:  BoolPtr(true),
		})
		if err != nil {
			t.Fatal(err)
		}
		return w, gw
	}

	req := ChatCompletionRequest{
		Model:     "zen-7b-instruct",
		Messages:  []ChatMessage{{Role: "user", Content: "adversarial security probe"}},
		MaxTokens: 32,
	}

	t.Run("forged_quote_signature_rejected", func(t *testing.T) {
		_, gw := newSingleWorkerGW(t, "forged-quote", FaultForgedQuoteSig)
		_, err := gw.ChatCompletions(ctx, req)
		if !errors.Is(err, ErrInvalidSignature) && !errors.Is(err, ErrSignerMismatch) {
			t.Fatalf("expected forged quote signature error, got %v", err)
		}
	})

	t.Run("high_s_malleated_quote_rejected", func(t *testing.T) {
		_, gw := newSingleWorkerGW(t, "high-s-quote", FaultHighSSignature)
		_, err := gw.ChatCompletions(ctx, req)
		if !errors.Is(err, ErrInvalidSignature) {
			t.Fatalf("expected ErrInvalidSignature for high-S quote, got %v", err)
		}
	})

	t.Run("expired_quote_rejected", func(t *testing.T) {
		_, gw := newSingleWorkerGW(t, "expired-quote", FaultExpiredQuote)
		_, err := gw.ChatCompletions(ctx, req)
		if !errors.Is(err, ErrQuoteExpired) {
			t.Fatalf("expected ErrQuoteExpired, got %v", err)
		}
	})

	t.Run("mismatched_output_hash_receipt_rejected", func(t *testing.T) {
		_, gw := newSingleWorkerGW(t, "mismatched-hash", FaultMismatchedReceiptHash)
		_, err := gw.ChatCompletions(ctx, req)
		if !errors.Is(err, ErrOutputHashMismatch) {
			t.Fatalf("expected ErrOutputHashMismatch, got %v", err)
		}
	})

	t.Run("corrupted_output_content_rejected", func(t *testing.T) {
		_, gw := newSingleWorkerGW(t, "corrupt-output", FaultCorruptOutput)
		_, err := gw.ChatCompletions(ctx, req)
		if !errors.Is(err, ErrOutputHashMismatch) {
			t.Fatalf("expected ErrOutputHashMismatch, got %v", err)
		}
	})

	t.Run("replay_nonce_rejected", func(t *testing.T) {
		_, gw := newSingleWorkerGW(t, "replay-nonce", FaultReplayNonce)
		if _, err := gw.ChatCompletions(ctx, req); err != nil {
			t.Fatalf("first execution with static nonce should succeed, got %v", err)
		}
		if _, err := gw.ChatCompletions(ctx, req); !errors.Is(err, ErrReplayNonce) {
			t.Fatalf("expected ErrReplayNonce on second execution with reused nonce, got %v", err)
		}
	})

	t.Run("tampered_worker_record_rejected", func(t *testing.T) {
		w, _ := newSingleWorkerGW(t, "tampered-record", FaultNone)
		rec, err := w.SignedRecord(time.Now().Unix(), 3600)
		if err != nil {
			t.Fatal(err)
		}
		rec.PriceMicroUSDPer1M = 1 // tamper price after signing
		dir := NewPeerDirectory(domain)
		if err := dir.RegisterWorker(rec, time.Now().Unix()); err == nil {
			t.Fatalf("expected tampered worker record to be rejected")
		}
	})
}

func TestConcurrent16ClientsRaceStress(t *testing.T) {
	top := setupDualGatewayTopology(t)
	const clients = 16
	const reqsPerClient = 6

	strategies := []Strategy{
		StrategyLowestCost,
		StrategyLowestTTFT,
		StrategyWeightedSLOScore,
		StrategyFailoverResilient,
	}

	var wg sync.WaitGroup
	errCh := make(chan error, clients*reqsPerClient)

	for c := 0; c < clients; c++ {
		wg.Add(1)
		go func(clientID int) {
			defer wg.Done()
			ctx := context.Background()
			ep := GatewayEndpoint{
				GatewayID:    top.communityGW.GatewayID(),
				OperatorType: OperatorTypeCommunity,
				BaseURL:      top.communitySrv.URL,
				Enabled:      true,
			}
			if clientID%2 == 0 {
				ep = GatewayEndpoint{
					GatewayID:    top.hanzoGW.GatewayID(),
					OperatorType: OperatorTypeHanzo,
					BaseURL:      top.hanzoSrv.URL,
					Enabled:      true,
				}
			}
			cli := NewMultiGatewayClient(top.domain, []GatewayEndpoint{ep}, nil)
			for r := 0; r < reqsPerClient; r++ {
				req := ChatCompletionRequest{
					Model:     "zen-7b-instruct",
					Messages:  []ChatMessage{{Role: "user", Content: fmt.Sprintf("client-%d-req-%d", clientID, r)}},
					MaxTokens: 32,
					Strategy:  string(strategies[(clientID+r)%len(strategies)]),
				}
				resp, err := cli.ChatCompletions(ctx, req)
				if err != nil {
					errCh <- fmt.Errorf("client %d req %d: %w", clientID, r, err)
					return
				}
				if err := VerifyReceipt(top.domain, *resp.EnsoReceipt, resp.EnsoQuote, CanonicalRequestHash(req), resp.Choices[0].Message.Content); err != nil {
					errCh <- fmt.Errorf("client %d req %d receipt verify: %w", clientID, r, err)
					return
				}
			}
		}(c)
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}
}

func TestSovereigntyConfigDirectoryExportAndFork(t *testing.T) {
	top := setupDualGatewayTopology(t)
	ctx := context.Background()

	// Export stateless config + verified worker directory from CommunityGateway.
	bundle, err := top.communityGW.ExportBundle()
	if err != nil {
		t.Fatalf("ExportBundle: %v", err)
	}
	if err := VerifyExportBundle(top.domain, *bundle, time.Now().Unix()); err != nil {
		t.Fatalf("VerifyExportBundle: %v", err)
	}

	// Tampered bundle must fail verification fail-closed.
	tampered := *bundle
	tampered.Config.GatewayFeeBps = 9999
	if err := VerifyExportBundle(top.domain, tampered, time.Now().Unix()); !errors.Is(err, ErrDirectoryCorrupted) {
		t.Fatalf("expected ErrDirectoryCorrupted for tampered bundle, got %v", err)
	}

	// Shut down ALL Hanzo infrastructure before booting forked third-party gateway.
	top.hanzoGW.Disable()
	top.hanzoSrv.Close()
	top.hanzoDir.Disable()
	top.hanzoDir.Close()
	top.hanzoGW.ResetCounters()

	forkKP, err := KeyPairFromSeed([]byte("operator-c-forked-gateway"))
	if err != nil {
		t.Fatal(err)
	}
	forkGW, err := NewGatewayFromBundle(*bundle, "operator-c-fork-gw", "Operator C Fork", OperatorTypeCommunity, 0, forkKP, nil)
	if err != nil {
		t.Fatalf("NewGatewayFromBundle: %v", err)
	}
	forkSrv := StartLoopbackServer(forkGW)
	defer forkSrv.Close()

	forkClient := NewMultiGatewayClient(top.domain, []GatewayEndpoint{
		{GatewayID: forkGW.GatewayID(), OperatorType: OperatorTypeCommunity, BaseURL: forkSrv.URL, Enabled: true},
	}, nil)

	req := ChatCompletionRequest{
		Model:     "zen-32b-coder",
		Messages:  []ChatMessage{{Role: "user", Content: "forked gateway inference test"}},
		MaxTokens: 32,
	}
	resp, err := forkClient.ChatCompletions(ctx, req)
	if err != nil {
		t.Fatalf("forked gateway ChatCompletions failed: %v", err)
	}
	if resp.EnsoRoute.GatewayID != "operator-c-fork-gw" || resp.EnsoRoute.GatewayFeeBps != 0 {
		t.Fatalf("unexpected forked gateway route: %+v", resp.EnsoRoute)
	}
	if top.hanzoGW.Calls() != 0 {
		t.Fatalf("expected 0 Hanzo calls during forked gateway execution, got %d", top.hanzoGW.Calls())
	}
}

func TestThreeNegativeAndBoundaryRegimes(t *testing.T) {
	res, err := RunNegativeAndBoundaryRegimes(DefaultDomain(), 20)
	if err != nil {
		t.Fatalf("RunNegativeAndBoundaryRegimes: %v", err)
	}
	if len(res) != 3 {
		t.Fatalf("expected 3 regimes, got %d", len(res))
	}
	wantNames := []string{
		"unverified_receipt_negative",
		"single_provider_no_failover_negative",
		"stale_quote_storm_boundary",
	}
	for i, r := range res {
		if r.Name != wantNames[i] {
			t.Errorf("regime[%d].Name = %q, want %q", i, r.Name, wantNames[i])
		}
		if !r.Validated {
			t.Errorf("regime %s failed validation: %+v", r.Name, r)
		}
	}
}

func TestZIPAppSurfaceEndToEnd(t *testing.T) {
	top := setupDualGatewayTopology(t)
	app := zip.New(zip.Config{})
	if err := Mount(app, luxlog.New("gateway-test"), top.communityGW); err != nil {
		t.Fatalf("Mount: %v", err)
	}

	callZIP := func(method, path string, body any) (*http.Response, []byte) {
		t.Helper()
		var r io.Reader
		if body != nil {
			b, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			r = bytes.NewReader(b)
		}
		req := httptest.NewRequest(method, path, r)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := app.Test(req, zip.TestConfig{Timeout: 10 * time.Second, FailOnTimeout: true})
		if err != nil {
			t.Fatalf("%s %s failed: %v", method, path, err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		return resp, raw
	}

	// GET /v1/gateway/health
	resp, raw := callZIP(http.MethodGet, "/v1/gateway/health", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/v1/gateway/health status=%d body=%s", resp.StatusCode, string(raw))
	}

	// GET /v1/models
	resp, raw = callZIP(http.MethodGet, "/v1/models", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/v1/models status=%d body=%s", resp.StatusCode, string(raw))
	}
	var models ModelsListResponse
	if err := json.Unmarshal(raw, &models); err != nil || len(models.Data) != 2 {
		t.Fatalf("invalid /v1/models response: err=%v count=%d", err, len(models.Data))
	}

	// GET /v1/gateway/providers
	resp, raw = callZIP(http.MethodGet, "/v1/gateway/providers", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/v1/gateway/providers status=%d body=%s", resp.StatusCode, string(raw))
	}

	// POST /v1/gateway/quotes
	resp, raw = callZIP(http.MethodPost, "/v1/gateway/quotes", QuotesQuery{Model: "zen-7b-instruct", MaxTokens: 32, Strategy: string(StrategyLowestCost)})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/v1/gateway/quotes status=%d body=%s", resp.StatusCode, string(raw))
	}

	// POST /v1/chat/completions
	chatReq := ChatCompletionRequest{
		Model:     "zen-7b-instruct",
		Messages:  []ChatMessage{{Role: "user", Content: "zip mounted OpenAI completion"}},
		MaxTokens: 32,
	}
	resp, raw = callZIP(http.MethodPost, "/v1/chat/completions", chatReq)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/v1/chat/completions status=%d body=%s", resp.StatusCode, string(raw))
	}
	var chatResp ChatCompletionResponse
	if err := json.Unmarshal(raw, &chatResp); err != nil || chatResp.EnsoReceipt == nil {
		t.Fatalf("invalid chat response: err=%v body=%s", err, string(raw))
	}

	// POST /v1/gateway/receipts/verify
	resp, raw = callZIP(http.MethodPost, "/v1/gateway/receipts/verify", VerifyReceiptRequest{
		Receipt:         *chatResp.EnsoReceipt,
		Quote:           chatResp.EnsoQuote,
		RequestHash:     CanonicalRequestHash(chatReq),
		ResponseContent: chatResp.Choices[0].Message.Content,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/v1/gateway/receipts/verify status=%d body=%s", resp.StatusCode, string(raw))
	}

	// GET /v1/gateway/export
	resp, raw = callZIP(http.MethodGet, "/v1/gateway/export", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/v1/gateway/export status=%d body=%s", resp.StatusCode, string(raw))
	}
	var bundle GatewayExportBundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		t.Fatalf("unmarshal export bundle: %v", err)
	}
	if err := VerifyExportBundle(top.domain, bundle, time.Now().Unix()); err != nil {
		t.Fatalf("VerifyExportBundle from zip export failed: %v", err)
	}

	// Second independent zip.App mounting HanzoGateway serves identical completion content.
	hanzoApp := zip.New(zip.Config{})
	if err := Mount(hanzoApp, luxlog.New("hanzo-gateway-test"), top.hanzoGW); err != nil {
		t.Fatalf("Mount HanzoGateway: %v", err)
	}
	bodyBytes, err := json.Marshal(chatReq)
	if err != nil {
		t.Fatal(err)
	}
	hReq := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(bodyBytes))
	hReq.Header.Set("Content-Type", "application/json")
	hResp, err := hanzoApp.Test(hReq, zip.TestConfig{Timeout: 10 * time.Second, FailOnTimeout: true})
	if err != nil {
		t.Fatalf("hanzo zip.App /v1/chat/completions: %v", err)
	}
	defer hResp.Body.Close()
	hRaw, _ := io.ReadAll(hResp.Body)
	if hResp.StatusCode != http.StatusOK {
		t.Fatalf("hanzo zip.App status=%d body=%s", hResp.StatusCode, string(hRaw))
	}
	var hanzoChat ChatCompletionResponse
	if err := json.Unmarshal(hRaw, &hanzoChat); err != nil {
		t.Fatalf("unmarshal hanzo chat: %v", err)
	}
	if hanzoChat.Choices[0].Message.Content != chatResp.Choices[0].Message.Content {
		t.Fatalf("dual zip.App gateways diverged: hanzo=%q comm=%q",
			hanzoChat.Choices[0].Message.Content, chatResp.Choices[0].Message.Content)
	}
}

func TestPeerDirectoryGossipAndSnapshot(t *testing.T) {
	top := setupDualGatewayTopology(t)
	ctx := context.Background()

	// Fresh community directory peer C syncs exclusively from Community Peer B
	// after Hanzo Directory is closed, proving zero Hanzo lock-in.
	top.hanzoDir.Disable()
	top.hanzoDir.Close()

	peerCKP, err := KeyPairFromSeed([]byte("test-comm-dir-peer-c"))
	if err != nil {
		t.Fatal(err)
	}
	peerC, err := NewDirectoryPeerServer("dir-community-gamma", "Community Peer Gamma", top.domain, peerCKP)
	if err != nil {
		t.Fatal(err)
	}
	defer peerC.Close()

	accepted, rejected, err := peerC.SyncFromPeer(ctx, top.communityDirB.URL(), nil)
	if err != nil {
		t.Fatalf("SyncFromPeer: %v", err)
	}
	if accepted != 3 || rejected != 0 {
		t.Fatalf("expected 3 accepted and 0 rejected workers, got accepted=%d rejected=%d", accepted, rejected)
	}

	// Signed snapshot export + offline verification + tamper rejection.
	snap, err := peerC.Directory().ExportSnapshot(peerCKP, peerC.PeerID, time.Now().Unix())
	if err != nil {
		t.Fatalf("ExportSnapshot: %v", err)
	}
	if err := VerifyDirectorySnapshot(top.domain, snap, time.Now().Unix()); err != nil {
		t.Fatalf("VerifyDirectorySnapshot: %v", err)
	}
	tampered := snap
	tampered.PeerID = "evil-directory"
	if err := VerifyDirectorySnapshot(top.domain, tampered, time.Now().Unix()); !errors.Is(err, ErrDirectoryCorrupted) {
		t.Fatalf("expected ErrDirectoryCorrupted on tampered snapshot, got %v", err)
	}
}
