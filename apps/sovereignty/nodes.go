// SPDX-License-Identifier: Apache-2.0 OR MIT

package sovereignty

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// --- Shared HTTP JSON Helpers ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErrJSON(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func doJSONRequest(client *http.Client, method, url string, in any, out any) (int, error) {
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return 0, err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return 0, err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var errPayload struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(respBytes, &errPayload) == nil && errPayload.Error != "" {
			return resp.StatusCode, fmt.Errorf("HTTP %d: %s", resp.StatusCode, errPayload.Error)
		}
		return resp.StatusCode, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBytes)))
	}
	if out != nil && len(respBytes) > 0 {
		if err := json.Unmarshal(respBytes, out); err != nil {
			return resp.StatusCode, err
		}
	}
	return resp.StatusCode, nil
}

// --- Core Stateful Services Exposed Over Real HTTP Servers ---

// BootstrapServer is a decentralized peer discovery, model manifest, and
// community governance node serving real HTTP over loopback.
type BootstrapServer struct {
	ID         string
	Plane      ControlPlaneKind
	Domain     EIP712Domain
	Server     *httptest.Server
	offline    atomic.Bool
	mu         sync.RWMutex
	providers  map[string]ProviderAdvertisement
	models     map[string]ModelManifest
	governance map[string]*GovernanceDecision
	quorum     int
}

// NewBootstrapServer starts an independent loopback HTTP bootstrap/registry server.
func NewBootstrapServer(id string, plane ControlPlaneKind, domain EIP712Domain, governanceQuorum int) *BootstrapServer {
	if governanceQuorum <= 0 {
		governanceQuorum = 2
	}
	b := &BootstrapServer{
		ID:         id,
		Plane:      plane,
		Domain:     domain,
		providers:  make(map[string]ProviderAdvertisement),
		models:     make(map[string]ModelManifest),
		governance: make(map[string]*GovernanceDecision),
		quorum:     governanceQuorum,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/health", b.handleHealth)
	mux.HandleFunc("/v1/peers/register", b.handleRegisterPeer)
	mux.HandleFunc("/v1/peers", b.handleListPeers)
	mux.HandleFunc("/v1/models", b.handleModels)
	mux.HandleFunc("/v1/models/", b.handleGetModel)
	mux.HandleFunc("/v1/governance/vote", b.handleGovernanceVote)
	mux.HandleFunc("/v1/governance/", b.handleGetGovernance)
	b.Server = httptest.NewServer(mux)
	return b
}

// URL returns the real loopback HTTP base URL.
func (b *BootstrapServer) URL() string { return b.Server.URL }

// Close shuts down the HTTP listener completely.
func (b *BootstrapServer) Close() {
	b.offline.Store(true)
	b.Server.Close()
}

func (b *BootstrapServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	if b.offline.Load() {
		writeErrJSON(w, http.StatusServiceUnavailable, ErrHanzoPlaneOffline)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":      b.ID,
		"plane":   b.Plane,
		"status":  "ok",
		"version": ProtocolVersion,
	})
}

func (b *BootstrapServer) handleRegisterPeer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErrJSON(w, http.StatusMethodNotAllowed, ErrInvalidRequest)
		return
	}
	var ad ProviderAdvertisement
	if err := json.NewDecoder(r.Body).Decode(&ad); err != nil {
		writeErrJSON(w, http.StatusBadRequest, err)
		return
	}
	if err := VerifyProviderAdvertisement(b.Domain, ad); err != nil {
		writeErrJSON(w, http.StatusUnauthorized, err)
		return
	}
	b.mu.Lock()
	b.providers[ad.ProviderID] = ad
	b.mu.Unlock()
	writeJSON(w, http.StatusOK, ad)
}

func (b *BootstrapServer) handleListPeers(w http.ResponseWriter, r *http.Request) {
	modelFilter := strings.TrimSpace(r.URL.Query().Get("model"))
	b.mu.RLock()
	out := make([]ProviderAdvertisement, 0, len(b.providers))
	for _, ad := range b.providers {
		if modelFilter == "" || containsString(ad.ModelIDs, modelFilter) {
			out = append(out, ad)
		}
	}
	b.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].ProviderID < out[j].ProviderID })
	writeJSON(w, http.StatusOK, map[string]any{"providers": out})
}

func (b *BootstrapServer) handleModels(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var m ModelManifest
		if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
			writeErrJSON(w, http.StatusBadRequest, err)
			return
		}
		if err := VerifyModelManifest(b.Domain, m); err != nil {
			writeErrJSON(w, http.StatusUnauthorized, err)
			return
		}
		b.mu.Lock()
		b.models[m.ModelID] = m
		b.mu.Unlock()
		writeJSON(w, http.StatusOK, m)
	case http.MethodGet:
		b.mu.RLock()
		list := make([]ModelManifest, 0, len(b.models))
		for _, m := range b.models {
			list = append(list, m)
		}
		b.mu.RUnlock()
		sort.Slice(list, func(i, j int) bool { return list[i].ModelID < list[j].ModelID })
		writeJSON(w, http.StatusOK, map[string]any{"models": list})
	default:
		writeErrJSON(w, http.StatusMethodNotAllowed, ErrInvalidRequest)
	}
}

func (b *BootstrapServer) handleGetModel(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/v1/models/")
	b.mu.RLock()
	m, ok := b.models[id]
	b.mu.RUnlock()
	if !ok {
		writeErrJSON(w, http.StatusNotFound, ErrNotFound)
		return
	}
	writeJSON(w, http.StatusOK, m)
}

func (b *BootstrapServer) handleGovernanceVote(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErrJSON(w, http.StatusMethodNotAllowed, ErrInvalidRequest)
		return
	}
	var vote GovernanceVote
	if err := json.NewDecoder(r.Body).Decode(&vote); err != nil {
		writeErrJSON(w, http.StatusBadRequest, err)
		return
	}
	if err := VerifyGovernanceVote(b.Domain, vote); err != nil {
		writeErrJSON(w, http.StatusUnauthorized, err)
		return
	}
	b.mu.Lock()
	dec, ok := b.governance[vote.ProposalID]
	if !ok {
		dec = &GovernanceDecision{
			ProposalID:     vote.ProposalID,
			Action:         vote.Action,
			Payload:        vote.Payload,
			QuorumRequired: b.quorum,
		}
		b.governance[vote.ProposalID] = dec
	}
	duplicate := false
	for _, existing := range dec.Votes {
		if SameAddress(existing.VoterAddress, vote.VoterAddress) {
			duplicate = true
			break
		}
	}
	if !duplicate {
		dec.Votes = append(dec.Votes, vote)
		if vote.Approve {
			dec.Approvals++
		}
		dec.Ratified = dec.Approvals >= dec.QuorumRequired
	}
	snapshot := *dec
	snapshot.Votes = append([]GovernanceVote(nil), dec.Votes...)
	b.mu.Unlock()
	writeJSON(w, http.StatusOK, snapshot)
}

func (b *BootstrapServer) handleGetGovernance(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/v1/governance/")
	b.mu.RLock()
	dec, ok := b.governance[id]
	if !ok {
		b.mu.RUnlock()
		writeErrJSON(w, http.StatusNotFound, ErrNotFound)
		return
	}
	snapshot := *dec
	snapshot.Votes = append([]GovernanceVote(nil), dec.Votes...)
	b.mu.RUnlock()
	writeJSON(w, http.StatusOK, snapshot)
}

// SnapshotState exports all signed providers, manifests, and governance decisions.
func (b *BootstrapServer) SnapshotState() ([]ProviderAdvertisement, []ModelManifest, []GovernanceDecision) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	providers := make([]ProviderAdvertisement, 0, len(b.providers))
	for _, p := range b.providers {
		providers = append(providers, p)
	}
	sort.Slice(providers, func(i, j int) bool { return providers[i].ProviderID < providers[j].ProviderID })

	models := make([]ModelManifest, 0, len(b.models))
	for _, m := range b.models {
		models = append(models, m)
	}
	sort.Slice(models, func(i, j int) bool { return models[i].ModelID < models[j].ModelID })

	govs := make([]GovernanceDecision, 0, len(b.governance))
	for _, g := range b.governance {
		cp := *g
		cp.Votes = append([]GovernanceVote(nil), g.Votes...)
		govs = append(govs, cp)
	}
	sort.Slice(govs, func(i, j int) bool { return govs[i].ProposalID < govs[j].ProposalID })
	return providers, models, govs
}

// HydrateFromFork imports verified providers, models, and governance records
// during an independent operator fork or migration.
func (b *BootstrapServer) HydrateFromFork(providers []ProviderAdvertisement, models []ModelManifest, govs []GovernanceDecision) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, p := range providers {
		b.providers[p.ProviderID] = p
	}
	for _, m := range models {
		b.models[m.ModelID] = m
	}
	for _, g := range govs {
		cp := g
		cp.Votes = append([]GovernanceVote(nil), g.Votes...)
		b.governance[g.ProposalID] = &cp
	}
}

// ArtifactMirrorServer stores and serves content-addressed model weight blobs
// keyed by their lowercase hex SHA-256 digest.
type ArtifactMirrorServer struct {
	ID            string
	Plane         ControlPlaneKind
	Server        *httptest.Server
	mu            sync.RWMutex
	blobs         map[string][]byte
	tamperDigests map[string]bool
}

// NewArtifactMirrorServer starts a real loopback content-addressed model mirror.
func NewArtifactMirrorServer(id string, plane ControlPlaneKind) *ArtifactMirrorServer {
	a := &ArtifactMirrorServer{
		ID:            id,
		Plane:         plane,
		blobs:         make(map[string][]byte),
		tamperDigests: make(map[string]bool),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"id": a.ID, "plane": a.Plane, "status": "ok"})
	})
	mux.HandleFunc("/v1/blobs/", a.handleBlob)
	a.Server = httptest.NewServer(mux)
	return a
}

// URL returns the mirror's base HTTP URL.
func (a *ArtifactMirrorServer) URL() string { return a.Server.URL }

// Close shuts down the HTTP mirror listener.
func (a *ArtifactMirrorServer) Close() { a.Server.Close() }

// InjectTamperedBlob flips a byte on subsequent GET responses for digest to
// verify fail-closed SHA-256 integrity checks on clients and providers.
func (a *ArtifactMirrorServer) InjectTamperedBlob(digest string, enable bool) {
	a.mu.Lock()
	a.tamperDigests[strings.ToLower(digest)] = enable
	a.mu.Unlock()
}

func (a *ArtifactMirrorServer) handleBlob(w http.ResponseWriter, r *http.Request) {
	digest := strings.ToLower(strings.TrimPrefix(r.URL.Path, "/v1/blobs/"))
	switch r.Method {
	case http.MethodPut:
		data, err := io.ReadAll(r.Body)
		if err != nil {
			writeErrJSON(w, http.StatusBadRequest, err)
			return
		}
		actual := SHA256Hex(data)
		if !strings.EqualFold(actual, digest) {
			writeErrJSON(w, http.StatusBadRequest, fmt.Errorf("%w: got %s want %s", ErrModelDigestMismatch, actual, digest))
			return
		}
		a.mu.Lock()
		a.blobs[digest] = append([]byte(nil), data...)
		a.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"digestSha256": digest, "sizeBytes": len(data)})
	case http.MethodGet:
		a.mu.RLock()
		blob, ok := a.blobs[digest]
		tamper := a.tamperDigests[digest]
		a.mu.RUnlock()
		if !ok {
			writeErrJSON(w, http.StatusNotFound, ErrNotFound)
			return
		}
		out := append([]byte(nil), blob...)
		if tamper && len(out) > 0 {
			out[0] ^= 0xff
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(out)
	default:
		writeErrJSON(w, http.StatusMethodNotAllowed, ErrInvalidRequest)
	}
}

// ProviderNodeServer is an independent compute worker node running its own HTTP
// inference endpoint with its own ephemeral secp256k1 identity.
type ProviderNodeServer struct {
	ProviderID   string
	KeyPair      *KeyPair
	Domain       EIP712Domain
	HTTPClient   *http.Client
	Server       *httptest.Server
	mu           sync.RWMutex
	modelCache   map[string][]byte
	tamperOutput bool
}

// NewProviderNodeServer starts a real loopback HTTP compute provider node.
func NewProviderNodeServer(providerID string, kp *KeyPair, domain EIP712Domain, client *http.Client) *ProviderNodeServer {
	p := &ProviderNodeServer{
		ProviderID: providerID,
		KeyPair:    kp,
		Domain:     domain,
		HTTPClient: client,
		modelCache: make(map[string][]byte),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"providerId": p.ProviderID,
			"address":    p.KeyPair.Address(),
			"status":     "ok",
		})
	})
	mux.HandleFunc("/v1/infer", p.handleInfer)
	p.Server = httptest.NewServer(mux)
	return p
}

// URL returns the provider's real HTTP URL.
func (p *ProviderNodeServer) URL() string { return p.Server.URL }

// Close shuts down the provider HTTP listener.
func (p *ProviderNodeServer) Close() { p.Server.Close() }

// SetTamperOutput toggles malicious output corruption for adversarial testing.
func (p *ProviderNodeServer) SetTamperOutput(v bool) {
	p.mu.Lock()
	p.tamperOutput = v
	p.mu.Unlock()
}

// FetchAndVerifyModel downloads content-addressed model weights from mirrorURL
// and verifies SHA-256 before caching them locally.
func (p *ProviderNodeServer) FetchAndVerifyModel(mirrorURL, expectedDigest string) error {
	blob, err := DownloadAndVerifyModelBlob(p.HTTPClient, mirrorURL, expectedDigest)
	if err != nil {
		return err
	}
	p.mu.Lock()
	p.modelCache[strings.ToLower(expectedDigest)] = blob
	p.mu.Unlock()
	return nil
}

// BuildSignedAdvertisement constructs a provider-signed ProviderAdvertisement.
func (p *ProviderNodeServer) BuildSignedAdvertisement(modelIDs []string, pricePer1K uint64, capacityRPM uint32, now time.Time) (ProviderAdvertisement, error) {
	ad := ProviderAdvertisement{
		ProviderID:       p.ProviderID,
		OperatorAddress:  p.KeyPair.Address(),
		EndpointURL:      p.URL(),
		ModelIDs:         append([]string(nil), modelIDs...),
		PricePer1KAtomic: pricePer1K,
		CapacityRPM:      capacityRPM,
		IssuedAt:         now.Unix(),
		ExpiresAt:        now.Add(24 * time.Hour).Unix(),
	}
	if err := SignProviderAdvertisement(p.Domain, p.KeyPair, &ad); err != nil {
		return ProviderAdvertisement{}, err
	}
	return ad, nil
}

func (p *ProviderNodeServer) handleInfer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErrJSON(w, http.StatusMethodNotAllowed, ErrInvalidRequest)
		return
	}
	var req InferenceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrJSON(w, http.StatusBadRequest, err)
		return
	}
	p.mu.RLock()
	blob, ok := p.modelCache[strings.ToLower(req.ModelDigestSHA256)]
	tamper := p.tamperOutput
	p.mu.RUnlock()
	if !ok {
		writeErrJSON(w, http.StatusNotFound, fmt.Errorf("%w: model %s not loaded on provider %s", ErrNotFound, req.ModelDigestSHA256, p.ProviderID))
		return
	}
	outText, outDigest, tokens := ExecuteDeterministicInference(blob, req.Prompt, req.Seed, req.MaxTokens)
	if tamper {
		outText = outText + " [tampered]"
		outDigest = SHA256Hex([]byte(outText))
	}
	receipt := InferenceExecutionReceipt{
		JobID:              req.JobID,
		ProviderID:         p.ProviderID,
		ProviderAddress:    p.KeyPair.Address(),
		ModelID:            req.ModelID,
		ModelDigestSHA256:  strings.ToLower(req.ModelDigestSHA256),
		InputDigestSHA256:  ComputeRequestInputDigest(req),
		OutputText:         outText,
		OutputDigestSHA256: outDigest,
		TokensGenerated:    tokens,
		ExecutedAt:         time.Now().UTC().Unix(),
		VerificationClass:  VerificationClassDeterministicHash,
	}
	if err := SignExecutionReceipt(p.Domain, p.KeyPair, &receipt); err != nil {
		writeErrJSON(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, receipt)
}

// SchedulerServer is a stateless HTTP job scheduler that discovers eligible
// providers from its configured bootstrap URLs and dispatches inference over HTTP.
type SchedulerServer struct {
	ID            string
	Plane         ControlPlaneKind
	Domain        EIP712Domain
	BootstrapURLs []string
	HTTPClient    *http.Client
	Server        *httptest.Server
	rrCounter     atomic.Uint64
}

// NewSchedulerServer starts a real loopback HTTP scheduler node.
func NewSchedulerServer(id string, plane ControlPlaneKind, domain EIP712Domain, bootstrapURLs []string, client *http.Client) *SchedulerServer {
	s := &SchedulerServer{
		ID:            id,
		Plane:         plane,
		Domain:        domain,
		BootstrapURLs: append([]string(nil), bootstrapURLs...),
		HTTPClient:    client,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"id": s.ID, "plane": s.Plane, "status": "ok"})
	})
	mux.HandleFunc("/v1/schedule", s.handleSchedule)
	s.Server = httptest.NewServer(mux)
	return s
}

// URL returns the scheduler's HTTP base URL.
func (s *SchedulerServer) URL() string { return s.Server.URL }

// Close shuts down the scheduler HTTP listener.
func (s *SchedulerServer) Close() { s.Server.Close() }

type scheduleDispatchRequest struct {
	Request           InferenceRequest `json:"request"`
	PreferredProvider string           `json:"preferredProvider,omitempty"`
}

func (s *SchedulerServer) handleSchedule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErrJSON(w, http.StatusMethodNotAllowed, ErrInvalidRequest)
		return
	}
	var in scheduleDispatchRequest
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErrJSON(w, http.StatusBadRequest, err)
		return
	}
	providers, err := DiscoverPeersFromBootstraps(s.HTTPClient, s.Domain, s.BootstrapURLs, in.Request.ModelID)
	if err != nil {
		writeErrJSON(w, http.StatusServiceUnavailable, err)
		return
	}
	if len(providers) == 0 {
		writeErrJSON(w, http.StatusNotFound, fmt.Errorf("%w: no providers for model %s", ErrNotFound, in.Request.ModelID))
		return
	}
	var chosen ProviderAdvertisement
	if in.PreferredProvider != "" {
		found := false
		for _, p := range providers {
			if p.ProviderID == in.PreferredProvider {
				chosen = p
				found = true
				break
			}
		}
		if !found {
			writeErrJSON(w, http.StatusNotFound, fmt.Errorf("%w: preferred provider %s not found", ErrNotFound, in.PreferredProvider))
			return
		}
	} else {
		idx := s.rrCounter.Add(1) - 1
		chosen = providers[int(idx)%len(providers)]
	}
	var receipt InferenceExecutionReceipt
	if _, err := doJSONRequest(s.HTTPClient, http.MethodPost, chosen.EndpointURL+"/v1/infer", in.Request, &receipt); err != nil {
		writeErrJSON(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, receipt)
}

// FacilitatorServer is an independent EIP-712 payment settlement facilitator
// with replay protection, atomic balance conservation, and a hash-chained ledger.
type FacilitatorServer struct {
	ID            string
	Plane         ControlPlaneKind
	KeyPair       *KeyPair
	Domain        EIP712Domain
	Server        *httptest.Server
	mu            sync.RWMutex
	balances      map[string]uint64
	mintedTotal   uint64
	seenPayments  map[string]struct{}
	ledger        []SettlementReceipt
	prevChainHash string
}

// NewFacilitatorServer starts a real loopback HTTP payment facilitator node.
func NewFacilitatorServer(id string, plane ControlPlaneKind, kp *KeyPair, domain EIP712Domain) *FacilitatorServer {
	f := &FacilitatorServer{
		ID:            id,
		Plane:         plane,
		KeyPair:       kp,
		Domain:        domain,
		balances:      make(map[string]uint64),
		seenPayments:  make(map[string]struct{}),
		prevChainHash: "genesis",
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"id":      f.ID,
			"plane":   f.Plane,
			"address": f.KeyPair.Address(),
			"status":  "ok",
		})
	})
	mux.HandleFunc("/v1/payments/mint", f.handleMint)
	mux.HandleFunc("/v1/payments/settle", f.handleSettle)
	mux.HandleFunc("/v1/payments/balance/", f.handleBalance)
	mux.HandleFunc("/v1/payments/ledger", f.handleLedger)
	f.Server = httptest.NewServer(mux)
	return f
}

// URL returns the facilitator HTTP base URL.
func (f *FacilitatorServer) URL() string { return f.Server.URL }

// Close shuts down the facilitator HTTP listener.
func (f *FacilitatorServer) Close() { f.Server.Close() }

type mintReq struct {
	Address string `json:"address"`
	Amount  uint64 `json:"amount"`
}

func (f *FacilitatorServer) handleMint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErrJSON(w, http.StatusMethodNotAllowed, ErrInvalidRequest)
		return
	}
	var in mintReq
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErrJSON(w, http.StatusBadRequest, err)
		return
	}
	norm, err := NormalizeAddress(in.Address)
	if err != nil {
		writeErrJSON(w, http.StatusBadRequest, err)
		return
	}
	f.mu.Lock()
	f.balances[norm] += in.Amount
	f.mintedTotal += in.Amount
	bal := f.balances[norm]
	f.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"address": norm, "balance": bal})
}

func (f *FacilitatorServer) handleSettle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErrJSON(w, http.StatusMethodNotAllowed, ErrInvalidRequest)
		return
	}
	var auth PaymentAuthorization
	if err := json.NewDecoder(r.Body).Decode(&auth); err != nil {
		writeErrJSON(w, http.StatusBadRequest, err)
		return
	}
	if err := VerifyPaymentAuthorization(f.Domain, auth); err != nil {
		writeErrJSON(w, http.StatusUnauthorized, err)
		return
	}
	if auth.ValidBefore > 0 && time.Now().UTC().Unix() > auth.ValidBefore {
		writeErrJSON(w, http.StatusBadRequest, fmt.Errorf("%w: payment authorization expired", ErrInvalidRequest))
		return
	}
	payer, err := NormalizeAddress(auth.PayerAddress)
	if err != nil {
		writeErrJSON(w, http.StatusBadRequest, err)
		return
	}
	payee, err := NormalizeAddress(auth.PayeeAddress)
	if err != nil {
		writeErrJSON(w, http.StatusBadRequest, err)
		return
	}
	f.mu.Lock()
	if _, exists := f.seenPayments[auth.PaymentID]; exists {
		f.mu.Unlock()
		writeErrJSON(w, http.StatusConflict, ErrReplayDetected)
		return
	}
	if f.balances[payer] < auth.AmountAtomic {
		f.mu.Unlock()
		writeErrJSON(w, http.StatusPaymentRequired, ErrInsufficientBalance)
		return
	}
	f.balances[payer] -= auth.AmountAtomic
	f.balances[payee] += auth.AmountAtomic
	f.seenPayments[auth.PaymentID] = struct{}{}

	settledAt := time.Now().UTC().Unix()
	prevHash := f.prevChainHash
	ledgerHash := SHA256Hex(
		[]byte(prevHash),
		[]byte(auth.PaymentID),
		[]byte(auth.JobID),
		[]byte(payer),
		[]byte(payee),
		[]byte(fmt.Sprintf("%d:%d", auth.AmountAtomic, settledAt)),
	)
	receipt := SettlementReceipt{
		PaymentID:          auth.PaymentID,
		JobID:              auth.JobID,
		FacilitatorID:      f.ID,
		FacilitatorAddress: f.KeyPair.Address(),
		PayerAddress:       payer,
		PayeeAddress:       payee,
		AmountAtomic:       auth.AmountAtomic,
		SettledAt:          settledAt,
		PrevLedgerHash:     prevHash,
		LedgerHash:         ledgerHash,
	}
	if err := SignSettlementReceipt(f.Domain, f.KeyPair, &receipt); err != nil {
		// Roll back balance mutation on signing failure.
		f.balances[payee] -= auth.AmountAtomic
		f.balances[payer] += auth.AmountAtomic
		delete(f.seenPayments, auth.PaymentID)
		f.mu.Unlock()
		writeErrJSON(w, http.StatusInternalServerError, err)
		return
	}
	f.prevChainHash = ledgerHash
	f.ledger = append(f.ledger, receipt)
	f.mu.Unlock()
	writeJSON(w, http.StatusOK, receipt)
}

func (f *FacilitatorServer) handleBalance(w http.ResponseWriter, r *http.Request) {
	addr := strings.TrimPrefix(r.URL.Path, "/v1/payments/balance/")
	norm, err := NormalizeAddress(addr)
	if err != nil {
		writeErrJSON(w, http.StatusBadRequest, err)
		return
	}
	f.mu.RLock()
	bal := f.balances[norm]
	f.mu.RUnlock()
	writeJSON(w, http.StatusOK, map[string]any{"address": norm, "balance": bal})
}

func (f *FacilitatorServer) handleLedger(w http.ResponseWriter, r *http.Request) {
	f.mu.RLock()
	out := append([]SettlementReceipt(nil), f.ledger...)
	drift := f.conservationDriftLocked()
	f.mu.RUnlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"entries":           out,
		"conservationDrift": drift,
	})
}

func (f *FacilitatorServer) conservationDriftLocked() int64 {
	var sum uint64
	for _, b := range f.balances {
		sum += b
	}
	return int64(sum) - int64(f.mintedTotal)
}

// ConservationDrift returns the exact atomic drift between balances and minted supply.
func (f *FacilitatorServer) ConservationDrift() int64 {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.conservationDriftLocked()
}

// SnapshotState exports the settlement ledger and account balances for fork bundles.
func (f *FacilitatorServer) SnapshotState() ([]SettlementReceipt, map[string]uint64) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	ledger := append([]SettlementReceipt(nil), f.ledger...)
	bals := make(map[string]uint64, len(f.balances))
	for k, v := range f.balances {
		bals[k] = v
	}
	return ledger, bals
}

// HydrateFromFork restores balances and settlement ledger on an independent forked facilitator.
func (f *FacilitatorServer) HydrateFromFork(ledger []SettlementReceipt, bals map[string]uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.balances = make(map[string]uint64, len(bals))
	f.mintedTotal = 0
	for k, v := range bals {
		f.balances[k] = v
		f.mintedTotal += v
	}
	f.ledger = append([]SettlementReceipt(nil), ledger...)
	f.seenPayments = make(map[string]struct{}, len(ledger))
	f.prevChainHash = "genesis"
	for _, s := range ledger {
		f.seenPayments[s.PaymentID] = struct{}{}
		f.prevChainHash = s.LedgerHash
	}
}

// SovereignVaultServer stores client-side AES-256-GCM encrypted user workspace
// envelopes without ever possessing plaintext or user decryption keys.
type SovereignVaultServer struct {
	ID        string
	Plane     ControlPlaneKind
	Domain    EIP712Domain
	Server    *httptest.Server
	mu        sync.RWMutex
	envelopes map[string]EncryptedDataEnvelope
}

// NewSovereignVaultServer starts a real loopback HTTP encrypted data vault.
func NewSovereignVaultServer(id string, plane ControlPlaneKind, domain EIP712Domain) *SovereignVaultServer {
	v := &SovereignVaultServer{
		ID:        id,
		Plane:     plane,
		Domain:    domain,
		envelopes: make(map[string]EncryptedDataEnvelope),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"id": v.ID, "plane": v.Plane, "status": "ok"})
	})
	mux.HandleFunc("/v1/vault/snapshots", v.handlePutSnapshot)
	mux.HandleFunc("/v1/vault/snapshots/", v.handleGetSnapshot)
	mux.HandleFunc("/v1/vault/export", v.handleExportAll)
	v.Server = httptest.NewServer(mux)
	return v
}

// URL returns the vault's base HTTP URL.
func (v *SovereignVaultServer) URL() string { return v.Server.URL }

// Close shuts down the vault HTTP listener.
func (v *SovereignVaultServer) Close() { v.Server.Close() }

func (v *SovereignVaultServer) handlePutSnapshot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErrJSON(w, http.StatusMethodNotAllowed, ErrInvalidRequest)
		return
	}
	var env EncryptedDataEnvelope
	if err := json.NewDecoder(r.Body).Decode(&env); err != nil {
		writeErrJSON(w, http.StatusBadRequest, err)
		return
	}
	if env.CapabilityManifest.CustodialEscrow {
		writeErrJSON(w, http.StatusBadRequest, fmt.Errorf("%w: custodial escrow must be false", ErrInvalidRequest))
		return
	}
	sh, err := envelopeStructHash(env)
	if err != nil {
		writeErrJSON(w, http.StatusBadRequest, err)
		return
	}
	signer, err := RecoverSignerAddress(v.Domain.TypedDataDigest(sh), env.OwnerSignature)
	if err != nil || !SameAddress(signer, env.OwnerAddress) {
		writeErrJSON(w, http.StatusUnauthorized, ErrInvalidSignature)
		return
	}
	v.mu.Lock()
	v.envelopes[env.SnapshotID] = env
	v.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"snapshotId": env.SnapshotID, "stored": true})
}

func (v *SovereignVaultServer) handleGetSnapshot(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/v1/vault/snapshots/")
	v.mu.RLock()
	env, ok := v.envelopes[id]
	v.mu.RUnlock()
	if !ok {
		writeErrJSON(w, http.StatusNotFound, ErrNotFound)
		return
	}
	writeJSON(w, http.StatusOK, env)
}

func (v *SovereignVaultServer) handleExportAll(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"envelopes": v.SnapshotState()})
}

// SnapshotState exports all stored encrypted envelopes in deterministic order.
func (v *SovereignVaultServer) SnapshotState() []EncryptedDataEnvelope {
	v.mu.RLock()
	defer v.mu.RUnlock()
	out := make([]EncryptedDataEnvelope, 0, len(v.envelopes))
	for _, e := range v.envelopes {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SnapshotID < out[j].SnapshotID })
	return out
}

// HydrateFromFork imports encrypted envelopes onto an independent operator vault.
func (v *SovereignVaultServer) HydrateFromFork(envs []EncryptedDataEnvelope) {
	v.mu.Lock()
	defer v.mu.Unlock()
	for _, e := range envs {
		v.envelopes[e.SnapshotID] = e
	}
}

// --- Control Plane A (Hanzo-Operated Convenience Plane) ---

// HanzoControlPlane groups all Hanzo-operated convenience servers so they can
// be cleanly killed together by KillHanzoControlPlane().
type HanzoControlPlane struct {
	Gateway     *httptest.Server
	Registry    *BootstrapServer
	Mirror      *ArtifactMirrorServer
	Scheduler   *SchedulerServer
	Facilitator *FacilitatorServer
	Vault       *SovereignVaultServer
	killed      atomic.Bool
}

// NewHanzoControlPlane starts all Hanzo-operated convenience endpoints and
// registers every one of them with guard so they are counted and blocked on kill.
func NewHanzoControlPlane(domain EIP712Domain, guard *HostBlocker) (*HanzoControlPlane, error) {
	facKP, err := GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	client := guard.NewHTTPClient(5 * time.Second)
	reg := NewBootstrapServer("hanzo-registry", PlaneHanzo, domain, 2)
	mir := NewArtifactMirrorServer("hanzo-mirror", PlaneHanzo)
	sched := NewSchedulerServer("hanzo-scheduler", PlaneHanzo, domain, []string{reg.URL()}, client)
	fac := NewFacilitatorServer("hanzo-facilitator", PlaneHanzo, facKP, domain)
	vault := NewSovereignVaultServer("hanzo-vault", PlaneHanzo, domain)

	hp := &HanzoControlPlane{
		Registry:    reg,
		Mirror:      mir,
		Scheduler:   sched,
		Facilitator: fac,
		Vault:       vault,
	}
	gwMux := http.NewServeMux()
	gwMux.HandleFunc("/v1/health", func(w http.ResponseWriter, r *http.Request) {
		if hp.killed.Load() {
			writeErrJSON(w, http.StatusServiceUnavailable, ErrHanzoPlaneOffline)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"service":     "hanzo-gateway",
			"plane":       PlaneHanzo,
			"registry":    reg.URL(),
			"mirror":      mir.URL(),
			"scheduler":   sched.URL(),
			"facilitator": fac.URL(),
			"vault":       vault.URL(),
		})
	})
	hp.Gateway = httptest.NewServer(gwMux)

	guard.RegisterHanzoEndpoint(hp.Gateway.URL)
	guard.RegisterHanzoEndpoint(reg.URL())
	guard.RegisterHanzoEndpoint(mir.URL())
	guard.RegisterHanzoEndpoint(sched.URL())
	guard.RegisterHanzoEndpoint(fac.URL())
	guard.RegisterHanzoEndpoint(vault.URL())
	return hp, nil
}

// Kill shuts down every Hanzo-operated HTTP listener immediately.
func (hp *HanzoControlPlane) Kill() {
	if hp == nil {
		return
	}
	if hp.killed.Swap(true) {
		return
	}
	hp.Gateway.Close()
	hp.Scheduler.Close()
	hp.Facilitator.Close()
	hp.Registry.Close()
	hp.Mirror.Close()
	hp.Vault.Close()
}

// --- Control Plane B (Independent Community Operator Plane) ---

// CommunityControlPlane is an independently administered decentralized control
// plane with zero references to Hanzo infrastructure.
type CommunityControlPlane struct {
	OperatorID     string
	OperatorKP     *KeyPair
	Domain         EIP712Domain
	BootstrapNodes []*BootstrapServer
	Mirror         *ArtifactMirrorServer
	Scheduler      *SchedulerServer
	Facilitator    *FacilitatorServer
	Vault          *SovereignVaultServer
}

// NewCommunityControlPlane starts a multi-peer community control plane running
// over independent loopback HTTP listeners.
func NewCommunityControlPlane(operatorID string, domain EIP712Domain, client *http.Client, bootstrapCount int) (*CommunityControlPlane, error) {
	if bootstrapCount < 1 {
		bootstrapCount = 2
	}
	opKP, err := GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	facKP, err := GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	boots := make([]*BootstrapServer, bootstrapCount)
	bootURLs := make([]string, bootstrapCount)
	for i := 0; i < bootstrapCount; i++ {
		boots[i] = NewBootstrapServer(fmt.Sprintf("%s-bootstrap-%d", operatorID, i+1), PlaneCommunity, domain, 2)
		bootURLs[i] = boots[i].URL()
	}
	mir := NewArtifactMirrorServer(operatorID+"-mirror", PlaneCommunity)
	sched := NewSchedulerServer(operatorID+"-scheduler", PlaneCommunity, domain, bootURLs, client)
	fac := NewFacilitatorServer(operatorID+"-facilitator", PlaneCommunity, facKP, domain)
	vault := NewSovereignVaultServer(operatorID+"-vault", PlaneCommunity, domain)

	return &CommunityControlPlane{
		OperatorID:     operatorID,
		OperatorKP:     opKP,
		Domain:         domain,
		BootstrapNodes: boots,
		Mirror:         mir,
		Scheduler:      sched,
		Facilitator:    fac,
		Vault:          vault,
	}, nil
}

// BootstrapURLs returns all community bootstrap HTTP endpoints.
func (cp *CommunityControlPlane) BootstrapURLs() []string {
	urls := make([]string, len(cp.BootstrapNodes))
	for i, b := range cp.BootstrapNodes {
		urls[i] = b.URL()
	}
	return urls
}

// Close shuts down every server in the community plane.
func (cp *CommunityControlPlane) Close() {
	if cp == nil {
		return
	}
	cp.Scheduler.Close()
	cp.Facilitator.Close()
	cp.Mirror.Close()
	cp.Vault.Close()
	for _, b := range cp.BootstrapNodes {
		b.Close()
	}
}

// ExportForkBundle builds and signs a complete portable NetworkForkBundle from
// this community operator's live state.
func (cp *CommunityControlPlane) ExportForkBundle() (NetworkForkBundle, error) {
	providers, models, govs := cp.BootstrapNodes[0].SnapshotState()
	ledger, bals := cp.Facilitator.SnapshotState()
	vault := cp.Vault.SnapshotState()

	bundle := NetworkForkBundle{
		ProtocolVersion:  ProtocolVersion,
		ExportedAt:       time.Now().UTC().Unix(),
		OperatorID:       cp.OperatorID,
		OperatorAddress:  cp.OperatorKP.Address(),
		Providers:        providers,
		Models:           models,
		SettlementLedger: ledger,
		Balances:         bals,
		Governance:       govs,
		EncryptedVault:   vault,
	}
	if err := SignForkBundle(cp.Domain, cp.OperatorKP, &bundle); err != nil {
		return NetworkForkBundle{}, err
	}
	return bundle, nil
}

// HydrateFromFork verifies bundle offline and hydrates every component of this
// fresh community operator plane from the portable snapshot.
func (cp *CommunityControlPlane) HydrateFromFork(bundle NetworkForkBundle) error {
	if err := VerifyForkBundleOffline(cp.Domain, bundle); err != nil {
		return err
	}
	for _, b := range cp.BootstrapNodes {
		b.HydrateFromFork(bundle.Providers, bundle.Models, bundle.Governance)
	}
	cp.Facilitator.HydrateFromFork(bundle.SettlementLedger, bundle.Balances)
	cp.Vault.HydrateFromFork(bundle.EncryptedVault)
	return nil
}

// --- Decentralized Client Protocol Helpers ---

// DiscoverPeersFromBootstraps queries independent bootstrap peers in order,
// verifies every returned ProviderAdvertisement EIP-712 signature locally, and
// fails closed with ErrBootstrapQuorumLost if zero bootstrap peers are reachable.
func DiscoverPeersFromBootstraps(client *http.Client, domain EIP712Domain, bootstrapURLs []string, modelID string) ([]ProviderAdvertisement, error) {
	if len(bootstrapURLs) == 0 {
		return nil, ErrBootstrapQuorumLost
	}
	reachable := 0
	dedup := make(map[string]ProviderAdvertisement)
	for _, base := range bootstrapURLs {
		target := base + "/v1/peers"
		if modelID != "" {
			target += "?model=" + modelID
		}
		var out struct {
			Providers []ProviderAdvertisement `json:"providers"`
		}
		if _, err := doJSONRequest(client, http.MethodGet, target, nil, &out); err != nil {
			continue
		}
		reachable++
		for _, ad := range out.Providers {
			if err := VerifyProviderAdvertisement(domain, ad); err != nil {
				continue
			}
			dedup[ad.ProviderID] = ad
		}
	}
	if reachable == 0 {
		return nil, ErrBootstrapQuorumLost
	}
	res := make([]ProviderAdvertisement, 0, len(dedup))
	for _, ad := range dedup {
		res = append(res, ad)
	}
	sort.Slice(res, func(i, j int) bool { return res[i].ProviderID < res[j].ProviderID })
	return res, nil
}

// DiscoverModelManifest queries independent bootstrap peers for modelID and
// verifies the publisher's EIP-712 signature locally.
func DiscoverModelManifest(client *http.Client, domain EIP712Domain, bootstrapURLs []string, modelID string) (ModelManifest, error) {
	if len(bootstrapURLs) == 0 {
		return ModelManifest{}, ErrBootstrapQuorumLost
	}
	reachable := 0
	for _, base := range bootstrapURLs {
		var m ModelManifest
		status, err := doJSONRequest(client, http.MethodGet, base+"/v1/models/"+modelID, nil, &m)
		if err != nil {
			if status == http.StatusNotFound {
				reachable++
			}
			continue
		}
		reachable++
		if err := VerifyModelManifest(domain, m); err != nil {
			return ModelManifest{}, err
		}
		return m, nil
	}
	if reachable == 0 {
		return ModelManifest{}, ErrBootstrapQuorumLost
	}
	return ModelManifest{}, ErrNotFound
}

// DownloadAndVerifyModelBlob fetches content-addressed model weight bytes from
// mirrorURL and verifies SHA-256(bytes) == expectedDigest before returning.
func DownloadAndVerifyModelBlob(client *http.Client, mirrorURL, expectedDigest string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, mirrorURL+"/v1/blobs/"+strings.ToLower(expectedDigest), nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("sovereignty: mirror GET %s returned HTTP %d", expectedDigest, resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	actual := SHA256Hex(data)
	if !strings.EqualFold(actual, expectedDigest) {
		return nil, fmt.Errorf("%w: mirror served %s expected %s", ErrModelDigestMismatch, actual, expectedDigest)
	}
	return data, nil
}

// UploadModelBlob uploads content-addressed model bytes to mirrorURL.
func UploadModelBlob(client *http.Client, mirrorURL, digest string, data []byte) error {
	req, err := http.NewRequest(http.MethodPut, mirrorURL+"/v1/blobs/"+strings.ToLower(digest), bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("sovereignty: mirror PUT failed HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func containsString(list []string, target string) bool {
	for _, s := range list {
		if s == target {
			return true
		}
	}
	return false
}
