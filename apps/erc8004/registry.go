// SPDX-License-Identifier: Apache-2.0 OR MIT

package erc8004

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Reference EVM execution gas constants modeled on ERC-8004 Solidity contracts
// (ERC-721 IdentityRegistry + DelegationRevocation + ReputationRegistry).
const (
	GasRegisterAgent      uint64 = 148000
	GasUpdateAgent        uint64 = 64000
	GasRegisterDelegation uint64 = 92000 // Optional on-chain anchor; pure EIP-712 off-chain grant is 0 gas.
	GasRevokeDelegation   uint64 = 46000
	GasBumpEpoch          uint64 = 29000
	GasSubmitFeedback     uint64 = 88000
)

// Clock returns the current Unix timestamp in seconds. Injectable for deterministic tests.
type Clock func() int64

func defaultClock() int64 {
	return time.Now().Unix()
}

// IdentityRegistry implements a deterministic local EVM-compatible ERC-8004 Identity,
// Credential, and Delegation Revocation registry. It operates with zero Hanzo-controlled
// dependencies and exports self-verifying state snapshots.
type IdentityRegistry struct {
	mu           sync.RWMutex
	domain       EIP712Domain
	clock        Clock
	nextTokenID  uint64
	blockNumber  uint64
	stateRoot    [32]byte
	agents       map[string]*AgentIdentity   // agentID -> identity
	byTokenID    map[uint64]string           // tokenID -> agentID
	byOwner      map[string][]string         // normalized ownerAddr -> []agentID
	credentials  map[string]SignedCredential // credentialID -> credential
	delegations  map[string]*DelegationGrant // delegationID -> grant
	revocations  map[string]RevocationRecord // delegationID -> revocation record
	revokedNonce map[string]map[uint64]bool  // agentID -> used revocation nonces
	txLog        []ChainTxReceipt
}

// NewIdentityRegistry creates a clean-room ERC-8004 registry bound to domain.
// If domain.Name is empty, DefaultDomain() is used.
func NewIdentityRegistry(domain EIP712Domain, clock Clock) *IdentityRegistry {
	if domain.Name == "" {
		domain = DefaultDomain()
	}
	if clock == nil {
		clock = defaultClock
	}
	genesisRoot := domainGenesis(domain)
	return &IdentityRegistry{
		domain:       domain,
		clock:        clock,
		nextTokenID:  1,
		blockNumber:  1,
		stateRoot:    genesisRoot,
		agents:       make(map[string]*AgentIdentity),
		byTokenID:    make(map[uint64]string),
		byOwner:      make(map[string][]string),
		credentials:  make(map[string]SignedCredential),
		delegations:  make(map[string]*DelegationGrant),
		revocations:  make(map[string]RevocationRecord),
		revokedNonce: make(map[string]map[uint64]bool),
	}
}

// BytesSlice is a small helper on EIP712Domain via standalone helper below.
func domainGenesis(d EIP712Domain) [32]byte {
	sep := d.DomainSeparator()
	return Keccak256Bytes([]byte("erc8004:genesis:v1"), sep[:])
}

// Domain returns the EIP-712 domain used by this registry.
func (r *IdentityRegistry) Domain() EIP712Domain {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.domain
}

// Now returns the current registry timestamp (Unix seconds).
func (r *IdentityRegistry) Now() int64 {
	return r.clock()
}

// StateRoot returns the current hex-encoded chained Keccak-256 state root.
func (r *IdentityRegistry) StateRoot() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return "0x" + hex.EncodeToString(r.stateRoot[:])
}

// BlockNumber returns the current deterministic test-chain block height.
func (r *IdentityRegistry) BlockNumber() uint64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.blockNumber
}

// RegisterAgent verifies the owner's EIP-712 signature and registers a portable ERC-8004
// agent identity advertising capabilities plus MCP and A2A endpoints.
func (r *IdentityRegistry) RegisterAgent(in AgentIdentity) (*AgentIdentity, ChainTxReceipt, error) {
	ownerNorm, err := NormalizeAddress(in.OwnerAddress)
	if err != nil {
		return nil, ChainTxReceipt{}, fmt.Errorf("%w: ownerAddress: %v", ErrInvalidRequest, err)
	}
	ctrlAddr, err := AddressFromCompressedPubKeyHex(in.ControllerPubKey)
	if err != nil {
		return nil, ChainTxReceipt{}, fmt.Errorf("%w: controllerPubKey: %v", ErrInvalidRequest, err)
	}
	if in.ControllerAddress != "" && !SameAddress(in.ControllerAddress, ctrlAddr) {
		return nil, ChainTxReceipt{}, fmt.Errorf("%w: controllerAddress %s does not match controllerPubKey %s", ErrInvalidRequest, in.ControllerAddress, ctrlAddr)
	}
	paymentNorm := ""
	if strings.TrimSpace(in.PaymentWallet) != "" {
		paymentNorm, err = NormalizeAddress(in.PaymentWallet)
		if err != nil {
			return nil, ChainTxReceipt{}, fmt.Errorf("%w: paymentWallet: %v", ErrInvalidRequest, err)
		}
	}
	if strings.TrimSpace(in.MetadataURI) == "" {
		return nil, ChainTxReceipt{}, fmt.Errorf("%w: metadataUri is required", ErrInvalidRequest)
	}
	if in.Version == 0 {
		in.Version = 1
	}
	if in.Status == "" {
		in.Status = StatusActive
	}
	if in.Status != StatusActive && in.Status != StatusSuspended && in.Status != StatusRevoked {
		return nil, ChainTxReceipt{}, fmt.Errorf("%w: invalid status %q", ErrInvalidRequest, in.Status)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if in.ChainID == 0 {
		in.ChainID = r.domain.ChainID
	}
	if in.ChainID != r.domain.ChainID {
		return nil, ChainTxReceipt{}, fmt.Errorf("%w: chainId %d does not match registry chainId %d", ErrInvalidRequest, in.ChainID, r.domain.ChainID)
	}
	if in.RegistryAddress == "" {
		in.RegistryAddress = r.domain.VerifyingContract
	}
	if !SameAddress(in.RegistryAddress, r.domain.VerifyingContract) {
		return nil, ChainTxReceipt{}, fmt.Errorf("%w: registryAddress mismatch", ErrInvalidRequest)
	}

	in.OwnerAddress = ownerNorm
	in.ControllerAddress = ctrlAddr
	in.PaymentWallet = paymentNorm
	in.RegistryAddress = r.domain.VerifyingContract

	digest := in.RegistrationDigest(r.domain)
	if err := VerifySigner(digest, in.OwnerSignature, ownerNorm); err != nil {
		return nil, ChainTxReceipt{}, err
	}

	tokenID := r.nextTokenID
	if in.TokenID != 0 {
		if _, exists := r.byTokenID[in.TokenID]; exists {
			return nil, ChainTxReceipt{}, ErrAgentAlreadyExists
		}
		tokenID = in.TokenID
		if tokenID >= r.nextTokenID {
			r.nextTokenID = tokenID + 1
		}
	} else {
		r.nextTokenID++
	}

	now := r.clock()
	agentID := CanonicalAgentID(r.domain.ChainID, r.domain.VerifyingContract, tokenID)
	stored := cloneAgent(&in)
	stored.TokenID = tokenID
	stored.AgentID = agentID
	if stored.RegisteredAt == 0 {
		stored.RegisteredAt = now
	}
	stored.UpdatedAt = now
	stored.Capabilities = sortedCopy(stored.Capabilities)

	tx := r.appendTxLocked("register_agent", ownerNorm, agentID, GasRegisterAgent, digest[:])
	stored.RegistrationTxHash = tx.TxHash

	r.agents[agentID] = stored
	r.byTokenID[tokenID] = agentID
	r.byOwner[ownerNorm] = append(r.byOwner[ownerNorm], agentID)

	return cloneAgent(stored), tx, nil
}

// UpdateAgent updates an existing ERC-8004 agent's metadata, capabilities, MCP/A2A endpoints,
// or lifecycle status with an owner EIP-712 signature and strictly increasing Version.
func (r *IdentityRegistry) UpdateAgent(in AgentIdentity) (*AgentIdentity, ChainTxReceipt, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	cur, ok := r.agents[in.AgentID]
	if !ok {
		return nil, ChainTxReceipt{}, ErrAgentNotFound
	}
	if in.Version <= cur.Version {
		return nil, ChainTxReceipt{}, fmt.Errorf("%w: update version %d must exceed current version %d", ErrInvalidRequest, in.Version, cur.Version)
	}
	if !SameAddress(in.OwnerAddress, cur.OwnerAddress) {
		return nil, ChainTxReceipt{}, ErrUnauthorizedSigner
	}
	ctrlAddr, err := AddressFromCompressedPubKeyHex(in.ControllerPubKey)
	if err != nil {
		return nil, ChainTxReceipt{}, fmt.Errorf("%w: controllerPubKey: %v", ErrInvalidRequest, err)
	}
	in.ChainID = r.domain.ChainID
	in.RegistryAddress = r.domain.VerifyingContract
	in.OwnerAddress = cur.OwnerAddress
	in.ControllerAddress = ctrlAddr
	if in.PaymentWallet != "" {
		normPay, err := NormalizeAddress(in.PaymentWallet)
		if err != nil {
			return nil, ChainTxReceipt{}, fmt.Errorf("%w: paymentWallet: %v", ErrInvalidRequest, err)
		}
		in.PaymentWallet = normPay
	}

	digest := in.RegistrationDigest(r.domain)
	if err := VerifySigner(digest, in.OwnerSignature, cur.OwnerAddress); err != nil {
		return nil, ChainTxReceipt{}, err
	}

	updated := cloneAgent(&in)
	updated.TokenID = cur.TokenID
	updated.AgentID = cur.AgentID
	updated.RevocationEpoch = cur.RevocationEpoch
	updated.RegisteredAt = cur.RegisteredAt
	updated.UpdatedAt = r.clock()
	updated.Capabilities = sortedCopy(updated.Capabilities)

	tx := r.appendTxLocked("update_agent", cur.OwnerAddress, cur.AgentID, GasUpdateAgent, digest[:])
	updated.RegistrationTxHash = tx.TxHash
	r.agents[cur.AgentID] = updated
	return cloneAgent(updated), tx, nil
}

// GetAgent returns a defensive copy of the registered AgentIdentity.
func (r *IdentityRegistry) GetAgent(agentID string) (*AgentIdentity, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ag, ok := r.agents[agentID]
	if !ok {
		return nil, ErrAgentNotFound
	}
	return cloneAgent(ag), nil
}

// ListAgents returns all registered agents ordered deterministically by TokenID.
func (r *IdentityRegistry) ListAgents() []*AgentIdentity {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*AgentIdentity, 0, len(r.agents))
	for _, ag := range r.agents {
		out = append(out, cloneAgent(ag))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TokenID < out[j].TokenID })
	return out
}

// DiscoverByCapability returns active agents matching an optional capability and/or protocol ("mcp", "a2a").
func (r *IdentityRegistry) DiscoverByCapability(capability, protocol string) []*AgentIdentity {
	r.mu.RLock()
	defer r.mu.RUnlock()

	wantCap := strings.ToLower(strings.TrimSpace(capability))
	wantProto := strings.ToLower(strings.TrimSpace(protocol))

	var out []*AgentIdentity
	for _, ag := range r.agents {
		if ag.Status != StatusActive {
			continue
		}
		if wantCap != "" && !hasCapability(ag, wantCap) {
			continue
		}
		if wantProto != "" && !hasProtocol(ag, wantProto) {
			continue
		}
		out = append(out, cloneAgent(ag))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TokenID < out[j].TokenID })
	return out
}

func hasCapability(ag *AgentIdentity, want string) bool {
	for _, c := range ag.Capabilities {
		if strings.ToLower(strings.TrimSpace(c)) == want {
			return true
		}
	}
	for _, ep := range ag.MCPEndpoints {
		for _, c := range ep.Capabilities {
			if strings.ToLower(strings.TrimSpace(c)) == want {
				return true
			}
		}
	}
	for _, ep := range ag.A2AEndpoints {
		for _, c := range ep.Capabilities {
			if strings.ToLower(strings.TrimSpace(c)) == want {
				return true
			}
		}
	}
	return false
}

func hasProtocol(ag *AgentIdentity, proto string) bool {
	if proto == "mcp" && len(ag.MCPEndpoints) > 0 {
		return true
	}
	if proto == "a2a" && len(ag.A2AEndpoints) > 0 {
		return true
	}
	for _, ep := range ag.MCPEndpoints {
		if strings.ToLower(ep.Protocol) == proto {
			return true
		}
	}
	for _, ep := range ag.A2AEndpoints {
		if strings.ToLower(ep.Protocol) == proto {
			return true
		}
	}
	return false
}

// VerifyCredentialOffline cryptographically verifies a SignedCredential with ZERO registry
// or Hanzo infrastructure dependency.
func VerifyCredentialOffline(cred SignedCredential, domain EIP712Domain, now int64) error {
	if strings.TrimSpace(cred.CredentialID) == "" || strings.TrimSpace(cred.AgentID) == "" || strings.TrimSpace(cred.ClaimType) == "" {
		return fmt.Errorf("%w: credential missing required fields", ErrInvalidRequest)
	}
	if cred.ExpiresAt > 0 && now > cred.ExpiresAt {
		return ErrCredentialExpired
	}
	if _, err := NormalizeAddress(cred.IssuerAddress); err != nil {
		return fmt.Errorf("%w: issuerAddress: %v", ErrInvalidRequest, err)
	}
	if _, err := NormalizeAddress(cred.SubjectAddress); err != nil {
		return fmt.Errorf("%w: subjectAddress: %v", ErrInvalidRequest, err)
	}
	digest := cred.Digest(domain)
	return VerifySigner(digest, cred.Signature, cred.IssuerAddress)
}

// RegisterCredential verifies and stores a SignedCredential for an existing active agent.
func (r *IdentityRegistry) RegisterCredential(cred SignedCredential) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	ag, ok := r.agents[cred.AgentID]
	if !ok {
		return ErrAgentNotFound
	}
	if ag.Status != StatusActive {
		return ErrAgentInactive
	}
	if err := VerifyCredentialOffline(cred, r.domain, r.clock()); err != nil {
		return err
	}
	cred.IssuerAddress, _ = NormalizeAddress(cred.IssuerAddress)
	cred.SubjectAddress, _ = NormalizeAddress(cred.SubjectAddress)
	r.credentials[cred.CredentialID] = cloneCredential(cred)
	return nil
}

// ValidateDelegationOffline verifies a DelegationGrant's ID integrity, expiration, and
// EIP-712 OwnerSignature without contacting any remote service.
func ValidateDelegationOffline(grant DelegationGrant, expectedOwner string, domain EIP712Domain, now int64) error {
	if strings.TrimSpace(grant.AgentID) == "" || strings.TrimSpace(grant.TaskScope) == "" {
		return fmt.Errorf("%w: delegation missing agentId or taskScope", ErrInvalidRequest)
	}
	if len(grant.AllowedTools) == 0 {
		return fmt.Errorf("%w: delegation must explicitly allowlist at least one tool", ErrInvalidRequest)
	}
	if len(grant.AllowedResources) == 0 {
		return fmt.Errorf("%w: delegation must explicitly scope at least one resource", ErrInvalidRequest)
	}
	if grant.ExpiresAt <= grant.IssuedAt {
		return fmt.Errorf("%w: delegation expiresAt must exceed issuedAt", ErrInvalidRequest)
	}
	if now > grant.ExpiresAt {
		return ErrDelegationExpired
	}
	ownerNorm, err := NormalizeAddress(grant.OwnerAddress)
	if err != nil {
		return fmt.Errorf("%w: ownerAddress: %v", ErrInvalidRequest, err)
	}
	if expectedOwner != "" && !SameAddress(ownerNorm, expectedOwner) {
		return ErrUnauthorizedSigner
	}
	delegateNorm, err := NormalizeAddress(grant.DelegateAddress)
	if err != nil {
		return fmt.Errorf("%w: delegateAddress: %v", ErrInvalidRequest, err)
	}
	if grant.DelegatePubKey != "" {
		derived, err := AddressFromCompressedPubKeyHex(grant.DelegatePubKey)
		if err != nil || !SameAddress(derived, delegateNorm) {
			return fmt.Errorf("%w: delegatePubKey does not match delegateAddress", ErrInvalidRequest)
		}
	}
	expectedID := grant.ComputeID()
	if grant.DelegationID != expectedID {
		return fmt.Errorf("%w: delegationId mismatch (got %s, want %s)", ErrInvalidRequest, grant.DelegationID, expectedID)
	}
	digest := grant.Digest(domain)
	return VerifySigner(digest, grant.OwnerSignature, ownerNorm)
}

// RegisterDelegation validates and registers a bounded DelegationGrant on the test chain.
func (r *IdentityRegistry) RegisterDelegation(grant DelegationGrant) (ChainTxReceipt, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	ag, ok := r.agents[grant.AgentID]
	if !ok {
		return ChainTxReceipt{}, ErrAgentNotFound
	}
	if ag.Status != StatusActive {
		return ChainTxReceipt{}, ErrAgentInactive
	}
	if err := ValidateDelegationOffline(grant, ag.OwnerAddress, r.domain, r.clock()); err != nil {
		return ChainTxReceipt{}, err
	}
	if grant.RevocationEpoch < ag.RevocationEpoch {
		return ChainTxReceipt{}, ErrRevocationEpochStale
	}
	if _, revoked := r.revocations[grant.DelegationID]; revoked {
		return ChainTxReceipt{}, ErrDelegationRevoked
	}
	if _, exists := r.delegations[grant.DelegationID]; exists {
		return ChainTxReceipt{}, ErrReplayDetected
	}

	stored := cloneDelegation(&grant)
	stored.OwnerAddress, _ = NormalizeAddress(grant.OwnerAddress)
	stored.DelegateAddress, _ = NormalizeAddress(grant.DelegateAddress)
	stored.AllowedTools = sortedCopy(grant.AllowedTools)
	stored.AllowedResources = sortedCopy(grant.AllowedResources)

	digest := stored.Digest(r.domain)
	tx := r.appendTxLocked("register_delegation", stored.OwnerAddress, stored.DelegationID, GasRegisterDelegation, digest[:])
	r.delegations[stored.DelegationID] = stored
	return tx, nil
}

// GetDelegation retrieves a registered delegation grant by ID.
func (r *IdentityRegistry) GetDelegation(delegationID string) (*DelegationGrant, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	g, ok := r.delegations[delegationID]
	if !ok {
		return nil, ErrDelegationNotFound
	}
	return cloneDelegation(g), nil
}

// RevokeDelegation immediately invalidates a compromised or unneeded delegation in O(1).
// Subsequent tool, sandbox, and payment checks fail closed with zero stale grace window.
func (r *IdentityRegistry) RevokeDelegation(agentID, delegationID, ownerSig string, nonce uint64) (ChainTxReceipt, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	ag, ok := r.agents[agentID]
	if !ok {
		return ChainTxReceipt{}, ErrAgentNotFound
	}
	if g, exists := r.delegations[delegationID]; exists && g.AgentID != agentID {
		return ChainTxReceipt{}, fmt.Errorf("%w: delegation %s does not belong to agent %s", ErrUnauthorizedSigner, delegationID, agentID)
	}
	if used := r.revokedNonce[agentID]; used != nil && used[nonce] {
		return ChainTxReceipt{}, ErrReplayDetected
	}
	digest := RevocationDigest(r.domain, agentID, delegationID, nonce)
	if err := VerifySigner(digest, ownerSig, ag.OwnerAddress); err != nil {
		return ChainTxReceipt{}, err
	}
	if r.revokedNonce[agentID] == nil {
		r.revokedNonce[agentID] = make(map[uint64]bool)
	}
	r.revokedNonce[agentID][nonce] = true

	tx := r.appendTxLocked("revoke_delegation", ag.OwnerAddress, delegationID, GasRevokeDelegation, digest[:])
	r.revocations[delegationID] = RevocationRecord{
		DelegationID: delegationID,
		AgentID:      agentID,
		OwnerAddress: ag.OwnerAddress,
		RevokedAt:    r.clock(),
		Nonce:        nonce,
		OwnerSig:     ownerSig,
		TxHash:       tx.TxHash,
	}
	return tx, nil
}

// BumpRevocationEpoch atomically invalidates every delegation for agentID issued with
// a lower RevocationEpoch in O(1) storage.
func (r *IdentityRegistry) BumpRevocationEpoch(agentID string, newEpoch uint64, ownerSig string) (ChainTxReceipt, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	ag, ok := r.agents[agentID]
	if !ok {
		return ChainTxReceipt{}, ErrAgentNotFound
	}
	if newEpoch <= ag.RevocationEpoch {
		return ChainTxReceipt{}, fmt.Errorf("%w: newEpoch %d must exceed current epoch %d", ErrInvalidRequest, newEpoch, ag.RevocationEpoch)
	}
	digest := EpochBumpDigest(r.domain, agentID, newEpoch)
	if err := VerifySigner(digest, ownerSig, ag.OwnerAddress); err != nil {
		return ChainTxReceipt{}, err
	}
	ag.RevocationEpoch = newEpoch
	ag.UpdatedAt = r.clock()
	return r.appendTxLocked("bump_revocation_epoch", ag.OwnerAddress, agentID, GasBumpEpoch, digest[:]), nil
}

// IsRevoked performs a live O(1) check of whether a delegation is explicitly revoked,
// superseded by the agent's revocation epoch, or belongs to a non-active agent.
func (r *IdentityRegistry) IsRevoked(delegationID, agentID string, grantEpoch uint64) (bool, string) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if _, revoked := r.revocations[delegationID]; revoked {
		return true, "explicit_delegation_revoked"
	}
	ag, ok := r.agents[agentID]
	if !ok {
		return true, "agent_not_found"
	}
	if ag.Status != StatusActive {
		return true, "agent_inactive"
	}
	if grantEpoch < ag.RevocationEpoch {
		return true, "revocation_epoch_stale"
	}
	return false, ""
}

// RecordExternalTx appends a verified transaction (such as reputation feedback) to the
// deterministic test-chain log and advances the state root.
func (r *IdentityRegistry) RecordExternalTx(action, actor, subjectID string, gasUsed uint64, commitment []byte) ChainTxReceipt {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.appendTxLocked(action, actor, subjectID, gasUsed, commitment)
}

func (r *IdentityRegistry) appendTxLocked(action, actor, subjectID string, gasUsed uint64, commitment []byte) ChainTxReceipt {
	r.blockNumber++
	now := r.clock()
	txDigest := Keccak256Bytes(
		r.stateRoot[:],
		uint64Bytes(r.blockNumber),
		[]byte(action),
		[]byte(strings.ToLower(actor)),
		[]byte(subjectID),
		uint64Bytes(gasUsed),
		commitment,
	)
	txHash := "0x" + hex.EncodeToString(txDigest[:])
	r.stateRoot = Keccak256Bytes(r.stateRoot[:], uint64Bytes(r.blockNumber), txDigest[:])
	receipt := ChainTxReceipt{
		TxHash:      txHash,
		BlockNumber: r.blockNumber,
		Timestamp:   now,
		Action:      action,
		Actor:       actor,
		SubjectID:   subjectID,
		GasUsed:     gasUsed,
		StateRoot:   "0x" + hex.EncodeToString(r.stateRoot[:]),
	}
	r.txLog = append(r.txLog, receipt)
	return receipt
}

// ExportSnapshot exports all registry state (optionally joined with reputation receipts &
// feedback) into a sovereign, self-verifying StateSnapshot.
func (r *IdentityRegistry) ExportSnapshot(rep *ReputationRegistry) *StateSnapshot {
	r.mu.RLock()
	agents := make([]AgentIdentity, 0, len(r.agents))
	for _, ag := range r.agents {
		agents = append(agents, *cloneAgent(ag))
	}
	sort.Slice(agents, func(i, j int) bool { return agents[i].TokenID < agents[j].TokenID })

	creds := make([]SignedCredential, 0, len(r.credentials))
	for _, c := range r.credentials {
		creds = append(creds, cloneCredential(c))
	}
	sort.Slice(creds, func(i, j int) bool { return creds[i].CredentialID < creds[j].CredentialID })

	dels := make([]DelegationGrant, 0, len(r.delegations))
	for _, g := range r.delegations {
		dels = append(dels, *cloneDelegation(g))
	}
	sort.Slice(dels, func(i, j int) bool { return dels[i].DelegationID < dels[j].DelegationID })

	revs := make([]RevocationRecord, 0, len(r.revocations))
	for _, rv := range r.revocations {
		revs = append(revs, rv)
	}
	sort.Slice(revs, func(i, j int) bool { return revs[i].DelegationID < revs[j].DelegationID })

	txs := make([]ChainTxReceipt, len(r.txLog))
	copy(txs, r.txLog)

	snap := &StateSnapshot{
		FormatVersion: "erc8004-snapshot/v1",
		Domain:        r.domain,
		BlockNumber:   r.blockNumber,
		ExportedAt:    r.clock(),
		StateRoot:     "0x" + hex.EncodeToString(r.stateRoot[:]),
		Agents:        agents,
		Credentials:   creds,
		Delegations:   dels,
		Revocations:   revs,
		TxLog:         txs,
	}
	r.mu.RUnlock()

	if rep != nil {
		snap.WorkReceipts, snap.Feedback = rep.exportAll()
	}
	return snap
}

// WriteSnapshotJSONL streams the exported state as newline-delimited JSON records
// (header + typed entity records) for portable archival, auditing, and migration.
func WriteSnapshotJSONL(w io.Writer, snap *StateSnapshot) error {
	if snap == nil {
		return fmt.Errorf("%w: nil snapshot", ErrInvalidRequest)
	}
	enc := json.NewEncoder(w)
	type jsonlRow struct {
		Type string `json:"type"`
		Data any    `json:"data"`
	}
	header := map[string]any{
		"formatVersion": snap.FormatVersion,
		"domain":        snap.Domain,
		"blockNumber":   snap.BlockNumber,
		"exportedAt":    snap.ExportedAt,
		"stateRoot":     snap.StateRoot,
	}
	if err := enc.Encode(jsonlRow{Type: "header", Data: header}); err != nil {
		return err
	}
	for _, a := range snap.Agents {
		if err := enc.Encode(jsonlRow{Type: "agent", Data: a}); err != nil {
			return err
		}
	}
	for _, c := range snap.Credentials {
		if err := enc.Encode(jsonlRow{Type: "credential", Data: c}); err != nil {
			return err
		}
	}
	for _, d := range snap.Delegations {
		if err := enc.Encode(jsonlRow{Type: "delegation", Data: d}); err != nil {
			return err
		}
	}
	for _, rv := range snap.Revocations {
		if err := enc.Encode(jsonlRow{Type: "revocation", Data: rv}); err != nil {
			return err
		}
	}
	for _, wr := range snap.WorkReceipts {
		if err := enc.Encode(jsonlRow{Type: "work_receipt", Data: wr}); err != nil {
			return err
		}
	}
	for _, fb := range snap.Feedback {
		if err := enc.Encode(jsonlRow{Type: "feedback", Data: fb}); err != nil {
			return err
		}
	}
	for _, tx := range snap.TxLog {
		if err := enc.Encode(jsonlRow{Type: "tx", Data: tx}); err != nil {
			return err
		}
	}
	return nil
}

// ReadSnapshotJSONL decodes a JSONL-exported snapshot back into a StateSnapshot.
func ReadSnapshotJSONL(r io.Reader) (*StateSnapshot, error) {
	snap := &StateSnapshot{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var env struct {
			Type string          `json:"type"`
			Data json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(line, &env); err != nil {
			return nil, fmt.Errorf("%w: jsonl decode: %v", ErrInvalidRequest, err)
		}
		switch env.Type {
		case "header":
			var h struct {
				FormatVersion string       `json:"formatVersion"`
				Domain        EIP712Domain `json:"domain"`
				BlockNumber   uint64       `json:"blockNumber"`
				ExportedAt    int64        `json:"exportedAt"`
				StateRoot     string       `json:"stateRoot"`
			}
			if err := json.Unmarshal(env.Data, &h); err != nil {
				return nil, err
			}
			snap.FormatVersion = h.FormatVersion
			snap.Domain = h.Domain
			snap.BlockNumber = h.BlockNumber
			snap.ExportedAt = h.ExportedAt
			snap.StateRoot = h.StateRoot
		case "agent":
			var a AgentIdentity
			if err := json.Unmarshal(env.Data, &a); err != nil {
				return nil, err
			}
			snap.Agents = append(snap.Agents, a)
		case "credential":
			var c SignedCredential
			if err := json.Unmarshal(env.Data, &c); err != nil {
				return nil, err
			}
			snap.Credentials = append(snap.Credentials, c)
		case "delegation":
			var d DelegationGrant
			if err := json.Unmarshal(env.Data, &d); err != nil {
				return nil, err
			}
			snap.Delegations = append(snap.Delegations, d)
		case "revocation":
			var rv RevocationRecord
			if err := json.Unmarshal(env.Data, &rv); err != nil {
				return nil, err
			}
			snap.Revocations = append(snap.Revocations, rv)
		case "work_receipt":
			var wr WorkReceipt
			if err := json.Unmarshal(env.Data, &wr); err != nil {
				return nil, err
			}
			snap.WorkReceipts = append(snap.WorkReceipts, wr)
		case "feedback":
			var fb ReputationFeedback
			if err := json.Unmarshal(env.Data, &fb); err != nil {
				return nil, err
			}
			snap.Feedback = append(snap.Feedback, fb)
		case "tx":
			var tx ChainTxReceipt
			if err := json.Unmarshal(env.Data, &tx); err != nil {
				return nil, err
			}
			snap.TxLog = append(snap.TxLog, tx)
		default:
			return nil, fmt.Errorf("%w: unknown jsonl record type %q", ErrInvalidRequest, env.Type)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return snap, nil
}

// VerifySnapshotOffline independently verifies every cryptographic signature, receipt hash,
// revocation proof, and chained state root in an exported snapshot with zero network or
// Hanzo dependency.
func VerifySnapshotOffline(snap *StateSnapshot) error {
	if snap == nil {
		return fmt.Errorf("%w: nil snapshot", ErrSnapshotTampered)
	}
	root := domainGenesis(snap.Domain)
	for _, tx := range snap.TxLog {
		txBytes, err := decodeHex(tx.TxHash)
		if err != nil || len(txBytes) != 32 {
			return fmt.Errorf("%w: invalid tx hash %q", ErrSnapshotTampered, tx.TxHash)
		}
		root = Keccak256Bytes(root[:], uint64Bytes(tx.BlockNumber), txBytes)
		wantRoot := "0x" + hex.EncodeToString(root[:])
		if !strings.EqualFold(wantRoot, tx.StateRoot) {
			return fmt.Errorf("%w: tx %s state root mismatch (computed %s, got %s)", ErrSnapshotTampered, tx.TxHash, wantRoot, tx.StateRoot)
		}
	}
	if !strings.EqualFold("0x"+hex.EncodeToString(root[:]), snap.StateRoot) {
		return fmt.Errorf("%w: final state root mismatch", ErrSnapshotTampered)
	}

	owners := make(map[string]string, len(snap.Agents))
	for _, ag := range snap.Agents {
		digest := ag.RegistrationDigest(snap.Domain)
		if err := VerifySigner(digest, ag.OwnerSignature, ag.OwnerAddress); err != nil {
			return fmt.Errorf("%w: agent %s signature: %v", ErrSnapshotTampered, ag.AgentID, err)
		}
		owners[ag.AgentID] = ag.OwnerAddress
	}
	for _, cred := range snap.Credentials {
		if err := VerifyCredentialOffline(cred, snap.Domain, 0); err != nil {
			return fmt.Errorf("%w: credential %s: %v", ErrSnapshotTampered, cred.CredentialID, err)
		}
	}
	for _, g := range snap.Delegations {
		owner, ok := owners[g.AgentID]
		if !ok {
			return fmt.Errorf("%w: delegation %s references unknown agent %s", ErrSnapshotTampered, g.DelegationID, g.AgentID)
		}
		if err := ValidateDelegationOffline(g, owner, snap.Domain, g.IssuedAt); err != nil {
			return fmt.Errorf("%w: delegation %s: %v", ErrSnapshotTampered, g.DelegationID, err)
		}
	}
	for _, rv := range snap.Revocations {
		owner, ok := owners[rv.AgentID]
		if !ok {
			return fmt.Errorf("%w: revocation %s references unknown agent %s", ErrSnapshotTampered, rv.DelegationID, rv.AgentID)
		}
		digest := RevocationDigest(snap.Domain, rv.AgentID, rv.DelegationID, rv.Nonce)
		if err := VerifySigner(digest, rv.OwnerSig, owner); err != nil {
			return fmt.Errorf("%w: revocation %s signature: %v", ErrSnapshotTampered, rv.DelegationID, err)
		}
	}
	receiptByHash := make(map[string]WorkReceipt, len(snap.WorkReceipts))
	for _, wr := range snap.WorkReceipts {
		if err := VerifyWorkReceiptOffline(wr, snap.Domain); err != nil {
			return fmt.Errorf("%w: work receipt %s: %v", ErrSnapshotTampered, wr.ReceiptID, err)
		}
		receiptByHash[strings.ToLower(wr.WorkReceiptHash)] = wr
	}
	for _, fb := range snap.Feedback {
		wr, ok := receiptByHash[strings.ToLower(fb.WorkReceiptHash)]
		if !ok {
			return fmt.Errorf("%w: feedback %s missing matching paid work receipt %s", ErrSnapshotTampered, fb.FeedbackID, fb.WorkReceiptHash)
		}
		if err := VerifyFeedbackOffline(fb, wr, snap.Domain); err != nil {
			return fmt.Errorf("%w: feedback %s: %v", ErrSnapshotTampered, fb.FeedbackID, err)
		}
	}
	return nil
}

// ImportSnapshot verifies an exported snapshot offline and reconstructs a fully operational
// independent IdentityRegistry + ReputationRegistry pair for chain/operator migration.
func ImportSnapshot(snap *StateSnapshot, clock Clock) (*IdentityRegistry, *ReputationRegistry, error) {
	if err := VerifySnapshotOffline(snap); err != nil {
		return nil, nil, err
	}
	reg := NewIdentityRegistry(snap.Domain, clock)
	reg.blockNumber = snap.BlockNumber
	rootBytes, err := decodeHex(snap.StateRoot)
	if err != nil || len(rootBytes) != 32 {
		return nil, nil, ErrSnapshotTampered
	}
	copy(reg.stateRoot[:], rootBytes)

	var maxToken uint64
	for _, ag := range snap.Agents {
		cp := cloneAgent(&ag)
		reg.agents[cp.AgentID] = cp
		reg.byTokenID[cp.TokenID] = cp.AgentID
		reg.byOwner[cp.OwnerAddress] = append(reg.byOwner[cp.OwnerAddress], cp.AgentID)
		if cp.TokenID > maxToken {
			maxToken = cp.TokenID
		}
	}
	reg.nextTokenID = maxToken + 1
	for _, cred := range snap.Credentials {
		reg.credentials[cred.CredentialID] = cloneCredential(cred)
	}
	for _, del := range snap.Delegations {
		cp := cloneDelegation(&del)
		reg.delegations[cp.DelegationID] = cp
	}
	for _, rv := range snap.Revocations {
		reg.revocations[rv.DelegationID] = rv
		if reg.revokedNonce[rv.AgentID] == nil {
			reg.revokedNonce[rv.AgentID] = make(map[uint64]bool)
		}
		reg.revokedNonce[rv.AgentID][rv.Nonce] = true
	}
	reg.txLog = append([]ChainTxReceipt(nil), snap.TxLog...)

	rep := NewReputationRegistry(reg)
	for _, wr := range snap.WorkReceipts {
		rep.importWorkReceipt(wr)
	}
	for _, fb := range snap.Feedback {
		rep.importFeedback(fb)
	}
	return reg, rep, nil
}

// BytesSlice helper for [32]byte without polluting exported API.
func (d EIP712Domain) genesisRoot() [32]byte {
	return domainGenesis(d)
}

func cloneAgent(a *AgentIdentity) *AgentIdentity {
	cp := *a
	cp.Capabilities = append([]string(nil), a.Capabilities...)
	cp.MCPEndpoints = cloneEndpoints(a.MCPEndpoints)
	cp.A2AEndpoints = cloneEndpoints(a.A2AEndpoints)
	return &cp
}

func cloneCredential(c SignedCredential) SignedCredential {
	cp := c
	cp.Capabilities = append([]string(nil), c.Capabilities...)
	cp.MCPEndpoints = cloneEndpoints(c.MCPEndpoints)
	cp.A2AEndpoints = cloneEndpoints(c.A2AEndpoints)
	return cp
}

func cloneDelegation(g *DelegationGrant) *DelegationGrant {
	cp := *g
	cp.AllowedTools = append([]string(nil), g.AllowedTools...)
	cp.AllowedResources = append([]string(nil), g.AllowedResources...)
	return &cp
}

func cloneEndpoints(in []EndpointDescriptor) []EndpointDescriptor {
	if len(in) == 0 {
		return nil
	}
	out := make([]EndpointDescriptor, len(in))
	for i, ep := range in {
		ep.Capabilities = append([]string(nil), ep.Capabilities...)
		out[i] = ep
	}
	return out
}

// FormatTokenID returns a decimal string for token ID formatting convenience.
func FormatTokenID(id uint64) string {
	return strconv.FormatUint(id, 10)
}
