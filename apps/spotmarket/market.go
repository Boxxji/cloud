// SPDX-License-Identifier: Apache-2.0 OR MIT

package spotmarket

import (
	"encoding/hex"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
)

// Config controls verification, collateral slashing, anti-Sybil limits, and
// decentralized operation for a Market instance.
type Config struct {
	// VerifySignatures enforces EIP-2 low-S secp256k1 signature verification
	// on all offers and bids. Default true; only disabled in explicit negative-
	// control benchmarks.
	VerifySignatures bool

	// EnforceSlashing enforces minimum provider collateral bonds, strict agreed-
	// price billing, and SLA-breach / bait-and-switch bond slashing. Default true.
	EnforceSlashing bool

	// MaxPendingBidsPerProviderPerOrder caps how many bids a single provider may
	// submit against one Order to prevent Sybil/spam flooding. Default 1.
	MaxPendingBidsPerProviderPerOrder int

	// MinBondBPS is the minimum provider collateral required per bid as basis
	// points of maximum bid value (e.g. 2500 = 25%). Default 2500.
	MinBondBPS int

	// VerificationCostPerSigMicroUSD is the explicitly metered compute cost per
	// cryptographic verification operation in microdollars. Default 2 (0.000002 USD).
	VerificationCostPerSigMicroUSD int64

	// SettlementCostPerReceiptMicroUSD is the explicitly metered ledger clearing
	// overhead per settlement receipt in microdollars. Default 5 (0.000005 USD).
	SettlementCostPerReceiptMicroUSD int64

	// HanzoControlPlaneDisabled models full decentralized operation with all
	// Hanzo-operated infrastructure unreachable. The protocol never calls Hanzo
	// infrastructure in either mode (HanzoCalls == 0).
	HanzoControlPlaneDisabled bool
}

// DefaultConfig returns production-safe fail-closed defaults for the open spot market.
func DefaultConfig() Config {
	return Config{
		VerifySignatures:                  true,
		EnforceSlashing:                   true,
		MaxPendingBidsPerProviderPerOrder: 1,
		MinBondBPS:                        2500,
		VerificationCostPerSigMicroUSD:    2,
		SettlementCostPerReceiptMicroUSD:  5,
		HanzoControlPlaneDisabled:         true,
	}
}

// ComputeTokenCostMicroUSD calculates the exact integer microdollar cost for
// `tokens` billed at `microUSDPer1M` microdollars per 1,000,000 tokens without
// risking int64 overflow or floating-point rounding drift.
func ComputeTokenCostMicroUSD(tokens int64, microUSDPer1M int64) int64 {
	if tokens <= 0 || microUSDPer1M <= 0 {
		return 0
	}
	q := tokens / 1_000_000
	r := tokens % 1_000_000
	return q*microUSDPer1M + (r*microUSDPer1M+999_999)/1_000_000
}

// Market is a self-contained, thread-safe reverse-auction GPU spot market,
// escrow/bond ledger, Enso telemetry tracker, and permissionless peer registry.
type Market struct {
	mu  sync.RWMutex
	cfg Config

	// Offers, orders, bids, leases, and receipts
	offers          map[string]SignedOffer
	orders          map[string]Order
	orderCleared    map[string]bool
	bidsByOrder     map[string][]SignedBid
	bidByID         map[string]SignedBid
	leases          map[string]*Lease
	receipts        map[string]SettlementReceipt
	receiptOrder    []string
	leaseOrder      []string
	telemetry       map[string]ProviderTelemetry
	peers           map[string]PeerNode
	activeSlotsUsed map[string]int

	// Anti-replay & anti-Sybil tracking
	usedOfferNonces map[string]map[uint64]struct{}
	usedBidNonces   map[string]map[uint64]struct{}
	orderProvBids   map[string]map[string]int

	// Exact integer microdollar accounting
	buyerBalances          map[string]int64
	buyerEscrow            map[string]int64
	providerBalances       map[string]int64
	providerLockedBonds    map[string]int64
	totalDepositedMicroUSD int64

	// Metering & decentralization counters
	sigVerifications   atomic.Int64
	hanzoCalls         atomic.Int64
	leaseSeq           int64
	receiptSeq         int64
	verificationCostMu int64
}

// NewMarket initializes a new standalone spot market with the supplied config.
func NewMarket(cfg Config) *Market {
	if cfg.MaxPendingBidsPerProviderPerOrder <= 0 {
		cfg.MaxPendingBidsPerProviderPerOrder = 1
	}
	if cfg.MinBondBPS < 0 {
		cfg.MinBondBPS = 0
	}
	return &Market{
		cfg:                 cfg,
		offers:              make(map[string]SignedOffer),
		orders:              make(map[string]Order),
		orderCleared:        make(map[string]bool),
		bidsByOrder:         make(map[string][]SignedBid),
		bidByID:             make(map[string]SignedBid),
		leases:              make(map[string]*Lease),
		receipts:            make(map[string]SettlementReceipt),
		telemetry:           make(map[string]ProviderTelemetry),
		peers:               make(map[string]PeerNode),
		activeSlotsUsed:     make(map[string]int),
		usedOfferNonces:     make(map[string]map[uint64]struct{}),
		usedBidNonces:       make(map[string]map[uint64]struct{}),
		orderProvBids:       make(map[string]map[string]int),
		buyerBalances:       make(map[string]int64),
		buyerEscrow:         make(map[string]int64),
		providerBalances:    make(map[string]int64),
		providerLockedBonds: make(map[string]int64),
	}
}

// Config returns the active market configuration.
func (m *Market) Config() Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg
}

// HanzoCalls returns the number of calls made to Hanzo-operated infrastructure.
// In the decentralized spot market protocol this is always 0.
func (m *Market) HanzoCalls() int64 {
	return m.hanzoCalls.Load()
}

// SignatureVerifications returns the cumulative count of cryptographic
// signature verifications performed by the market.
func (m *Market) SignatureVerifications() int64 {
	return m.sigVerifications.Load()
}

// TotalVerificationCostMicroUSD returns cumulative explicitly metered
// cryptographic verification overhead in microdollars.
func (m *Market) TotalVerificationCostMicroUSD() int64 {
	return m.sigVerifications.Load() * m.cfg.VerificationCostPerSigMicroUSD
}

// DepositBuyer credits a buyer's integer microdollar ledger balance.
func (m *Market) DepositBuyer(buyerID string, microUSD int64) error {
	if buyerID == "" || microUSD <= 0 {
		return ErrInsufficientBalance
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.buyerBalances[buyerID] += microUSD
	m.totalDepositedMicroUSD += microUSD
	return nil
}

// DepositProvider credits a provider's integer microdollar collateral balance.
func (m *Market) DepositProvider(providerID string, microUSD int64) error {
	if providerID == "" || microUSD <= 0 {
		return ErrInsufficientBalance
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.providerBalances[providerID] += microUSD
	m.totalDepositedMicroUSD += microUSD
	return nil
}

// BuyerBalance returns a buyer's available and escrowed microdollar balances.
func (m *Market) BuyerBalance(buyerID string) (available int64, escrowed int64) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.buyerBalances[buyerID], m.buyerEscrow[buyerID]
}

// ProviderBalance returns a provider's available and locked-bond balances.
func (m *Market) ProviderBalance(providerID string) (available int64, lockedBond int64) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.providerBalances[providerID], m.providerLockedBonds[providerID]
}

// LedgerSnapshot returns an immutable copy of all ledger accounts along with
// the exact conservation drift (which must always be 0).
func (m *Market) LedgerSnapshot() LedgerSnapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.ledgerSnapshotLocked()
}

func (m *Market) ledgerSnapshotLocked() LedgerSnapshot {
	snap := LedgerSnapshot{
		BuyerBalances:          copyInt64Map(m.buyerBalances),
		BuyerEscrow:            copyInt64Map(m.buyerEscrow),
		ProviderBalances:       copyInt64Map(m.providerBalances),
		ProviderLockedBonds:    copyInt64Map(m.providerLockedBonds),
		TotalDepositedMicroUSD: m.totalDepositedMicroUSD,
	}
	var sum int64
	for _, v := range snap.BuyerBalances {
		sum += v
	}
	for _, v := range snap.BuyerEscrow {
		sum += v
	}
	for _, v := range snap.ProviderBalances {
		sum += v
	}
	for _, v := range snap.ProviderLockedBonds {
		sum += v
	}
	snap.ConservationDrift = sum - snap.TotalDepositedMicroUSD
	return snap
}

// CheckConservation validates that total balances across buyer available,
// buyer escrow, provider available, and provider locked bonds equal total
// deposited funds with zero microdollar drift.
func (m *Market) CheckConservation() error {
	snap := m.LedgerSnapshot()
	if snap.ConservationDrift != 0 {
		return fmt.Errorf("%w: drift=%d microUSD", ErrLedgerDrift, snap.ConservationDrift)
	}
	return nil
}

// RegisterPeer adds or updates a permissionless peer node in the local gossip
// registry.
func (m *Market) RegisterPeer(peer PeerNode) error {
	if peer.PeerID == "" || peer.Endpoint == "" {
		return fmt.Errorf("spotmarket: peer requires id and endpoint")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	regions := append([]string(nil), peer.Regions...)
	sort.Strings(regions)
	peer.Regions = regions
	m.peers[peer.PeerID] = peer
	return nil
}

// RegisterOffer validates and indexes a provider's SignedOffer.
func (m *Market) RegisterOffer(so SignedOffer, nowUnix int64) error {
	o := so.Offer
	if o.OfferID == "" || o.ProviderID == "" || o.Hardware.GPUModel == "" || len(o.SupportedModels) == 0 {
		return ErrInvalidOffer
	}
	if o.Pricing.MicroUSDPer1MTokens <= 0 || o.Hardware.AvailableVRAMGB <= 0 || o.AvailableSlots <= 0 {
		return ErrInvalidOffer
	}
	if o.ExpiresAtUnix <= nowUnix {
		return ErrExpiredOffer
	}

	if m.cfg.VerifySignatures {
		m.sigVerifications.Add(1)
		if err := VerifySignedOffer(so); err != nil {
			return err
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cfg.VerifySignatures {
		if seen, ok := m.usedOfferNonces[o.ProviderPubKeyHex]; ok {
			if _, dup := seen[o.Nonce]; dup {
				return ErrReplayNonce
			}
		} else {
			m.usedOfferNonces[o.ProviderPubKeyHex] = make(map[uint64]struct{})
		}
		m.usedOfferNonces[o.ProviderPubKeyHex][o.Nonce] = struct{}{}
	}

	// Copy slice for immutability
	models := append([]string(nil), o.SupportedModels...)
	sort.Strings(models)
	so.Offer.SupportedModels = models
	m.offers[o.OfferID] = so

	if _, exists := m.telemetry[o.ProviderID]; !exists {
		ttft := float64(o.SLO.TargetTTFTMs)
		if ttft <= 0 {
			ttft = 180.0
		}
		m.telemetry[o.ProviderID] = ProviderTelemetry{
			ProviderID:        o.ProviderID,
			MeasuredTTFTMs:    ttft,
			MeasuredLatencyMs: ttft * 3.0,
			MeasuredTokPerSec: o.SLO.MinThroughputTokPerSec,
			ReliabilityBPS:    9000,
		}
	}
	return nil
}

// ListOffers returns active non-expired offers sorted deterministically by OfferID.
func (m *Market) ListOffers(nowUnix int64) []SignedOffer {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]SignedOffer, 0, len(m.offers))
	for _, so := range m.offers {
		if so.Offer.ExpiresAtUnix > nowUnix {
			out = append(out, so)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Offer.OfferID < out[j].Offer.OfferID
	})
	return out
}

// SubmitOrder registers a buyer's auction order and locks its escrow in the ledger.
func (m *Market) SubmitOrder(order Order, nowUnix int64) error {
	if order.OrderID == "" || order.BuyerID == "" || order.Model == "" || order.RequestedTokens <= 0 || order.MaxMicroUSDPer1MTokens <= 0 {
		return ErrInvalidOrder
	}
	if order.ExpiresAtUnix <= nowUnix {
		return ErrExpiredOrder
	}
	minEscrow := ComputeTokenCostMicroUSD(order.RequestedTokens, order.MaxMicroUSDPer1MTokens)
	if order.EscrowMicroUSD == 0 {
		order.EscrowMicroUSD = minEscrow
	}
	if order.EscrowMicroUSD < minEscrow {
		return fmt.Errorf("%w: escrow %d < required ceiling %d", ErrInsufficientBalance, order.EscrowMicroUSD, minEscrow)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if _, dup := m.orders[order.OrderID]; dup {
		return fmt.Errorf("%w: duplicate order %s", ErrInvalidOrder, order.OrderID)
	}
	if m.buyerBalances[order.BuyerID] < order.EscrowMicroUSD {
		return fmt.Errorf("%w: buyer %s balance %d < escrow %d", ErrInsufficientBalance, order.BuyerID, m.buyerBalances[order.BuyerID], order.EscrowMicroUSD)
	}
	m.buyerBalances[order.BuyerID] -= order.EscrowMicroUSD
	m.buyerEscrow[order.BuyerID] += order.EscrowMicroUSD
	m.orders[order.OrderID] = order
	m.orderProvBids[order.OrderID] = make(map[string]int)
	return nil
}

// SubmitBid verifies and accepts a provider's reverse-auction SignedBid against
// an open Order, enforcing signature validity, expiry, replay protection,
// anti-Sybil bid limits, real capacity bounds, and provider collateral bonding.
func (m *Market) SubmitBid(sb SignedBid, nowUnix int64) error {
	b := sb.Bid
	if b.BidID == "" || b.OrderID == "" || b.OfferID == "" || b.ProviderID == "" || b.OfferedTokens <= 0 || b.BidMicroUSDPer1MTokens <= 0 {
		return ErrInvalidBid
	}
	if b.ExpiresAtUnix <= nowUnix {
		return ErrExpiredBid
	}

	if m.cfg.VerifySignatures {
		m.sigVerifications.Add(1)
		if err := VerifySignedBid(sb); err != nil {
			return err
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	order, ok := m.orders[b.OrderID]
	if !ok {
		return fmt.Errorf("%w: order %s", ErrNotFound, b.OrderID)
	}
	if order.ExpiresAtUnix <= nowUnix {
		return ErrExpiredOrder
	}
	if m.orderCleared[b.OrderID] {
		return fmt.Errorf("%w: order %s already cleared", ErrInvalidBid, b.OrderID)
	}
	if _, dup := m.bidByID[b.BidID]; dup {
		return fmt.Errorf("%w: duplicate bid %s", ErrInvalidBid, b.BidID)
	}

	offer, ok := m.offers[b.OfferID]
	if !ok {
		return fmt.Errorf("%w: offer %s", ErrNotFound, b.OfferID)
	}
	if offer.Offer.ExpiresAtUnix <= nowUnix {
		return ErrExpiredOffer
	}
	if offer.Offer.ProviderID != b.ProviderID {
		return fmt.Errorf("%w: bid provider does not match offer provider", ErrInvalidBid)
	}
	if m.cfg.VerifySignatures && offer.Offer.ProviderPubKeyHex != b.ProviderPubKeyHex {
		return fmt.Errorf("%w: bid pubkey does not match offer pubkey", ErrInvalidSignature)
	}

	// Anti-replay nonce check
	if m.cfg.VerifySignatures {
		if seen, exists := m.usedBidNonces[b.ProviderPubKeyHex]; exists {
			if _, dup := seen[b.Nonce]; dup {
				return ErrReplayNonce
			}
		} else {
			m.usedBidNonces[b.ProviderPubKeyHex] = make(map[uint64]struct{})
		}
	}

	// Anti-Sybil per-order bid limit check
	if m.cfg.VerifySignatures {
		if m.orderProvBids[b.OrderID][b.ProviderID] >= m.cfg.MaxPendingBidsPerProviderPerOrder {
			return ErrSybilBidLimit
		}
	}

	// Capacity over-claim check against real unallocated provider slots & VRAM
	freeSlots := offer.Offer.AvailableSlots - m.activeSlotsUsed[b.ProviderID]
	if m.cfg.VerifySignatures {
		if freeSlots <= 0 || b.CommittedVRAMGB > offer.Offer.Hardware.AvailableVRAMGB {
			return ErrCapacityOverclaim
		}
	}

	// Collateral bond lock
	if m.cfg.EnforceSlashing && m.cfg.MinBondBPS > 0 {
		allocCap := b.OfferedTokens
		if allocCap > order.RequestedTokens {
			allocCap = order.RequestedTokens
		}
		bidVal := ComputeTokenCostMicroUSD(allocCap, b.BidMicroUSDPer1MTokens)
		minBond := (bidVal*int64(m.cfg.MinBondBPS) + 9999) / 10000
		if minBond < 1 {
			minBond = 1
		}
		if b.BondMicroUSD < minBond {
			return fmt.Errorf("%w: bond %d < required %d", ErrInsufficientBond, b.BondMicroUSD, minBond)
		}
	}
	if b.BondMicroUSD > 0 {
		if m.providerBalances[b.ProviderID] < b.BondMicroUSD {
			return fmt.Errorf("%w: provider %s balance %d < bond %d", ErrInsufficientBalance, b.ProviderID, m.providerBalances[b.ProviderID], b.BondMicroUSD)
		}
		m.providerBalances[b.ProviderID] -= b.BondMicroUSD
		m.providerLockedBonds[b.ProviderID] += b.BondMicroUSD
	}

	if m.cfg.VerifySignatures {
		m.usedBidNonces[b.ProviderPubKeyHex][b.Nonce] = struct{}{}
	}
	m.orderProvBids[b.OrderID][b.ProviderID]++
	m.bidsByOrder[b.OrderID] = append(m.bidsByOrder[b.OrderID], sb)
	m.bidByID[b.BidID] = sb
	return nil
}

// ClearOrder runs the neutral Enso auction selector across all submitted bids
// for orderID, awards one or more Leases (supporting partial fills across
// multiple providers when enabled), unlocks bonds for non-winning bids, and
// refunds unused buyer escrow.
func (m *Market) ClearOrder(orderID string, nowUnix int64) ([]Lease, []Rejection, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	order, ok := m.orders[orderID]
	if !ok {
		return nil, nil, fmt.Errorf("%w: order %s", ErrNotFound, orderID)
	}
	if m.orderCleared[orderID] {
		return nil, nil, fmt.Errorf("%w: order %s already cleared", ErrInvalidOrder, orderID)
	}

	bids := m.bidsByOrder[orderID]
	candidates := make([]Candidate, 0, len(bids))
	for _, sb := range bids {
		offer, exists := m.offers[sb.Bid.OfferID]
		if !exists {
			continue
		}
		freeSlots := offer.Offer.AvailableSlots - m.activeSlotsUsed[sb.Bid.ProviderID]
		candidates = append(candidates, Candidate{
			SignedBid:   sb,
			SignedOffer: offer,
			Telemetry:   m.telemetry[sb.Bid.ProviderID],
			FreeSlots:   freeSlots,
		})
	}

	if m.cfg.VerifySignatures {
		// Re-verification at clearing time catches any bid/offer mutated in flight.
		m.sigVerifications.Add(int64(len(candidates) * 2))
	}
	ranked, rejections := RankCandidates(order, candidates, nowUnix, m.cfg.VerifySignatures)

	winningBidIDs := make(map[string]bool)
	awarded := make([]Lease, 0)
	remainingTokens := order.RequestedTokens
	remainingEscrow := order.EscrowMicroUSD
	usedProviders := make(map[string]bool)

	for _, rc := range ranked {
		if remainingTokens <= 0 {
			break
		}
		bid := rc.Candidate.SignedBid.Bid
		offer := rc.Candidate.SignedOffer.Offer

		// Avoid double-allocating the same provider twice on one order
		if usedProviders[bid.ProviderID] {
			continue
		}
		if offer.AvailableSlots-m.activeSlotsUsed[bid.ProviderID] <= 0 {
			continue
		}

		alloc := bid.OfferedTokens
		if alloc > remainingTokens {
			alloc = remainingTokens
		}
		if !order.AllowPartialFill && alloc < order.RequestedTokens {
			continue
		}

		leaseCost := ComputeTokenCostMicroUSD(alloc, bid.BidMicroUSDPer1MTokens)
		if leaseCost > remainingEscrow {
			continue
		}

		m.leaseSeq++
		leaseID := fmt.Sprintf("lease-%06d", m.leaseSeq)
		slashBPS := offer.SLO.SlashBPSOnBreach
		if slashBPS <= 0 {
			slashBPS = 5000
		}

		lease := &Lease{
			LeaseID:                   leaseID,
			OrderID:                   order.OrderID,
			BidID:                     bid.BidID,
			OfferID:                   bid.OfferID,
			BuyerID:                   order.BuyerID,
			ProviderID:                bid.ProviderID,
			Status:                    LeaseActive,
			AllocatedTokens:           alloc,
			AgreedMicroUSDPer1MTokens: bid.BidMicroUSDPer1MTokens,
			EscrowLockedMicroUSD:      leaseCost,
			ProviderBondMicroUSD:      bid.BondMicroUSD,
			SlashBPSOnBreach:          slashBPS,
			StartedAtUnix:             nowUnix,
		}
		m.leases[leaseID] = lease
		m.leaseOrder = append(m.leaseOrder, leaseID)
		m.activeSlotsUsed[bid.ProviderID]++
		usedProviders[bid.ProviderID] = true
		winningBidIDs[bid.BidID] = true

		remainingTokens -= alloc
		remainingEscrow -= leaseCost
		awarded = append(awarded, *lease)

		if !order.AllowPartialFill {
			break
		}
	}

	// Unlock bonds for every non-winning bid so zero provider funds remain trapped.
	for _, sb := range bids {
		if !winningBidIDs[sb.Bid.BidID] && sb.Bid.BondMicroUSD > 0 {
			m.providerLockedBonds[sb.Bid.ProviderID] -= sb.Bid.BondMicroUSD
			m.providerBalances[sb.Bid.ProviderID] += sb.Bid.BondMicroUSD
		}
	}

	// Refund unused buyer escrow immediately (price improvement, partial fill, or unfilled).
	if remainingEscrow > 0 {
		m.buyerEscrow[order.BuyerID] -= remainingEscrow
		m.buyerBalances[order.BuyerID] += remainingEscrow
	}

	m.orderCleared[orderID] = true

	if len(awarded) == 0 {
		return nil, rejections, ErrNoEligibleBids
	}
	return awarded, rejections, nil
}

// SettleLease settles an active Lease according to its DeliveryReport, enforces
// agreed pricing and collateral slashing, updates measured Enso telemetry, and
// emits a deterministic SettlementReceipt with exact zero microdollar drift.
func (m *Market) SettleLease(leaseID string, report DeliveryReport, nowUnix int64) (SettlementReceipt, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	lease, ok := m.leases[leaseID]
	if !ok {
		return SettlementReceipt{}, fmt.Errorf("%w: lease %s", ErrNotFound, leaseID)
	}
	if lease.Status != LeaseActive {
		return SettlementReceipt{}, fmt.Errorf("%w: lease %s status=%s", ErrLeaseAlreadySettled, leaseID, lease.Status)
	}

	if m.activeSlotsUsed[lease.ProviderID] > 0 {
		m.activeSlotsUsed[lease.ProviderID]--
	}

	delivered := report.DeliveredTokens
	if delivered < 0 {
		delivered = 0
	}
	if delivered > lease.AllocatedTokens {
		delivered = lease.AllocatedTokens
	}

	baitAndSwitch := report.BaitAndSwitchPriceAttempted ||
		(report.ReportedMicroUSDPer1MTokens > 0 && report.ReportedMicroUSDPer1MTokens > lease.AgreedMicroUSDPer1MTokens)

	var (
		providerPayout int64
		buyerRefund    int64
		slashedBond    int64
		bondReturned   int64
		status         LeaseStatus
		verClass       VerificationClass
	)

	if m.cfg.EnforceSlashing {
		verClass = VerificationEconomicStake
		if baitAndSwitch {
			// Fraudulent post-award price inflation / bait-and-switch: zero payout,
			// full escrow refund to buyer, and 100% bond slash paid to buyer.
			status = LeaseSlashedBaitSwitch
			delivered = 0
			providerPayout = 0
			buyerRefund = lease.EscrowLockedMicroUSD
			slashedBond = lease.ProviderBondMicroUSD
			bondReturned = 0
		} else if !report.Completed || delivered < lease.AllocatedTokens {
			// Mid-lease crash or partial non-delivery: pay only for delivered useful
			// tokens, refund remaining escrow, slash SLA breach bond fraction.
			if delivered > 0 {
				status = LeasePartialCompleted
			} else {
				status = LeaseSlashedNonDelivery
			}
			providerPayout = ComputeTokenCostMicroUSD(delivered, lease.AgreedMicroUSDPer1MTokens)
			if providerPayout > lease.EscrowLockedMicroUSD {
				providerPayout = lease.EscrowLockedMicroUSD
			}
			buyerRefund = lease.EscrowLockedMicroUSD - providerPayout
			slashBPS := lease.SlashBPSOnBreach
			if slashBPS <= 0 {
				slashBPS = 5000
			}
			if slashBPS > 10000 {
				slashBPS = 10000
			}
			slashedBond = (lease.ProviderBondMicroUSD * int64(slashBPS)) / 10000
			bondReturned = lease.ProviderBondMicroUSD - slashedBond
		} else {
			status = LeaseCompleted
			providerPayout = ComputeTokenCostMicroUSD(delivered, lease.AgreedMicroUSDPer1MTokens)
			if providerPayout > lease.EscrowLockedMicroUSD {
				providerPayout = lease.EscrowLockedMicroUSD
			}
			buyerRefund = lease.EscrowLockedMicroUSD - providerPayout
			slashedBond = 0
			bondReturned = lease.ProviderBondMicroUSD
		}
	} else {
		// Negative-control unverified mode (slashing & price-enforcement disabled):
		// dishonest providers can bill inflated prices up to locked escrow and
		// suffer zero bond slashing on non-delivery.
		verClass = VerificationUnverified
		billedRate := lease.AgreedMicroUSDPer1MTokens
		if report.ReportedMicroUSDPer1MTokens > billedRate {
			billedRate = report.ReportedMicroUSDPer1MTokens
		}
		if baitAndSwitch {
			status = LeasePartialCompleted
			providerPayout = lease.EscrowLockedMicroUSD
			buyerRefund = 0
		} else if !report.Completed {
			status = LeaseSlashedNonDelivery
			// Even on crash, unverified settlement fails to claw back partial escrow
			providerPayout = lease.EscrowLockedMicroUSD / 2
			buyerRefund = lease.EscrowLockedMicroUSD - providerPayout
		} else {
			status = LeaseCompleted
			providerPayout = ComputeTokenCostMicroUSD(delivered, billedRate)
			if providerPayout > lease.EscrowLockedMicroUSD {
				providerPayout = lease.EscrowLockedMicroUSD
			}
			buyerRefund = lease.EscrowLockedMicroUSD - providerPayout
		}
		slashedBond = 0
		bondReturned = lease.ProviderBondMicroUSD
	}

	// Execute exact conserving ledger transfers:
	//   BuyerEscrow:        -EscrowLocked
	//   BuyerBalance:       +BuyerRefund + SlashedBond
	//   ProviderLockedBond: -ProviderBond
	//   ProviderBalance:    +ProviderPayout + BondReturned
	// Net delta = -Escrow + (Escrow - Payout) + Slashed - Bond + Payout + (Bond - Slashed) == 0.
	m.buyerEscrow[lease.BuyerID] -= lease.EscrowLockedMicroUSD
	m.buyerBalances[lease.BuyerID] += buyerRefund + slashedBond
	m.providerLockedBonds[lease.ProviderID] -= lease.ProviderBondMicroUSD
	m.providerBalances[lease.ProviderID] += providerPayout + bondReturned

	lease.Status = status
	lease.DeliveredTokens = delivered
	lease.SettledAtUnix = nowUnix

	// Update measured Enso telemetry
	m.updateTelemetryLocked(lease.ProviderID, report, status)

	m.receiptSeq++
	overhead := report.VerificationOverheadMicroUSD
	if overhead == 0 {
		overhead = m.cfg.SettlementCostPerReceiptMicroUSD + 2*m.cfg.VerificationCostPerSigMicroUSD
	}
	rec := SettlementReceipt{
		ReceiptID:                    fmt.Sprintf("rcpt-%06d", m.receiptSeq),
		LeaseID:                      lease.LeaseID,
		OrderID:                      lease.OrderID,
		BidID:                        lease.BidID,
		BuyerID:                      lease.BuyerID,
		ProviderID:                   lease.ProviderID,
		Status:                       status,
		AllocatedTokens:              lease.AllocatedTokens,
		DeliveredTokens:              delivered,
		AgreedMicroUSDPer1MTokens:    lease.AgreedMicroUSDPer1MTokens,
		BuyerEscrowLockedMicroUSD:    lease.EscrowLockedMicroUSD,
		ProviderPayoutMicroUSD:       providerPayout,
		BuyerRefundMicroUSD:          buyerRefund,
		SlashedBondMicroUSD:          slashedBond,
		BondReturnedMicroUSD:         bondReturned,
		VerificationOverheadMicroUSD: overhead,
		VerificationClass:            verClass,
		SettledAtUnix:                nowUnix,
	}
	digest := ReceiptCommitment(rec)
	rec.ReceiptHashHex = hex.EncodeToString(digest[:])
	m.receipts[rec.ReceiptID] = rec
	m.receiptOrder = append(m.receiptOrder, rec.ReceiptID)

	return rec, nil
}

// FailoverLease re-allocates undelivered tokens from a failed or slashed lease
// onto the highest-ranked healthy alternative provider using Enso selection.
func (m *Market) FailoverLease(failedLeaseID string, nowUnix int64) (*Lease, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	failed, ok := m.leases[failedLeaseID]
	if !ok {
		return nil, fmt.Errorf("%w: lease %s", ErrNotFound, failedLeaseID)
	}
	remainingTokens := failed.AllocatedTokens - failed.DeliveredTokens
	if remainingTokens <= 0 {
		return nil, fmt.Errorf("spotmarket: lease %s has no undelivered tokens", failedLeaseID)
	}
	origOrder, ok := m.orders[failed.OrderID]
	if !ok {
		return nil, fmt.Errorf("%w: order %s", ErrNotFound, failed.OrderID)
	}

	failoverOrder := origOrder
	failoverOrder.RequestedTokens = remainingTokens
	failoverOrder.AllowPartialFill = true

	// Build spot failover candidates from active signed offers of OTHER providers.
	candidates := make([]Candidate, 0, len(m.offers))
	for _, so := range m.offers {
		o := so.Offer
		if o.ProviderID == failed.ProviderID {
			continue
		}
		if o.ExpiresAtUnix <= nowUnix {
			continue
		}
		freeSlots := o.AvailableSlots - m.activeSlotsUsed[o.ProviderID]
		if freeSlots <= 0 {
			continue
		}
		// Spot failover uses the provider's already-signed list offer price.
		synthBid := SignedBid{
			Bid: Bid{
				ProtocolVersion:        ProtocolVersion,
				BidID:                  "failover-bid-" + o.OfferID,
				OrderID:                origOrder.OrderID,
				OfferID:                o.OfferID,
				ProviderID:             o.ProviderID,
				ProviderPubKeyHex:      o.ProviderPubKeyHex,
				BidMicroUSDPer1MTokens: o.Pricing.MicroUSDPer1MTokens,
				OfferedTokens:          remainingTokens,
				CommittedVRAMGB:        o.Hardware.AvailableVRAMGB,
				IssuedAtUnix:           o.IssuedAtUnix,
				ExpiresAtUnix:          o.ExpiresAtUnix,
				Nonce:                  o.Nonce,
			},
			VerificationClass: VerificationCryptoSignature,
		}
		candidates = append(candidates, Candidate{
			SignedBid:   synthBid,
			SignedOffer: so,
			Telemetry:   m.telemetry[o.ProviderID],
			FreeSlots:   freeSlots,
		})
	}

	// Verify offer signatures before failover ranking when VerifySignatures is active.
	verifiedCandidates := candidates
	if m.cfg.VerifySignatures {
		verifiedCandidates = make([]Candidate, 0, len(candidates))
		for _, c := range candidates {
			m.sigVerifications.Add(1)
			if err := VerifySignedOffer(c.SignedOffer); err == nil {
				verifiedCandidates = append(verifiedCandidates, c)
			}
		}
	}

	ranked, _ := RankCandidates(failoverOrder, verifiedCandidates, nowUnix, false)
	for _, rc := range ranked {
		offer := rc.Candidate.SignedOffer.Offer
		cost := ComputeTokenCostMicroUSD(remainingTokens, offer.Pricing.MicroUSDPer1MTokens)
		if m.buyerBalances[origOrder.BuyerID] < cost {
			continue
		}
		bond := int64(0)
		if m.cfg.EnforceSlashing && m.cfg.MinBondBPS > 0 {
			bond = (cost*int64(m.cfg.MinBondBPS) + 9999) / 10000
			if bond < 1 {
				bond = 1
			}
			if m.providerBalances[offer.ProviderID] < bond {
				continue
			}
		}

		// Lock buyer escrow & provider bond conserving total balance.
		m.buyerBalances[origOrder.BuyerID] -= cost
		m.buyerEscrow[origOrder.BuyerID] += cost
		if bond > 0 {
			m.providerBalances[offer.ProviderID] -= bond
			m.providerLockedBonds[offer.ProviderID] += bond
		}

		m.leaseSeq++
		newLeaseID := fmt.Sprintf("lease-%06d", m.leaseSeq)
		slashBPS := offer.SLO.SlashBPSOnBreach
		if slashBPS <= 0 {
			slashBPS = 5000
		}
		newLease := &Lease{
			LeaseID:                   newLeaseID,
			OrderID:                   origOrder.OrderID,
			BidID:                     rc.Candidate.SignedBid.Bid.BidID,
			OfferID:                   offer.OfferID,
			BuyerID:                   origOrder.BuyerID,
			ProviderID:                offer.ProviderID,
			Status:                    LeaseActive,
			AllocatedTokens:           remainingTokens,
			AgreedMicroUSDPer1MTokens: offer.Pricing.MicroUSDPer1MTokens,
			EscrowLockedMicroUSD:      cost,
			ProviderBondMicroUSD:      bond,
			SlashBPSOnBreach:          slashBPS,
			StartedAtUnix:             nowUnix,
			FailoverFromLeaseID:       failedLeaseID,
		}
		m.leases[newLeaseID] = newLease
		m.leaseOrder = append(m.leaseOrder, newLeaseID)
		m.activeSlotsUsed[offer.ProviderID]++

		failed.Status = LeaseFailedOver
		cp := *newLease
		return &cp, nil
	}

	return nil, ErrNoEligibleBids
}

// ExpireStale purges expired offers and unlocks bonds on expired uncleared orders.
func (m *Market) ExpireStale(nowUnix int64) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	expired := 0
	for id, so := range m.offers {
		if so.Offer.ExpiresAtUnix <= nowUnix {
			delete(m.offers, id)
			expired++
		}
	}
	for orderID, ord := range m.orders {
		if m.orderCleared[orderID] || ord.ExpiresAtUnix > nowUnix {
			continue
		}
		for _, sb := range m.bidsByOrder[orderID] {
			if sb.Bid.BondMicroUSD > 0 {
				m.providerLockedBonds[sb.Bid.ProviderID] -= sb.Bid.BondMicroUSD
				m.providerBalances[sb.Bid.ProviderID] += sb.Bid.BondMicroUSD
			}
		}
		if ord.EscrowMicroUSD > 0 {
			m.buyerEscrow[ord.BuyerID] -= ord.EscrowMicroUSD
			m.buyerBalances[ord.BuyerID] += ord.EscrowMicroUSD
		}
		m.orderCleared[orderID] = true
		expired++
	}
	return expired
}

// Telemetry returns a copy of a provider's measured telemetry.
func (m *Market) Telemetry(providerID string) (ProviderTelemetry, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t, ok := m.telemetry[providerID]
	return t, ok
}

// Lease returns a copy of a lease by ID.
func (m *Market) Lease(leaseID string) (Lease, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	l, ok := m.leases[leaseID]
	if !ok {
		return Lease{}, false
	}
	return *l, true
}

// Receipts returns all settlement receipts in deterministic issuance order.
func (m *Market) Receipts() []SettlementReceipt {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]SettlementReceipt, 0, len(m.receiptOrder))
	for _, id := range m.receiptOrder {
		out = append(out, m.receipts[id])
	}
	return out
}

func (m *Market) updateTelemetryLocked(providerID string, report DeliveryReport, status LeaseStatus) {
	t := m.telemetry[providerID]
	t.ProviderID = providerID
	t.ObservedSampleCount++

	const alpha = 0.30
	if report.ObservedTTFTMs > 0 {
		if t.ObservedSampleCount == 1 || t.MeasuredTTFTMs <= 0 {
			t.MeasuredTTFTMs = report.ObservedTTFTMs
		} else {
			t.MeasuredTTFTMs = alpha*report.ObservedTTFTMs + (1-alpha)*t.MeasuredTTFTMs
		}
	}
	if report.ObservedLatencyMs > 0 {
		if t.ObservedSampleCount == 1 || t.MeasuredLatencyMs <= 0 {
			t.MeasuredLatencyMs = report.ObservedLatencyMs
		} else {
			t.MeasuredLatencyMs = alpha*report.ObservedLatencyMs + (1-alpha)*t.MeasuredLatencyMs
		}
	}
	if report.ObservedTokPerSec > 0 {
		if t.ObservedSampleCount == 1 || t.MeasuredTokPerSec <= 0 {
			t.MeasuredTokPerSec = report.ObservedTokPerSec
		} else {
			t.MeasuredTokPerSec = alpha*report.ObservedTokPerSec + (1-alpha)*t.MeasuredTokPerSec
		}
	}

	switch status {
	case LeaseCompleted:
		t.CompletedJobs++
	case LeaseSlashedBaitSwitch:
		t.FailedJobs++
		t.SlashedJobs++
	default:
		t.FailedJobs++
		if status == LeaseSlashedNonDelivery {
			t.SlashedJobs++
		}
	}

	// Laplace-smoothed reliability with 4x slash penalty so bait-and-switch or
	// chronically crashing providers are rapidly demoted by Enso.
	const priorSuccess = 9.0
	const priorTotal = 10.0
	num := priorSuccess + float64(t.CompletedJobs)
	den := priorTotal + float64(t.CompletedJobs+t.FailedJobs) + 4.0*float64(t.SlashedJobs)
	rel := int((num / den) * 10000.0)
	if rel < 0 {
		rel = 0
	} else if rel > 10000 {
		rel = 10000
	}
	t.ReliabilityBPS = rel
	m.telemetry[providerID] = t
}

func copyInt64Map(src map[string]int64) map[string]int64 {
	dst := make(map[string]int64, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
