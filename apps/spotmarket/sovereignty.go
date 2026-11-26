// SPDX-License-Identifier: Apache-2.0 OR MIT

package spotmarket

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"sort"

	"github.com/luxfi/crypto/secp256k1"
)

// GossipSnapshot builds a deterministic, permissionless snapshot of active
// peers, signed offers, and measured provider telemetry with a SHA-256 state root.
func (m *Market) GossipSnapshot(nowUnix int64) GossipSnapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.gossipSnapshotLocked(nowUnix)
}

func (m *Market) gossipSnapshotLocked(nowUnix int64) GossipSnapshot {
	peers := make([]PeerNode, 0, len(m.peers))
	for _, p := range m.peers {
		cp := p
		cp.Regions = append([]string(nil), p.Regions...)
		sort.Strings(cp.Regions)
		peers = append(peers, cp)
	}
	sort.Slice(peers, func(i, j int) bool {
		return peers[i].PeerID < peers[j].PeerID
	})

	offers := make([]SignedOffer, 0, len(m.offers))
	for _, so := range m.offers {
		if so.Offer.ExpiresAtUnix > nowUnix {
			cp := so
			cp.Offer.SupportedModels = append([]string(nil), so.Offer.SupportedModels...)
			sort.Strings(cp.Offer.SupportedModels)
			offers = append(offers, cp)
		}
	}
	sort.Slice(offers, func(i, j int) bool {
		return offers[i].Offer.OfferID < offers[j].Offer.OfferID
	})

	telemetry := make(map[string]ProviderTelemetry, len(m.telemetry))
	for k, v := range m.telemetry {
		telemetry[k] = v
	}

	snap := GossipSnapshot{
		ProtocolVersion: ProtocolVersion,
		GeneratedAtUnix: nowUnix,
		Peers:           peers,
		ActiveOffers:    offers,
		Telemetry:       telemetry,
	}
	root := gossipStateRoot(snap)
	snap.StateRootHex = hex.EncodeToString(root[:])
	return snap
}

func gossipStateRoot(s GossipSnapshot) [32]byte {
	var buf bytes.Buffer
	writeLenPrefixed(&buf, "HIP1350:GOSSIP:V1")
	writeLenPrefixed(&buf, s.ProtocolVersion)
	writeInt64(&buf, s.GeneratedAtUnix)

	writeUint64(&buf, uint64(len(s.Peers)))
	for _, p := range s.Peers {
		writeLenPrefixed(&buf, p.PeerID)
		writeLenPrefixed(&buf, p.Endpoint)
		writeLenPrefixed(&buf, p.PubKeyHex)
		writeInt64(&buf, p.LastSeenUnix)
	}

	writeUint64(&buf, uint64(len(s.ActiveOffers)))
	for _, so := range s.ActiveOffers {
		writeLenPrefixed(&buf, so.Offer.OfferID)
		writeLenPrefixed(&buf, so.CommitmentHex)
		writeLenPrefixed(&buf, so.SignatureHex)
	}

	telKeys := make([]string, 0, len(s.Telemetry))
	for k := range s.Telemetry {
		telKeys = append(telKeys, k)
	}
	sort.Strings(telKeys)
	writeUint64(&buf, uint64(len(telKeys)))
	for _, k := range telKeys {
		t := s.Telemetry[k]
		writeLenPrefixed(&buf, t.ProviderID)
		writeUint64(&buf, math.Float64bits(t.MeasuredTTFTMs))
		writeInt64(&buf, t.CompletedJobs)
		writeInt64(&buf, t.FailedJobs)
		writeInt64(&buf, t.SlashedJobs)
		writeInt64(&buf, int64(t.ReliabilityBPS))
	}

	return sha256.Sum256(buf.Bytes())
}

// BundleCommitment computes the deterministic SHA-256 digest of a
// MarketExportBundle covering gossip state, exact ledger balances, leases,
// and settlement receipts.
func BundleCommitment(b MarketExportBundle) [32]byte {
	var buf bytes.Buffer
	writeLenPrefixed(&buf, "HIP1350:EXPORT_BUNDLE:V1")
	writeLenPrefixed(&buf, b.ProtocolVersion)
	writeInt64(&buf, b.ExportedAtUnix)
	writeLenPrefixed(&buf, b.ExporterPubKeyHex)
	writeLenPrefixed(&buf, b.Gossip.StateRootHex)

	// Ledger canonical serialization
	writeInt64(&buf, b.Ledger.TotalDepositedMicroUSD)
	writeInt64(&buf, b.Ledger.ConservationDrift)
	writeSortedInt64Map(&buf, b.Ledger.BuyerBalances)
	writeSortedInt64Map(&buf, b.Ledger.BuyerEscrow)
	writeSortedInt64Map(&buf, b.Ledger.ProviderBalances)
	writeSortedInt64Map(&buf, b.Ledger.ProviderLockedBonds)

	// Leases
	writeUint64(&buf, uint64(len(b.Leases)))
	for _, l := range b.Leases {
		writeLenPrefixed(&buf, l.LeaseID)
		writeLenPrefixed(&buf, l.OrderID)
		writeLenPrefixed(&buf, l.ProviderID)
		writeLenPrefixed(&buf, string(l.Status))
		writeInt64(&buf, l.AllocatedTokens)
		writeInt64(&buf, l.DeliveredTokens)
		writeInt64(&buf, l.EscrowLockedMicroUSD)
		writeInt64(&buf, l.ProviderBondMicroUSD)
	}

	// Receipts
	writeUint64(&buf, uint64(len(b.Receipts)))
	for _, r := range b.Receipts {
		writeLenPrefixed(&buf, r.ReceiptID)
		writeLenPrefixed(&buf, r.ReceiptHashHex)
	}

	return sha256.Sum256(buf.Bytes())
}

func writeSortedInt64Map(buf *bytes.Buffer, m map[string]int64) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	writeUint64(buf, uint64(len(keys)))
	for _, k := range keys {
		writeLenPrefixed(buf, k)
		writeInt64(buf, m[k])
	}
}

// ExportBundle produces a cryptographically signed, self-contained state dump
// so any user or operator can verify, migrate, or fork the entire market
// without upstream Hanzo coordination.
func (m *Market) ExportBundle(signer *secp256k1.PrivateKey, nowUnix int64) (MarketExportBundle, error) {
	if signer == nil {
		return MarketExportBundle{}, ErrInvalidSignature
	}
	m.mu.RLock()
	gossip := m.gossipSnapshotLocked(nowUnix)
	ledger := m.ledgerSnapshotLocked()

	leases := make([]Lease, 0, len(m.leaseOrder))
	for _, id := range m.leaseOrder {
		if l, ok := m.leases[id]; ok {
			leases = append(leases, *l)
		}
	}
	receipts := make([]SettlementReceipt, 0, len(m.receiptOrder))
	for _, id := range m.receiptOrder {
		receipts = append(receipts, m.receipts[id])
	}
	m.mu.RUnlock()

	if ledger.ConservationDrift != 0 {
		return MarketExportBundle{}, fmt.Errorf("%w: drift=%d", ErrLedgerDrift, ledger.ConservationDrift)
	}

	bundle := MarketExportBundle{
		ProtocolVersion:   ProtocolVersion,
		ExportedAtUnix:    nowUnix,
		ExporterPubKeyHex: hex.EncodeToString(signer.PublicKey().Bytes()),
		Gossip:            gossip,
		Ledger:            ledger,
		Leases:            leases,
		Receipts:          receipts,
		VerificationClass: VerificationCryptoSignature,
	}
	digest := BundleCommitment(bundle)
	sig, err := SignDigestLowS(signer, digest)
	if err != nil {
		return MarketExportBundle{}, err
	}
	bundle.CommitmentHex = hex.EncodeToString(digest[:])
	bundle.SignatureHex = hex.EncodeToString(sig[:])
	return bundle, nil
}

// VerifyExportBundle verifies the exporter's EIP-2 low-S secp256k1 signature,
// gossip state root, every included SignedOffer signature, every receipt hash,
// and exact integer ledger conservation (drift == 0).
func VerifyExportBundle(bundle MarketExportBundle) error {
	if bundle.ProtocolVersion != ProtocolVersion {
		return fmt.Errorf("%w: unsupported protocol version %q", ErrInvalidExportBundle, bundle.ProtocolVersion)
	}
	expectedRoot := gossipStateRoot(bundle.Gossip)
	if hex.EncodeToString(expectedRoot[:]) != bundle.Gossip.StateRootHex {
		return fmt.Errorf("%w: gossip state root mismatch", ErrInvalidExportBundle)
	}

	// Verify exact ledger conservation independently
	var sum int64
	for _, v := range bundle.Ledger.BuyerBalances {
		sum += v
	}
	for _, v := range bundle.Ledger.BuyerEscrow {
		sum += v
	}
	for _, v := range bundle.Ledger.ProviderBalances {
		sum += v
	}
	for _, v := range bundle.Ledger.ProviderLockedBonds {
		sum += v
	}
	if sum != bundle.Ledger.TotalDepositedMicroUSD || bundle.Ledger.ConservationDrift != 0 {
		return fmt.Errorf("%w: ledger drift detected (sum=%d deposited=%d)", ErrLedgerDrift, sum, bundle.Ledger.TotalDepositedMicroUSD)
	}

	// Verify every active offer's signature
	for _, so := range bundle.Gossip.ActiveOffers {
		if err := VerifySignedOffer(so); err != nil {
			return fmt.Errorf("%w: offer %s: %v", ErrInvalidExportBundle, so.Offer.OfferID, err)
		}
	}

	// Verify every settlement receipt hash
	for _, r := range bundle.Receipts {
		d := ReceiptCommitment(r)
		if hex.EncodeToString(d[:]) != r.ReceiptHashHex {
			return fmt.Errorf("%w: receipt %s hash mismatch", ErrInvalidExportBundle, r.ReceiptID)
		}
	}

	// Verify exporter commitment & secp256k1 low-S signature
	digest := BundleCommitment(bundle)
	if hex.EncodeToString(digest[:]) != bundle.CommitmentHex {
		return fmt.Errorf("%w: bundle commitment mismatch", ErrInvalidExportBundle)
	}
	pubBytes, err := hex.DecodeString(bundle.ExporterPubKeyHex)
	if err != nil {
		return fmt.Errorf("%w: invalid exporter pubkey hex", ErrInvalidExportBundle)
	}
	sigBytes, err := hex.DecodeString(bundle.SignatureHex)
	if err != nil {
		return fmt.Errorf("%w: invalid exporter signature hex", ErrInvalidExportBundle)
	}
	if err := VerifyDigestLowS(pubBytes, digest, sigBytes); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidExportBundle, err)
	}
	return nil
}

// ImportBundle verifies a signed MarketExportBundle and boots a completely
// independent forked Market instance with zero Hanzo connectivity.
func ImportBundle(bundle MarketExportBundle, cfg Config, nowUnix int64) (*Market, error) {
	if err := VerifyExportBundle(bundle); err != nil {
		return nil, err
	}
	cfg.HanzoControlPlaneDisabled = true
	m := NewMarket(cfg)
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, p := range bundle.Gossip.Peers {
		m.peers[p.PeerID] = p
	}
	for _, so := range bundle.Gossip.ActiveOffers {
		if so.Offer.ExpiresAtUnix > nowUnix {
			m.offers[so.Offer.OfferID] = so
			if _, ok := m.usedOfferNonces[so.Offer.ProviderPubKeyHex]; !ok {
				m.usedOfferNonces[so.Offer.ProviderPubKeyHex] = make(map[uint64]struct{})
			}
			m.usedOfferNonces[so.Offer.ProviderPubKeyHex][so.Offer.Nonce] = struct{}{}
		}
	}
	for k, t := range bundle.Gossip.Telemetry {
		m.telemetry[k] = t
	}

	m.buyerBalances = copyInt64Map(bundle.Ledger.BuyerBalances)
	m.buyerEscrow = copyInt64Map(bundle.Ledger.BuyerEscrow)
	m.providerBalances = copyInt64Map(bundle.Ledger.ProviderBalances)
	m.providerLockedBonds = copyInt64Map(bundle.Ledger.ProviderLockedBonds)
	m.totalDepositedMicroUSD = bundle.Ledger.TotalDepositedMicroUSD

	for _, l := range bundle.Leases {
		cp := l
		m.leases[l.LeaseID] = &cp
		m.leaseOrder = append(m.leaseOrder, l.LeaseID)
		if l.Status == LeaseActive {
			m.activeSlotsUsed[l.ProviderID]++
		}
	}
	m.leaseSeq = int64(len(bundle.Leases))

	for _, r := range bundle.Receipts {
		m.receipts[r.ReceiptID] = r
		m.receiptOrder = append(m.receiptOrder, r.ReceiptID)
	}
	m.receiptSeq = int64(len(bundle.Receipts))

	return m, nil
}
