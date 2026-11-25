// SPDX-License-Identifier: Apache-2.0 OR MIT

package x402

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// NonceClaim uniquely identifies an ERC-3009 authorization across chains, tokens,
// and payers.
type NonceClaim struct {
	Network string `json:"network"`
	Asset   string `json:"asset"`
	From    string `json:"from"`
	Nonce   string `json:"nonce"`
}

// Key returns the canonical lowercase composite key for c.
func (c NonceClaim) Key() string {
	return strings.ToLower(strings.Join([]string{
		strings.TrimSpace(c.Network),
		strings.TrimSpace(c.Asset),
		strings.TrimSpace(c.From),
		strings.TrimSpace(c.Nonce),
	}, "|"))
}

// ReserveOutcome classifies the atomic result of attempting to admit a payment
// authorization and optional Idempotency-Key.
type ReserveOutcome string

const (
	ReserveAdmitted            ReserveOutcome = "admitted"
	ReserveIdempotentHit       ReserveOutcome = "idempotent_hit"
	ReserveIdempotencyMismatch ReserveOutcome = "idempotency_mismatch"
	ReserveIdempotencyInFlight ReserveOutcome = "idempotency_in_flight"
	ReserveNonceReplay         ReserveOutcome = "nonce_replay"
	ReserveNonceInFlight       ReserveOutcome = "nonce_in_flight"
)

// CachedResponse captures the verified answer of a settled request so exact
// idempotent retries return the same answer and receipt without re-charging.
type CachedResponse struct {
	StatusCode            int    `json:"statusCode"`
	ContentType           string `json:"contentType,omitempty"`
	Body                  []byte `json:"body"`
	PaymentResponseHeader string `json:"paymentResponseHeader,omitempty"`
	ReceiptID             string `json:"receiptId,omitempty"`
}

// IdempotencyRecord tracks a single Idempotency-Key across retries.
type IdempotencyRecord struct {
	Key             string          `json:"key"`
	ClaimKey        string          `json:"claimKey"`
	RequestBodyHash string          `json:"requestBodyHash"`
	InFlight        bool            `json:"inFlight"`
	Committed       bool            `json:"committed"`
	Response        *CachedResponse `json:"response,omitempty"`
	UpdatedAt       int64           `json:"updatedAt"`
}

// ReserveResult returns the outcome of NonceReplayStore.Reserve.
type ReserveResult struct {
	Outcome ReserveOutcome
	Cached  *CachedResponse
	Reason  string
}

type nonceJournalEntry struct {
	ClaimKey    string             `json:"claimKey"`
	Idempotency *IdempotencyRecord `json:"idempotency,omitempty"`
	CommittedAt int64              `json:"committedAt"`
}

// MemoryNonceStore is a concurrency-safe NonceReplayStore with optional
// append-only JSONL persistence so spent nonces and idempotent receipts survive
// process restarts without any external centralized service.
type MemoryNonceStore struct {
	mu          sync.Mutex
	inflight    map[string]struct{}
	spent       map[string]int64
	idempotency map[string]*IdempotencyRecord
	journalPath string
	now         func() time.Time
}

// NewMemoryNonceStore creates an in-memory NonceReplayStore.
func NewMemoryNonceStore() *MemoryNonceStore {
	return &MemoryNonceStore{
		inflight:    make(map[string]struct{}),
		spent:       make(map[string]int64),
		idempotency: make(map[string]*IdempotencyRecord),
	}
}

// NewFileNonceStore opens or creates a persistent JSONL-backed NonceReplayStore.
func NewFileNonceStore(path string) (*MemoryNonceStore, error) {
	s := NewMemoryNonceStore()
	s.journalPath = path
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("x402: nonce store dir: %w", err)
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, fmt.Errorf("x402: open nonce store: %w", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var entry nonceJournalEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			return nil, fmt.Errorf("x402: corrupt nonce journal: %w", err)
		}
		if entry.ClaimKey != "" {
			s.spent[entry.ClaimKey] = entry.CommittedAt
		}
		if entry.Idempotency != nil && entry.Idempotency.Key != "" {
			rec := *entry.Idempotency
			rec.InFlight = false
			rec.Committed = true
			s.idempotency[rec.Key] = &rec
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("x402: scan nonce journal: %w", err)
	}
	return s, nil
}

func (s *MemoryNonceStore) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

// Reserve atomically checks idempotency and nonce freshness, admitting at most
// one concurrent execution per ERC-3009 nonce.
func (s *MemoryNonceStore) Reserve(_ context.Context, claim NonceClaim, idempotencyKey, reqBodyHash string) (ReserveResult, error) {
	claimKey := claim.Key()
	idempotencyKey = strings.TrimSpace(idempotencyKey)

	s.mu.Lock()
	defer s.mu.Unlock()

	if idempotencyKey != "" {
		if rec, ok := s.idempotency[idempotencyKey]; ok {
			if rec.RequestBodyHash != reqBodyHash {
				return ReserveResult{
					Outcome: ReserveIdempotencyMismatch,
					Reason:  "idempotency key reused with a different request payload",
				}, nil
			}
			if claimKey != "" && rec.ClaimKey != "" && rec.ClaimKey != claimKey {
				return ReserveResult{
					Outcome: ReserveIdempotencyMismatch,
					Reason:  "idempotency key reused with a different payment authorization",
				}, nil
			}
			if rec.Committed && rec.Response != nil {
				copied := cloneCachedResponse(rec.Response)
				return ReserveResult{
					Outcome: ReserveIdempotentHit,
					Cached:  copied,
				}, nil
			}
			if rec.InFlight {
				return ReserveResult{
					Outcome: ReserveIdempotencyInFlight,
					Reason:  "identical idempotent request is already in flight",
				}, nil
			}
		}
	}

	if _, ok := s.spent[claimKey]; ok {
		return ReserveResult{
			Outcome: ReserveNonceReplay,
			Reason:  "erc3009 authorization nonce already settled",
		}, nil
	}
	if _, busy := s.inflight[claimKey]; busy {
		return ReserveResult{
			Outcome: ReserveNonceInFlight,
			Reason:  "erc3009 authorization nonce already in flight",
		}, nil
	}

	s.inflight[claimKey] = struct{}{}
	if idempotencyKey != "" {
		s.idempotency[idempotencyKey] = &IdempotencyRecord{
			Key:             idempotencyKey,
			ClaimKey:        claimKey,
			RequestBodyHash: reqBodyHash,
			InFlight:        true,
			UpdatedAt:       s.clock().UTC().Unix(),
		}
	}
	return ReserveResult{Outcome: ReserveAdmitted}, nil
}

// Commit marks the ERC-3009 nonce permanently spent and stores the cached
// response for exact idempotent retries.
func (s *MemoryNonceStore) Commit(_ context.Context, claim NonceClaim, idempotencyKey string, cached *CachedResponse) error {
	claimKey := claim.Key()
	idempotencyKey = strings.TrimSpace(idempotencyKey)
	now := s.clock().UTC().Unix()

	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.inflight, claimKey)
	s.spent[claimKey] = now

	var savedRec *IdempotencyRecord
	if idempotencyKey != "" {
		rec, ok := s.idempotency[idempotencyKey]
		if !ok {
			rec = &IdempotencyRecord{
				Key:      idempotencyKey,
				ClaimKey: claimKey,
			}
			s.idempotency[idempotencyKey] = rec
		}
		rec.InFlight = false
		rec.Committed = true
		rec.Response = cloneCachedResponse(cached)
		rec.UpdatedAt = now
		cp := *rec
		cp.Response = cloneCachedResponse(cached)
		savedRec = &cp
	}

	if s.journalPath != "" {
		entry := nonceJournalEntry{
			ClaimKey:    claimKey,
			Idempotency: savedRec,
			CommittedAt: now,
		}
		line, err := json.Marshal(entry)
		if err != nil {
			return fmt.Errorf("x402: marshal nonce journal: %w", err)
		}
		f, err := os.OpenFile(s.journalPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return fmt.Errorf("x402: append nonce journal: %w", err)
		}
		_, werr := f.Write(append(line, '\n'))
		cerr := f.Close()
		if werr != nil {
			return fmt.Errorf("x402: write nonce journal: %w", werr)
		}
		if cerr != nil {
			return fmt.Errorf("x402: close nonce journal: %w", cerr)
		}
	}
	return nil
}

// Release frees an in-flight reservation when verification or inference fails
// prior to settlement so the unspent authorization can still be used.
func (s *MemoryNonceStore) Release(_ context.Context, claim NonceClaim, idempotencyKey string) error {
	claimKey := claim.Key()
	idempotencyKey = strings.TrimSpace(idempotencyKey)

	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.inflight, claimKey)
	if idempotencyKey != "" {
		if rec, ok := s.idempotency[idempotencyKey]; ok && !rec.Committed {
			delete(s.idempotency, idempotencyKey)
		}
	}
	return nil
}

// IsSpent reports whether claim has been committed as settled.
func (s *MemoryNonceStore) IsSpent(_ context.Context, claim NonceClaim) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.spent[claim.Key()]
	return ok
}

// LookupIdempotency returns a copy of the stored IdempotencyRecord if present.
func (s *MemoryNonceStore) LookupIdempotency(_ context.Context, idempotencyKey string) (*IdempotencyRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.idempotency[strings.TrimSpace(idempotencyKey)]
	if !ok {
		return nil, false
	}
	cp := *rec
	cp.Response = cloneCachedResponse(rec.Response)
	return &cp, true
}

func cloneCachedResponse(c *CachedResponse) *CachedResponse {
	if c == nil {
		return nil
	}
	cp := *c
	if c.Body != nil {
		cp.Body = append([]byte(nil), c.Body...)
	}
	return &cp
}
