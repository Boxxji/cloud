package meter

// usage.go — what a metered act is: who is asked, what is debited, and the words a
// refusal is told in. These are the meter's own contract; the books that answer
// them are a [Ledger] a deployment registers.

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/hanzoai/decimal"
	hz "github.com/hanzoai/money"
)

// OnCapError, when set, is called (best-effort) whenever the cap check reaches no
// verdict — a timeout, an unreachable commerce, an enforced cap whose spend cannot be
// read. The request is then refused; the hook lets the host log it without this leaf
// package taking a logger. nil = no-op.
var OnCapError func(error)

// ErrInsufficientBalance is returned by Authorize when commerce confirms the
// user's available balance is non-positive. It is distinct from a connectivity
// failure so callers can map it to HTTP 402 (vs 503 for "unknown").
var ErrInsufficientBalance = errors.New("metering: insufficient balance")

// ErrSpendCapExceeded is returned by Authorize when the caller is FUNDED but a
// configured per-scope spend cap (issue #70) would be exceeded by this request.
// It is DISTINCT from ErrInsufficientBalance: the balance is fine, the tenant's
// own policy ceiling is not — callers map it to a 402 spend_cap_exceeded, not the
// out-of-funds insufficient_balance.
var ErrSpendCapExceeded = errors.New("metering: spend cap exceeded")

// ErrSpendCapUnknown is returned by Authorize when the caller is FUNDED but the spend
// cap could not be checked: commerce did not answer, the check ran out of time, or an
// enforced cap's spend could not be read. A cap nobody could read is not a cap that
// allows, so under the fail-closed posture the request is refused (HTTP 503
// spend_cap_unavailable, retry). An org with no cap is never this: commerce answers
// allow without reading any spend.
var ErrSpendCapUnknown = errors.New("metering: spend cap could not be read")

// AuthInput identifies who to authorize.
//
// (Org, User) IS THE MONEY'S ADDRESS: Org names the LEDGER that holds the balance,
// User the ACCOUNT within it. Both halves are resolved by the ONE rule —
// principal.WalletOf, which is hanzoai/account.Payer — and a caller passes what it
// resolved, never a re-derivation of its own.
//
// User is therefore the payer's SUBJECT, not "the org slug". For a pooled tenant
// the two coincide, because Payer answers the org itself and finance reads the org
// pool from a bare slug — which is why "User is always the org" held for years and
// why it was wrong: in the shared signup org, whose members are strangers to each
// other, Payer answers "<org>/<name>" and the pool is a balance that member neither
// owns nor can spend. A gate keyed on the org there checks a pool while the debit
// spends a person, and sdk/meter/wallet.go catalogues what that costs.
//
// A caller that legitimately holds only an org — a resource meter billing an org's
// build minutes, say — passes the org and gets the pool; that is the same rule,
// answered for an org credential, not an exception to it.
//
// Actor is the full "org/sub" identity (e.g. "hanzo/alice") recorded on the usage
// transaction for the audit trail. It is ATTRIBUTION ONLY: for a machine key the
// payer is the org while the actor is the key, so the two axes are never each other.
//
// Currency defaults to "usd".
type AuthInput struct {
	User     string
	Actor    string
	Org      string
	Currency string
	// Amount, when non-zero, gates on available >= Amount instead of the bare
	// available > 0. Use it to authorize a known up-front charge (e.g. the first
	// hour of a machine) so a 1-cent balance cannot green-light an arbitrarily
	// expensive request. Zero preserves the "any positive balance" gate.
	//
	// It is the exact, typed value — the same one Usage.Amount carries, at the
	// ledger's own 18-decimal precision — so the gate and the debit that follows
	// it weigh the SAME number. A cents-rounded gate admitted a charge the debit
	// then wrote in full, which is how a sub-cent price gets authorized against a
	// figure nobody spent.
	Amount hz.Amount

	// AmountCents is the same charge in whole cents, for the HTTP path to
	// commerce and for callers that have not got a typed value. Amount wins when
	// both are set.
	AmountCents int64

	// Project and Service scope the per-scope spend cap + rate limit (issue #70).
	// Service is server-derived (route/provider). Empty = the org-wide default
	// scope. Forwarded to commerce so the right scope cap is resolved; they never
	// change which BALANCE is gated — that is the address (Org, User), always.
	Project string
	Service string

	// ProjectValidated reports whether Project is bound to a VALIDATED identity
	// claim. When false, commerce DEGRADES a project-scoped hard cap to a soft warn
	// (records + warns, never 402) so a forgeable X-Project-Id can neither hard-stop
	// nor be evaded. The org and service axes are always validated. Today IAM mints
	// no project claim, so cloud sends false; when it does, cloud sends true and
	// project caps auto-harden.
	ProjectValidated bool
}

// Verdict is the full gate outcome AuthorizeVerdict returns, so a gate can render
// the distinct denial shapes AND emit the soft-warn header from ONE round trip.
//
//	Allow=true,  Reason="",                     WarnPct=p  -> allow; if p>0 emit X-Spend-Warn.
//	Allow=false, Reason="insufficient_balance"             -> 402 out of funds.
//	Allow=false, Reason="spend_cap", Cap/Spent            -> 402 spend cap exceeded.
type Verdict struct {
	Allow      bool
	Reason     string // "", "insufficient_balance", "spend_cap"
	WarnPct    int
	CapCents   int64
	SpentCents int64
}

// ScopeRule is one scope's rate-limit config, consumed by the cloud
// ScopeRateLimit middleware. Only rows with a positive RateLimitRpm are returned.
//
// The rows are READ over the internal plane (client.FinanceScopeRules), not over
// this client: the reader is an edge middleware, and a GET /v1/billing/alerts
// through the commerce transport re-dispatched the whole shared app back through
// that same middleware until the depth guard 502'd. This type is the shape the
// limiter keeps; the wire that fills it is the socket.
type ScopeRule struct {
	Project      string
	Service      string
	RateLimitRpm int
}

// Usage is one usage event to record. The amount (the cost to debit) is the
// essential beside the billing key (User); the rest is descriptive metadata
// commerce stores on the transaction.
//
// Amount is the debit as an exact hanzoai/money Amount — the canonical, typed value,
// native 18-decimal USD (the co-resident finance ledger's precision). One typed
// value, no precedence rules: a caller that has the exact cost (zen, which
// prices per token at 18-dp) sets Amount directly and the co-resident path
// debits it with NO rounding. The legacy int64 wire fields (AmountCents,
// AmountMicros) remain only for the HTTP path to commerce and for older callers
// that build a Usage without a typed Amount; from them Record reconstructs the
// same Amount. Amount, when non-zero, always wins.
type Usage struct {
	User     string `json:"user"`            // the ACCOUNT half of the debit's address (see AuthInput.User) — a pooled org's slug, or the payer subject the gate authorized.
	Actor    string `json:"actor,omitempty"` // org/sub identity for the audit trail (commerce ignores unknown fields today; forward-compatible).
	Org      string `json:"-"`               // routed via X-Org-Id, not the body.
	Currency string `json:"currency,omitempty"`

	// Amount is the exact debit, typed. Not serialized: the co-resident finance
	// path reads it directly; the HTTP path derives the wire fields below from it.
	Amount hz.Amount `json:"-"`

	// AmountCents is the debit in whole cents (legacy wire field). Set by older
	// callers and by Record when serializing a typed Amount for commerce. When
	// Amount is set, this is ignored on the co-resident path.
	AmountCents int64 `json:"amount"`
	// AmountMicros is the debit in micro-USD (1e6 = $1), sub-cent precision for the
	// HTTP path so a tiny per-call cost is not lost to cent rounding. Commerce
	// prefers it over AmountCents (usage.go: effMicros); when set, AmountCents may
	// be 0. Zero/absent → commerce falls back to AmountCents*10000. Ignored on the
	// co-resident path when Amount is set.
	AmountMicros int64 `json:"amountMicros,omitempty"`

	Model    string `json:"model,omitempty"`
	Provider string `json:"provider,omitempty"`
	// Project and Service attribute this debit to a scope so commerce records the
	// dimensions the per-scope spend cap sums over (issue #70). Empty = the
	// org-wide default scope.
	Project          string `json:"project,omitempty"`
	Service          string `json:"service,omitempty"`
	PromptTokens     int    `json:"promptTokens,omitempty"`
	CompletionTokens int    `json:"completionTokens,omitempty"`
	TotalTokens      int    `json:"totalTokens,omitempty"`
	// RequestID is the request's CORRELATION id — the X-Request-Id a caller sent or the
	// edge minted, carried so a debit can be traced back to the call that made it. It is
	// attribution and nothing else; the ledger's idempotency key is [Usage.Ref], which
	// the server mints and no caller can choose. See [Usage.Seal].
	RequestID string `json:"requestId,omitempty"`
	// Ref is the SERVER's name for the metered act this Usage records, and the ledger's
	// idempotency key for its debit. It never crosses the wire inbound and no caller can
	// choose it: [Usage.Seal] mints it, once, when the act is fixed for recording.
	//
	// A caller that already HOLDS a server-assigned identity for the act — a message
	// row's id, an x402 settlement id, a domain registration ref — sets it instead, and
	// that identity is what makes the act's own retry exactly-once.
	Ref      string `json:"-"`
	Premium  bool   `json:"premium,omitempty"`
	Stream   bool   `json:"stream,omitempty"`
	Status   string `json:"status,omitempty"`
	ClientIP string `json:"clientIp,omitempty"`
	// Cash says the debit draws from the wallet's cash alone: the usage policy refused
	// granted credit for what was bought (the ledger input's Cash).
	Cash bool `json:"cash,omitempty"`
	// Cost is what serving the call cost the platform, exact (the ledger input's Cost).
	Cost hz.Amount `json:"-"`
	// Class is the model's usage class: premium, ours or free.
	Class string `json:"class,omitempty"`
	// Units is the work served, in the unit the call is priced in; zero reads
	// TotalTokens.
	Units int64 `json:"units,omitempty"`
	// PaidBy is who pays (plan or hanzo): plan or hanzo move no money and are counted.
	PaidBy string `json:"paidBy,omitempty"`
	// Key is the API key the call arrived on, "<org>/<id>": attribution beside Actor, kept
	// in the usage log so a charge names its key as well as its person.
	Key string `json:"key,omitempty"`
}

// Seal fixes this usage event's identity, once.
//
// A metered act needs a name the SERVER chose, because the ledger dedups on that name
// and the payer must not be the one who picks it. Seal is where the name is minted, and
// it is IDEMPOTENT: sealing a Usage that already carries a Ref returns it unchanged.
//
// That is the whole of the exactly-once contract, and both halves matter:
//
//   - STABLE across a retry of ONE act. Seal before the hand-off and the sealed value IS
//     the act; recording it again — a re-send after a lost reply, a re-run of a queued
//     debit — finds the same ref and moves the money once.
//   - DISTINCT across DIFFERENT acts. Two calls are two Usage values and two seals, so
//     two inferences bill twice however identical their fields, and however hard a
//     caller pins its X-Request-Id.
//
// [Client.Record] seals what it is given, so a caller that does not retry need not think
// about it; a caller that DOES retry seals first and holds the sealed value.
func (u Usage) Seal() Usage {
	if u.Ref == "" {
		u.Ref = mintRef()
	}
	return u
}

// mintRef is a fresh act name: 128 random bits, stdlib only — the same idiom the ledger
// mints its own entry ids with, so a usage ref reads the same wherever it was born.
// Exhausted entropy is not a reason to bill twice, so a failed read yields no name and
// the ledger mints the entry's own (a single, additive debit).
func mintRef() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	return "act_" + hex.EncodeToString(b[:])
}

// Clone returns a Usage that OWNS every string it carries.
//
// A Usage assembled inside a request handler routinely carries zero-copy views
// into the server's reused request arena: c.User(), c.RequestID() and the
// forwarded client IP are header reads that alias fasthttp's buffer, and that
// buffer is handed to the NEXT request on the same connection the instant the
// handler returns. Retaining such a Usage past its handler is a use-after-free
// whose symptom is not a crash — it is another caller's bytes marshalled onto
// this caller's debit, on a connection two tenants took turns on.
//
// So anything that retains a Usage clones it first. cloud.Meter.Record records on a
// background goroutine and clones there, once, rather than each of its callers
// having to remember.
func (u Usage) Clone() Usage {
	u.User = strings.Clone(u.User)
	u.Actor = strings.Clone(u.Actor)
	u.Org = strings.Clone(u.Org)
	u.Currency = strings.Clone(u.Currency)
	u.Model = strings.Clone(u.Model)
	u.Provider = strings.Clone(u.Provider)
	u.Project = strings.Clone(u.Project)
	u.Service = strings.Clone(u.Service)
	u.RequestID = strings.Clone(u.RequestID)
	u.Ref = strings.Clone(u.Ref)
	u.Status = strings.Clone(u.Status)
	u.ClientIP = strings.Clone(u.ClientIP)
	u.Class = strings.Clone(u.Class)
	u.PaidBy = strings.Clone(u.PaidBy)
	u.Key = strings.Clone(u.Key)
	return u
}

// Money is the charge this gate weighs. Amount wins; otherwise the int64 wire field
// is reconstructed, so a caller that has not got a typed value still gates. Zero means
// "any positive balance", the gate's behaviour when no specific charge is named.
func (in AuthInput) Money() hz.Amount {
	if !in.Amount.IsZero() {
		return in.Amount
	}
	if in.AmountCents > 0 {
		return hz.New(decimal.New(in.AmountCents, 2), hz.USD)
	}
	return hz.Zero(hz.USD)
}

// Money is the debit this Usage carries, as the one exact value — resolving the
// precedence the type documents: the typed Amount when set, else micro-USD, else
// whole cents.
//
// It is EXPORTED because "is there anything to bill here?" is the same question
// wherever it is asked, and asking it any other way gets a different answer. The
// resource meter asked it as `AmountCents <= 0 && AmountMicros <= 0` and so
// dropped, silently and before Record ever saw it, every usage priced only as a
// typed Amount — which is exactly the shape a per-token 18-dp caller sends. Money
// billed nobody and appeared nowhere: not an error, not a log, no row.
//
// One question, one answer, one place. A caller that needs the value and a caller
// that only needs to know whether there IS one both read this.
func (u Usage) Money() hz.Amount {
	if !u.Amount.IsZero() {
		return u.Amount
	}
	if u.AmountMicros > 0 {
		// micro-USD (1e6 = $1).
		return hz.New(decimal.New(u.AmountMicros, 6), hz.USD)
	}
	if u.AmountCents > 0 {
		return hz.New(decimal.New(u.AmountCents, 2), hz.USD)
	}
	return hz.Zero(hz.USD)
}

// WorkUnits is the work a call served: Units when the caller named it, else its tokens.
func (u Usage) WorkUnits() int64 {
	if u.Units != 0 {
		return u.Units
	}
	return int64(u.TotalTokens)
}

// RecordResult is the commerce response to a usage write.
type RecordResult struct {
	TransactionID string `json:"transactionId"`
	User          string `json:"user"`
	Amount        int64  `json:"amount"`
	Currency      string `json:"currency"`
	Type          string `json:"type"`
}

// CurrencyOr is cur, or "usd" when it is blank.
func CurrencyOr(cur string) string {
	if cur = strings.TrimSpace(cur); cur != "" {
		return cur
	}
	return "usd"
}
