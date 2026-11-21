package meter

// client.go — the one client every Hanzo surface meters through: check the balance
// before, record the cost after.
//
// The rules a caller can rely on are here, whichever books answer: an act names its
// user and its org or it is refused (an unattributable request must never be gated
// against, or charged to, whoever happens to be the default); a debit is sealed with
// the server's name for the act before it is handed on; a negative debit is refused.
// What the books say about the money is the registered [Ledger]'s.

import (
	"context"
	"fmt"
	"strings"
)

// Client meters usage against a [Ledger]. It is safe for concurrent use.
type Client struct {
	ledger Ledger
}

// New builds a Client over the ledger the deployment registered, opened with cfg.
//
// With none registered: a process that was not told to bill gets [Free]; one that was
// (a named deployment, or cfg.BaseURL) gets a Client that refuses every call with
// [ErrNoDriver], returned beside the error so a caller that checks it fails at boot
// and one that does not fails every billable call.
func New(cfg Config) (*Client, error) {
	open := registered()
	if open == nil {
		if cfg.told() {
			return &Client{ledger: refusing{}}, ErrNoDriver
		}
		return &Client{ledger: free{}}, nil
	}
	l, err := open(cfg)
	if err != nil {
		return nil, err
	}
	return &Client{ledger: l}, nil
}

// Enabled reports whether the books answer from THIS process. False means the ledger
// lives elsewhere, not that nothing bills: the gate and the debit then cross the
// internal plane to the process that owns it.
func (c *Client) Enabled() bool { return c != nil && c.ledger != nil && c.ledger.Enabled() }

// Authorize is the pre-request gate. It is the thin error-mapping wrapper over
// AuthorizeVerdict, preserving the proven three-outcome contract:
//
//	(nil)                       -> allow.
//	(ErrInsufficientBalance)    -> deny: out of funds          (map to HTTP 402).
//	(ErrSpendCapExceeded)       -> deny: funded but over a per-scope cap (HTTP 402
//	                               spend_cap_exceeded — distinct from out-of-funds).
//	(ErrSpendCapUnknown)        -> funded, but the cap could not be read; fail-closed
//	                               denies (HTTP 503 spend_cap_unavailable).
//	(other error)               -> balance unknown; denies      (map to HTTP 503
//	                               balance_unavailable). No switch allows it.
func (c *Client) Authorize(ctx context.Context, in AuthInput) error {
	v, err := c.AuthorizeVerdict(ctx, in)
	if err != nil {
		return err // connectivity/unknown; fail posture already applied inside.
	}
	if v.Allow {
		return nil
	}
	if v.Reason == "spend_cap" {
		return ErrSpendCapExceeded
	}
	return ErrInsufficientBalance
}

// AuthorizeVerdict is the full pre-request gate: it checks FUNDS first and, only
// when funded, the per-scope SPEND CAP verdict, both under the ledger's one fail
// posture. The returned WarnPct (>0 when at/over a covering cap's soft threshold)
// lets the caller emit X-Spend-Warn from this one round trip.
func (c *Client) AuthorizeVerdict(ctx context.Context, in AuthInput) (Verdict, error) {
	// WHO IS ASKING, decided above the topology. Identity is a fact about the
	// caller, not about where the ledger happens to live, so an unattributable
	// request is refused the same on both deployments.
	if strings.TrimSpace(in.User) == "" {
		// No identity -> cannot bill, so it is denied (anonymous traffic must be
		// handled by a public-path bypass before reaching here).
		return Verdict{}, fmt.Errorf("metering: empty user")
	}
	// No LEDGER -> cannot bill either, and there is no default to fall back on: an
	// org-less principal gated against the brand's balance would read a wallet it has
	// no claim on, and every unattributable request in the fleet would be authorized
	// by whatever Hanzo happens to be holding. An unresolvable org refuses; it never
	// charges — or clears — someone else.
	if strings.TrimSpace(in.Org) == "" {
		return Verdict{}, fmt.Errorf("metering: empty org")
	}
	return c.ledger.AuthorizeVerdict(ctx, in)
}

// Balance is the subject's spendable prepaid balance in cents, inside org's books,
// rounded down: it decides admission and nothing is billed from it.
func (c *Client) Balance(ctx context.Context, subject, org, currency string) (int64, error) {
	return c.ledger.Balance(ctx, subject, org, currency)
}

// Record writes a usage event: every served call is counted, a $0 one included, and a
// wallet is debited when the call is the wallet's to pay.
//
// A negative amount is refused. It is a no-op (nil, nil) only on a deployment that
// runs no biller at all — never merely because the ledger is in another process.
// Usage recording is deliberately decoupled from gating: the work already happened
// and must be recorded, so balance is NOT re-checked here.
//
// Provider is the service name doing the metering when no model/provider is
// natural (e.g. "search", "functions"); set it on Usage.Provider.
func (c *Client) Record(ctx context.Context, u Usage) (*RecordResult, error) {
	u, err := c.sealed(u, "Record")
	if err != nil {
		return nil, err
	}
	return c.ledger.Record(ctx, u)
}

// Post records one served call durably and returns: the ledger holds it when Post
// returns nil. A $0 call is counted like any other; a negative one is refused.
func (c *Client) Post(ctx context.Context, u Usage) error {
	u, err := c.sealed(u, "Post")
	if err != nil {
		return err
	}
	return c.ledger.Post(ctx, u)
}

// Drain posts the debits queued for the books until ctx ends. The process that owns
// the books runs it; logf reports what it could not post. A ledger that owns nothing
// queued returns at once.
func (c *Client) Drain(ctx context.Context, logf func(msg string, kv ...any)) {
	if d, ok := c.ledger.(Drainer); ok {
		d.Drain(ctx, logf)
	}
}

// sealed applies the rules every debit meets before it reaches the books.
func (c *Client) sealed(u Usage, verb string) (Usage, error) {
	if amt := u.Money(); amt.Sign() < 0 {
		return u, fmt.Errorf("metering: a usage of %s is below zero", amt)
	}
	if strings.TrimSpace(u.User) == "" {
		return u, fmt.Errorf("metering: %s requires a user", verb)
	}
	// The DEBIT names its ledger or it does not happen. Same rule as the gate, and the
	// same reason: a default would silently make the brand org pay for work it never
	// asked for.
	if strings.TrimSpace(u.Org) == "" {
		return u, fmt.Errorf("metering: %s requires an org", verb)
	}
	if u.Currency == "" {
		u.Currency = "usd"
	}
	// NAME THE ACT BEFORE BILLING IT. The ledger dedups on this name, so it is the
	// server's to choose — an unsealed Usage gets a fresh one here and bills on its own,
	// a caller that must survive its own retry sealed it already and that seal stands.
	return u.Seal(), nil
}
