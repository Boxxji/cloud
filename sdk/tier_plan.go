package cloud

import (
	"context"
	"strings"

	"github.com/hanzoai/account"
)

// tier_plan.go — "is this payer on an Unlimited (unbounded) plan?" answered once,
// from the same tier machinery every gate uses, so no two opinions about who is
// Unlimited.
//
// Unlimited is the plan whose class allowances are flags.Unbounded
// (apps/flags/carried.go: "unlimited" → Premium Unbounded, Ours Unbounded). It
// pays for covered runs and leases whatever the wallet holds — $0 included. A
// subject on any other rung (free, dev, pro-3x …) or with no plan reads false.
//
// The tier is commerce's own answer for the payer's subject, so a plan the flag
// store names unlimited and the tier that reads "unlimited" agree, and a plan
// that is not unlimited never reads as it. A tier that cannot be read reads as
// not-Unlimited rather than permission: fail-closed.
func TierAllows(ctx context.Context, org string, payer account.Account) bool {
	if payer.Zero() {
		return false
	}
	tier, err := Tier(ctx, payer.Subject(), org)
	if err != nil || tier == "" {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(tier), "unlimited")
}
