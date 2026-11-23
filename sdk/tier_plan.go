package cloud

import (
	"context"
	"strings"

	"github.com/hanzoai/account"
)

// TierAllows reports whether payer is on the Unlimited plan, whose runs and leases
// the wallet does not gate. It asks the plan, not the tier: Unlimited is a pro tier.
// A plan that cannot be read is not Unlimited.
func TierAllows(ctx context.Context, org string, payer account.Account) bool {
	if payer.Zero() {
		return false
	}
	plan, err := Plan(ctx, payer.Subject(), org)
	if err != nil || plan == "" {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(plan), "unlimited")
}
