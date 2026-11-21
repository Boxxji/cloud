package meter

import (
	"testing"

	"github.com/hanzoai/decimal"
	hz "github.com/hanzoai/money"
)

var credit = hz.Currency{Code: "USD", Decimals: 18, Symbol: "$", Numeric: "840", Name: "US Dollar credit"}

// Verifies Money's precedence: typed Amount wins (18-dp native, no floor), then
// micros, then cents, then zero.
func TestUsageMoney(t *testing.T) {
	// Typed Amount at 18-dp: 0.00132 USD.
	typed := hz.New(decimal.New(132, 5), credit)
	u := Usage{User: "x", Amount: typed}
	if got := u.Money().Decimal(); got.Cmp(typed.Decimal()) != 0 {
		t.Errorf("typed 0.00132 USD: got %s, want exact", got)
	}

	// Legacy micros: 2000 micros = 0.002 USD.
	if got := (Usage{User: "x", AmountMicros: 2000}).Money().Decimal(); got.Cmp(decimal.New(2, 3)) != 0 {
		t.Errorf("micros 2000: got %s, want 0.002", got)
	}

	// Legacy cents: 50 cents.
	if got := (Usage{User: "x", AmountCents: 50}).Money().Decimal(); got.Cmp(decimal.New(5, 1)) != 0 {
		t.Errorf("cents 50: got %s, want 0.5", got)
	}

	// Zero.
	if !(Usage{User: "x"}).Money().IsZero() {
		t.Error("empty usage should be zero")
	}

	// Typed wins over legacy fields when both set.
	u4 := Usage{User: "x", Amount: typed, AmountCents: 999, AmountMicros: 999}
	if u4.Money().Decimal().Cmp(typed.Decimal()) != 0 {
		t.Errorf("typed should win over legacy fields: got %s", u4.Money().Decimal())
	}
}

// A usage's work is its named units, else its tokens.
func TestWorkUnits(t *testing.T) {
	if got := (Usage{Units: 7, TotalTokens: 3}).WorkUnits(); got != 7 {
		t.Errorf("named units: %d", got)
	}
	if got := (Usage{TotalTokens: 3}).WorkUnits(); got != 3 {
		t.Errorf("tokens: %d", got)
	}
}
