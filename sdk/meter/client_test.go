package meter

import (
	"context"
	"errors"
	"github.com/hanzoai/decimal"
	hz "github.com/hanzoai/money"
	"testing"
)

// No ledger is linked into this test binary, so these pin what a process does
// without one. The failure they exist to prevent is a deployment that stopped
// debiting and looked healthy.

func TestAProcessToldToBillWithNoLedgerRefusesLoudly(t *testing.T) {
	for name, tell := range map[string]func(t *testing.T) Config{
		"a named deployment": func(t *testing.T) Config { t.Setenv("CLOUD_ENV", "mainnet"); return Config{} },
		"a commerce base":    func(t *testing.T) Config { t.Setenv("CLOUD_ENV", ""); return Config{BaseURL: "http://commerce:8001"} },
	} {
		t.Run(name, func(t *testing.T) {
			c, err := New(tell(t))
			if !errors.Is(err, ErrNoDriver) {
				t.Fatalf("New = %v, want ErrNoDriver", err)
			}
			ctx := context.Background()
			in := AuthInput{User: "acme", Org: "acme"}
			if err := c.Authorize(ctx, in); !errors.Is(err, ErrNoDriver) {
				t.Errorf("Authorize = %v, want ErrNoDriver: an unconfigured gate must not admit", err)
			}
			u := Usage{User: "acme", Org: "acme", AmountCents: 5}
			if _, err := c.Record(ctx, u); !errors.Is(err, ErrNoDriver) {
				t.Errorf("Record = %v, want ErrNoDriver: a debit must not vanish", err)
			}
			if err := c.Post(ctx, u); !errors.Is(err, ErrNoDriver) {
				t.Errorf("Post = %v, want ErrNoDriver", err)
			}
			if _, err := c.Balance(ctx, "acme", "acme", ""); !errors.Is(err, ErrNoDriver) {
				t.Errorf("Balance = %v, want ErrNoDriver", err)
			}
			if c.Enabled() {
				t.Error("a refusing client reports enabled")
			}
		})
	}
}

func TestAProcessNotToldToBillMetersNothing(t *testing.T) {
	t.Setenv("CLOUD_ENV", "")
	c, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := c.Authorize(ctx, AuthInput{User: "u", Org: "o"}); err != nil {
		t.Errorf("Authorize = %v, want free", err)
	}
	if res, err := c.Record(ctx, Usage{User: "u", Org: "o", AmountCents: 5}); err != nil || res != nil {
		t.Errorf("Record = %v, %v, want nothing charged", res, err)
	}
}

// Identity is decided above the ledger, so the free default refuses an
// unattributable act exactly as the real books do.
func TestAnActWithoutAUserOrAnOrgIsRefusedWhoeverAnswers(t *testing.T) {
	t.Setenv("CLOUD_ENV", "")
	c, _ := New(Config{})
	ctx := context.Background()
	if err := c.Authorize(ctx, AuthInput{Org: "o"}); err == nil {
		t.Error("an empty user was authorized")
	}
	if err := c.Authorize(ctx, AuthInput{User: "u"}); err == nil {
		t.Error("an empty org was authorized")
	}
	if _, err := c.Record(ctx, Usage{Org: "o"}); err == nil {
		t.Error("a debit with no user was recorded")
	}
	if _, err := c.Record(ctx, Usage{User: "u"}); err == nil {
		t.Error("a debit with no org was recorded")
	}
	if _, err := c.Record(ctx, Usage{User: "u", Org: "o", Amount: hz.New(decimal.New(-1, 2), credit)}); err == nil {
		t.Error("a negative debit was recorded")
	}
}
