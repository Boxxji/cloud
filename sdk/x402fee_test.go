package cloud

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hanzoai/cloud/sdk/meter"
	"github.com/zap-proto/zip"
)

// rail is a payment rail the test scripts: what a check and a settle answer, and
// every step it was asked, in order. Asked for the terms it writes the challenge
// header, as the host does.
type rail struct {
	check, settle FeeAnswer
	err           error
	steps         []FeeStep
}

// install puts r behind the X402Fee hook for one test and restores the host's
// after.
func (r *rail) install(t *testing.T) *rail {
	t.Helper()
	prev := hostHooks.Load()
	t.Cleanup(func() { hostHooks.Store(prev) })
	SetHooks(Hooks{X402Fee: func(c *zip.Ctx, _ string, step FeeStep) (FeeAnswer, error) {
		r.steps = append(r.steps, step)
		switch step {
		case FeeTerms:
			c.SetHeader("PAYMENT-REQUIRED", "terms")
			return FeeAnswer{}, nil
		case FeeCheck:
			return r.check, r.err
		}
		return r.settle, r.err
	}})
	return r
}

// meteredRoute is a route that bills its fee the way the metered products do:
// check a payment, gate the balance (whose refusal carries the challenge), act,
// then settle the payment in place of the fee's debit.
func meteredRoute(gate error) *zip.App {
	app := zip.New(zip.Config{DisableStartupMessage: true})
	app.Raw(http.MethodPost, "/act", func(c *zip.Ctx) error {
		pay, err := CheckFee(c, "meter:function.invoke")
		if err != nil {
			return DenyResource(c, err)
		}
		if gate != nil {
			ChallengeFee(c, "meter:function.invoke", gate)
			return DenyResource(c, gate)
		}
		return c.JSON(http.StatusOK, map[string]any{"paidByX402": pay.Settle()})
	})
	return app
}

func hit(t *testing.T, app *zip.App) (int, []byte, http.Header) {
	t.Helper()
	resp, err := app.Test(httptest.NewRequest(http.MethodPost, "/act", nil), zip.TestConfig{Timeout: 30 * time.Second, FailOnTimeout: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b, resp.Header
}

// The refusal an unfunded caller gets is the balance gate's own, byte for byte,
// whether or not a payment rail is there: x402 adds the PAYMENT-REQUIRED header
// and nothing else.
func TestChallengeLeavesTheRefusalAsItWas(t *testing.T) {
	before := hostHooks.Load()
	hostHooks.Store(&Hooks{})
	code0, body0, hdr0 := hit(t, meteredRoute(meter.ErrInsufficientBalance))
	hostHooks.Store(before)
	if code0 != http.StatusPaymentRequired || hdr0.Get("PAYMENT-REQUIRED") != "" {
		t.Fatalf("with no rail: %d %q, want a bare 402", code0, hdr0.Get("PAYMENT-REQUIRED"))
	}

	r := (&rail{}).install(t)
	code, body, hdr := hit(t, meteredRoute(meter.ErrInsufficientBalance))
	if code != code0 || !bytes.Equal(body, body0) {
		t.Fatalf("with a rail the refusal changed:\n %d %s\nwas %d %s", code, body, code0, body0)
	}
	if hdr.Get("PAYMENT-REQUIRED") != "terms" || len(r.steps) != 2 || r.steps[1] != FeeTerms {
		t.Fatalf("challenge %q after steps %v, want the terms asked once after the check", hdr.Get("PAYMENT-REQUIRED"), r.steps)
	}
	if !bytes.Contains(body, []byte(`"code":"insufficient_balance"`)) || !bytes.Contains(body, []byte(`"billingUrl"`)) {
		t.Fatalf("the refusal is not the money wire's: %s", body)
	}
}

// Only a refusal for want of funds is one paying clears. A spend cap, a balance
// nobody could read and a caller with no ledger get no challenge.
func TestChallengeOnlyForWantOfFunds(t *testing.T) {
	for _, gate := range []error{meter.ErrSpendCapExceeded, errors.New("commerce unreachable"), ErrNoLedger} {
		r := (&rail{}).install(t)
		_, _, hdr := hit(t, meteredRoute(gate))
		if hdr.Get("PAYMENT-REQUIRED") != "" || len(r.steps) != 1 {
			t.Fatalf("%v: steps %v, want the check alone and no challenge", gate, r.steps)
		}
	}
}

// A payment that checks out is settled once the act is done, and is the fee when
// it settles. One that does not settle leaves the fee to the route's debit. One
// that does not check out is the refusal, in the rail's own status and code, before
// the act. A rail that could not answer the check is unknown, never free.
func TestFeePaymentOutcomes(t *testing.T) {
	r := (&rail{check: FeeAnswer{OK: true}, settle: FeeAnswer{OK: true}}).install(t)
	if code, b, _ := hit(t, meteredRoute(nil)); code != http.StatusOK || !bytes.Contains(b, []byte(`"paidByX402":true`)) {
		t.Fatalf("a settled payment = %d %s, want served and paid", code, b)
	}
	if len(r.steps) != 2 || r.steps[0] != FeeCheck || r.steps[1] != FeeSettle {
		t.Fatalf("steps %v, want a check then a settle", r.steps)
	}

	(&rail{check: FeeAnswer{OK: true}, settle: FeeAnswer{Status: http.StatusPaymentRequired, Code: "nonce_replayed"}}).install(t)
	if code, b, _ := hit(t, meteredRoute(nil)); code != http.StatusOK || !bytes.Contains(b, []byte(`"paidByX402":false`)) {
		t.Fatalf("a payment that did not settle = %d %s, want served with the fee left to the debit", code, b)
	}

	r = (&rail{check: FeeAnswer{Status: http.StatusPaymentRequired, Code: "nonce_replayed", Reason: "payment nonce already used"}}).install(t)
	code, b, _ := hit(t, meteredRoute(nil))
	if code != http.StatusPaymentRequired || !bytes.Contains(b, []byte(`"code":"nonce_replayed"`)) || len(r.steps) != 1 {
		t.Fatalf("a refused payment = %d %s after %v, want 402 nonce_replayed and nothing settled", code, b, r.steps)
	}

	(&rail{err: errors.New("x402 down")}).install(t)
	if code, b, _ := hit(t, meteredRoute(nil)); code != http.StatusServiceUnavailable {
		t.Fatalf("a rail that did not answer = %d %s, want 503", code, b)
	}

	// No answer — nothing presented, or nothing sold — bills as it always has.
	r = (&rail{}).install(t)
	if code, b, _ := hit(t, meteredRoute(nil)); code != http.StatusOK || !bytes.Contains(b, []byte(`"paidByX402":false`)) || len(r.steps) != 1 {
		t.Fatalf("no answer = %d %s after %v, want served, the fee left to the debit, nothing settled", code, b, r.steps)
	}
	var none *FeePayment
	if none.Settle() {
		t.Fatal("no payment settled")
	}
}
