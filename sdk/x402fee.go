package cloud

// x402fee.go — a metered act's flat fee, paid per request over x402.
//
// A metered route (a function invoke, an agent run, a provisioned resource) gates
// its flat fee on the caller's prepaid balance before the act and debits it once
// the act is done — and only if it was done: a run the model refused, a sandbox
// that could not be reached, a create that failed, costs nothing. The payment rail
// sells the same act for the same fee to a caller that pays per request, and this
// file is the policy that fits the one into the other without changing that rule:
//
//   - CHECK BEFORE. A request that carries a payment (PAYMENT-SIGNATURE) has it
//     checked against the fee's terms where the route gates its balance: the
//     signature, the terms, the window, a nonce not yet spent. Nothing moves. A
//     payment that does not check out is the refusal, with the challenge on its
//     headers, before anything runs.
//   - THE GATE STILL ADMITS. The rail settles a payment on the ledger, from the
//     caller's own Hanzo wallet — the one the gate weighs — so the gate's answer is
//     the payment's answer too, and skipping it would admit an act a valid
//     signature over an empty wallet can never pay for.
//   - SETTLE AFTER. Once the act is done and billable, the payment is settled, once,
//     and the receipt rides PAYMENT-RESPONSE: the payment WAS the fee, so the
//     balance is not debited for it. A payment that does not settle then — spent by
//     a concurrent request, a wallet drained in between — leaves the fee to the
//     ordinary debit, so the act is never free; PAYMENT-RESPONSE says it failed.
//   - CHALLENGE ON REFUSAL. When the gate refuses for want of funds, the rail's
//     terms ride the refusal on PAYMENT-REQUIRED. The status and the body are the
//     gate's own, byte for byte; a client that speaks x402 reads the header.
//
// A rail that is not in this fleet, or that sells no metered fee here (no platform
// wallet, a fee of zero), changes nothing: no payment is checked, the gate decides
// and the debit is taken as before. The wire — the header names, the ops, their
// input and answer — is client's, so the host answers the hook (internal/host). The
// framework holds only the policy, and a process with no host has no rail.

import (
	"net/http"

	luxlog "github.com/luxfi/log"
	"github.com/zap-proto/zip"
)

// FeeStep is what one ask of the payment rail is for.
type FeeStep int

const (
	// FeeTerms asks for a fee's terms alone: the challenge a refusal carries.
	FeeTerms FeeStep = iota
	// FeeCheck checks the request's payment against the fee's terms. Nothing moves.
	FeeCheck
	// FeeSettle settles the request's payment, once.
	FeeSettle
)

// FeeAnswer is what the payment rail answered for one metered fee.
type FeeAnswer struct {
	// OK is a payment that checked out (FeeCheck) or settled (FeeSettle).
	OK bool
	// Status, Code and Reason are the rail's refusal of the payment. A zero Status
	// with OK false is no answer at all: no payment was presented, no payer could be
	// charged, or the rail sells nothing here, and the route bills as it always has.
	Status int
	Code   string
	Reason string
}

// FeePayment is a request's x402 payment for one metered fee: checked when the act
// is admitted, settled once the act is done. A nil one is no payment, and settles
// nothing.
type FeePayment struct {
	c        *zip.Ctx
	resource string
}

// CheckFee checks the payment a request carries for a metered act's fee, where the
// route gates its balance. It returns the payment to settle once the act is done,
// nil when there is none to take, or a refusal to answer as one (Denied,
// DenyResource) — a payment that does not check out, with the challenge on the
// response, or a rail that could not answer, which is unknown and never free. The
// route gates its balance after it either way.
func CheckFee(c *zip.Ctx, resource string) (*FeePayment, error) {
	f := hooks().X402Fee
	if f == nil || c == nil {
		return nil, nil
	}
	out, err := f(c, resource, FeeCheck)
	switch {
	case err != nil:
		return nil, err
	case out.OK:
		return &FeePayment{c: c, resource: resource}, nil
	case out.Status == 0:
		return nil, nil
	}
	return nil, &zip.HTTPError{Status: out.Status, Code: out.Code, Msg: out.Reason}
}

// Settle settles the payment once the act is done and billable, and reports
// whether it paid the fee. true: the fee is paid, debit none. false: the fee is the
// route's to debit as it always has — there was no payment, or it did not settle.
func (p *FeePayment) Settle() bool {
	f := hooks().X402Fee
	if p == nil || f == nil {
		return false
	}
	out, err := f(p.c, p.resource, FeeSettle)
	if err != nil || !out.OK {
		if l := luxlog.Default(); l != nil {
			l.Warn("x402: a checked payment did not settle; the fee is debited from the balance",
				"resource", p.resource, "code", out.Code, "reason", out.Reason, "err", err)
		}
		return false
	}
	return true
}

// ChallengeFee puts the x402 terms for a metered fee on the response to a balance
// refusal for want of funds, so the refusal says what the act costs in a form a
// paying client acts on. It writes a header and nothing else: gateErr is still the
// answer, rendered exactly as before. A refusal for any other reason — a spend cap,
// an unknown balance, no payer — gets no challenge, because paying does not clear it.
func ChallengeFee(c *zip.Ctx, resource string, gateErr error) {
	f := hooks().X402Fee
	if f == nil || c == nil || gateErr == nil {
		return
	}
	if he := Denial(gateErr, ""); he.Status != http.StatusPaymentRequired || he.Code != "insufficient_balance" {
		return
	}
	_, _ = f(c, resource, FeeTerms) // best effort: without the terms the refusal still stands
}
