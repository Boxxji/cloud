package principal

import (
	"context"
	"strings"

	"github.com/zap-proto/zip"
)

// Act is the operator behind an IAM impersonation token: a SuperAdmin signed in AS
// a customer for a support session. IAM signs the TARGET's claims (sub, owner,
// orgs) and names the operator beside them in `act {sub, owner, name}` with
// `imp: true` (iam LLM.md "Impersonation"). The identity boundary reads both off
// the verified payload and mints this; nothing a request carries can set it. The
// zero Act is everyone acting as themselves.
//
// AUTHORITY STAYS THE TARGET'S. No gate reads an Act to admit anything: Org, Super
// and every scope resolve from sub, owner and orgs exactly as for the target's own
// token. An Act is read for three things only — refusing a support session the
// writes that would outlive it (cloud's Contain and Confine), charging its metered
// use to nobody, and naming the operator on every audit row it causes.
type Act struct {
	// Sub is the operator's IAM subject, act.sub. It is what crosses the plane as
	// zip.HeaderActedBy and what an event's impersonated_by records.
	Sub string `json:"sub"`
	// Owner and Name are the operator's IAM row, act.owner and act.name — "admin"
	// and "z" — which is how a person reads who it was.
	Owner string `json:"owner,omitempty"`
	Name  string `json:"name,omitempty"`
}

// Impersonated returns the operator behind this request's credential, read from
// the boundary's own attestation (Mint), never from a header. False for a caller
// acting as themselves and for a request no boundary attested.
func Impersonated(c *zip.Ctx) (Act, bool) {
	p, ok := Minted(c)
	if !ok || p.Act.Sub == "" {
		return Act{}, false
	}
	return p.Act, true
}

// actKey names the request-scoped slot WithAct parks the operator in. Unexported
// zero-size type, so only this package can mint or read one.
type actKey struct{}

// WithAct parks the operator behind this request's credential on ctx, the way
// WithOrg parks the org, so a typed op and an emit point that holds only a
// context read it as a value — one that stays true after the request is recycled.
// A caller acting as themselves parks nothing.
func WithAct(ctx context.Context, c *zip.Ctx) context.Context {
	a, ok := Impersonated(c)
	if !ok {
		return ctx
	}
	return context.WithValue(ctx, actKey{}, a)
}

// ActFrom is the operator behind the call ctx carries: the one WithAct parked
// where a request was, else the subject zip forwarded across the plane
// (X-Acted-By, which the boundary alone writes and strips on ingress). Zero for a
// caller acting as themselves.
func ActFrom(ctx context.Context) Act {
	if a, ok := ctx.Value(actKey{}).(Act); ok {
		return a
	}
	return Act{Sub: strings.TrimSpace(zip.CallerOf(ctx).ActedBy)}
}
