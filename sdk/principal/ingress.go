package principal

import (
	"github.com/hanzoai/authz"
	"github.com/zap-proto/zip"
)

// HeaderUserBrand carries WHICH BRAND'S IAM vouched for the principal, resolved
// from the token's verified `iss` through the one brand registry (brand.ForIssuer).
//
// It is a SECOND fact, distinct from the deployment's own brand: one cloud binary
// serves every brand's API host and trusts every brand's issuer (trustedIssuers),
// so `cfg.Brand` says which brand this PROCESS is and this header says which
// brand this CALLER is. A plane that keys rows by brand — a tenant key, a
// derived-key salt — must be able to compare them, because "the process assumed
// hanzo" and "lux.id signed this" disagreeing is one org's rows landing in
// another's key space.
//
// It is minted only from validated claims and stripped on ingress like every
// other authority header, so it is never a value a caller chose. Absent for a
// principal that carries no issuer to resolve — an sk- API key, which this
// deployment's own IAM issued — and a consumer must treat absent as "no second
// fact to compare", never as a brand.
const HeaderUserBrand = "X-User-Brand"

// HeaderUserIsApp marks a validated principal that is an APPLICATION acting as
// itself — an organization's own machine identity, minted by the client_credentials
// grant.
//
// It is a KIND, not a role, and it is the fact only this boundary can state: the
// token proves it by SHAPE (appPrincipal), which is gone by the time anything
// downstream sees a header. It carries an organization the credential cannot choose
// — IAM mints an app token no membership set, so the org-switch below admits
// nothing and the effective org is always the application's own owner.
//
// It grants nothing on its own. An app holds NEITHER admin scope, deliberately:
// authz.Claims.OrgAdmin refuses every machine by construction, because an app is
// issued for a purpose and not handed an org's self-service surface. An endpoint
// whose act IS a purpose reads this to admit an org's own machine credential and
// bound it to that org — which is how a build carries the organization it publishes
// for instead of a shared secret that names none.
//
// Stripped on ingress with every other authority header and re-injected here from
// validated claims alone, so it is never a value a caller chose.
const HeaderUserIsApp = "X-User-IsApp"

// HeaderUserOrgs carries the ORGS THE PRINCIPAL BELONGS TO — the slugs of IAM's
// signed `orgs` membership set, comma-separated, home first as IAM writes it.
//
// X-Org-Id says which org this request ACTS IN, which is one org because a
// request has one tenant. This says which orgs the caller MAY act in, which is
// the different question an org switcher asks — and the only place that fact
// exists is the token, so without it a surface listing "your orgs" has to either
// re-validate the JWT itself (a second auth path) or ask IAM again (a hop for
// something already in hand). Hanzo Base's space could not list one Base per
// org for exactly that reason.
//
// It authorizes NOTHING on its own. Acting in an org still goes through the
// effective-org decision below, which honours a selection only when the same
// signed set contains it — so a reader of this header learns what to OFFER, and
// the boundary decides what is allowed.
//
// Same shape as X-User-Brand beside it: an issuer fact rendered by cloud for its
// own apps, minted only from validated claims and stripped on ingress, so it is
// never a value a caller chose. Absent for a principal carrying no membership set
// — an sk- key, a client_credentials machine — and a consumer must read absent as
// "no orgs to offer", never as "every org".
const HeaderUserOrgs = "X-User-Orgs"

// HeaderKey names the API key a request arrived on, as `<org>/<id>`: the org the
// key is filed in and its id there. Downstream it is what a key's own spend is
// kept by (the AI usage records carry it), and it names its own org because the
// org a call is billed to need not be the key's. Written only from a key IAM
// resolved, and stripped on ingress like every other authority header, so a
// caller can never charge another key's budget by naming it. Absent for every
// other credential.
const HeaderKey = "X-Key-Id"

// HeaderUserApproved is whether the principal is off the waitlist ("true" /
// "false"), the bit admission's approval resolver reads before it asks IAM
// (apps/admission/approval.go). Nothing on ingress mints it, so it is stripped
// like every other authority header: a client cannot clear its own waitlist by
// sending it.
const HeaderUserApproved = "X-User-Approved"

// Stripped is every identity name ingress DELETES, taken from the estate's own list
// rather than restated here.
//
// authz.Headers is defined as "every header the edge writes, and therefore every
// header it must strip" — the two being ONE list is what makes a forged identity
// header impossible rather than unlikely. Deriving from it keeps that property as the
// estate grows: a name authz adds is swept here the day it is added, with no second
// list to remember. The two categories above still differ in how a value is RESTORED,
// and they still say so; they no longer get to disagree about what is REMOVED.
//
// Two deliberate adjustments, each a fact about this binary rather than a copy:
//
//   - X-User-Brand, X-User-IsApp, X-User-Orgs, X-Key-Id and X-User-Approved are
//     cloud's own (which brand's IAM vouched for the principal, whether it is an
//     application acting as itself, its memberships, the API key it arrived on, and
//     whether it is off the waitlist), so authz does not name them and this adds them. X-Acted-By is zip's: the operator behind an
//     impersonation token, minted at ingress from the verified `act` and from nothing a
//     request carries.
//   - X-Request-Id is EXCLUDED. Alone among these it is a correlation id the caller
//     legitimately supplies and the edge propagates verbatim; deleting it would break
//     the trace support follows, and it authorizes nothing.
var Stripped = func() []string {
	out := []string{HeaderUserBrand, HeaderUserIsApp, HeaderUserOrgs, HeaderKey, HeaderUserApproved, zip.HeaderActedBy}
	for _, h := range append(append([]string{}, authz.Headers...), authz.Retired...) {
		if h != authz.HeaderRequestID {
			out = append(out, h)
		}
	}
	return out
}()
