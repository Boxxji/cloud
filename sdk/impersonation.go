package cloud

// impersonation.go — what a support session may not do.
//
// A SuperAdmin opens a customer's site AS the customer through IAM's impersonation
// (iam LLM.md "Impersonation"): the token carries the person's sub, owner and orgs,
// names the operator in `act`, says `imp: true` and lives at most fifteen minutes.
// The boundary (SanitizeIdentity) reads `act` off the verified payload and mints it
// onto the principal; nothing a request carries can set it.
//
// AUTHORITY IS THE TARGET'S. Every gate authorizes on sub, owner and orgs exactly
// as for the person's own token, and nothing here reads `act` to admit anything.
// The session reads what the person can, but a credential's value.
//
// NOTHING IT TOUCHES OUTLIVES IT, AND IT MOVES NO MONEY. A key, a secret or a
// membership minted in the window would outlive the window, so would a token read
// out of custody, and a charge or a payout is the person's money. IAM refuses
// every write of its own to an `imp` bearer, but cloud writes IAM with its OWN
// credential (keys, memberships, the profile), so IAM never sees the bearer
// there: cloud has to refuse, here, before IAM may name a single application in
// IAM_IMPERSONATION_APPS. apps/account (supported) and apps/team (sendInvite)
// refuse the same writes where cloud's credential is used, under any address.
//
// NOR DOES IT SPEAK FOR THE PERSON: no link, token or invitation another party
// can use, and nothing made public, live or listed in their name. The one write
// under /v1/iam it keeps is ending itself (ending).
//
// TWO HALVES, ONE DECISION (confined). Contain asks about the ADDRESS a request
// reached, for every route typed or raw; it sits inside AuditTrail so each refusal
// is on the trail with the operator named. Confine asks about the OPERATION a door
// reached (MCP, the call plane, the graph), where the address is the door and the
// operation is in the payload — the split Permit already makes for a key's grant.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/hanzoai/cloud/sdk/audit"
	"github.com/hanzoai/cloud/sdk/principal"
	"github.com/zap-proto/zip"
)

// support is every address a support session may not write, and what it is. A
// pattern names the route and everything under it, on segment boundaries; `*`
// is one segment; prefixed with a method it names that one operation and nothing
// under it. A write is any method but GET, HEAD and OPTIONS. Lowercase, because
// it is compared with the address as the router matches it (RoutePath).
var support = []struct{ at, what string }{
	// Credentials: each outlives the session that would mint it.
	{"/v1/account/keys", "API keys"},
	{"/v1/commerce/store/token", "API keys"},
	{"/v1/principal/keys", "principal keys"},
	{"/v1/agent/targets/*/key", "daemon keys"},
	{"/v1/webhook", "webhooks"}, // a new endpoint answers its signing secret; an edit repoints the feed
	{"/v1/share/enable", "tunnel credentials"},
	{"/v1/share/rotate", "tunnel credentials"},
	{"/v1/connection", "connected accounts"},
	{"/v1/ai/connections", "connected accounts"},
	{"/v1/ai/providers", "provider credentials"},
	{"/v1/ai/remote-connections", "remote connections"},
	{"/v1/provider/*/connect", "connected accounts"},
	{"/v1/provider/*/disconnect", "connected accounts"},
	{"/v1/provider/*/claim", "connected accounts"},
	{"/v1/provider/github/user", "connected accounts"},
	{"/v1/ai/signin-sessions", "sessions"},
	{"/v1/team/account/cookie", "sessions"},
	{"/v1/notify/credentials", "provider credentials"},
	{"/v1/kms", "KMS secrets"},
	{"/v1/environment/*/secrets", "secrets"},
	// Links, tokens and invitations in the person's name: each is a bearer, used by
	// whoever holds it, after the session and by people it never named.
	{"/v1/dataroom/links", "share links"},
	{"/v1/agent/chat/conversations/*/shares", "share links"},
	{"DELETE /v1/agent/chat/shares/*", "share links"}, // POST /shares/read beside it is a viewer's read
	{"/v1/affiliate/me/links", "share links"},
	{"/v1/esign/documents/*/recipients", "signing links"}, // each answers its signer's token
	{"/v1/esign/documents/*/send", "signing links"},
	{"/v1/sandbox/*/preview", "preview links"}, // the cookie it opens lives twelve hours
	{"/v1/meet", "meetings"},                   // a join token is the person to everyone in the room
	// Publication: whatever goes public, live or listed in the person's name.
	{"/v1/dataroom/trust", "the trust centre"},
	{"/v1/trust", "the trust centre"},
	{"/v1/marketplace/listings", "listings"},
	{"/v1/affiliate/me/handle", "public listings"},
	{"/v1/leaderboard/optin", "public listings"},
	{"/v1/research/grants", "publication"},
	{"PATCH /v1/git/repos/*", "visibility"},
	{"PATCH /v1/project/*", "visibility"},
	{"/v1/project/*/publish", "publication"},
	{"/v1/project/*/releases/*/activate", "publication"},
	{"/v1/social/posts", "publication"},       // one scheduled in the past publishes at once
	{"/v1/marketing/calendar", "publication"}, // so does one scheduled ahead, after the session
	{"/v1/content/publish", "publication"},
	{"/v1/cloudflare/workers/scripts/*/subdomain", "publication"},
	{"/v1/ad/campaigns/*/launch", "publication"},
	{"/v1/campaign/*/launch", "publication"},
	// o11y, every write: the tenant's telemetry — dashboards and their public links,
	// alerts, channels, ingestion and service-account keys, roles. Its POST queries
	// go with it; GET reads stay.
	{"/v1/o11y", "telemetry settings"},
	// The IAM account, which IAM refuses to an impersonated bearer itself: sign-in,
	// password, MFA, passkeys, keys, memberships, invitations. Cloud's own writes of
	// it — creating an org and its owner membership, the profile — go the same way.
	// The one write it keeps is ending itself (ending).
	{"/v1/iam", "the IAM account"},
	{"/v1/account/orgs", "memberships"},
	{"/v1/account/avatar", "the profile"},
	{"/v1/account/appearance", "the profile"},
	// Money: payment methods, plans, top-ups, recharge, invoices, payouts, the
	// billing roster — every write under billing — and every other charge or payout.
	{"/v1/billing", "billing"},
	{"/v1/plan/subscriptions", "plans"},
	{"/v1/pricing/subscriptions", "plans"},
	{"/v1/team/billing", "plans"},
	{"/v1/company/payment", "payments"},
	{"/v1/domain/register", "purchases"},
	{"/v1/domain/renew", "purchases"},
	{"/v1/domain/transfer", "purchases"},
	{"/v1/commerce/store/*/charge", "payments"},
	{"/v1/commerce/store/*/checkout", "payments"},
	{"/v1/commerce/store/*/authorize", "payments"},
	{"/v1/commerce/store/*/capture", "payments"},
	{"/v1/commerce/store/*/paypal", "payments"},
	{"/v1/commerce/transfer", "payouts"},
	{"/v1/marketplace/seller/payout", "payouts"},
	{"/v1/marketplace/jobs/*/release", "payouts"},
	{"/v1/marketplace/jobs/*/refund", "payouts"},
	{"/v1/author/connect", "payouts"},
	{"/v1/wallet", "wallets"},
	{"/v1/commerce/wallet", "wallets"}, // its accounts are the addresses money is paid to
	// Acts in the person's own name that bind them after the session: a signature,
	// a sworn tax certification, a state filing, identity verification, and every
	// record of who owns the company.
	{"/v1/company/esign", "signatures"},
	{"/v1/esign/o/*/sign", "signatures"},
	{"/v1/legal/documents/*/sign", "signatures"},
	{"/v1/legal/filings", "filings"},
	{"/v1/tax/filings", "filings"},
	{"/v1/tax/forms", "filings"},
	{"/v1/compliance", "identity verification"},
	{"/v1/company/ein", "filings"},
	{"/v1/company/advance", "filings"},
	{"/v1/company/kyc", "identity verification"},
	{"/v1/company/genesis", "the cap table"},
	{"/v1/company/fundraise", "securities"},
	{"/v1/captable", "the cap table"},
	{"/v1/tax/profile", "tax certifications"},
	{"/v1/tax/w9", "tax certifications"},
}

// custody is every read that hands a credential's VALUE out, refused to a support
// session on any method: a token read in the window is one the operator keeps.
// KMS needs no line here, because its own grant opens a value only to a named
// holder and an impersonation names none (apps/kms typed.go).
var custody = []struct{ at, what string }{
	{"/v1/connection/*/token", "custodied tokens"},
	{"/v1/o11y/cloud_integrations/*/credentials", "integration credentials"},
	{"/v1/iam/tokens", "sign-in tokens"},
}

// confined is the one decision: nil, or the 403 that says what a support session
// may not change or read at method + addr.
func confined(method, addr string) error {
	for _, at := range spellings(addr) {
		for _, s := range custody {
			if fits(method, at, s.at) {
				return zip.Errorf(http.StatusForbidden,
					"a support session cannot read %s: the person does that signed in as themselves", s.what)
			}
		}
		switch method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			continue
		}
		for _, s := range support {
			if fits(method, at, s.at) {
				return zip.Errorf(http.StatusForbidden,
					"a support session cannot change %s: the person does that signed in as themselves", s.what)
			}
		}
	}
	return nil
}

// spellings is every address a handler behind this router may read addr as, in
// segments: as the router matches it (RoutePath), and percent-decoded and
// cleaned, because a net/http handler mounted under a prefix (o11y's) decodes
// and cleans before it matches. Refusing on any of them is the safe direction.
func spellings(addr string) [][]string {
	seen := map[string]bool{}
	var out [][]string
	add := func(a string) {
		a = RoutePath(a)
		if !seen[a] {
			seen[a] = true
			out = append(out, strings.Split(strings.Trim(a, "/"), "/"))
		}
	}
	add(addr)
	add(path.Clean("/" + addr))
	if raw, err := url.PathUnescape(addr); err == nil {
		add(raw)
		add(path.Clean("/" + raw))
	}
	return out
}

// fits reports whether method at the address segments at falls under pattern: at
// or below its address, whose `*` segment matches any one segment, or exactly the
// one operation a method-prefixed pattern names. under (scope.go) is the same
// question for a pattern with no wildcard and no method.
func fits(method string, at []string, pattern string) bool {
	verb, addr, one := strings.Cut(pattern, " ")
	if !one {
		addr = verb
	} else if verb != method {
		return false
	}
	ps := strings.Split(strings.Trim(addr, "/"), "/")
	if len(at) < len(ps) || one && len(at) != len(ps) {
		return false
	}
	for i, p := range ps {
		if p != "*" && p != at[i] {
			return false
		}
	}
	return true
}

// Operator is the Operator behind this request's credential, zero for a caller
// acting as themselves. It reads the boundary's attestation, never a header.
func Operator(c *zip.Ctx) principal.Act {
	a, _ := principal.Impersonated(c)
	return a
}

// Contain refuses a support session every write the table names, by ADDRESS,
// but the one that ends it. Witness installs it inside AuditTrail, so the refusal
// is recorded with its operator; a caller acting as themselves pays one Locals
// read.
func Contain() zip.Handler {
	return func(c *zip.Ctx) error {
		if Operator(c).Sub != "" && !ending(c) {
			if err := confined(c.Method(), c.Path()); err != nil {
				return err
			}
		}
		return c.Next()
	}
}

// The two IAM addresses a session ends itself at (hanzoai/iam internal/oidc).
const (
	iamRevoke = "/v1/iam/oauth/revoke" // RFC 7009
	iamLogout = "/v1/iam/oauth/logout" // OIDC RP-Initiated Logout; its GET is a read
)

// ending reports whether this request is a support session ending ITSELF, the
// one IAM write it keeps: a POST revoking the very bearer it presents, or a POST
// sign-out naming no token but its own. Revoking another token is refused like
// every other IAM write. Only Contain asks it: both routes are raw, so no door
// reaches them as an operation, and Confine refuses all of /v1/iam.
func ending(c *zip.Ctx) bool {
	own := CallerBearer(c)
	if c.Method() != http.MethodPost || own == "" {
		return false
	}
	// RoutePath is the address as the router matches it; a path that reads as
	// either of these there decodes and cleans to the same, so one spelling is all.
	switch RoutePath(c.Path()) {
	case iamRevoke:
		return iamParam(c, "token") == own
	case iamLogout:
		hint := iamParam(c, "id_token_hint")
		return hint == "" || names(c, hint)
	}
	return false
}

// iamParam reads key as IAM's handlers do (oidc.param): the query first, then the
// form. Reading it any other way would admit one token and let IAM revoke another.
func iamParam(c *zip.Ctx, key string) string {
	if v := c.Query(key); v != "" {
		return v
	}
	return c.Fiber().FormValue(key)
}

// names reports whether an id_token_hint names this session: the person it acts
// as and the operator behind it. It narrows and never admits on its own, so the
// signature is IAM's to check: a forged hint that passes here names nothing IAM
// honours.
func names(c *zip.Ctx, hint string) bool {
	parts := strings.Split(hint, ".")
	if len(parts) != 3 {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	var claims struct {
		Sub string `json:"sub"`
		Act struct {
			Sub string `json:"sub"`
		} `json:"act"`
	}
	if json.Unmarshal(raw, &claims) != nil {
		return false
	}
	return claims.Sub != "" && claims.Sub == c.User() && claims.Act.Sub == Operator(c).Sub
}

// Confine is the op-invoke half: the same decision about the OPERATION a door
// reached. It reads the operator the request's boundary attested where a request
// is behind the call, and the one zip forwarded across the plane where none is.
// Asked of every invoke rather than only a door's: the answer for an address the
// router matched is the one Contain gave, so asking twice costs a table walk.
func Confine() zip.Authorizer {
	return func(ctx context.Context, op zip.Op, _ any) (zip.Decision, error) {
		allow := zip.Decision{Effect: zip.Allow}
		act := principal.ActFrom(ctx)
		if c, live := Request(ctx); live && act.Sub == "" {
			act = Operator(c)
		}
		if act.Sub == "" {
			return allow, nil
		}
		return allow, confined(op.Method, op.Path)
	}
}

// ActOf names the operator behind the call ctx carries, as the trail records it
// (audit.Recorder.Acting).
func ActOf(ctx context.Context) audit.Act { return trailAct(principal.ActFrom(ctx)) }

// trailAct is an operator in the trail's spelling.
func trailAct(a principal.Act) audit.Act {
	return audit.Act{Sub: a.Sub, Owner: a.Owner, Name: a.Name}
}
