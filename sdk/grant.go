package cloud

// grant.go is the second half of the authorization rule, and the axis gate.go
// deliberately does not have.
//
// gate.go answers HOW MUCH AUTHORITY A CALLER HAS — Validated, Super, OrgAdmin.
// That is a property of the person. This answers HOW MUCH OF THAT AUTHORITY A
// PARTICULAR CREDENTIAL CARRIES, which is a property of the key, and the two are
// orthogonal: the same human holds a session that may reach everything and a
// deploy key that may reach one model. Spelling the second as a fourth Scope
// would say the holder is less privileged, which is false and would leak into
// every check that reads authority.
//
// A GRANT ONLY EVER NARROWS. There is no entry that adds reach, so a key can
// never carry more than its holder — the composed rule is
//
//	Scope.Admits(AuthorityOf(c)) && GrantOf(c).Covers(kind, name)
//
// and a mistake in a grant can cost availability, never privilege.
//
// EMPTY MEANS UNRESTRICTED, and that is a decision rather than an oversight: all
// eleven keys in the estate carry no reach today, so any other default silently
// revokes production on the deploy that ships this. Restriction is opt-in and
// visible in the key's own row.
//
// WHERE IT IS ASKED. At the site that knows the target, because only that site
// does: the model is known at the AI edge, the project at the project resolver,
// the capability at the identity boundary, which sees every request's address
// (Permits). One call each, never a second copy of the rule.
//
// WHAT A KEY MAY DO WITH A CAPABILITY. Two kinds name capabilities — the app
// that serves an address, as the routing table answers it (manifest.OwnerOf):
//
//	product:train   read and write /v1/train
//	read:billing    only read /v1/billing (GET, HEAD, OPTIONS)
//	read:*          only read, anywhere: a read-only key
//
// A key naming neither reaches every capability its holder does. A key naming
// either reaches only what they name. Together these are the three ways a key's
// permissions are set: all (neither), restricted (a list), read-only (read:*).
//
// WHAT A KEY MAY DO ON THE DEPLOY CONSOLE. One kind names the console's writes,
// asked by the one op that makes them (apps/deploy sync):
//
//	deploy:rollback   sync an application to an earlier revision of its own
//	deploy:sync       sync an application to what git or its publisher declares
//
// A key naming neither may make whichever its holder may. With product:deploy
// beside it, deploy:rollback is the least a key can hold and still undo a bad
// deploy: the console's reads and its rollback, and no other capability.

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/hanzoai/cloud/sdk/principal"
	"github.com/zap-proto/zip"
)

// Grant is the set of things one credential may reach, read off the key's scope.
//
// Two shapes share the field and each reader ignores the other's:
//
//	publish       a CLASS — this key has no secret half (schema.KeyScopePublish)
//	model:zen5    a REACH — kind and name, the question Covers answers
//
// They coexist because a publishable key is also a key that may be narrowed, and
// splitting them into two fields would make "which one wins" a question Somebody
// has to answer at every read.
type Grant []string

// GrantClassPublish is the one CLASS entry, IAM's storage value for a key with no
// secret half. It is not a reach and Covers never consults it.
const GrantClassPublish = "publish"

// GrantOf is what the credential THIS request arrived on may reach. It is the
// second half of the rule gate.go states the first half of:
//
//	Scope.Admits(AuthorityOf(c)) && GrantOf(c).Covers(kind, name)
//
// Read off the boundary's own attestation, so a request cannot state its own
// limit — the same rule the org follows. An unattested request has no
// credential and therefore no limit; it is refused by the gate, not by this.
func GrantOf(c *zip.Ctx) Grant {
	p, ok := principal.Minted(c)
	if !ok {
		return nil
	}
	return Grant(p.Limit)
}

// ParseGrant reads a key's scope. Comma-separated, blanks dropped, order
// irrelevant — it is a set.
func ParseGrant(scope string) Grant {
	var g Grant
	for part := range strings.SplitSeq(scope, ",") {
		if p := strings.TrimSpace(part); p != "" {
			g = append(g, p)
		}
	}
	return g
}

// GrantKinds is every kind a limit may name, and it is the CLOSED set of
// questions the platform actually asks. A kind absent here is refused at the
// mint rather than stored, because a limit nothing consults is worse than no
// limit at all: it reads as a narrowing in the listing and is one nowhere.
//
// Adding a kind means adding the Covers call that asks it, in the same change.
var GrantKinds = []string{"deploy", "model", "project", "product", "read"}

// ParseLimit reads the `kind:name` entries an operator wrote and REFUSES what
// cannot be enforced. Duplicates collapse; order does not survive, because a
// grant is a set.
func ParseLimit(entries []string) (Grant, error) {
	seen := map[string]bool{}
	var g Grant
	for _, raw := range entries {
		e := strings.TrimSpace(raw)
		if e == "" {
			continue
		}
		kind, name, ok := strings.Cut(e, ":")
		if !ok || strings.TrimSpace(name) == "" {
			return nil, fmt.Errorf("limit %q must be kind:name, one of %s", raw, strings.Join(GrantKinds, ", "))
		}
		if !slices.Contains(GrantKinds, kind) {
			return nil, fmt.Errorf("limit %q names %q, which nothing enforces; use one of %s", raw, kind, strings.Join(GrantKinds, ", "))
		}
		// The grant is stored as ONE comma-separated field, so a comma or a space in a
		// name would split into entries nobody wrote — a class among them.
		if strings.ContainsAny(strings.TrimSpace(name), ", \t\r\n") {
			return nil, fmt.Errorf("limit %q has a name with a comma or a space in it", raw)
		}
		if e = kind + ":" + strings.TrimSpace(name); !seen[e] {
			seen[e] = true
			g = append(g, e)
		}
	}
	return g, nil
}

// String renders a grant as the one field IAM stores.
func (g Grant) String() string { return strings.Join(g, ",") }

// Publishable reports whether the key carries the publish CLASS.
func (g Grant) Publishable() bool {
	return slices.Contains(g, GrantClassPublish)
}

// Reach is the narrowing half of the grant — every `kind:name` entry of a kind
// GrantKinds names. The class is not a reach, and neither is the key's budget or
// rate, so none of them appears in it.
func (g Grant) Reach() Grant {
	var out Grant
	for _, e := range g {
		if kind, _, ok := strings.Cut(e, ":"); ok && slices.Contains(GrantKinds, kind) {
			out = append(out, e)
		}
	}
	return out
}

// A key's budget and rate ride in the same field as its reach, as entries that only
// the sites enforcing them read:
//
//	spend:month:5000   at most $50.00 of usage in a calendar month (UTC)
//	spend:total:20000  at most $200.00 of usage, ever
//	rate:minute:60     at most 60 requests a minute
//
// Amounts are cents. Each only ever narrows, like everything else in a grant.
const (
	spendMonth = "spend:month:"
	spendTotal = "spend:total:"
	rateMinute = "rate:minute:"
)

// Budget is what the key may spend, in cents: per calendar month and in total.
// Zero is no limit.
func (g Grant) Budget() (month, total int64) {
	return g.number(spendMonth), g.number(spendTotal)
}

// Rate is how many requests a minute the key may make. Zero is no limit.
func (g Grant) Rate() int { return int(g.number(rateMinute)) }

// number reads the one entry under prefix, or zero.
func (g Grant) number(prefix string) int64 {
	for _, e := range g {
		if v, ok := strings.CutPrefix(e, prefix); ok {
			if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
				return n
			}
		}
	}
	return 0
}

// Policy is g with its budget and rate set: the class and reach kept, a zero
// dropping that limit.
func (g Grant) Policy(month, total int64, rate int) Grant {
	var out Grant
	for _, e := range g {
		if !strings.HasPrefix(e, spendMonth) && !strings.HasPrefix(e, spendTotal) && !strings.HasPrefix(e, rateMinute) {
			out = append(out, e)
		}
	}
	if month > 0 {
		out = append(out, spendMonth+strconv.FormatInt(month, 10))
	}
	if total > 0 {
		out = append(out, spendTotal+strconv.FormatInt(total, 10))
	}
	if rate > 0 {
		out = append(out, rateMinute+strconv.Itoa(rate))
	}
	return out
}

// Covers reports whether this credential may reach kind/name.
//
// A grant that names NOTHING OF THIS KIND does not restrict this kind — a key
// limited to one project is not thereby limited to zero models. Restriction is
// per kind, so adding a kind at one call site cannot silently revoke a key that
// was written before that site existed.
//
// `kind:*` is the whole kind. An empty name is refused whenever the kind is
// restricted at all: the caller could not say what it was reaching, and a
// credential that names a limit must not be satisfied by silence.
func (g Grant) Covers(kind, name string) bool {
	prefix := kind + ":"
	restricted := false
	for _, e := range g {
		if !strings.HasPrefix(e, prefix) {
			continue
		}
		restricted = true
		switch v := e[len(prefix):]; v {
		case "*":
			return true
		case name:
			if name != "" {
				return true
			}
		}
	}
	return !restricted
}

// Permits reports whether this credential may make a request to capability,
// writing or only reading. capability is "" for an address no app serves, which
// only a whole-kind entry (`product:*`, `read:*`) reaches.
func (g Grant) Permits(capability string, write bool) bool {
	restricted := false
	for _, e := range g {
		kind, name, ok := strings.Cut(e, ":")
		if !ok || (kind != "product" && kind != "read") {
			continue
		}
		restricted = true
		if name != "*" && (name != capability || capability == "") {
			continue
		}
		if kind == "product" || !write {
			return true
		}
	}
	return !restricted
}
