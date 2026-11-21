package audit

import (
	"cmp"
	"net/http"
)

// Access is one KMS operation as a chain keeps it: the verb on org:ref, who
// asked, and the verdict the grant rule returned. A value operation reads,
// writes or deletes one secret; a listing (verb "list") names what a subtree
// holds.
//
// kms builds it for its own chain, and admin builds it from the same fields when
// kms ships the access over the plane, so the two chains cannot describe one act
// two ways. verdict is "grant", "super", "admin" (a listing by an admin of the
// org, the one act org admin is admitted to), "deny" or "would-deny"; anything else is
// recorded as a denial, because a record that claims a success it cannot name is
// worse than one that errs toward refusal.
//
// The holder is named with the client its token was issued to when the two
// differ: a person's token names the app it was minted through, and a machine is
// its own client.
func Access(org, verb, ref, verdict, holder, client, user string, super bool) Record {
	who := cmp.Or(holder, "(none)")
	if client != "" && client != holder {
		who += " via " + client
	}
	rec := Record{
		Actor:    Actor{Org: org, Sub: user},
		Action:   "kms." + verb,
		Resource: Resource{Type: "kms.secret", ID: org + ":" + ref},
		Auth:     AuthContext{Method: "jwt", IsAdmin: super},
	}
	switch verdict {
	case "grant":
		rec.Outcome = Outcome{Result: "success", Status: http.StatusOK, Reason: "grant covers holder " + who}
	case "super":
		rec.Outcome = Outcome{Result: "success", Status: http.StatusOK, Reason: "superadmin " + who}
	case "admin":
		rec.Outcome = Outcome{Result: "success", Status: http.StatusOK, Reason: "org admin " + who}
	case "would-deny":
		rec.Outcome = Outcome{Result: "success", Status: http.StatusOK, Reason: "would-deny: no grant covers holder " + who}
	default:
		rec.Outcome = Outcome{Result: "deny", Status: http.StatusForbidden, Reason: "no grant covers holder " + who}
	}
	return rec
}
