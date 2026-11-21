package audit

import "testing"

// Every verdict the grant rule can return lands as the outcome a reader of the
// trail needs: a served read is a success naming why, a refusal is a deny, and
// an unknown verdict errs toward deny rather than claiming a success.
func TestAccessNamesTheVerdict(t *testing.T) {
	for _, c := range []struct {
		verdict, result, reason string
		status                  int
	}{
		{"grant", "success", "grant covers holder hanzo-ci", 200},
		{"super", "success", "superadmin hanzo-ci", 200},
		{"admin", "success", "org admin hanzo-ci", 200},
		{"would-deny", "success", "would-deny: no grant covers holder hanzo-ci", 200},
		{"deny", "deny", "no grant covers holder hanzo-ci", 403},
		{"", "deny", "no grant covers holder hanzo-ci", 403},
	} {
		r := Access("hanzo", "read", "/deploy/GITHUB_TOKEN@prod", c.verdict, "hanzo-ci", "hanzo-ci", "u1", false)
		if r.Outcome.Result != c.result || r.Outcome.Status != c.status || r.Outcome.Reason != c.reason {
			t.Errorf("%q: outcome %+v", c.verdict, r.Outcome)
		}
		if r.Action != "kms.read" || r.Resource.Type != "kms.secret" || r.Resource.ID != "hanzo:/deploy/GITHUB_TOKEN@prod" {
			t.Errorf("%q: action %q resource %+v", c.verdict, r.Action, r.Resource)
		}
		if r.Actor.Org != "hanzo" || r.Actor.Sub != "u1" {
			t.Errorf("%q: actor %+v", c.verdict, r.Actor)
		}
	}
}

// A person's token names the app it was minted through; a machine is its own
// client and is named once.
func TestAccessNamesTheClientBesideTheHolder(t *testing.T) {
	if got := Access("hanzo", "write", "/x@prod", "super", "hanzo/z", "hanzo-cli", "", true).Outcome.Reason; got != "superadmin hanzo/z via hanzo-cli" {
		t.Errorf("person: %q", got)
	}
	if got := Access("hanzo", "read", "/x@prod", "deny", "", "", "", false).Outcome.Reason; got != "no grant covers holder (none)" {
		t.Errorf("no holder: %q", got)
	}
	if r := Access("hanzo", "write", "/x@prod", "super", "hanzo/z", "", "", true); !r.Auth.IsAdmin || r.Action != "kms.write" {
		t.Errorf("super write: %+v", r)
	}
}
