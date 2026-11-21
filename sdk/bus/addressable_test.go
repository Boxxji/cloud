package bus

import (
	"testing"

	"github.com/hanzoai/namespace"
)

// addressable_test.go asks the question the comment above addressable answers
// for the SLUGGER: is the whole function injective?
//
// Sanitize refuses to be the identity on a name already shaped like one of its
// folds (looksSuffixed), which is what stops a folded name from being addressed
// by an org registered under it. addressable's OWN fallback — the bare
// sha256[:8] hex it returns for a name the slugger refuses — carries no such
// refusal: sixteen lowercase-hex characters is itself a clean DNS label, so it
// is a value Sanitize is the identity on, and the two branches share a codomain.
func TestAddressableBranchesDoNotShareACodomain(t *testing.T) {
	// A name the slugger refuses: whitespace is the rune class no fold survives.
	const refused = "a b"
	if namespace.Sanitize(refused) != "" {
		t.Fatalf("%q is no longer a name the slugger refuses; pick one it does", refused)
	}
	fallback := addressable(refused)
	if namespace.Sanitize(fallback) == fallback {
		t.Errorf("addressable's fallback %q is a name the slugger is the IDENTITY on: an org "+
			"registered under it addresses the same subject, stream and bucket. The slugger "+
			"refuses that for its own folds (looksSuffixed) and the fallback inherits no such refusal",
			fallback)
	}
}

// TestPhysIsATokenWhateverTheOrg holds the subject to the shape a NATS subject
// may have: no dot, no star, no space — the property C1 was raised about.
func TestPhysIsATokenWhateverTheOrg(t *testing.T) {
	for _, org := range []string{
		"hanzo", "hanzo.ai", "a.*.b", "*", ">", "a b", "HANZO", "-x-",
		"hanzo-ai-46cf0af5224ce42a", strings_repeat("z", 200),
	} {
		got := Phys(org, "patrol")
		if !token(got, true) {
			t.Errorf("Phys(%q) = %q is not a single subject token", org, got)
		}
	}
}

func strings_repeat(s string, n int) string {
	out := make([]byte, 0, n*len(s))
	for range n {
		out = append(out, s...)
	}
	return string(out)
}
