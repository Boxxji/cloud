package brand

import (
	"slices"
	"testing"
)

// Every issuer a brand's tokens may carry is trusted by its own discovery document.
func TestDiscoveriesNameEveryIssuer(t *testing.T) {
	d := Discoveries()
	for _, want := range []string{
		"https://hanzo.ai/.well-known/openid-configuration",
		"https://hanzo.id/.well-known/openid-configuration",
	} {
		if !slices.Contains(d, want) {
			t.Fatalf("Discoveries() lacks %s: %v", want, d)
		}
	}
	seen := map[string]bool{}
	for _, u := range d {
		if seen[u] {
			t.Fatalf("Discoveries() repeats %s", u)
		}
		seen[u] = true
	}
}
