package cloud

import "testing"

// A push is ours when the login is empty, carries GitHub's App suffix in any
// case, or is one of the forge accounts that write on the estate's behalf.
// Anything else is a person, including a name that merely starts like ours.
func TestIsBotActor(t *testing.T) {
	for login, want := range map[string]bool{
		"":                 true,
		"  ":               true,
		"hanzo-actions":    true,
		"hanzo-sync":       true,
		"Hanzo-Sync":       true,
		"renovate[BOT]":    true,
		"hanzo-cloud[bot]": true,
		"zeekay":           false,
		"hanzo-syncer":     false,
		"sync":             false,
	} {
		if got := IsBotActor(login); got != want {
			t.Errorf("IsBotActor(%q) = %v, want %v", login, got, want)
		}
	}
}
