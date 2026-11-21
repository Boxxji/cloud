package meter

import "testing"

func TestUnitName(t *testing.T) {
	for unit, want := range map[string]string{
		"session":              "Agent sessions",
		"op":                   "Storage requests",
		"desktop/visor":        "Desktop sandbox",
		"browser/visor":        "Browser sandbox",
		"dev/visor":            "Dev sandbox",
		"sandbox/desktop":      "Desktop sandbox hours",
		"sandbox/android/disk": "Android sandbox disk",
		" bot ":                "Bots",
		// An AI model is its own name, slash and all.
		"zen5":           "zen5",
		"openai/gpt-4o":  "openai/gpt-4o",
		"sandbox/nope":   "sandbox/nope",
		"desktop/a/b":    "desktop/a/b",
		"sandbox/dev/ex": "sandbox/dev/ex",
		"":               "",
	} {
		if got := UnitName(unit); got != want {
			t.Errorf("UnitName(%q) = %q, want %q", unit, got, want)
		}
	}
}
