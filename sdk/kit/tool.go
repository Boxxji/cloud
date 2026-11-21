package kit

import (
	"os"
	"os/exec"
	"testing"
)

// CI reports whether this run is the gate's.
func CI() bool {
	for _, name := range []string{"CI", "GITHUB_ACTIONS", "HANZO_CI"} {
		if v := os.Getenv(name); v != "" && v != "false" && v != "0" {
			return true
		}
	}
	return false
}

// Tool answers the path of each named program, in order.
func Tool(t testing.TB, names ...string) []string {
	t.Helper()
	paths := make([]string, len(names))
	for i, name := range names {
		path, err := exec.LookPath(name)
		if err != nil {
			if CI() {
				t.Fatalf("%s is not on the gate's PATH, so this test did not run: %v", name, err)
			}
			t.Skipf("%s is not installed", name)
		}
		paths[i] = path
	}
	return paths
}
