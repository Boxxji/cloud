package kit

import (
	"path/filepath"
	"testing"
)

func TestCIReadsTheRunnersWord(t *testing.T) {
	for _, name := range []string{"CI", "GITHUB_ACTIONS", "HANZO_CI"} {
		t.Setenv(name, "")
	}
	if CI() {
		t.Fatal("a run no runner named reads as the gate's")
	}
	for _, off := range []string{"false", "0"} {
		t.Setenv("CI", off)
		if CI() {
			t.Fatalf("CI=%s reads as the gate's", off)
		}
	}
	t.Setenv("CI", "")
	t.Setenv("HANZO_CI", "true")
	if !CI() {
		t.Fatal("HANZO_CI=true does not read as the gate's")
	}
}

func TestToolAnswersThePathOfAProgramThatIsThere(t *testing.T) {
	got := Tool(t, "go")
	if len(got) != 1 || !filepath.IsAbs(got[0]) {
		t.Fatalf("Tool(go) = %v, want one absolute path", got)
	}
}
