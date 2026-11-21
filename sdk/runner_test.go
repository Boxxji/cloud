package cloud

import (
	"strconv"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/util/validation"
)

// A runner's name is an object name and a label value — the Job's own, and the
// job-name label its pod carries — whatever the repository is called. A dot
// beside a hyphen is neither, so foo._bar was a Job the API server refused.
func TestRunnerNameIsAnObjectName(t *testing.T) {
	for repo, want := range map[string]string{
		"foo._bar":          "runner-github-foo.bar-7",
		"a.-b":              "runner-github-a.b-7",
		"a..b":              "runner-github-a.b-7",
		"hanzo.ai":          "runner-github-hanzo.ai-7",
		"hanzoai_extension": "runner-github-hanzoai-extension-7",
		"weird__name__":     "runner-github-weird--name-7",
		"_.lead":            "runner-github-lead-7",
		"trail._":           "runner-github-trail-7",
		"Ünï.code":          "runner-github-n.code-7",
	} {
		if got := RunnerName("github", repo, 7, 0); got != want {
			t.Errorf("RunnerName(%q) = %q, want %q", repo, got, want)
		}
	}
}

func FuzzRunnerName(f *testing.F) {
	for _, repo := range []string{"foo._bar", "hanzo.ai", "a_.-_b", strings.Repeat("x.", 60), "Ünïcode", "-.-", "", strings.Repeat("_", 100)} {
		f.Add(repo, int64(52011983745), 3)
	}
	f.Fuzz(func(t *testing.T, repo string, id int64, try int) {
		if id <= 0 {
			return
		}
		try = min(max(try, 0), 9)
		name := RunnerName("github", repo, id, try)
		if errs := validation.IsDNS1123Subdomain(name); len(errs) > 0 {
			t.Fatalf("RunnerName(%q, %d, %d) = %q: %v", repo, id, try, name, errs)
		}
		if errs := validation.IsValidLabelValue(name); len(errs) > 0 {
			t.Fatalf("RunnerName(%q, %d, %d) = %q is no label value: %v", repo, id, try, name, errs)
		}
		tail := "-" + strconv.FormatInt(id, 10)
		if try > 0 {
			tail += "-r" + strconv.Itoa(try)
		}
		if !strings.HasSuffix(name, tail) {
			t.Fatalf("RunnerName(%q, %d, %d) = %q lost its id", repo, id, try, name)
		}
	})
}

// macOS and Windows are hosts, by any of their spellings, read part by part —
// never a substring, so a windmill is not Windows — and a label naming linux is
// Linux's.
func TestPodless(t *testing.T) {
	for _, l := range []string{"macOS", "macos-14", "macos14", "osx", "darwin-arm64", "m1", "M2", "m3", "m4",
		"self_hosted_mac", "Windows", "windows-2022", "win-amd64", "win32", "Win64", "windows_x64"} {
		if !Podless(l) {
			t.Errorf("Podless(%q) = false, want a host", l)
		}
	}
	for _, l := range []string{"windmill", "machine-learning", "twin", "gpu-macro", "linux-win-cross", "linux_mac_tools",
		"linux-amd64", "self-hosted", "ubuntu-latest", "X64", "ARM64", "m10", "hanzo-build-linux-amd64"} {
		if Podless(l) {
			t.Errorf("Podless(%q) = true, want a pod's", l)
		}
	}
}
