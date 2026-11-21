package env

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// probeSHA is a syntactically real object name that is not any commit in this
// repo, so a process reporting it can only have got it from the linker or from
// the parent that linked it.
const probeSHA = "0123456789abcdef0123456789abcdef01234567"

// decoySHA is the value a pod might carry in its environment. It is a legitimate
// object name, so nothing downstream can tell it from a real one — which is why a
// child must only ever report what its host published over it.
const decoySHA = "fedcba9876543210fedcba9876543210fedcba98"

// An ordinary `go test` build passes no -X and inherits no published build, and
// that is the case that has to be LOUD rather than plausible: a build which
// cannot name its commit must say exactly that.
//
// Empty is the specific wrong answer. An empty string renders as `"revision":""`
// — a field that is present, looks like a real payload, and reads to a human
// skimming a rollout check as "no revision recorded" rather than "this process
// cannot tell you what it is".
func TestRevisionOfAnUnstampedBuildIsUnknown(t *testing.T) {
	if revision != "" {
		t.Fatalf("this test binary was stamped (%q); it must run unstamped to assert the default", revision)
	}
	t.Setenv(revisionEnv, "")
	got := Revision()
	if got != "unknown" {
		t.Fatalf("Revision() = %q, want %q", got, "unknown")
	}
	if got == "" {
		t.Fatal(`Revision() = "" — an unknown revision must be the word "unknown", never a blank that reads as a populated field`)
	}
}

// Everything that is NOT a commit reports "unknown", including the values most
// likely to arrive by accident: an unexpanded ${REVISION} when a build-arg was
// never passed, a branch name from a non-git build context, and a short sha from
// a `git rev-parse --short` somebody thought was equivalent.
//
// A near-miss is worse than no answer, because someone acts on it.
func TestRevisionReportsOnlyAFullCommitName(t *testing.T) {
	restore := revision
	t.Cleanup(func() { revision = restore })

	for _, bad := range []string{
		"",
		"unknown",
		"${REVISION}",
		"main",
		"dev",
		"v1.801.426",
		"0123456789ab", // short sha
		"0123456789abcdef0123456789abcdef0123456",    // 39
		"0123456789abcdef0123456789abcdef012345678",  // 41
		"0123456789ABCDEF0123456789ABCDEF01234567",   // uppercase
		"0123456789abcdef0123456789abcdef0123456g",   // non-hex
		" 0123456789abcdef0123456789abcdef01234567",  // leading space
		"0123456789abcdef0123456789abcdef01234567\n", // trailing newline
		"0123456789abcdef0123456789abcdef01234567-dirty",
	} {
		revision = bad
		if got := Revision(); got != "unknown" {
			t.Errorf("revision=%q: Revision() = %q, want %q", bad, got, "unknown")
		}
		if IsCommit(bad) {
			t.Errorf("IsCommit(%q) = true, want false", bad)
		}
	}

	revision = probeSHA
	if got := Revision(); got != probeSHA {
		t.Fatalf("revision=%q: Revision() = %q, want it reported verbatim", probeSHA, got)
	}
	if !IsCommit(probeSHA) {
		t.Fatalf("IsCommit(%q) = false, want true", probeSHA)
	}
}

// Version's rungs, in order. The operator's HANZO_VERSION is what makes a rollout
// verifiable — it carries the tag that was deployed, so a pod reports the build
// it actually is instead of the link-time default — and an explicit CLOUD_VERSION
// still wins over it.
func TestVersionSourcing(t *testing.T) {
	restore := version
	t.Cleanup(func() { version = restore })
	version = "v1.786.207"

	t.Setenv("HANZO_VERSION", "")
	t.Setenv(versionEnv, "v9.9.9")
	if got := Version(); got != "v9.9.9" {
		t.Errorf("Version() = %q, want v9.9.9 (from CLOUD_VERSION)", got)
	}

	t.Setenv(versionEnv, "")
	t.Setenv("HANZO_VERSION", "v1.801.233")
	if got := Version(); got != "v1.801.233" {
		t.Errorf("Version() = %q, want v1.801.233 (from HANZO_VERSION)", got)
	}

	t.Setenv(versionEnv, "v9.9.9")
	if got := Version(); got != "v9.9.9" {
		t.Errorf("Version() = %q, want v9.9.9 (CLOUD_VERSION overrides HANZO_VERSION)", got)
	}

	t.Setenv(versionEnv, "")
	t.Setenv("HANZO_VERSION", "")
	if got := Version(); got != version {
		t.Errorf("Version() = %q, want the linked %q", got, version)
	}

	version = ""
	if got := Version(); got != "dev" {
		t.Errorf("Version() = %q, want dev — an unstamped, unlabelled build is never mistaken for a released one", got)
	}
}

// THE ONE THAT MATTERS FOR THE LINKER. It links a real binary with the flag the
// image passes and asks the PROCESS what it is.
//
// A test that merely assigned `revision` itself would pass forever while the real
// stamp reached nothing: `-X` naming an import path or symbol the linker cannot
// resolve is not an error, it is dropped silently, and the binary then reports the
// perfectly legitimate "unknown". So renaming this package, moving the variable or
// mistyping the path in the Dockerfile all fail in the one way nobody looks at —
// unless something links and runs the result. This does.
//
// The child is handed a DECOY in the environment, because a dropped stamp would
// otherwise be covered by the runtime path: a binary that answers its parent's
// value looks identical to one that answers its own until the two disagree.
func TestRevisionStampReachesTheLinker(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "revision.test")

	build := exec.Command("go", "test", "-c", "-o", bin,
		"-ldflags", "-X github.com/hanzoai/cloud/sdk/env.revision="+probeSHA, ".")
	build.Env = append(os.Environ(), "GOWORK=off")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("linking a stamped test binary failed: %v\n%s", err, out)
	}

	run := exec.Command(bin, "-test.run", "^TestRevisionIsTheStampedCommit$", "-test.v")
	run.Env = append(os.Environ(), revisionEnv+"="+decoySHA)
	out, err := run.CombinedOutput()

	// Read the ANSWER out of the output, never the exit code. A skipped test and a
	// passing test exit 0 alike, so an inner test that skips itself when it finds
	// no stamp reports success in precisely the case this is here to catch.
	want := "REVISION=" + probeSHA
	if err != nil || !bytes.Contains(out, []byte(want)) {
		t.Fatalf("the stamped binary never printed %q: the -X flag named an import path or "+
			"symbol the linker could not resolve, so it was silently dropped and every "+
			"health response this fleet serves would report \"unknown\".\nerr: %v\n%s",
			want, err, out)
	}
	t.Logf("the process was asked and answered:\n%s", out)
}

// TestRevisionIsTheStampedCommit is the inner half of the test above — the
// assertion that runs INSIDE the stamped binary. An ordinary run of this package
// links no -X, so it asserts nothing there; the outer test is what gives it a
// stamp and reads its verdict.
func TestRevisionIsTheStampedCommit(t *testing.T) {
	// Printed unconditionally, and printed first, because this line is
	// the outer test's evidence. Whatever this binary believes it is, it says so.
	t.Logf("REVISION=%s", Revision())
	if revision == "" {
		return // unstamped: TestRevisionStampReachesTheLinker links a stamped binary and runs this in it
	}
	if got := Revision(); got != probeSHA {
		t.Fatalf("Revision() = %q, want the linked %q", got, probeSHA)
	}
}

// THE RUNTIME PATH, end to end: a stamped host publishes its build and a child
// with no stamp of its own reports it. The child here is this test binary
// re-executed — unstamped, exactly like every per-app binary the image ships — so
// the only way it can answer probeSHA is by reading what Export wrote.
//
// The environment it starts from carries a DECOY revision, which is what a pod
// spec or a leftover variable looks like. Export overwrites it, so the answer is
// the host's build and never the environment's.
func TestExportReachesAnUnstampedChild(t *testing.T) {
	t.Setenv(versionEnv, "")
	t.Setenv("HANZO_VERSION", "")
	t.Setenv(revisionEnv, decoySHA)

	restoreV, restoreR := version, revision
	t.Cleanup(func() { version, revision = restoreV, restoreR })
	version, revision = "v8.5.180", probeSHA

	ExportBuild()

	run := exec.Command(os.Args[0], "-test.run", "^TestChildAnswersTheHostsBuild$", "-test.v")
	out, err := run.CombinedOutput()
	want := "BUILD=v8.5.180 " + probeSHA
	if err != nil || !bytes.Contains(out, []byte(want)) {
		t.Fatalf("the child never printed %q — a plugin cannot name the build it belongs to.\nerr: %v\n%s",
			want, err, out)
	}
	t.Logf("the child was asked and answered:\n%s", out)
}

// TestChildAnswersTheHostsBuild is the inner half: it runs in the child process
// TestExportReachesAnUnstampedChild starts, and says what build it answers with.
// The outer test reads that line.
func TestChildAnswersTheHostsBuild(t *testing.T) {
	if revision != "" {
		t.Fatalf("this binary was stamped (%q); the child must be unstamped, as every plugin is", revision)
	}
	t.Logf("BUILD=%s %s", Version(), Revision())
}
