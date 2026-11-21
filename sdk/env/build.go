package env

import "os"

// The build a process belongs to: the tag it was published under and the commit
// it was linked from.
//
// ONE BINARY CARRIES THE STAMP — the host, cmd/cloud. The linker writes both
// values into it (-X github.com/hanzoai/cloud/sdk/env.version and .revision)
// and into nothing else, the host publishes them to every process it starts
// (ExportBuild), and a plugin reads them back out of its environment.
//
// The stamp is a PER-COMMIT value, so whatever carries it has different bytes on
// every commit. Linked into every per-app binary it made each of them a new object
// each time anything anywhere changed, which is the whole reason an image could
// never ship less than its entire plugin set: no layer holding an untouched
// subsystem ever matched the one already on the node. Unstamped, a plugin's bytes
// are a function of its own source graph alone, and the image groups them into
// layers that stay byte-identical until one of their apps actually changes (see
// the Dockerfile).

// The environment the host publishes its build on, and the only channel a child
// has for it. CLOUD_VERSION is also the operator's own override, which is why
// ExportBuild resolves before it writes: the value a child inherits is the answer,
// already decided, rather than one more rung for it to climb.
const (
	versionEnv  = "CLOUD_VERSION"
	revisionEnv = "CLOUD_REVISION"
)

// version and revision are written by the linker, into the host alone:
//
//	-ldflags "-X github.com/hanzoai/cloud/sdk/env.version=<tag>
//	          -X github.com/hanzoai/cloud/sdk/env.revision=<40-hex>"
//
// The image proves the stamp landed by grepping /cloud's linked bytes, because
// `-X` naming a path or symbol the linker cannot resolve is not an error — it is
// dropped, silently, and every health response then reads "unknown" forever.
var version, revision string

// Version is what this build is CALLED — the X-Api-Version header, an operator's
// label. CLOUD_VERSION is the explicit override and what the host publishes;
// HANZO_VERSION is set on every container from the tag that was deployed, so a
// pod can name its own build without a rebuild; the linked tag is the default,
// and "dev" is what an untagged `go build` answers.
func Version() string {
	linked := version
	if linked == "" {
		linked = "dev"
	}
	return Or(versionEnv, Or("HANZO_VERSION", linked))
}

// Revision is the commit these bytes were built from, or "unknown".
//
// A stamped process answers from its own linked bytes. A plugin has no stamp and
// answers what the host published — which the host writes unconditionally, so a
// CLOUD_REVISION set from anywhere else is overwritten before any child exists
// and cannot name a commit the image was never built from.
//
// UNKNOWN IS A VALUE, NOT A BLANK, and only a full 40-char lowercase hex object
// name is ever reported: an unexpanded "${REVISION}", a branch name, "dev", a
// short sha and the empty string all read "unknown". A near-miss is worse than no
// answer at all, because someone acts on it.
func Revision() string {
	r := revision
	if r == "" {
		r = os.Getenv(revisionEnv)
	}
	if !IsCommit(r) {
		return "unknown"
	}
	return r
}

// IsCommit reports whether s names a git commit: a full 40-char lowercase hex
// object name, exactly.
//
// It is the ONE rule for that, applied at BOTH ends of the same wire — the
// builder refuses to pass build-arg:REVISION unless it holds (apps/platform), and
// this process refuses to report a value unless it holds — so the two cannot
// drift into disagreeing about what they hand each other.
func IsCommit(s string) bool {
	if len(s) != 40 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// ExportBuild publishes this process's build to the processes it starts, which inherit
// the environment (zip spawns a plugin with os.Environ()). The host calls it
// before it mounts anything.
//
// The revision written is the LINKED one and it is written even when there is
// none, so an unstamped host CLEARS the variable rather than passing on a value
// it did not produce. The version written is the resolved one, so the override an
// operator set on the pod survives into every child.
func ExportBuild() {
	_ = os.Setenv(versionEnv, Version())
	_ = os.Setenv(revisionEnv, revision)
}
