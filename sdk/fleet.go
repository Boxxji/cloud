package cloud

// fleet.go — what the framework asks of the deployment's app table.
//
// Which app owns an address, which prefixes an app is published under, what stage it
// is in and which subsystems run on hanzo-sql are facts of the fleet, not of the
// framework, so the framework holds no table of them: the host registers the answers
// once, at boot, as the openapi hook spec.Reserve is filled. Until it does, nothing is
// owned, nothing is staged and no subsystem is on hanzo-sql, which is a standalone
// process with no fleet.

import (
	"github.com/hanzoai/cloud/sdk/locus"
	"sync/atomic"
)

// Fleet answers the framework's questions about the app table. A nil field answers
// "nothing".
type Fleet struct {
	// OwnerOf names the app that owns a routed address.
	OwnerOf func(path string) string
	// Normalize rewrites the other grammatical number of a capability's name to the one
	// it is published under.
	Normalize func(path string) string
	// PrefixesFor is the address prefixes an app is published under.
	PrefixesFor func(name string) []string
	// StageOf is an app's stage: "", "alpha" or "beta".
	StageOf func(name string) string
	// OpenOf is the GET addresses of an app a caller may read before it has standing.
	OpenOf func(name string) []string
}

// StageBeta is the stage a platform-wide switch, not a per-org flag, lets a caller into.
const StageBeta = "beta"

var appTable atomic.Pointer[Fleet]

// SetFleet installs the deployment's app table. The host calls it once, at boot.
func SetFleet(f Fleet) { appTable.Store(&f) }

func fleetOf() Fleet {
	if f := appTable.Load(); f != nil {
		return *f
	}
	return Fleet{}
}

func appOwning(path string) string {
	if f := fleetOf().OwnerOf; f != nil {
		return f(path)
	}
	return ""
}

func normalize(path string) string {
	if f := fleetOf().Normalize; f != nil {
		return f(path)
	}
	return path
}

func prefixesFor(name string) []string {
	if f := fleetOf().PrefixesFor; f != nil {
		return f(name)
	}
	return nil
}

func stageOf(name string) string {
	if f := fleetOf().StageOf; f != nil {
		return f(name)
	}
	return ""
}

func openOf(name string) []string {
	if f := fleetOf().OpenOf; f != nil {
		return f(name)
	}
	return nil
}

// onSQL reports whether a subsystem's store runs on hanzo-sql: the registered
// server engine says, since which stores are ported is production wiring.
func onSQL(subsystem string) bool { return locus.Ported(subsystem) }
