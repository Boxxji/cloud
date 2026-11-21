// Copyright © 2026 Hanzo AI. MIT License.

package plane

import "context"

// Addr is the name of a peer, as a TYPE rather than as a bare string.
//
// Call takes the app as a string, and a string is the one kind of argument the
// compiler cannot check. apps/coding spelled its peer "agents" — the subsystem's
// own name for itself, in its store, its logs and its base — where the app
// REGISTERS as "agent" and serves exactly that one socket. Every session call a
// coding run made went to a name nothing answers, came back ErrNoPeer, and the
// run died before it reached a sandbox. The live failure read
// `app is not deployed here: agents`, which is what a missing deployment looks
// like, so it was read as one.
//
// A named type does not stop that on its own. What stops it is having ONE place
// the name is written: the generated client/<app> package, whose App constant is
// emitted from the app's own registration. Passing that value instead of a
// literal is what makes the two agree by construction — a caller who invents a
// spelling has nothing to pass.
type Addr string

// Call sends one typed op to this app and returns its typed answer.
//
// This is a GENERIC METHOD (Go 1.27): App is not a generic type, and the method
// declares In and Out itself. Before 1.27 the same thing had to be a free
// function taking the app as a parameter — which is exactly the shape that let
// the name travel as a loose string. The method form puts the name on the
// receiver, where it is a value with a type, and leaves the caller naming only
// what the op actually needs.
//
// It is a thin forward to Call, deliberately: routing, co-residency, waking a
// lazy peer and the ErrNoPeer contract are all decided in one place, and adding
// a second entry point must not become a second answer to any of them.
func (a Addr) Call[In, Out any](ctx context.Context, op string, in *In) (*Out, error) {
	return Call[In, Out](ctx, string(a), op, in)
}
