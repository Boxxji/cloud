package cloud

import (
	"context"
	"errors"
	"testing"

	"github.com/hanzoai/cloud/sdk/kit"
)

// A no-op dispatch client is not safe when no releaser is registered: platform runs as
// its own plugin and every plugin main mounts exactly one app, so "no releaser
// registered" is the state of every process that calls this, and each would be told its
// release had rolled out while no CR was patched. The dispatch therefore reports the
// absence instead of passing silently.
//
// Absence is now an error, and the error says the app is not deployed here.
func TestOnServiceReleaseAbsenceIsAnError(t *testing.T) {
	t.Setenv("ZIP_RUNTIME_DIR", kit.Sockets(t)) // no socket for platform
	t.Setenv("ZIP_ADDR", "")                    // and no router that could start one
	RegisterServiceReleaser(nil)

	err := OnServiceRelease(context.Background(), ServiceReleaseEvent{
		Service: "cloud", Image: "ghcr.io/hanzoai/cloud:v1.0.0",
	})
	if err == nil {
		t.Fatal("OnServiceRelease returned nil with no releaser and no peer — " +
			"a release that patched no CR, reported as success")
	}
	if !errors.Is(err, ErrNoPeer) {
		t.Fatalf("OnServiceRelease = %v, want an error wrapping ErrNoPeer so a "+
			"caller can tell 'platform is not deployed' from 'the rollout failed'", err)
	}
}

// TestOnServiceReleaseDispatch proves a registered releaser receives the exact
// event and its error propagates — the one inversion point platform installs
// when it IS co-resident. That leg was always correct and is unchanged.
func TestOnServiceReleaseDispatch(t *testing.T) {
	var got ServiceReleaseEvent
	sentinel := errors.New("boom")
	RegisterServiceReleaser(func(_ context.Context, ev ServiceReleaseEvent) error {
		got = ev
		return sentinel
	})
	t.Cleanup(func() { RegisterServiceReleaser(nil) })

	want := ServiceReleaseEvent{Service: "hanzo-app", Image: "ghcr.io/hanzoai/hanzo-app:v1.42.15", SHA: "abc1234"}
	if err := OnServiceRelease(context.Background(), want); !errors.Is(err, sentinel) {
		t.Fatalf("OnServiceRelease error = %v, want sentinel", err)
	}
	if got != want {
		t.Fatalf("releaser received %+v, want %+v", got, want)
	}
}

// TestCoResidentReleaserIsPreferred proves the local leg WINS when it exists: a
// co-resident releaser must never pay a socket round trip to reach itself.
func TestCoResidentReleaserIsPreferred(t *testing.T) {
	t.Setenv("ZIP_RUNTIME_DIR", kit.Sockets(t))
	t.Setenv("ZIP_ADDR", "")
	called := false
	RegisterServiceReleaser(func(context.Context, ServiceReleaseEvent) error {
		called = true
		return nil
	})
	t.Cleanup(func() { RegisterServiceReleaser(nil) })

	if err := OnServiceRelease(context.Background(), ServiceReleaseEvent{Service: "cloud", Image: "x:v1.0.0"}); err != nil {
		t.Fatalf("co-resident release = %v, want nil", err)
	}
	if !called {
		t.Fatal("co-resident releaser was not called; the local leg must win over the plane")
	}
}
