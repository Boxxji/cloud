package cloud_test

// A subsystem registers and gates inside the prefixes it declared, and has no
// way above them.

import (
	"net/http"
	"testing"
	"time"

	cloud "github.com/hanzoai/cloud/sdk"
	luxlog "github.com/luxfi/log"
	"github.com/zap-proto/zip"
)

// deny answers 401.
func deny(c *zip.Ctx) error { return c.JSON(http.StatusUnauthorized, map[string]string{"e": "denied"}) }

// pong answers 200.
func pong(c *zip.Ctx) error { return c.JSON(http.StatusOK, map[string]string{"ok": "pong"}) }

// get returns the status of an in-memory request.
func get(t *testing.T, app *zip.App, path string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "http://cloud.test"+path, nil)
	if err != nil {
		t.Fatalf("NewRequest %s: %v", path, err)
	}
	resp, err := app.Test(req, zip.TestConfig{Timeout: 30 * time.Second, FailOnTimeout: true})
	if err != nil {
		t.Fatalf("Test %s: %v", path, err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func mountAll(t *testing.T, app *zip.App, specs []cloud.Plugin) error {
	t.Helper()
	enable := make([]string, 0, len(specs))
	for _, s := range specs {
		enable = append(enable, s.Name)
	}
	return cloud.UseAll(app, specs,
		&cloud.Config{Enable: enable},
		cloud.Deps{})
}

func newApp() *zip.App {
	return zip.New(zip.Config{Logger: luxlog.NewNoOpLogger(), DisableStartupMessage: true})
}

// guard refuses everything; neighbour stays open.
func TestUseStaysInside(t *testing.T) {
	app := newApp()
	err := mountAll(t, app, []cloud.Plugin{
		{Name: "guard", Use: func(r cloud.Router, _ cloud.Deps) error {
			g := r.Group("/v1/guard")
			g.Use(zip.H(deny))
			g.Raw(http.MethodGet, "/whoami", pong)
			return nil
		}},
		{Name: "neighbour", Use: func(r cloud.Router, _ cloud.Deps) error {
			r.Group("/v1/neighbour").Raw(http.MethodGet, "/ping", pong)
			return nil
		}},
	})
	if err != nil {
		t.Fatalf("UseAll: %v", err)
	}

	if got := get(t, app, "/v1/neighbour/ping"); got != http.StatusOK {
		t.Errorf("neighbour = %d, want 200 — guard's middleware escaped its subsystem", got)
	}
	if got := get(t, app, "/v1/guard/whoami"); got != http.StatusUnauthorized {
		t.Errorf("guard = %d, want 401 — the subsystem's own gate must still run", got)
	}
}

// A gate covers each route the subsystem registered, on every prefix it holds.
func TestGateCoversOwnRoutes(t *testing.T) {
	app := newApp()
	err := mountAll(t, app, []cloud.Plugin{
		{Name: "identity", Prefixes: []string{"/v1/identity", "/login/oauth"},
			Use: func(r cloud.Router, _ cloud.Deps) error {
				r.Group("/v1/identity", deny).Raw(http.MethodGet, "/me", pong)
				r.Group("/login/oauth", deny).Raw(http.MethodGet, "/authorize", pong)
				return nil
			}},
		{Name: "neighbour", Use: func(r cloud.Router, _ cloud.Deps) error {
			r.Group("/v1/neighbour").Raw(http.MethodGet, "/ping", pong)
			return nil
		}},
	})
	if err != nil {
		t.Fatalf("UseAll: %v", err)
	}

	for _, p := range []string{"/v1/identity/me", "/login/oauth/authorize"} {
		if got := get(t, app, p); got != http.StatusUnauthorized {
			t.Errorf("%s = %d, want 401 — a route the subsystem registered must be gated", p, got)
		}
	}
	if got := get(t, app, "/v1/neighbour/ping"); got != http.StatusOK {
		t.Errorf("neighbour = %d, want 200 — another subsystem's subtree must stay open", got)
	}
}

// Asking for a prefix the subsystem does not hold fails the mount, and the
// routes it declared there serve nowhere.
func TestForeignPrefixFailsTheMount(t *testing.T) {
	app := newApp()
	err := mountAll(t, app, []cloud.Plugin{
		{Name: "neighbour", Use: func(r cloud.Router, _ cloud.Deps) error {
			r.Group("/v1/neighbour").Raw(http.MethodGet, "/ping", pong)
			return nil
		}},
		{Name: "greedy", Use: func(r cloud.Router, _ cloud.Deps) error {
			r.Group("/v1").Raw(http.MethodGet, "/neighbour/ping", deny)
			return nil
		}},
	})
	if err == nil {
		t.Fatal("UseAll accepted a subsystem that asked for a prefix above its own")
	}
	if got := get(t, app, "/v1/neighbour/ping"); got != http.StatusOK {
		t.Errorf("neighbour = %d, want 200 — a refused prefix reached another subsystem's route", got)
	}
}

// A leaf that reads like another subsystem's address composes under the prefix
// the subsystem holds, so it cannot answer there.
func TestSiblingAddressIsALeaf(t *testing.T) {
	app := newApp()
	err := mountAll(t, app, []cloud.Plugin{
		{Name: "other", Use: func(r cloud.Router, _ cloud.Deps) error {
			r.Group("/v1/other").Raw(http.MethodGet, "", pong)
			return nil
		}},
		{Name: "sneak", Use: func(r cloud.Router, _ cloud.Deps) error {
			r.Group("/v1/sneak").Raw(http.MethodGet, "/v1/other", deny)
			return nil
		}},
	})
	if err != nil {
		t.Fatalf("UseAll: %v", err)
	}
	if got := get(t, app, "/v1/other"); got != http.StatusOK {
		t.Errorf("/v1/other = %d, want 200 — a sibling's leaf answered at the address", got)
	}
	if got := get(t, app, "/v1/sneak/v1/other"); got != http.StatusUnauthorized {
		t.Errorf("/v1/sneak/v1/other = %d, want 401 — the leaf composes under the prefix", got)
	}
}

// A route registered at an absolute path beneath another subsystem's gated
// prefix fails the mount, so it never serves ungated.
func TestAbsolutePathCannotEscapeAGate(t *testing.T) {
	app := newApp()
	err := mountAll(t, app, []cloud.Plugin{
		{Name: "vault", Use: func(r cloud.Router, _ cloud.Deps) error {
			r.Use(zip.H(deny))
			r.Group("/v1/vault").Raw(http.MethodGet, "/secret", pong)
			return nil
		}},
		{Name: "sneak", Use: func(r cloud.Router, _ cloud.Deps) error {
			r.Raw(http.MethodGet, "/v1/vault/open", pong)
			return nil
		}},
	})
	if err == nil {
		t.Fatal("UseAll composed a route declared under another subsystem's prefix")
	}
	if got := get(t, app, "/v1/vault/secret"); got != http.StatusUnauthorized {
		t.Errorf("/v1/vault/secret = %d, want 401", got)
	}
	if got := get(t, app, "/v1/vault/open"); got == http.StatusOK {
		t.Errorf("/v1/vault/open = 200: the route serves, and no gate covers it")
	}
}

// The empty leaf is the group's own address.
func TestGroupGatesItsRoutes(t *testing.T) {
	app := newApp()
	err := mountAll(t, app, []cloud.Plugin{
		{Name: "vault", Use: func(r cloud.Router, _ cloud.Deps) error {
			g := r.Group("/v1/vault")
			auth := g.Group("/auth", deny)
			auth.Raw(http.MethodGet, "/login", pong)
			auth.Raw(http.MethodGet, "", pong)
			g.Raw(http.MethodGet, "/status", pong)
			return nil
		}},
	})
	if err != nil {
		t.Fatalf("UseAll: %v", err)
	}
	for _, p := range []string{"/v1/vault/auth/login", "/v1/vault/auth"} {
		if got := get(t, app, p); got != http.StatusUnauthorized {
			t.Errorf("%s = %d, want 401", p, got)
		}
	}
	if got := get(t, app, "/v1/vault/status"); got != http.StatusOK {
		t.Errorf("vault status = %d, want 200 — the group gate must not cover the whole subsystem", got)
	}
}

// Root mounts on the app, so its middleware reaches every route.
func TestRootCoversEveryRoute(t *testing.T) {
	app := newApp()
	err := mountAll(t, app, []cloud.Plugin{
		{Name: "edge", Root: func(a *zip.App, _ cloud.Deps) error {
			a.Use(zip.H(deny))
			return nil
		}},
		{Name: "neighbour", Use: func(r cloud.Router, _ cloud.Deps) error {
			r.Group("/v1/neighbour").Raw(http.MethodGet, "/ping", pong)
			return nil
		}},
	})
	if err != nil {
		t.Fatalf("UseAll: %v", err)
	}
	if got := get(t, app, "/v1/neighbour/ping"); got != http.StatusUnauthorized {
		t.Errorf("neighbour = %d, want 401 — host middleware must still reach every route", got)
	}
}

// Setting both Use and Root is refused.
func TestUseAndRootRefused(t *testing.T) {
	app := newApp()
	err := mountAll(t, app, []cloud.Plugin{
		{Name: "both",
			Use:  func(cloud.Router, cloud.Deps) error { return nil },
			Root: func(*zip.App, cloud.Deps) error { return nil }},
	})
	if err == nil {
		t.Fatal("UseAll accepted a subsystem declaring both Use and Root")
	}
}
