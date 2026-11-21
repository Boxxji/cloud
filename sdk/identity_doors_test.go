package cloud

// A FORGED IDENTITY IS REFUSED AT EVERY DOOR, OR AT NONE.
//
// SanitizeIdentity strips every identity header a client sent and writes back
// only what a validated credential says, so a caller cannot name its own tenant.
// That property is proven on one path — a plain GET /probe — and a typed
// operation is reachable more than one way. The three controls beside it turned
// out to hold on that one path and not on the others, each because the value
// they read was a property of the transport rather than of the operation. This
// is the same question asked of the identity boundary, which is the one where a
// gap would not be an accounting error.
//
// The operation reads identity the way an operation does: principal's typed
// readers, which resolve from the slot the boundary parked AND, failing that,
// from the caller a tools/call carries. That fallback is exactly why this needs
// asking — a reader that falls back to the caller is reading the request, and
// the request is where the forged headers were.
//
// THE POSITIVE CONTROL IS THE POINT. A test that drives three doors and finds no
// identity on any of them proves nothing on its own: it looks identical to three
// doors that never reached the operation. So the same forgery runs against the
// same app WITHOUT the boundary, where it must be seen on every door — that is
// what makes the refusal above a refusal rather than a silence.

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hanzoai/cloud/sdk/kit"
	"github.com/hanzoai/cloud/sdk/principal"
	"github.com/valyala/fasthttp"
	"github.com/zap-proto/zip"
)

type forgeIn struct {
	N int `json:"n"`
}

type forgeOut struct {
	OK bool `json:"ok"`
}

// forged is what the operation saw of the caller that claimed it.
type forged struct {
	org       string
	validated bool
}

type forgeRig struct {
	base string
	sock string
	app  *zip.App
	saw  *forged
}

// forgeApp mounts one typed op behind the identity boundary, or without it. The
// handler records what the OPERATION resolves, not what the middleware wrote,
// because the operation is what gates.
func forgeApp(t *testing.T, boundary bool) *forgeRig {
	t.Helper()
	t.Setenv(zip.RuntimeDirEnv, kit.Sockets(t))

	saw := &forged{}
	const service = "forge"
	app := zip.New(zip.Config{AppName: service})
	// THE BOUNDARY FIRST, then Bridge. Bridge copies org and validated onto the
	// context as it passes, so a Bridge installed ahead of the boundary captures
	// what the CLIENT sent and every typed reader downstream answers from that.
	// app.go installs them in this order; getting it wrong here cost a round and
	// is the reason forgeOrder below exists.
	if boundary {
		app.Use(SanitizeIdentity(nil))
	}
	app.Use(Bridge())
	app.Post("/v1/forge/run", func(ctx context.Context, in *forgeIn) (*forgeOut, error) {
		org, _ := principal.OrgFrom(ctx)
		saw.org = org
		saw.validated = principal.ValidatedFrom(ctx)
		return &forgeOut{OK: true}, nil
	}, zip.WithOperationID("forge_run"))
	if err := app.Build(); err != nil {
		t.Fatalf("build: %v", err)
	}

	sp := zip.SocketPath(service)
	go func() { _ = app.Listen(sp) }()
	t.Cleanup(func() { _ = app.Shutdown() })
	for deadline := time.Now().Add(5 * time.Second); ; {
		if _, err := os.Stat(sp); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the ZAP socket never appeared at %s", sp)
		}
		time.Sleep(2 * time.Millisecond)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = fasthttp.Serve(ln, app.Fiber().Handler()) }()
	t.Cleanup(func() { _ = ln.Close() })

	return &forgeRig{base: "http://" + ln.Addr().String(), sock: sp, app: app, saw: saw}
}

// claim stamps the identity a caller would like to have. No credential is
// presented: this is a client naming its own tenant.
func claim(h http.Header) {
	h.Set("Content-Type", "application/json")
	h.Set("X-Org-Id", "victim")
	h.Set("X-User-Id", "mallory")
	h.Set("X-User-Name", "mallory")
	h.Set("X-User-IsAdmin", "true")
}

// forgeDoors are the doors that carry a REQUEST — the only ones where a header
// can be forged at all. An in-process invoke has no headers to forge.
func forgeDoors(r *forgeRig) []struct {
	name string
	hit  func(t *testing.T)
} {
	return []struct {
		name string
		hit  func(t *testing.T)
	}{
		{"REST", func(t *testing.T) {
			t.Helper()
			req, _ := http.NewRequest(http.MethodPost, r.base+"/v1/forge/run", strings.NewReader(`{"n":1}`))
			claim(req.Header)
			res, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
			if err != nil {
				t.Fatalf("REST: %v", err)
			}
			defer res.Body.Close()
			_, _ = io.Copy(io.Discard, res.Body)
		}},
		{"MCP", func(t *testing.T) {
			t.Helper()
			frame, _ := json.Marshal(map[string]any{
				"jsonrpc": "2.0", "id": 1, "method": "tools/call",
				"params": map[string]any{"name": "forge_run", "arguments": map[string]any{"n": 1}},
			})
			req, _ := http.NewRequest(http.MethodPost, r.base+"/mcp", strings.NewReader(string(frame)))
			claim(req.Header)
			res, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
			if err != nil {
				t.Fatalf("MCP: %v", err)
			}
			defer res.Body.Close()
			body, _ := io.ReadAll(res.Body)
			var ans struct {
				Error *struct {
					Code    int    `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}
			if err := json.Unmarshal(body, &ans); err != nil {
				t.Fatalf("MCP: reply is not a frame: %v (%s)", err, body)
			}
			if ans.Error != nil {
				t.Fatalf("MCP: protocol error, so the op never ran: %d %s",
					ans.Error.Code, ans.Error.Message)
			}
		}},
		{"plane", func(t *testing.T) {
			t.Helper()
			// The call plane over HTTP, which is where a forged header can reach
			// it — over the socket the caller is stated by the process that dialed.
			req, _ := http.NewRequest(http.MethodPost,
				r.base+zip.CallPath+"forge_run", strings.NewReader(""))
			claim(req.Header)
			res, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
			if err != nil {
				t.Fatalf("plane: %v", err)
			}
			defer res.Body.Close()
			_, _ = io.Copy(io.Discard, res.Body)
		}},
	}
}

// THE CONTROL, first. Without the boundary the forgery lands on every door, so
// the doors reach the operation and the reader reports what it was told. Any
// door missing here means the refusal below is silence, not enforcement.
func TestAForgedIdentityIsSeenWithoutTheBoundary(t *testing.T) {
	for _, d := range forgeDoors(nil) {
		t.Run(d.name, func(t *testing.T) {
			r := forgeApp(t, false)
			for _, dd := range forgeDoors(r) {
				if dd.name != d.name {
					continue
				}
				dd.hit(t)
			}
			if r.saw.org != "victim" {
				t.Fatalf("%s: the operation resolved org %q with no boundary in front of it, "+
					"want victim — this door does not reach the operation, so the refusal "+
					"test proves nothing about it", d.name, r.saw.org)
			}
		})
	}
}

// AND THE REFUSAL. With the boundary, a client naming its own tenant resolves to
// nothing, on every door.
func TestAForgedIdentityIsRefusedAtEveryDoor(t *testing.T) {
	for _, d := range forgeDoors(nil) {
		t.Run(d.name, func(t *testing.T) {
			r := forgeApp(t, true)
			for _, dd := range forgeDoors(r) {
				if dd.name != d.name {
					continue
				}
				dd.hit(t)
			}
			if r.saw.org != "" {
				t.Errorf("%s: a caller with NO credential named org %q and the operation "+
					"resolved it — the identity boundary does not reach this door",
					d.name, r.saw.org)
			}
			if r.saw.validated {
				t.Errorf("%s: a caller with NO credential was resolved as validated", d.name)
			}
		})
	}
}
