package cloud

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hanzoai/cloud/sdk/audit"
	"github.com/zap-proto/zip"
)

// A site's beacon does not wait on the trail: an anonymous or customer POST to an
// ingest door writes no record, so a stalled trail cannot refuse analytics. A beacon
// that is denied, or sent with platform authority, is still recorded — and any other
// POST still is.
func TestAudit_BeaconsDoNotWaitOnTheTrail(t *testing.T) {
	rec, err := audit.Open(t.TempDir(), "audit", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	app := zip.New(zip.Config{})
	app.Use(AuditTrail(rec))
	for _, p := range []string{"/v1/event", "/v1/event/replay", "/v1/events"} {
		app.Raw(http.MethodPost, p, func(c *zip.Ctx) error {
			if c.Header("X-Deny") != "" {
				return zip.ErrUnauthorized("no key")
			}
			return c.JSON(http.StatusOK, map[string]int{"accepted": 1})
		})
	}
	count := func() int {
		_, n, err := rec.Query(t.Context(), audit.Filter{})
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	post := func(path string, as func(*http.Request), deny bool) {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		if as != nil {
			as(req)
		}
		if deny {
			req.Header.Set("X-Deny", "1")
		}
		mustTest(t, app, req)
	}

	post("/v1/event", nil, false)
	post("/v1/event/replay", asUser, false)
	if n := count(); n != 0 {
		t.Fatalf("a beacon wrote %d records; it must not wait on the trail", n)
	}
	post("/v1/event", nil, true)
	if n := count(); n != 1 {
		t.Fatalf("a denied beacon must be recorded, got %d", n)
	}
	post("/v1/event", asAdmin, false)
	if n := count(); n != 3 {
		t.Fatalf("a beacon with platform authority must be recorded begun and done, got %d", n-1)
	}
	post("/v1/events", asUser, false)
	if n := count(); n != 5 {
		t.Fatalf("a POST outside the ingest doors is a change and is recorded, got %d", n-3)
	}
}
