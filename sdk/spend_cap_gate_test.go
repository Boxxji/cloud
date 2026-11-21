package cloud

// Money-path tests for the issue #70 edge enforcement: the spend-cap 402, the
// unreadable-cap 503, the soft-warn header, and the per-scope rate limit — all
// driven end-to-end through the real zip stack against a fake commerce that
// controls each verdict: the balance over HTTP, the cap over the plane.

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hanzoai/cloud/sdk/meter"
	"github.com/zap-proto/zip"
)

// capCommerce answers the metering client's balance read. The cap verdict is
// asked over the plane (planetest.Commerce.Cap), where the process that owns the
// caps answers it.
//
// It also serves GET /v1/billing/alerts, which nothing may call any more: the
// rate rules come over the plane now (see middleware_ratelimit_plane_test.go),
// because that HTTP fetch was the in-process self-dispatch that 502'd. alertsHits
// stays here as the tripwire — a caller that goes back to the old wire trips it.
type capCommerce struct {
	balanceBody string // GET /v1/billing/balance (default funded).

	alertsHits atomic.Int32
}

func (f *capCommerce) server(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/billing/balance", func(w http.ResponseWriter, r *http.Request) {
		body := f.balanceBody
		if body == "" {
			body = `{"available":100000}`
		}
		_, _ = io.WriteString(w, body)
	})
	mux.HandleFunc("/v1/billing/alerts", func(w http.ResponseWriter, r *http.Request) {
		f.alertsHits.Add(1)
		_, _ = io.WriteString(w, `[]`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// (MED-4) A resource-path spend-cap denial renders the DISTINCT 402
// spend_cap_exceeded — mirroring the edge gate — never the 503 out-of-funds shape
// (wrong code + retry storm). One handler drives DenyResource with each error.
func TestDenyResource_SpendCapDistinct402(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		wantCode int
		wantBody string
	}{
		{"spend_cap", meter.ErrSpendCapExceeded, http.StatusPaymentRequired, "spend_cap_exceeded"},
		{"insufficient", meter.ErrInsufficientBalance, http.StatusPaymentRequired, "insufficient_balance"},
		{"cap unreadable", fmt.Errorf("%w: store busy", meter.ErrSpendCapUnknown), http.StatusServiceUnavailable, "spend_cap_unavailable"},
	}
	for _, tc := range cases {
		app := zip.New(zip.Config{})
		app.Raw(http.MethodPost, "/v1/x", func(c *zip.Ctx) error { return DenyResource(c, tc.err) })
		resp, err := app.Test(httptest.NewRequest(http.MethodPost, "/v1/x", nil), zip.TestConfig{Timeout: 30 * time.Second, FailOnTimeout: true})
		if err != nil {
			t.Fatalf("%s: Test: %v", tc.name, err)
		}
		if resp.StatusCode != tc.wantCode {
			t.Fatalf("%s: status = %d, want %d", tc.name, resp.StatusCode, tc.wantCode)
		}
		body, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(body), `"code":"`+tc.wantBody+`"`) {
			t.Fatalf("%s: body %q missing %q", tc.name, string(body), tc.wantBody)
		}
	}
}

func rateReq(t *testing.T, app *zip.App, org, project string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/agent/run", nil)
	req.Header.Set("X-Org-Id", org)
	req.Header.Set("X-User-Id", "alice")
	if project != "" {
		req.Header.Set("X-Project-Id", project)
	}
	resp, err := app.Test(req, zip.TestConfig{Timeout: 30 * time.Second, FailOnTimeout: true})
	if err != nil {
		t.Fatalf("Test request: %v", err)
	}
	return resp
}
