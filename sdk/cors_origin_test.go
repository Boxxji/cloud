package cloud

// Tests for the CORS origin predicate (cors_origin.go): every web origin may read
// the API, and only a first-party origin may read it with credentials.
//
// They drive real requests through the zip/fiber stack wherever the answer is
// observable on the wire, because the thing under test is a header contract, and
// they drive the predicate directly where the point is a rule rather than a header.

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/zap-proto/zip"
)

func do(t *testing.T, app *zip.App, method, origin string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(method, "/probe", nil)
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	// An OPTIONS with an Origin is a PREFLIGHT here, and a preflight is defined by
	// carrying this (Fetch). Without it the request is the RFC 9110 §9.3.7
	// question instead — a different question, answered by a different handler.
	if method == http.MethodOptions && origin != "" {
		req.Header.Set("Access-Control-Request-Method", http.MethodPost)
	}
	res, err := app.Test(req, zip.TestConfig{Timeout: 30 * time.Second, FailOnTimeout: true})
	if err != nil {
		t.Fatalf("test: %v", err)
	}
	return res
}
