package object_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zap-proto/zip"

	"github.com/hanzoai/cloud/sdk/object"
	"github.com/hanzoai/cloud/sdk/object/objecttest"
)

func TestLocalConformance(t *testing.T) {
	l := &object.Local{Dir: t.TempDir()}
	srv := httptest.NewServer(l.Handler())
	t.Cleanup(srv.Close)
	l.Base = func() string { return srv.URL }
	objecttest.Run(t, l, objecttest.Options{Conditional: true, Links: true})
}

// TestMiddlewareServesLinksThroughZip is the host's path: a link signed by the
// process-wide store, followed through the zip router.
func TestMiddlewareServesLinksThroughZip(t *testing.T) {
	t.Setenv("CLOUD_ENV", "test")
	t.Setenv("CLOUD_DATA_DIR", t.TempDir())
	t.Setenv("S3_ADMIN_ACCESS_KEY", "")
	t.Setenv(object.PublicEnv, "http://cloud.test")
	app := zip.New(zip.Config{})
	app.Use(object.Middleware())
	app.Use(zip.H(func(c *zip.Ctx) error { return c.String(200, "elsewhere") }))

	ctx := context.Background()
	s := object.Default()
	if err := s.Ensure(ctx, "middle"); err != nil {
		t.Fatal(err)
	}
	do := func(method, link, body string) (*http.Response, string) {
		t.Helper()
		req, _ := http.NewRequest(method, link, strings.NewReader(body))
		resp, err := app.Test(req, zip.TestConfig{Timeout: 30 * time.Second, FailOnTimeout: true})
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp, string(b)
	}
	put, err := s.Share(ctx, object.Share{Method: http.MethodPut, Bucket: "middle", Key: "a/b.txt", TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(put.URL, "http://cloud.test/v1/object/middle/a/b.txt?") {
		t.Fatalf("url = %s", put.URL)
	}
	if r, _ := do(http.MethodPut, put.URL, "through zip"); r.StatusCode != 200 {
		t.Fatalf("PUT = %d", r.StatusCode)
	}
	get, _ := s.Share(ctx, object.Share{Bucket: "middle", Key: "a/b.txt", TTL: time.Minute})
	if r, b := do(http.MethodGet, get.URL, ""); r.StatusCode != 200 || b != "through zip" {
		t.Fatalf("GET = %d %q", r.StatusCode, b)
	}
	if r, _ := do(http.MethodGet, strings.Replace(get.URL, "a/b.txt", "a/c.txt", 1), ""); r.StatusCode != 403 {
		t.Fatalf("another key under the same signature = %d", r.StatusCode)
	}
	if _, b := do(http.MethodGet, "http://cloud.test/other", ""); b != "elsewhere" {
		t.Fatalf("a request outside the prefix = %q", b)
	}
}
