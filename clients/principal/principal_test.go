// SPDX-License-Identifier: Apache-2.0 OR MIT

package principal

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zap-proto/zip"
)

type who struct{}

type seen struct {
	Org    string `json:"org"`
	OK     bool   `json:"ok"`
	Acting string `json:"acting"`
	Status int    `json:"status"`
}

// TestOrgFromAndActingReadTheValidatedCaller drives both through a real typed op,
// the only place a context carries a request.
func TestOrgFromAndActingReadTheValidatedCaller(t *testing.T) {
	app := zip.New(zip.Config{})
	app.Get("/probe", func(ctx context.Context, _ *who) (*seen, error) {
		org, ok := OrgFrom(ctx)
		out := &seen{Org: org, OK: ok, Status: http.StatusOK}
		acting, err := Acting(ctx)
		if err != nil {
			if he, isHTTP := err.(*zip.HTTPError); isHTTP {
				out.Status = he.Status
			}
		}
		out.Acting = acting
		return out, nil
	})

	cases := []struct {
		name         string
		user, org    string
		wantOK       bool
		wantActing   string
		wantStatus   int
		wantOrgValue string
	}{
		{"anonymous", "", "", false, "", http.StatusUnauthorized, ""},
		{"a forged org with no validated user", "", "victim", false, "", http.StatusUnauthorized, ""},
		{"a validated user in no org", "u1", "", false, "", http.StatusForbidden, ""},
		{"a validated user in an org", "u1", " acme ", true, "acme", http.StatusOK, "acme"},
		{"an org past the bound", "u1", strings.Repeat("a", MaxOrgLen+1), false, "", http.StatusForbidden, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/probe", nil)
			if c.user != "" {
				req.Header.Set("X-User-Id", c.user)
			}
			if c.org != "" {
				req.Header.Set("X-Org-Id", c.org)
			}
			res, err := app.Test(req)
			if err != nil {
				t.Fatal(err)
			}
			var got seen
			if err := decode(res.Body, &got); err != nil {
				t.Fatal(err)
			}
			if got.OK != c.wantOK || got.Org != c.wantOrgValue || got.Acting != c.wantActing || got.Status != c.wantStatus {
				t.Fatalf("got %+v, want ok=%v org=%q acting=%q status=%d", got, c.wantOK, c.wantOrgValue, c.wantActing, c.wantStatus)
			}
		})
	}
}

func decode(r interface{ Read([]byte) (int, error) }, v any) error {
	b, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}
