package cloud

// The sign-in routes answer a credentialed cross-origin request only from an
// identity origin (cors_origin.go, sessionRoute; middleware_edge.go, EdgeCORS).
// Every test here drives real requests through the zip/fiber stack.

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/zap-proto/zip"
)

// liveAllowlist is the shape of the production CLOUD_CORS_ORIGINS: brand-zone
// wildcards, so the app origins below are ADMITTED and the only thing standing
// between them and a credentialed sign-in is the route rule.
var liveAllowlist = []string{
	"*.hanzo.ai", "*.hanzo.app", "*.hanzo.id", "*.lux.id", "*.lux.network",
	"*.lux.cloud", "zoolabs.id", "*.zoo.ngo", "*.pars.id", "*.osage.id",
}

// liveIssuerMap is the production IAM_ISSUER_MAP (hanzoai/universe
// charts/app/values/hanzo/cloud.yaml), so the identity set under test is the one
// Config derives in production.
const liveIssuerMap = `{"auth.hanzo.ai":"https://hanzo.id","hanzo.id":"https://hanzo.id","iam.hanzo.ai":"https://hanzo.id","id.adnexus.dev":"https://id.adnexus.dev","id.bootno.de":"https://id.bootno.de","id.lux.network":"https://lux.id","id.pars.network":"https://pars.id","id.zoo.network":"https://zoolabs.id","lux.id":"https://lux.id","osage.id":"https://osage.id","pars.id":"https://pars.id","www.osage.id":"https://osage.id","www.zoolabs.id":"https://zoolabs.id","zoolabs.id":"https://zoolabs.id"}`

// appOrigins are pages the allowlist admits that are NOT identity origins.
// safe.lux.network is same-site with id.lux.network and console.hanzo.ai with
// iam.hanzo.ai, so the session cookie rides on their credentialed requests.
var appOrigins = []string{
	"https://safe.lux.network",
	"https://console.hanzo.ai",
	"https://www.hanzo.ai",
	"https://customer.hanzo.app",
	"https://console.lux.cloud",
	"https://zoo.ngo",
}

// identityOrigins are the pages a person signs in on. hanzo.ai is one: its /login
// is Hanzo's sign-in page.
var identityOrigins = []string{
	"https://hanzo.ai",
	"https://hanzo.id",
	"https://lux.id",
	"https://zoolabs.id",
	"https://pars.id",
	"https://osage.id",
	"https://iam.hanzo.ai",
	"https://id.hanzo.ai",
	"https://id.lux.network",
}

// signInRoutes is one address in every sessionRoutes entry, each the way the
// shipped SDKs and the identity SPA call it.
var signInRoutes = []struct{ method, path string }{
	{http.MethodPost, "/v1/iam/login"},
	{http.MethodGet, "/v1/iam/web3/nonce"},
	{http.MethodPost, "/v1/iam/web3/verify"},
	{http.MethodPost, "/v1/iam/signin"},
	{http.MethodPost, "/v1/iam/onboard"},
	{http.MethodGet, "/v1/iam/oauth/callback"},
	{http.MethodPost, "/v1/iam/oauth/federation/mfa"},
	{http.MethodGet, "/v1/iam/webauthn/signin/begin"},
	{http.MethodPost, "/v1/iam/webauthn/signin/finish"},
	{http.MethodGet, "/v1/iam/webauthn/signup/begin"},
	{http.MethodPost, "/v1/iam/webauthn/signup/finish"},
	{http.MethodPost, "/v1/iam/signup"},
	{http.MethodGet, "/v1/iam/accounts"},
	{http.MethodGet, "/v1/iam/oauth/authorize"},
	{http.MethodPost, "/v1/iam/oauth/authorize"},
	{http.MethodPost, "/v1/iam/oauth/device"},
	{http.MethodPost, "/v1/iam/oauth/device/info"},
}

// cookieRoutes' addresses, each with the method hanzoai/iam registers it under.
var cookieRouteCalls = []struct{ method, path string }{
	{http.MethodGet, "/v1/iam/account"},
	{http.MethodPut, "/v1/iam/account"},
	{http.MethodGet, "/v1/iam/whoami"},
	{http.MethodGet, "/v1/iam/consent"},
	{http.MethodPut, "/v1/iam/consent"},
	{http.MethodPost, "/v1/iam/preferences"},
	{http.MethodPut, "/v1/iam/password"},
	{http.MethodPost, "/v1/iam/link"},
	{http.MethodPost, "/v1/iam/unlink"},
	{http.MethodGet, "/v1/iam/linked-accounts"},
}

// pkceRoutes are what an app's PKCE client calls from its own origin: discovery,
// keys, the code-for-token exchange, userinfo, revoke and sign-out. None reads
// the session cookie; @hanzo/iam sends revoke with credentials: "include".
// Unchanged.
var pkceRoutes = []struct{ method, path string }{
	{http.MethodGet, "/.well-known/openid-configuration"},
	{http.MethodGet, "/v1/iam/.well-known/openid-configuration"},
	{http.MethodGet, "/.well-known/jwks"},
	{http.MethodGet, "/v1/iam/.well-known/jwks"},
	{http.MethodPost, "/v1/iam/oauth/token"},
	{http.MethodGet, "/v1/iam/oauth/userinfo"},
	{http.MethodPost, "/v1/iam/oauth/revoke"},
	{http.MethodPost, "/v1/iam/oauth/logout"},
	{http.MethodGet, "/v1/iam/organizations"},
}

// ask sends the actual request, or with preflight the browser's preflight for it.
func ask(t *testing.T, app *zip.App, method, path, origin string, preflight bool) *http.Response {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if preflight {
		req = httptest.NewRequest(http.MethodOptions, path, nil)
		req.Header.Set("Access-Control-Request-Method", method)
		req.Header.Set("Access-Control-Request-Headers", "content-type")
	}
	req.Header.Set("Origin", origin)
	res, err := app.Test(req, zip.TestConfig{Timeout: 30 * time.Second, FailOnTimeout: true})
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	return res
}

// credentialed reports whether a browser would hand origin the response to a
// request sent with credentials: "include".
func credentialed(res *http.Response, origin string) bool {
	return res.Header.Get("Access-Control-Allow-Origin") == origin &&
		res.Header.Get("Access-Control-Allow-Credentials") == "true"
}

// The identity set is the registry's plus the operator's pins, and never a host a
// customer could hold or a brand's marketing apex.
func TestIdentityHosts(t *testing.T) {
	registry := identityHosts("")
	for _, h := range []string{"hanzo.id", "lux.id", "zoolabs.id", "pars.id", "iam.hanzo.ai", "id.hanzo.ai", "id.lux.network", "id.bootno.de", "hanzo.ai"} {
		if !slices.Contains(registry, h) {
			t.Errorf("registry identity hosts %v lack %s", registry, h)
		}
	}
	pinned := identityHosts(liveIssuerMap)
	for _, h := range []string{"osage.id", "www.osage.id", "auth.hanzo.ai", "id.zoo.network", "www.zoolabs.id"} {
		if !slices.Contains(pinned, h) {
			t.Errorf("pinned identity hosts %v lack %s", pinned, h)
		}
	}
	for _, set := range [][]string{registry, pinned} {
		for _, h := range []string{"hanzo.app", "id.hanzo.app", "iam.hanzo.app", "www.hanzo.ai", "console.hanzo.ai", "lux.network", "zoo.ngo"} {
			if slices.Contains(set, h) {
				t.Errorf("identity hosts name %s, which is not a place people sign in", h)
			}
		}
	}
	if got := identityHosts("{not json"); !slices.Equal(got, registry) {
		t.Errorf("a malformed IAM_ISSUER_MAP changed the set: %v, want the registry's %v", got, registry)
	}
}
