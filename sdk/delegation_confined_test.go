package cloud

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/zap-proto/zip"
)

func TestDelegationScope(t *testing.T) {
	if got := delegationScope(nil); got != inferenceScope {
		t.Fatalf("delegationScope(nil) = %q, want %q", got, inferenceScope)
	}
	if got := delegationScope([]string{"research", "ai:inference", "research", "workflow:gpu", "  "}); got != "ai:inference research workflow:gpu" {
		t.Fatalf("delegationScope = %q, want %q", got, "ai:inference research workflow:gpu")
	}
}

func TestConfinedAllowedScopes(t *testing.T) {
	cases := []struct {
		name   string
		scope  string
		method string
		path   string
		wantOK bool
	}{
		{"plain responses", inferenceScope, http.MethodPost, "/v1/responses", true},
		{"plain decisions", inferenceScope, http.MethodPost, "/v1/decisions", true},
		{"plain models read", inferenceScope, http.MethodGet, "/v1/models", true},
		{"plain models write blocked", inferenceScope, http.MethodPost, "/v1/models", false},
		{"plain research blocked", inferenceScope, http.MethodGet, "/v1/research/experiments", false},
		{"plain gpu-jobs blocked", inferenceScope, http.MethodPost, "/v1/workflow/namespaces/gpu-jobs/jobs", false},

		{"research experiments get", inferenceScope + " research", http.MethodGet, "/v1/research/experiments", true},
		{"research runs post", inferenceScope + " research", http.MethodPost, "/v1/research/runs", true},
		{"research delete blocked", inferenceScope + " research", http.MethodDelete, "/v1/research/experiments/1", false},
		{"research grants blocked", inferenceScope + " research", http.MethodGet, "/v1/research/grants", false},
		{"research grants subpath blocked", inferenceScope + " research", http.MethodPost, "/v1/research/grants/1", false},
		{"research action authorize blocked", inferenceScope + " research", http.MethodPost, "/v1/research/actions/act-1/authorize", false},
		{"research cannot hit gpu-jobs", inferenceScope + " research", http.MethodPost, "/v1/workflow/namespaces/gpu-jobs/jobs", false},

		{"gpu workflow enqueue", inferenceScope + " workflow:gpu", http.MethodPost, "/v1/workflow/namespaces/gpu-jobs/jobs", true},
		{"gpu workflow other ns blocked", inferenceScope + " workflow:gpu", http.MethodPost, "/v1/workflow/namespaces/default/jobs", false},
		{"gpu fleet list get", inferenceScope + " workflow:gpu", http.MethodGet, "/v1/compute/fleet", true},
		{"gpu fleet post blocked", inferenceScope + " workflow:gpu", http.MethodPost, "/v1/compute/fleet", false},
		{"gpu fleet jobs post", inferenceScope + " workflow:gpu", http.MethodPost, "/v1/compute/fleet/jobs", true},
		{"gpu fleet job get", inferenceScope + " workflow:gpu", http.MethodGet, "/v1/compute/fleet/jobs/j1", true},
		{"gpu fleet delete blocked", inferenceScope + " workflow:gpu", http.MethodDelete, "/v1/compute/fleet/jobs/j1", false},
		{"gpu cannot hit kms", inferenceScope + " workflow:gpu", http.MethodGet, "/v1/kms/secrets", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := confinedAllowed(tc.scope, tc.path, tc.method)
			if tc.wantOK && err != nil {
				t.Fatalf("confinedAllowed(%q, %s, %s) = %v, want nil", tc.scope, tc.path, tc.method, err)
			}
			if !tc.wantOK && err == nil {
				t.Fatalf("confinedAllowed(%q, %s, %s) = nil, want 403", tc.scope, tc.path, tc.method)
			}
		})
	}
}

// TestLivenessNeverNegativeCachesInactive verifies that a transient IAM
// active=false answer fails closed on that call without poisoning the 30s
// liveness cache, and that a newly-revoked token drops any stale positive entry.
func TestLivenessNeverNegativeCachesInactive(t *testing.T) {
	var active atomic.Bool
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/iam/oauth/introspect" {
			http.NotFound(w, r)
			return
		}
		calls.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]bool{"active": active.Load()})
	}))
	t.Cleanup(srv.Close)

	t.Setenv("IAM_URL", srv.URL)
	t.Setenv("IAM_CLIENT_ID", "test-client")
	t.Setenv("IAM_CLIENT_SECRET", "test-secret")

	var l liveness
	exp := jwt.NewNumericDate(time.Now().Add(time.Hour))
	ctx := context.Background()

	// First call: transient active=false fails closed with errRevoked.
	active.Store(false)
	if err := l.check(ctx, "tok-transient", exp); !errors.Is(err, errRevoked) {
		t.Fatalf("transient inactive = %v, want errRevoked", err)
	}
	// Second call immediately after IAM recovers must succeed without waiting 30s.
	active.Store(true)
	if err := l.check(ctx, "tok-transient", exp); err != nil {
		t.Fatalf("after IAM recovery = %v, want nil", err)
	}
	if calls.Load() != 2 {
		t.Fatalf("introspect calls = %d, want 2 (no negative caching)", calls.Load())
	}
	// Third call hits positive cache.
	if err := l.check(ctx, "tok-transient", exp); err != nil {
		t.Fatalf("cached positive = %v, want nil", err)
	}
	if calls.Load() != 2 {
		t.Fatalf("introspect calls after cache hit = %d, want 2", calls.Load())
	}
}

// TestCallerIssuerAndTokenValidatorIssuer verifies that CallerIssuer reads the
// validated bearer's iss claim and TokenValidator populates Issuer and BillingAccount.
func TestCallerIssuerAndTokenValidatorIssuer(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks := jwksServer(t, &key.PublicKey)
	const issuer = "https://hanzo.id"
	tv := NewTokenValidator(issuer+WellKnown, fakeClient(issuer, jwks.URL))

	jwtTok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":             issuer,
		"sub":             "u-1",
		"owner":           "hanzo",
		"name":            "alice",
		"email":           "alice@hanzo.ai",
		"billing_account": "org:acme",
		"exp":             time.Now().Add(time.Hour).Unix(),
		"iat":             time.Now().Unix(),
	})
	jwtTok.Header["kid"] = "test-key"
	tok, err := jwtTok.SignedString(key)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	id, err := tv.Validate(tok)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if id.Issuer != issuer {
		t.Fatalf("Issuer = %q, want %q", id.Issuer, issuer)
	}
	if id.BillingAccount != "org:acme" {
		t.Fatalf("BillingAccount = %q, want %q", id.BillingAccount, "org:acme")
	}

	var gotIssuer string
	app := zip.New(zip.Config{})
	app.Use(SanitizeIdentity(newIdentityValidator(issuer, jwks.URL, 0)))
	app.Raw(http.MethodGet, "/v1/probe", func(c *zip.Ctx) error {
		gotIssuer = CallerIssuer(c)
		return c.Bytes(http.StatusOK, []byte("ok"))
	})
	req, _ := http.NewRequest(http.MethodGet, "http://x/v1/probe", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	res, err := app.Fiber().Test(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	if gotIssuer != issuer {
		t.Fatalf("CallerIssuer = %q, want %q", gotIssuer, issuer)
	}
}
