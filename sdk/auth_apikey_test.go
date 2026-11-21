// Copyright 2026 Hanzo AI Inc. All Rights Reserved.

package cloud

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"
)

// iamKeys.lookup maps an IAM get-user?accessKey row to the SAME idClaims a JWT
// yields, so the one minting path serves a key and a session identically.
func TestIAMKeysLookup(t *testing.T) {
	var gotKey, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.URL.Query().Get("accessKey")
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","data":{"owner":"hanzo","name":"z","email":"z@hanzo.ai","isAdmin":true}}`))
	}))
	defer srv.Close()

	k := &iamKeys{base: srv.URL, auth: "Basic test", http: srv.Client(), cache: NewCache[keyID, keyAnswer](time.Minute)}
	c := k.resolve(context.Background(), "sk-abc123").claims
	if c == nil {
		t.Fatal("resolve returned nil for a valid key")
	}
	if c.Owner != "hanzo" || c.Name != "z" || c.Email != "z@hanzo.ai" || !c.IsAdmin {
		t.Fatalf("claims = %+v, want owner=hanzo name=z email=z@hanzo.ai isAdmin=true", c)
	}
	// The key is passed as accessKey and the confidential credential is sent.
	if gotKey != "sk-abc123" {
		t.Errorf("IAM got accessKey=%q, want sk-abc123", gotKey)
	}
	if gotAuth != "Basic test" {
		t.Errorf("IAM got auth=%q, want the confidential Basic credential", gotAuth)
	}
	// The user id is the holder's row — never the bare name a holder chose, which
	// IAM admits in a UUID's shape — and the username is the name IAM's owner/name
	// lookups parse.
	if c.userID() != "hanzo/z" || c.username() != "z" {
		t.Errorf("userID=%q username=%q, want hanzo/z and z", c.userID(), c.username())
	}
}

// An unconfigured resolver (no confidential credential) resolves nothing, so an
// API key stays anonymous rather than mis-resolved.
func TestIAMKeysUnconfigured(t *testing.T) {
	k := &iamKeys{base: "http://iam", auth: "", cache: NewCache[keyID, keyAnswer](time.Minute)}
	if c := k.resolve(context.Background(), "sk-abc").claims; c != nil {
		t.Fatalf("unconfigured resolver returned %+v, want nil", c)
	}
}

// An unknown key (IAM status != ok) resolves to nil — a bad key never grants trust.
func TestIAMKeysUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"error","msg":"Unauthorized operation"}`))
	}))
	defer srv.Close()
	k := &iamKeys{base: srv.URL, auth: "Basic test", http: srv.Client(), cache: NewCache[keyID, keyAnswer](time.Minute)}
	if c := k.resolve(context.Background(), "sk-bad").claims; c != nil {
		t.Fatalf("unknown key resolved to %+v, want nil", c)
	}
}

// The cache serves a resolved key without a second IAM call (and caches a miss too,
// so a bad key cannot hammer IAM).
func TestIAMKeysCache(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		_, _ = w.Write([]byte(`{"status":"ok","data":{"owner":"hanzo","name":"z"}}`))
	}))
	defer srv.Close()
	k := &iamKeys{base: srv.URL, auth: "Basic test", http: srv.Client(), cache: NewCache[keyID, keyAnswer](time.Minute)}
	for range 3 {
		if k.resolve(context.Background(), "sk-x").claims == nil {
			t.Fatal("resolve nil")
		}
	}
	if calls != 1 {
		t.Fatalf("IAM called %d times, want 1 (cached)", calls)
	}
}

// A PUBLISHABLE key must resolve to its org through resolve-key — IAM's org-only
// endpoint — and NOT through get-user?accessKey, which refuses a pk- by design.
//
// Cloud sent every key prefix down the get-user endpoint, so a publishable key
// resolved to nothing at all: the ingest path a pk- exists for could never attribute
// a beacon to its tenant. A publishable key that resolves to nobody is a publishable
// key that does not work, which is the other half of why no surface used one.
func TestOrgForKey_PublishableResolvesThroughTheOrgOnlyEndpoint(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/iam/keys/org":
			// The real envelope: an org and a scope, and NO principal.
			_, _ = w.Write([]byte(`{"status":"ok","data":{"org":"acme","scope":"publish"}}`))
		default:
			// get-user?accessKey refuses a pk- exactly as IAM does.
			_, _ = w.Write([]byte(`{"status":"error","msg":"the entity does not exist"}`))
		}
	}))
	defer srv.Close()

	k := &iamKeys{base: srv.URL, auth: "Basic test", http: srv.Client(),
		cache: NewCache[keyID, keyAnswer](time.Minute), orgs: NewCache[keyID, string](time.Minute)}
	if org := k.resolveOrg(context.Background(), "pk-live-abc"); org != "acme" {
		t.Fatalf("resolveOrg = %q, want acme", org)
	}
	if len(paths) != 1 || paths[0] != "/v1/iam/keys/org" {
		t.Fatalf("a publishable key must be resolved at the org-only endpoint, got %v", paths)
	}
	// A publishable key yields an ORG and never a principal: there is no idClaims on
	// this path at all, which is what keeps a browser key from becoming a read grant.
	if c := k.resolve(context.Background(), "pk-live-abc").claims; c != nil {
		t.Fatalf("a publishable key resolved to a principal %+v — it must never authenticate", c)
	}
}

// The two endpoints answer different questions, so a secret key must NOT be sent to
// the org-only one (it would learn an org for a credential whose whole point is that
// it names a user), and a publishable key must not be sent to the principal one.
func TestOrgForKey_EachPrefixUsesItsOwnEndpoint(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/iam/keys/org":
			_, _ = w.Write([]byte(`{"status":"ok","data":{"org":"pub-org","scope":"publish"}}`))
		default:
			_, _ = w.Write([]byte(`{"status":"ok","data":{"owner":"secret-org","name":"z"}}`))
		}
	}))
	defer srv.Close()

	sharedKeysOnce = sync.Once{}
	t.Setenv("IAM_URL", srv.URL)
	t.Setenv("IAM_MINT_CLIENT_ID", "hanzo-console")
	t.Setenv("IAM_MINT_CLIENT_SECRET", "s3cr3t")
	sharedKeysInst = nil
	t.Cleanup(func() { sharedKeysOnce = sync.Once{}; sharedKeysInst = nil })

	if org, ok := OrgForKey(context.Background(), "sk-live-abc"); !ok || org != "secret-org" {
		t.Fatalf("secret key resolved to (%q,%v), want secret-org", org, ok)
	}
	if org, ok := OrgForKey(context.Background(), "pk-live-abc"); !ok || org != "pub-org" {
		t.Fatalf("publishable key resolved to (%q,%v), want pub-org — this is the pk- ingest path", org, ok)
	}
	// get-user?accessKey is the SECRET-key endpoint: it resolves sk- to the owning
	// user behind CapKeyResolve, and refuses a pk- by design. resolve-key is the
	// publishable endpoint, org-only. /v1/iam/users/get is neither — it is the typed
	// (owner, name) read, which carries no accessKey and cannot answer this
	// question at all.
	want := []string{"/v1/iam/keys/principal", "/v1/iam/keys/org"}
	if len(paths) != 2 || paths[0] != want[0] || paths[1] != want[1] {
		t.Fatalf("endpoints used = %v, want %v (one question each, never interchangeable)", paths, want)
	}
}

// resolveOrg fails CLOSED: an unconfigured resolver, an unknown/expired/
// non-publishable key, or a malformed envelope yields "" — never a default tenant,
// so a bad browser key can never write into someone else's partition.
func TestResolveOrg_FailsClosed(t *testing.T) {
	if k := (&iamKeys{base: "http://iam", auth: "", orgs: NewCache[keyID, string](time.Minute)}); k.resolveOrg(context.Background(), "pk-x") != "" {
		t.Fatal("an unconfigured resolver must resolve nothing")
	}
	for _, body := range []string{
		`{"status":"error","msg":"the entity does not exist"}`, // unknown / not publishable / expired
		`{"status":"ok","data":{"org":""}}`,                    // present but empty
		`{"status":"ok"}`,                                      // no data
		`not json at all`,
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(body))
		}))
		k := &iamKeys{base: srv.URL, auth: "Basic test", http: srv.Client(), orgs: NewCache[keyID, string](time.Minute)}
		if org := k.resolveOrg(context.Background(), "pk-live-abc"); org != "" {
			t.Fatalf("body %q resolved to org %q, want \"\"", body, org)
		}
		srv.Close()
	}
}

// A KEY AND A TOKEN FOR ONE IDENTITY NAME THE SAME PAYER.
//
// IAM answers `billing_account` when it validates a key exactly as it answers it
// in a token's claim — which ledger this credential spends from, decided where the
// grant shape is visible. Dropping it here did not leave the payer unknown, it
// left it WRONG: account.Payer falls out of its named-account arm to the shape
// rule, which answers Person(org, name) and never pools the signup org. A
// service account then names a wallet no funding path addresses — an admin grant
// credits the pool, a deposit names a member — so a first-party key reads $0
// beside the balance it is entitled to spend.
//
// It lands on the same authz.Claims field the token path fills, so
// renderBillingAccount mints X-Billing-Account-Id identically either way.
func TestIAMKeyCarriesThePayerItWasIssuedFor(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","data":{"owner":"hanzo","name":"svc","billing_account":"org:hanzo"}}`))
	}))
	defer srv.Close()

	k := &iamKeys{base: srv.URL, auth: "Basic test", http: srv.Client(), cache: NewCache[keyID, keyAnswer](time.Minute)}
	c := k.resolve(context.Background(), "sk-payer").claims
	if c == nil {
		t.Fatal("resolve returned nil for a valid key")
	}
	if c.BillingAccount != "org:hanzo" {
		t.Errorf("BillingAccount = %q, want org:hanzo — a key that drops its payer is "+
			"billed as a person against a wallet nothing funds", c.BillingAccount)
	}
}

// An IAM that does not answer the field leaves it empty rather than inventing
// one, which is exactly the behaviour that preceded reading it.
func TestIAMKeyWithoutAPayerNamesNone(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","data":{"owner":"hanzo","name":"svc"}}`))
	}))
	defer srv.Close()

	k := &iamKeys{base: srv.URL, auth: "Basic test", http: srv.Client(), cache: NewCache[keyID, keyAnswer](time.Minute)}
	c := k.resolve(context.Background(), "sk-nopayer").claims
	if c == nil {
		t.Fatal("resolve returned nil for a valid key")
	}
	if c.BillingAccount != "" {
		t.Errorf("BillingAccount = %q, want empty", c.BillingAccount)
	}
}

// A member's key is resolved on every request, so removing the member ends it on
// the next one. Here IAM stops answering for it after the first call, as it does
// the moment the membership is removed.
func TestIAMKeysMemberKeyIsNeverCached(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		if calls > 1 {
			_, _ = w.Write([]byte(`{"status":"error","msg":"the entity does not exist","code":"key_foreign_user"}`))
			return
		}
		_, _ = w.Write([]byte(`{"status":"ok","data":{"owner":"agency","name":"josh","org":"client"}}`))
	}))
	defer srv.Close()
	k := &iamKeys{base: srv.URL, auth: "Basic test", http: srv.Client(), cache: NewCache[keyID, keyAnswer](time.Minute)}
	if k.resolve(context.Background(), "sk-member").claims == nil {
		t.Fatal("the member's key did not resolve while the membership stood")
	}
	if c := k.resolve(context.Background(), "sk-member").claims; c != nil {
		t.Fatalf("after removal the key still resolved from cache as %+v", c)
	}
	if calls != 2 {
		t.Fatalf("IAM asked %d times, want 2 (no cache for a member's key)", calls)
	}
}

// What the key caches remember does not move when the caller's memory does. A key
// read from a header aliases fasthttp's request buffer, and the next request on the
// connection overwrites that buffer in place; an entry kept by reference to it
// stopped naming its own key, so the key was asked again, and an entry whose hash
// agreed with the newcomer's answered the newcomer instead.
func TestIAMKeysKeepNoReferenceToThePresentedKey(t *testing.T) {
	var mu sync.Mutex
	asked := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.Query().Get("accessKey")
		mu.Lock()
		asked[key]++
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","data":{"owner":"` + key + `","name":"z","org":"` + key + `"}}`))
	}))
	defer srv.Close()
	k := &iamKeys{base: srv.URL, auth: "Basic test", http: srv.Client(),
		cache: NewCache[keyID, keyAnswer](time.Minute), orgs: NewCache[keyID, string](time.Minute)}
	ctx := context.Background()

	for _, tc := range []struct {
		first, next string
		ask         func(string) string
	}{
		{"sk-aaaa", "sk-bbbb", func(key string) string {
			if c := k.resolve(ctx, key).claims; c != nil {
				return c.Owner
			}
			return ""
		}},
		{"pk-aaaa", "pk-bbbb", func(key string) string { return k.resolveOrg(ctx, key) }},
	} {
		buf := []byte(tc.first)
		header := unsafe.String(&buf[0], len(buf)) // the string a header read hands the boundary
		if got := tc.ask(header); got != tc.first {
			t.Fatalf("%s resolved to %q", tc.first, got)
		}
		copy(buf, tc.next) // the next request on the connection
		for _, key := range []string{tc.first, tc.next} {
			if got := tc.ask(key); got != key {
				t.Errorf("%s was answered as %q", key, got)
			}
		}
		if asked[tc.first] != 1 || asked[tc.next] != 1 {
			t.Errorf("IAM asked %d times about %s and %d about %s, want once each", asked[tc.first], tc.first, asked[tc.next], tc.next)
		}
	}
}

// THE KEY CACHE IS BOUNDED. Every distinct presented key is an entry, so the cache
// stops at cacheCap however many keys a caller invents.
func TestTheKeyCacheIsBounded(t *testing.T) {
	k := &iamKeys{cache: NewCache[keyID, keyAnswer](time.Minute)}
	for i := range cacheCap + 10 {
		k.cache.Put(idOf(fmt.Sprintf("sk-%d", i)), keyAnswer{})
	}
	k.cache.mu.Lock()
	n := len(k.cache.m)
	k.cache.mu.Unlock()
	if n > cacheCap {
		t.Fatalf("the cache holds %d entries, past its cap of %d", n, cacheCap)
	}
}

// AN IAM THAT DID NOT ANSWER IS NOT AN ANSWER. A 5xx, a dead socket or a body that
// is not IAM's says nothing about the key, so it is not remembered as "nobody" for
// a minute: the next request asks again, and resolves once IAM is back.
func TestAnUnansweringIAMIsNotRemembered(t *testing.T) {
	var asked atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if asked.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{"status":"ok","data":{"owner":"acme","name":"alice","scope":""}}`))
	}))
	t.Cleanup(srv.Close)
	k := &iamKeys{base: srv.URL, auth: "Basic test", http: srv.Client(), cache: NewCache[keyID, keyAnswer](time.Minute)}
	if a := k.resolve(context.Background(), "sk-live"); a.claims != nil {
		t.Fatal("a 503 resolved a principal")
	}
	if a := k.resolve(context.Background(), "sk-live"); a.claims == nil || a.claims.Owner != "acme" {
		t.Fatalf("the key IAM could not answer for was remembered as nobody: %+v", a)
	}
	if n := asked.Load(); n != 2 {
		t.Fatalf("IAM asked %d times, want 2", n)
	}
	k.resolve(context.Background(), "sk-live")
	if n := asked.Load(); n != 2 {
		t.Fatalf("an answer IAM gave was not remembered: asked %d times", n)
	}
}

// JUNK EVICTS JUNK. IAM's refusals are cached apart from its principals, so a flood
// of unknown keys — free for any caller to mint — fills and drops the refusals and
// leaves a customer's cached answer where it was.
//
// MUTATION: cache refusals beside principals and the customer's key is asked again.
func TestJunkKeysEvictOnlyJunk(t *testing.T) {
	var asked atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked.Add(1)
		if r.URL.Query().Get("accessKey") != "sk-good" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"status":"error","code":"key_unknown"}`))
			return
		}
		_, _ = w.Write([]byte(`{"status":"ok","data":{"owner":"acme","name":"alice"}}`))
	}))
	t.Cleanup(srv.Close)
	k := &iamKeys{base: srv.URL, auth: "Basic test", http: srv.Client(), cache: NewCache[keyID, keyAnswer](time.Minute)}
	ctx := context.Background()
	if a := k.resolve(ctx, "sk-good"); a.claims == nil {
		t.Fatal("sk-good did not resolve")
	}
	for i := range cacheCap + 10 {
		k.resolve(ctx, fmt.Sprintf("sk-junk-%d", i))
	}
	before := asked.Load()
	if a := k.resolve(ctx, "sk-good"); a.claims == nil {
		t.Fatal("sk-good stopped resolving")
	}
	if n := asked.Load() - before; n != 0 {
		t.Fatalf("a flood of junk keys evicted a customer's cached answer: asked again %d times", n)
	}
}

// ONE KEY, ONE QUESTION IN FLIGHT. Requests arriving together on a key whose answer
// is not cached — a fresh key, or a member's, which is never cached — wait on one
// lookup rather than each asking IAM.
//
// MUTATION: drop the in-flight map (flight) and IAM is asked once per request.
func TestConcurrentLookupsOfOneKeyAskOnce(t *testing.T) {
	var asked atomic.Int64
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked.Add(1)
		<-release
		_, _ = w.Write([]byte(`{"status":"ok","data":{"owner":"home","name":"bob","org":"acme","key":"m-row"}}`))
	}))
	t.Cleanup(srv.Close)
	k := &iamKeys{base: srv.URL, auth: "Basic test", http: srv.Client(), cache: NewCache[keyID, keyAnswer](time.Minute)}
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if a := k.resolve(context.Background(), "sk-member"); a.claims == nil {
				t.Error("a waiting caller got no principal")
			}
		}()
	}
	for asked.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond) // the other nineteen are waiting on the one lookup
	close(release)
	wg.Wait()
	if n := asked.Load(); n != 1 {
		t.Fatalf("20 concurrent requests on one key asked IAM %d times, want 1", n)
	}
}

// THE PRODUCTION RESOLVER REMEMBERS A REFUSAL. Built the way the boundary builds it
// (newIAMKeys), one revoked key presented again and again — a CI loop on a key
// Somebody revoked — asks IAM once a minute, not once a request.
//
// MUTATION: build the refusals' cache without a TTL and IAM is asked five times.
func TestTheProductionResolverRemembersRefusals(t *testing.T) {
	var asked atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked.Add(1)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"status":"error","msg":"the entity does not exist","code":"key_revoked"}`))
	}))
	t.Cleanup(srv.Close)
	k := newIAMKeys()
	k.base, k.auth, k.http = srv.URL, "Basic test", srv.Client()
	for range 5 {
		if a := k.resolve(context.Background(), "sk-revoked-in-a-ci-loop"); a.claims != nil || a.why != "key_revoked" {
			t.Fatalf("a revoked key resolved as %+v", a)
		}
	}
	if n := asked.Load(); n != 1 {
		t.Fatalf("one revoked key presented five times asked IAM %d times, want 1", n)
	}
}

// Only IAM's key_* reasons are answers about a key (store.KeyFailure); any other
// refusal is IAM talking about cloud, and is no answer at all.
func TestOnlyAKeyReasonIsAnAnswerAboutTheKey(t *testing.T) {
	for code, want := range map[string]bool{
		"key_unknown": true, "key_revoked": true, "key_expired": true, "key_wrong_door": true,
		"": false, "too_many_requests": false, "unauthorized": false,
	} {
		if a, answered := keyRefused(code); answered != want || (want && a.why != code) {
			t.Errorf("keyRefused(%q) = %+v, %v; want answered=%v", code, a, answered, want)
		}
	}
}
