package cloud

// A KEY ACTS IN ITS ORG WHILE ITS HOLDER'S MEMBERSHIP OPENS IT.
//
// That is the rule f721eb3fc gave a person (authz Claims.opens, asked through
// EffectiveOrg), and for a key IAM asks it of the holder's row when the key
// resolves (iam store.Acts), so the boundary takes the org IAM names and never a
// second one. These tests run the REAL IAM resolver against rows written straight
// into its store — including rows today's mint refuses to write — and drive each
// key through SanitizeIdentity:
//
//	legacy     a plain member's key in an org the platform runs, or in a brand's
//	           directory: refused 403 key_not_tenant, at every address, never
//	           re-scoped to an org the holder does act in
//	removed    a member's key whose membership is gone: dead with it
//	demoted    an admin's key whose holder became a plain member: refused
//	admin      an admin's key in the platform org they run: acts there, and never
//	           as its admin (a key is no one's admin panel)
//	service    a machine's key acts in its own org; a machine of another org
//	           holding a plain membership of a platform org does not
//	controls   a customer org's members act in it, home key and member key alike,
//	           and a funded org's plain member acts in it as their token does

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hanzoai/authz"
	"github.com/hanzoai/iam/pkg/schema"
	iamstore "github.com/hanzoai/iam/pkg/store"
	iamserver "github.com/hanzoai/iam/server"
	"github.com/hanzoai/orm"
	luxlog "github.com/luxfi/log"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/cloud/sdk/principal"
)

// keyIAM is the embedded IAM over one store, answering keys/principal to the
// confidential client the boundary authenticates as, the way the deployment
// grants it (IAM_KEY_RESOLVE_APPS).
type keyIAM struct {
	db   orm.DB
	url  string
	auth string
}

const keyConsoleSecret = "console-key-secret"

func newKeyIAM(t *testing.T) *keyIAM {
	t.Helper()
	signing, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	block := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(signing)})
	if err := os.WriteFile(filepath.Join(dir, "cert-hanzo"), block, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("IAM_SIGNING_KEYS", dir)
	t.Setenv("IAM_ISSUER", "https://hanzo.id")
	t.Setenv("IAM_KEY_RESOLVE_APPS", "hanzo-console")

	db, err := iamstore.Open("sqlite", t.TempDir()+"/iam.db", "")
	if err != nil {
		t.Fatalf("open identity store: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	cert := orm.New[schema.Cert](db)
	cert.Owner, cert.Name = "admin", "cert-hanzo"
	cert.Type, cert.CryptoAlgorithm, cert.BitSize = "x509", "RS256", 2048
	cert.SetId("admin/cert-hanzo")
	if err := cert.CreateCtx(ctx); err != nil {
		t.Fatalf("seed cert: %v", err)
	}
	console := orm.New[schema.Application](db)
	console.Owner, console.Name, console.ClientId, console.ClientSecret = "admin", "hanzo-console", "hanzo-console", keyConsoleSecret
	console.Organization, console.Cert = "hanzo", "cert-hanzo"
	console.GrantTypes = []string{"client_credentials"}
	console.SetId("admin/hanzo-console")
	if err := console.CreateCtx(ctx); err != nil {
		t.Fatalf("seed hanzo-console: %v", err)
	}
	if err := iamserver.RequireIssuer(); err != nil {
		t.Fatalf("install the issuer: %v", err)
	}
	app := iamserver.NewApp(db)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req := httptest.NewRequest(r.Method, r.URL.RequestURI(), r.Body)
		req.Header = r.Header.Clone()
		req.Host = "hanzo.id"
		res, err := app.Test(req, zip.TestConfig{Timeout: 30 * time.Second, FailOnTimeout: true})
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer func() { _ = res.Body.Close() }()
		for k, vs := range res.Header {
			w.Header()[k] = vs
		}
		w.WriteHeader(res.StatusCode)
		_, _ = io.Copy(w, res.Body)
	}))
	t.Cleanup(srv.Close)
	return &keyIAM{db: db, url: srv.URL, auth: "Basic " + base64.StdEncoding.EncodeToString([]byte("hanzo-console:"+keyConsoleSecret))}
}

func (id *keyIAM) org(t *testing.T, name string) {
	t.Helper()
	o := orm.New[schema.Organization](id.db)
	o.Owner, o.Name, o.DisplayName = "admin", name, name
	o.SetId("admin/" + name)
	if err := o.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed org %s: %v", name, err)
	}
}

// user writes a row: kind "" for a person, schema.ServiceAccount for a machine.
func (id *keyIAM) user(t *testing.T, owner, name string, admin bool, kind string) {
	t.Helper()
	u := orm.New[schema.User](id.db)
	u.Owner, u.Name, u.IsAdmin, u.Type = owner, name, admin, kind
	u.SetId(owner + "/" + name)
	if err := u.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed user %s/%s: %v", owner, name, err)
	}
}

func (id *keyIAM) member(t *testing.T, user, org, role string) {
	t.Helper()
	if _, err := iamstore.EnsureMembership(context.Background(), id.db, user, org, role); err != nil {
		t.Fatalf("membership %s in %s: %v", user, org, err)
	}
}

// key writes a secret key row filed in org for holder ("<home>/<name>") the way
// the mint writes one — digest, never the secret — and answers the secret. It
// asks nothing of the mint, so it writes rows the mint would refuse: the legacy
// keys this file exists for.
func (id *keyIAM) key(t *testing.T, org, name, holder string) string {
	t.Helper()
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	secret := "sk-live-" + hex.EncodeToString(raw)
	k := orm.New[schema.Key](id.db)
	k.Owner, k.Name, k.User, k.Type, k.State = org, name, holder, "User", "Active"
	k.AccessKey = "pk-" + hex.EncodeToString(raw[:8])
	k.AccessSecretDigest = schema.DigestSecret(secret)
	k.Prefix = schema.PrefixOf(secret)
	k.SetId(org + "/" + name)
	if err := k.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed key %s/%s: %v", org, name, err)
	}
	return secret
}

// boundary is SanitizeIdentity resolving keys against this IAM, remembering no
// principal, so every request reads the holder's standing as it stands.
func (id *keyIAM) boundary(t *testing.T) *zip.App {
	t.Helper()
	signing, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	v := newIdentityValidator(testIssuer, jwksServer(t, &signing.PublicKey).URL, 0)
	v.keys = &iamKeys{base: id.url, auth: id.auth, http: &http.Client{Timeout: 30 * time.Second},
		cache: NewCache[keyID, keyAnswer](0), refused: NewCache[keyID, keyAnswer](0)}
	app := zip.New(zip.Config{Logger: luxlog.NewNoOpLogger()})
	app.Use(SanitizeIdentity(v))
	app.Use(zip.H(func(c *zip.Ctx) error {
		p, _ := principal.Minted(c)
		return c.JSON(http.StatusOK, map[string]string{
			"org": c.Header(authz.HeaderOrg), "user": c.Header(authz.HeaderUser),
			"orgadmin": c.Header(authz.HeaderUserOrgAdmin), "super": c.Header(authz.HeaderUserAdmin),
			"kind": string(p.Kind),
		})
	}))
	return app
}

// keyAnswerSeen is what one request was answered: the status, the refusal's code, and the
// principal the handler saw when it was reached.
type keyAnswerSeen struct {
	status  int
	code    string
	reached bool
	org     string
	user    string
	kind    string
	admin   bool
}

func keyAsk(t *testing.T, app *zip.App, method, path, key, org string) keyAnswerSeen {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	if org != "" {
		req.Header.Set("X-Org-Id", org)
	}
	res, err := app.Test(req, zip.TestConfig{Timeout: 30 * time.Second, FailOnTimeout: true})
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = res.Body.Close() }()
	var body map[string]any
	_ = json.NewDecoder(res.Body).Decode(&body)
	str := func(k string) string { s, _ := body[k].(string); return s }
	out := keyAnswerSeen{status: res.StatusCode, code: str("code")}
	if _, ok := body["kind"]; ok && res.StatusCode == http.StatusOK {
		out.reached, out.org, out.user, out.kind = true, str("org"), str("user"), str("kind")
		out.admin = str("orgadmin") == "true" || str("super") == "true"
	}
	return out
}

// estate is the orgs and people the cases below are about.
type estate struct {
	id   *keyIAM
	app  *zip.App
	keys map[string]string
}

func newEstate(t *testing.T) *estate {
	t.Helper()
	id := newKeyIAM(t)
	for _, o := range []string{"hanzo", "lux", "hanzo-id", "acme", "beta", "adnexus", "pats-lab"} {
		id.org(t, o)
	}
	id.user(t, "hanzo", "pat", false, "")                     // a customer who landed in the brand org
	id.member(t, "hanzo/pat", "pats-lab", iamstore.RoleOwner) // and founded an org of their own
	id.user(t, "hanzo-id", "cara", false, "")                 // a directory customer
	id.user(t, "hanzo", "ada", true, "")                      // one of the people who run hanzo
	id.user(t, "hanzo", "ci", false, schema.ServiceAccount)   // hanzo's own machine
	id.user(t, "acme", "robot", false, schema.ServiceAccount)
	id.member(t, "acme/robot", "lux", iamstore.RoleMember) // another org's machine, a plain member of lux
	id.user(t, "acme", "dan", false, "")
	id.user(t, "acme", "bob", false, "")
	id.member(t, "acme/bob", "beta", iamstore.RoleMember)
	id.user(t, "adnexus", "eve", false, "")

	keys := map[string]string{
		"legacy":    id.key(t, "hanzo", "pat-secret-1", "hanzo/pat"),
		"directory": id.key(t, "hanzo-id", "cara-secret-1", "hanzo-id/cara"),
		"admin":     id.key(t, "hanzo", "ada-secret-1", "hanzo/ada"),
		"service":   id.key(t, "hanzo", "ci-secret-1", "hanzo/ci"),
		"foreign":   id.key(t, "lux", "robot-secret-1", "acme/robot"),
		"home":      id.key(t, "acme", "dan-secret-1", "acme/dan"),
		"member":    id.key(t, "beta", "acme~bob-secret-1", "acme/bob"),
		"funded":    id.key(t, "adnexus", "eve-secret-1", "adnexus/eve"),
	}
	return &estate{id: id, app: id.boundary(t), keys: keys}
}

// TestALegacyKeyActsNowhere is a plain member's key in an org the platform runs
// and a directory customer's key in the directory: IAM refuses both by name, the
// boundary answers 403 saying why on every method, and no request reaches a
// handler — not even one naming an org the holder does act in.
func TestALegacyKeyActsNowhere(t *testing.T) {
	e := newEstate(t)
	for _, name := range []string{"legacy", "directory"} {
		for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete} {
			for _, org := range []string{"", "hanzo", "pats-lab"} {
				got := keyAsk(t, e.app, method, "/v1/provisioning/s3", e.keys[name], org)
				if got.status != http.StatusForbidden || got.code != "key_not_tenant" || got.reached {
					t.Errorf("%s key, %s with X-Org-Id %q: %+v, want 403 key_not_tenant and no handler", name, method, org, got)
				}
			}
		}
	}
}

// TestARemovedMembersKeyDiesWithTheMembership: a member's key acts in the org it
// was minted in while the membership stands, and removing the member ends it on
// the next request — the row goes with the membership, so the key is nobody, and
// a row that outlived its membership is refused by name.
func TestARemovedMembersKeyDiesWithTheMembership(t *testing.T) {
	e := newEstate(t)
	if got := keyAsk(t, e.app, http.MethodGet, "/v1/provisioning/s3", e.keys["member"], ""); !got.reached || got.org != "beta" || got.user != "acme/bob" {
		t.Fatalf("bob's key before removal: %+v, want it to act in beta as acme/bob", got)
	}
	if _, err := iamstore.DeleteMembership(context.Background(), e.id.db, "acme/bob", "beta"); err != nil {
		t.Fatalf("remove bob from beta: %v", err)
	}
	got := keyAsk(t, e.app, http.MethodGet, "/v1/provisioning/s3", e.keys["member"], "beta")
	if got.reached && (got.org != "" || got.user != "") {
		t.Fatalf("bob's key after removal acted as %+v", got)
	}
	// A member's key row written before removal took the keys with it: the
	// membership is gone, the row is not, and IAM refuses it by name.
	stale := e.id.key(t, "beta", "acme~bob-secret-2", "acme/bob")
	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		if got := keyAsk(t, e.app, method, "/v1/provisioning/s3", stale, ""); got.status != http.StatusForbidden || got.code != "key_foreign_user" || got.reached {
			t.Errorf("a key outliving its membership, %s: %+v, want 403 key_foreign_user", method, got)
		}
	}
}

// TestAnAdminsKeyActsWhereTheyRunAndEndsWithTheRole: the key of a person who runs
// a platform org acts there, as a key and never as the org's admin; when they
// become a plain member the key is refused on the next request.
func TestAnAdminsKeyActsWhereTheyRunAndEndsWithTheRole(t *testing.T) {
	e := newEstate(t)
	got := keyAsk(t, e.app, http.MethodGet, "/v1/provisioning/s3", e.keys["admin"], "")
	if !got.reached || got.org != "hanzo" || got.kind != string(principal.Key) || got.admin {
		t.Fatalf("ada's key: %+v, want it to act in hanzo as a key holding neither admin scope", got)
	}
	u, err := iamstore.GetUserByName(context.Background(), e.id.db, "hanzo", "ada")
	if err != nil || u == nil {
		t.Fatalf("read ada: %v", err)
	}
	u.IsAdmin = false
	if err := u.UpdateCtx(context.Background()); err != nil {
		t.Fatalf("demote ada: %v", err)
	}
	if got := keyAsk(t, e.app, http.MethodGet, "/v1/provisioning/s3", e.keys["admin"], ""); got.status != http.StatusForbidden || got.code != "key_not_tenant" || got.reached {
		t.Fatalf("ada's key after her role ended: %+v, want 403 key_not_tenant", got)
	}
}

// TestAServiceKeyActsInItsOwnOrgOnly: a machine's key acts in the org its row
// lives in, a platform org included — the machine clause of the rule — and a
// machine of another org holding a plain membership of a platform org acts in
// none of it.
func TestAServiceKeyActsInItsOwnOrgOnly(t *testing.T) {
	e := newEstate(t)
	if got := keyAsk(t, e.app, http.MethodGet, "/v1/provisioning/s3", e.keys["service"], ""); !got.reached || got.org != "hanzo" || got.admin {
		t.Fatalf("hanzo's machine key: %+v, want it to act in hanzo with no admin scope", got)
	}
	if got := keyAsk(t, e.app, http.MethodGet, "/v1/provisioning/s3", e.keys["foreign"], ""); got.status != http.StatusForbidden || got.code != "key_not_tenant" || got.reached {
		t.Fatalf("acme's machine key filed in lux: %+v, want 403 key_not_tenant", got)
	}
}

// TestCustomerKeysActInTheirOrg is the positive control: a customer org's plain
// member acts in it by home key, a member's key acts in the org it was minted
// in, and a funded org's plain member acts in it as their token would.
func TestCustomerKeysActInTheirOrg(t *testing.T) {
	e := newEstate(t)
	for name, want := range map[string]string{"home": "acme", "member": "beta", "funded": "adnexus"} {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			if got := keyAsk(t, e.app, method, "/v1/provisioning/s3", e.keys[name], ""); !got.reached || got.org != want || got.admin {
				t.Errorf("%s key, %s: %+v, want it to act in %s with no admin scope", name, method, got, want)
			}
		}
	}
}

// TestAKeyActsWhereItsHoldersTokenWould holds the key rule to the token rule: for
// every person behind a key, the key acts in its org exactly when a token IAM
// would sign for that person (its `orgs`, store.MemberOrgRefs) may act there
// (Acts, the boundary's own switch). One rule, read off two credentials.
func TestAKeyActsWhereItsHoldersTokenWould(t *testing.T) {
	e := newEstate(t)
	ctx := context.Background()
	for name, row := range map[string][3]string{
		"legacy": {"hanzo", "pat", "hanzo"}, "directory": {"hanzo-id", "cara", "hanzo-id"},
		"admin": {"hanzo", "ada", "hanzo"}, "home": {"acme", "dan", "acme"},
		"member": {"acme", "bob", "beta"}, "funded": {"adnexus", "eve", "adnexus"},
	} {
		u, err := iamstore.GetUserByName(ctx, e.id.db, row[0], row[1])
		if err != nil || u == nil {
			t.Fatalf("read %s/%s: %v", row[0], row[1], err)
		}
		var claims authz.Claims
		for _, ref := range iamstore.MemberOrgRefs(ctx, e.id.db, u) {
			claims.Orgs = append(claims.Orgs, authz.Membership{Org: ref.Org, Role: authz.Role(ref.Role)})
		}
		token := Acts(&claims, row[2])
		got := keyAsk(t, e.app, http.MethodGet, "/v1/provisioning/s3", e.keys[name], "")
		key := got.reached && got.org == row[2]
		if key != token {
			t.Errorf("%s: the key acts in %s = %v, the holder's token may act there = %v (%+v)", name, row[2], key, token, got)
		}
	}
}
