package botauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// memory is a Store held in a variable, as KMS holds it in production.
type memory struct {
	mu    sync.Mutex
	set   []byte
	saves int
}

func (m *memory) Load(context.Context) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.set == nil {
		return nil, ErrNoKeys
	}
	return bytes.Clone(m.set), nil
}

func (m *memory) Save(_ context.Context, set []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.set, m.saves = bytes.Clone(set), m.saves+1
	return nil
}

// rfcSeed is RFC 9421 Appendix B.1.4's test-key-ed25519, the key the Web Bot
// Auth drafts and Cloudflare's documentation sign their examples with.
const rfcSeed = "n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU"

func seedLine(t *testing.T) []byte {
	t.Helper()
	set, err := NewKeySet()
	if err != nil {
		t.Fatal(err)
	}
	return set
}

// TestTheCloudflareVectorSignsByteForByte holds the signature base and the
// signature to the vector Cloudflare publishes for Web Bot Auth (and
// draft-meunier-web-bot-auth-architecture-05 A.2.3): Ed25519 is deterministic,
// so the same key, inputs and base give the same bytes, and any drift in how
// the base is built shows here before a verifier refuses it.
func TestTheCloudflareVectorSignsByteForByte(t *testing.T) {
	keys, err := Parse([]byte(rfcSeed))
	if err != nil {
		t.Fatal(err)
	}
	pub := keys.Public()[0]
	if got := base64.RawURLEncoding.EncodeToString(pub); got != "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs" {
		t.Fatalf("public key %s, not RFC 9421's", got)
	}
	if got := Thumbprint(pub); got != "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U" {
		t.Fatalf("thumbprint %s, not the vector's keyid", got)
	}
	r := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	r.Host = ""
	err = signRequest(r, keys[0], "https://signature-agent.test", time.Unix(1735689600, 0), time.Unix(1735693200, 0),
		"e8N7S2MFd/qrd6T2R3tdfAuuANngKI7LFtKYI/vowzk4lAZYadIX6wW25MwG7DCT9RUKAJ0qVkU0mEeLElW1qg==")
	if err != nil {
		t.Fatal(err)
	}
	for h, want := range map[string]string{
		"Signature-Agent": `"https://signature-agent.test"`,
		"Signature-Input": `sig1=("@authority" "signature-agent");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=1735693200;nonce="e8N7S2MFd/qrd6T2R3tdfAuuANngKI7LFtKYI/vowzk4lAZYadIX6wW25MwG7DCT9RUKAJ0qVkU0mEeLElW1qg==";tag="web-bot-auth"`,
		"Signature":       `sig1=:jdq0SqOwHdyHr9+r5jw3iYZH6aNGKijYp/EstF4RQTQdi5N5YYKrD+mCT1HA1nZDsi6nJKuHxUi/5Syp3rLWBA==:`,
	} {
		if got := r.Header.Get(h); got != want {
			t.Errorf("%s:\n got %s\nwant %s", h, got, want)
		}
	}
	doc := Directory(keys.Public())
	if err := Verify(r, doc, time.Unix(1735689700, 0)); err != nil {
		t.Fatalf("the vector does not verify against its own directory: %v", err)
	}
}

// site is a verifier: it reads the directory Signature-Agent names over the
// network and answers 200 to a request that verifies, 401 with the reason to one
// that does not, and records every Host it was asked for.
func site(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		agent := strings.Trim(r.Header.Get("Signature-Agent"), `"`)
		if agent == "" {
			http.Error(w, "unsigned", http.StatusUnauthorized)
			return
		}
		resp, err := http.Get(agent)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		doc, _ := io.ReadAll(resp.Body)
		if err := Verify(r, doc, time.Now()); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, "verified")
	}))
}

// publisher serves s's directory at Path, as the crawl app does.
func publisher(t *testing.T, s *Signer) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != Path {
			http.NotFound(w, r)
			return
		}
		doc, h, err := s.Directory(r.Context(), r.Host)
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		for k, v := range h {
			w.Header()[k] = v
		}
		w.Header().Set("Content-Type", Media)
		_, _ = w.Write(doc)
	}))
}

// signer is a Signer over a fresh memory store whose directory dir publishes,
// installed as the process's signer for the test.
func signer(t *testing.T, store *memory) (*Signer, *httptest.Server) {
	t.Helper()
	s := &Signer{Store: store}
	dir := publisher(t, s)
	t.Cleanup(dir.Close)
	s.Agent = dir.URL + Path
	Use(s)
	t.Cleanup(func() { Use(nil) })
	return s, dir
}

func get(t *testing.T, c *http.Client, url string) (int, string) {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, strings.TrimSpace(string(b))
}

// TestASignedRequestVerifiesAgainstThePublishedDirectory is the issue's own check
// run end to end: the first directory request mints the deployment's key and
// publishes it, a request sent through the shared transport is verified by a site
// that knows nothing but the Signature-Agent it was sent, and the directory
// proves it holds the key it publishes.
func TestASignedRequestVerifiesAgainstThePublishedDirectory(t *testing.T) {
	store := &memory{}
	s, dir := signer(t, store)

	resp, err := http.Get(s.Agent)
	if err != nil {
		t.Fatal(err)
	}
	doc, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != Media {
		t.Fatalf("directory: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	if store.saves != 1 {
		t.Fatalf("the first directory request saved %d key sets, want 1", store.saves)
	}
	if strings.Contains(string(doc), `"d"`) || bytes.Contains(doc, store.set[:20]) {
		t.Fatal("the directory carries private material")
	}
	if err := VerifyDirectory(resp.Header, strings.TrimPrefix(dir.URL, "http://"), doc, time.Now()); err != nil {
		t.Fatalf("the directory does not prove its key: %v", err)
	}

	verifier := site(t)
	defer verifier.Close()
	if code, body := get(t, Client(&http.Client{}), verifier.URL); code != http.StatusOK {
		t.Fatalf("a signed request was refused: %d %s", code, body)
	}
	if code, _ := get(t, &http.Client{}, verifier.URL); code != http.StatusUnauthorized {
		t.Fatalf("the verifier admitted an unsigned request: %d", code)
	}
	if _, err := s.Provision(context.Background()); err != nil || store.saves != 1 {
		t.Fatalf("a stored key set was minted again: %v, %d saves", err, store.saves)
	}
}

// TestASignatureThatDoesNotMatchIsRefused is the other half: a verifier holding
// the published directory refuses a signature made by a key it does not publish,
// one that claims a published keyid but was made by another key, one altered on
// the way, one carried to another host, and one past its window.
func TestASignatureThatDoesNotMatchIsRefused(t *testing.T) {
	ours := &memory{set: seedLine(t)}
	s := &Signer{Store: ours, Agent: "https://api.hanzo.test" + Path}
	keys, err := s.Keys(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	doc := Directory(keys.Public())
	now := time.Now()

	signed := func(t *testing.T, with *Signer, url string) *http.Request {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, url, nil)
		r.Host = ""
		if err := with.Sign(r); err != nil {
			t.Fatal(err)
		}
		r.Host = r.URL.Host
		return r
	}
	if err := Verify(signed(t, s, "https://example.com/a"), doc, now); err != nil {
		t.Fatalf("the control does not verify: %v", err)
	}

	stranger := &Signer{Store: &memory{set: seedLine(t)}, Agent: s.Agent}
	forged := signed(t, stranger, "https://example.com/a")
	// The stranger's signature, relabelled with our keyid: the claim matches the
	// directory and the bytes do not.
	strangerKeys, _ := stranger.Keys(context.Background())
	relabelled := forged.Clone(context.Background())
	relabelled.Header.Set("Signature-Input", strings.Replace(forged.Header.Get("Signature-Input"),
		Thumbprint(strangerKeys.Public()[0]), Thumbprint(keys.Public()[0]), 1))
	altered := signed(t, s, "https://example.com/a")
	sig := altered.Header.Get("Signature")
	altered.Header.Set("Signature", sig[:6]+flip(sig[6])+sig[7:])
	elsewhere := signed(t, s, "https://example.com/a")
	elsewhere.Host = "victim.example"
	agent := signed(t, s, "https://example.com/a")
	agent.Header.Set("Signature-Agent", `"https://impostor.test`+Path+`"`)
	late := signed(t, s, "https://example.com/a")

	for name, c := range map[string]struct {
		r   *http.Request
		at  time.Time
		why string
	}{
		"a key the directory does not publish": {forged, now, "is not in the directory"},
		"a published keyid on another key":     {relabelled, now, "does not verify"},
		"an altered signature":                 {altered, now, "does not verify"},
		"another host":                         {elsewhere, now, "does not verify"},
		"another signature agent":              {agent, now, "does not verify"},
		"past its window":                      {late, now.Add(Window + time.Second), "expired"},
		"unsigned":                             {httptest.NewRequest(http.MethodGet, "https://example.com/", nil), now, "tagged"},
	} {
		err := Verify(c.r, doc, c.at)
		if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), c.why) {
			t.Errorf("%s: %v, want a refusal that says %q", name, err, c.why)
		}
	}
}

func flip(c byte) string {
	if c == 'A' {
		return "B"
	}
	return "A"
}

// TestEachRedirectHopIsSignedForItsOwnHost: a signature covers one authority, so
// a fetch that is redirected to another host must arrive there signed for THAT
// host, which is the transport signing every hop rather than the first.
func TestEachRedirectHopIsSignedForItsOwnHost(t *testing.T) {
	signer(t, &memory{})
	verifier := site(t)
	defer verifier.Close()
	var firstSigned bool
	bounce := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		firstSigned = r.Header.Get("Signature") != ""
		http.Redirect(w, r, verifier.URL, http.StatusFound)
	}))
	defer bounce.Close()
	if _, err := Default().Provision(context.Background()); err != nil {
		t.Fatal(err)
	}
	if code, body := get(t, Client(&http.Client{}), bounce.URL); code != http.StatusOK || !firstSigned {
		t.Fatalf("the redirected fetch: %d %s (first hop signed: %v)", code, body, firstSigned)
	}
}

// TestRotationPublishesBothAndSignsWithTheFirst is the rotation the package doc
// describes: with two lines the first signs and both are published, so a request
// signed with either verifies until its key leaves the set, and none after.
func TestRotationPublishesBothAndSignsWithTheFirst(t *testing.T) {
	old, next := seedLine(t), seedLine(t)
	store := &memory{set: append(bytes.Clone(next), old...)}
	clock := time.Now()
	s := &Signer{Store: store, Agent: "https://api.hanzo.test" + Path, Now: func() time.Time { return clock }}
	keys, err := s.Keys(context.Background())
	if err != nil || len(keys) != 2 {
		t.Fatalf("two lines read as %d keys: %v", len(keys), err)
	}
	doc := Directory(keys.Public())
	published, _ := Published(doc)
	if len(published) != 2 {
		t.Fatalf("the directory publishes %d keys, want both", len(published))
	}

	r := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	r.Host = ""
	if err := s.Sign(r); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.Header.Get("Signature-Input"), Thumbprint(keys.Public()[0])) {
		t.Fatal("the request was not signed with the first line's key")
	}
	r.Host = r.URL.Host

	// Signed before the rotation, with the key now second: still good.
	before := &Signer{Store: &memory{set: old}, Agent: s.Agent}
	o := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	o.Host = ""
	if err := before.Sign(o); err != nil {
		t.Fatal(err)
	}
	o.Host = o.URL.Host
	if err := Verify(o, doc, time.Now()); err != nil {
		t.Fatalf("the outgoing key stopped verifying while it is still published: %v", err)
	}

	// The old line removed: after Refresh every process reads the new set, and
	// the directory stops vouching for the old key.
	store.set = next
	clock = clock.Add(Refresh + time.Second)
	keys, _ = s.Keys(context.Background())
	if len(keys) != 1 {
		t.Fatalf("after the old line left, %d keys are read", len(keys))
	}
	if err := Verify(o, Directory(keys.Public()), time.Now()); !errors.Is(err, ErrRefused) {
		t.Fatalf("a retired key still verifies: %v", err)
	}
}

// TestNoSignerOrNoKeySendsTheRequestUnsigned: signing never costs a fetch. A
// process with no signer, or whose store holds no key, sends what it sent before.
func TestNoSignerOrNoKeySendsTheRequestUnsigned(t *testing.T) {
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = r.Header.Clone() }))
	defer srv.Close()

	Use(nil)
	if code, _ := get(t, Client(&http.Client{}), srv.URL); code != http.StatusOK || got.Get("Signature") != "" {
		t.Fatalf("with no signer: %d, Signature %q", code, got.Get("Signature"))
	}
	store := &memory{}
	Use(&Signer{Store: store, Agent: "https://api.hanzo.test" + Path})
	defer Use(nil)
	if code, _ := get(t, Client(&http.Client{}), srv.URL); code != http.StatusOK || got.Get("Signature") != "" {
		t.Fatalf("with no key: %d, Signature %q", code, got.Get("Signature"))
	}
	if store.saves != 0 {
		t.Fatal("a fetch minted a key; only the directory may")
	}
}

// TestAKeySetErrorNamesTheLineNotTheKey: a malformed set is reported by line
// number, so the error a log carries never holds a seed.
func TestAKeySetErrorNamesTheLineNotTheKey(t *testing.T) {
	good := strings.TrimSpace(string(seedLine(t)))
	bad := good[:20]
	_, err := Parse([]byte("# rotation in progress\n" + good + "\n" + bad + "\n"))
	if err == nil || !strings.Contains(err.Error(), "line 3") || strings.Contains(err.Error(), bad) {
		t.Fatalf("Parse: %v", err)
	}
	if _, err := Parse([]byte("\n# nothing\n")); !errors.Is(err, ErrNoKeys) {
		t.Fatalf("an empty set: %v", err)
	}
	keys, err := Parse([]byte(base64.StdEncoding.EncodeToString(make([]byte, ed25519.SeedSize))))
	if err != nil || len(keys) != 1 {
		t.Fatalf("standard base64 with padding: %v", err)
	}
}

// TestSignForSignsTheAuthorityAVerifierReads: SignFor is Sign for a request this
// process does not send. Its headers, carried by a request to that host, verify
// against the published directory; the scheme's default port is dropped the way a
// verifier drops it; and they do not verify on any other host.
func TestSignForSignsTheAuthorityAVerifierReads(t *testing.T) {
	s := &Signer{Agent: "https://api.hanzo.test" + Path, Store: &memory{set: seedLine(t)}}
	keys, err := s.Keys(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	doc := Directory(keys.Public())
	for _, tc := range []struct{ scheme, authority, url string }{
		{"https", "Example.COM", "https://example.com/a?b=c"},
		{"https", "example.com:443", "https://example.com/"},
		{"https", "example.com:8443", "https://example.com:8443/"},
		{"http", "example.com:80", "http://example.com/"},
		{"https", "[2001:db8::1]:443", "https://[2001:db8::1]/"},
	} {
		h, expires, err := s.SignFor(context.Background(), tc.scheme, tc.authority)
		if err != nil {
			t.Fatalf("%s %s: %v", tc.scheme, tc.authority, err)
		}
		if d := time.Until(expires); d <= 0 || d > Window {
			t.Fatalf("%s: expires in %v", tc.authority, d)
		}
		carry := func(url string) *http.Request {
			r := httptest.NewRequest(http.MethodGet, url, nil)
			r.Host = r.URL.Host
			for k := range h {
				r.Header.Set(k, h.Get(k))
			}
			return r
		}
		if err := Verify(carry(tc.url), doc, time.Now()); err != nil {
			t.Errorf("%s %s does not verify at %s: %v", tc.scheme, tc.authority, tc.url, err)
		}
		if err := Verify(carry("https://another.test/"), doc, time.Now()); !errors.Is(err, ErrRefused) {
			t.Errorf("%s verified on another host: %v", tc.authority, err)
		}
	}
	if _, _, err := s.SignFor(context.Background(), "ftp", "example.com"); err == nil {
		t.Error("an ftp scheme was signed for")
	}
	if _, _, err := (&Signer{Agent: s.Agent, Store: &memory{}}).SignFor(context.Background(), "https", "example.com"); !errors.Is(err, ErrNoKeys) {
		t.Errorf("a signer with no key: %v, want ErrNoKeys", err)
	}
}

// TestAuthorityIsAHostAndAPortOnly: what SignFor signs is exactly what a verifier
// compares with the Host it received, so anything else is refused rather than
// signed as given.
func TestAuthorityIsAHostAndAPortOnly(t *testing.T) {
	for in, want := range map[string]string{
		"example.com":        "example.com",
		" EXAMPLE.com ":      "example.com",
		"example.com:8443":   "example.com:8443",
		"192.0.2.1":          "192.0.2.1",
		"[2001:db8::1]":      "[2001:db8::1]",
		"[2001:db8::1]:8443": "[2001:db8::1]:8443",
		"xn--bcher-kva.ch":   "xn--bcher-kva.ch",
	} {
		if got, ok := Authority(in); !ok || got != want {
			t.Errorf("Authority(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	for _, bad := range []string{
		"", "https://example.com", "example.com/", "example.com/x", "ada@example.com",
		"exa mple.com", "example.com:", "example.com:0", "example.com:65536", "example.com:08",
		"example.com:x", ".example.com", "example.com.", "a..b", "[::1", "[192.0.2.1]", "exa\tmple.com", "example.com\r\n:80",
		"2001:db8::1", "bücher.ch", "example.com?q", "example.com#f",
		strings.Repeat("a", 260),
	} {
		if got, ok := Authority(bad); ok {
			t.Errorf("Authority(%q) = %q, accepted", bad, got)
		}
	}
}
