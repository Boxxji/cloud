package object

import (
	"bytes"
	"context"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// newLocal is a Local served over HTTP, with links pointing at itself: what a
// browser would talk to.
func newLocal(t *testing.T) (*Local, string) {
	t.Helper()
	l := &Local{Dir: t.TempDir()}
	srv := httptest.NewServer(l.Handler())
	t.Cleanup(srv.Close)
	l.Base = func() string { return srv.URL }
	return l, srv.URL
}

func read(t *testing.T, s Store, b, k string, o Get) string {
	t.Helper()
	body, err := s.Open(context.Background(), b, k, o)
	if err != nil {
		t.Fatalf("open %s/%s: %v", b, k, err)
	}
	defer body.Close()
	v, _ := io.ReadAll(body)
	return string(v)
}

func TestPutGetStatRemove(t *testing.T) {
	ctx := context.Background()
	l, _ := newLocal(t)
	if _, err := l.Put(ctx, "photos", "a", strings.NewReader("x"), 1, Put{}); !NoBucket(err) {
		t.Fatalf("put into a bucket nobody made = %v, want NoBucket", err)
	}
	if err := l.Ensure(ctx, "photos"); err != nil {
		t.Fatal(err)
	}
	if err := l.Ensure(ctx, "photos"); err != nil {
		t.Fatalf("ensure twice: %v", err)
	}
	info, err := l.Put(ctx, "photos", "dir/a.txt", strings.NewReader("hello"), 5, Put{ContentType: "text/plain", CacheControl: "no-store", Meta: map[string]string{"Owner": "z"}})
	if err != nil {
		t.Fatal(err)
	}
	if info.Size != 5 || info.ETag != "5d41402abc4b2a76b9719d911017c592" {
		t.Fatalf("info = %+v", info)
	}
	st, err := l.Stat(ctx, "photos", "dir/a.txt")
	if err != nil || st.ContentType != "text/plain" || st.CacheControl != "no-store" || st.Meta["owner"] != "z" {
		t.Fatalf("stat = %+v, %v", st, err)
	}
	if got := read(t, l, "photos", "dir/a.txt", Get{}); got != "hello" {
		t.Fatalf("read = %q", got)
	}
	if got := read(t, l, "photos", "dir/a.txt", Get{Ranged: true, First: 1, Last: 3}); got != "ell" {
		t.Fatalf("range = %q", got)
	}
	if got := read(t, l, "photos", "dir/a.txt", Get{Ranged: true, First: 3, Last: -1}); got != "lo" {
		t.Fatalf("open range = %q", got)
	}
	// A key and a key beneath it coexist, as in an object store.
	if _, err := l.Put(ctx, "photos", "dir", strings.NewReader("flat"), 4, Put{}); err != nil {
		t.Fatal(err)
	}
	if read(t, l, "photos", "dir", Get{}) != "flat" || read(t, l, "photos", "dir/a.txt", Get{}) != "hello" {
		t.Fatal("a key and the keys beneath it must not share a file")
	}
	// Overwrite replaces.
	if _, err := l.Put(ctx, "photos", "dir/a.txt", strings.NewReader("bye"), -1, Put{}); err != nil {
		t.Fatal(err)
	}
	if read(t, l, "photos", "dir/a.txt", Get{}) != "bye" {
		t.Fatal("overwrite")
	}
	if _, err := l.Stat(ctx, "photos", "nope"); !NoKey(err) {
		t.Fatalf("stat absent = %v", err)
	}
	if _, err := l.Stat(ctx, "nobucket", "a"); !NoBucket(err) {
		t.Fatalf("stat in absent bucket = %v", err)
	}
	if err := l.Remove(ctx, "photos", "nope"); err != nil {
		t.Fatalf("remove absent key = %v, want nil", err)
	}
	if err := l.Remove(ctx, "photos", "dir/a.txt"); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Stat(ctx, "photos", "dir/a.txt"); !NoKey(err) {
		t.Fatal("removed object still there")
	}
	if _, err := l.Put(ctx, "photos", "short", strings.NewReader("abc"), 9, Put{}); err == nil {
		t.Fatal("a body shorter than declared was stored")
	}
	if _, err := l.Stat(ctx, "photos", "short"); !NoKey(err) {
		t.Fatal("a refused put left an object")
	}
}

func TestBucketsAndDrop(t *testing.T) {
	ctx := context.Background()
	l, _ := newLocal(t)
	for _, b := range []string{"aaa", "bbb"} {
		if err := l.Ensure(ctx, b); err != nil {
			t.Fatal(err)
		}
	}
	got, _ := l.Buckets(ctx)
	if len(got) != 2 || got[0].Name != "aaa" || got[1].Name != "bbb" || got[0].Created.IsZero() {
		t.Fatalf("buckets = %v", got)
	}
	_, _ = l.Put(ctx, "aaa", "k", strings.NewReader("v"), 1, Put{})
	if err := l.Drop(ctx, "aaa"); !NotEmpty(err) {
		t.Fatalf("drop non-empty = %v", err)
	}
	if err := l.Drop(ctx, "bbb"); err != nil {
		t.Fatal(err)
	}
	if err := l.Drop(ctx, "bbb"); !NoBucket(err) {
		t.Fatalf("drop absent = %v", err)
	}
	if err := l.Ensure(ctx, "../x"); err == nil {
		t.Fatal("a path was taken for a bucket")
	}
}

func TestList(t *testing.T) {
	ctx := context.Background()
	l, _ := newLocal(t)
	_ = l.Ensure(ctx, "lst")
	for _, k := range []string{"a/1", "a/2", "a/b/3", "b/1", "c"} {
		if _, err := l.Put(ctx, "lst", k, strings.NewReader(k), -1, Put{}); err != nil {
			t.Fatal(err)
		}
	}
	keys := func(o List) string {
		var out []string
		for i, err := range l.List(ctx, "lst", o) {
			if err != nil {
				t.Fatal(err)
			}
			if i.Dir {
				out = append(out, "["+i.Key+"]")
			} else {
				out = append(out, i.Key)
			}
		}
		return strings.Join(out, " ")
	}
	if got := keys(List{}); got != "a/1 a/2 a/b/3 b/1 c" {
		t.Fatalf("all = %s", got)
	}
	if got := keys(List{Prefix: "a/"}); got != "a/1 a/2 a/b/3" {
		t.Fatalf("prefix = %s", got)
	}
	if got := keys(List{Shallow: true}); got != "[a/] [b/] c" {
		t.Fatalf("shallow = %s", got)
	}
	if got := keys(List{Prefix: "a/", Shallow: true}); got != "a/1 a/2 [a/b/]" {
		t.Fatalf("shallow prefix = %s", got)
	}
	if got := keys(List{Max: 2}); got != "a/1 a/2" {
		t.Fatalf("max = %s", got)
	}
	for _, err := range l.List(ctx, "ghost", List{}) {
		if !NoBucket(err) {
			t.Fatalf("list of absent bucket = %v", err)
		}
	}
}

func TestCopyAndConditional(t *testing.T) {
	ctx := context.Background()
	l, _ := newLocal(t)
	_ = l.Ensure(ctx, "cpy")
	src, _ := l.Put(ctx, "cpy", "src", strings.NewReader("data"), 4, Put{ContentType: "text/x", CacheControl: "max-age=1", Meta: map[string]string{"k": "v"}})
	got, err := l.Copy(ctx, Ref{"cpy", "dst"}, Ref{"cpy", "src"}, Copy{})
	if err != nil || got.ContentType != "text/x" || got.CacheControl != "max-age=1" || got.Meta["k"] != "v" || got.ETag != src.ETag {
		t.Fatalf("copy = %+v, %v", got, err)
	}
	got, err = l.Copy(ctx, Ref{"cpy", "dst2"}, Ref{"cpy", "src"}, Copy{Replace: true, ContentType: "text/y"})
	if err != nil || got.ContentType != "text/y" || got.CacheControl != "" {
		t.Fatalf("replacing copy = %+v, %v", got, err)
	}
	if _, err := l.Copy(ctx, Ref{"cpy", "z"}, Ref{"cpy", "ghost"}, Copy{}); !NoKey(err) {
		t.Fatalf("copy of absent = %v", err)
	}

	if _, err := l.Put(ctx, "cpy", "fence", strings.NewReader("1"), 1, Put{IfAbsent: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Put(ctx, "cpy", "fence", strings.NewReader("2"), 1, Put{IfAbsent: true}); !Conflict(err) {
		t.Fatalf("second create = %v, want conflict", err)
	}
	cur, _ := l.Stat(ctx, "cpy", "fence")
	if _, err := l.Put(ctx, "cpy", "fence", strings.NewReader("3"), 1, Put{IfMatch: "stale"}); !Conflict(err) {
		t.Fatalf("stale write = %v, want conflict", err)
	}
	if _, err := l.Put(ctx, "cpy", "fence", strings.NewReader("4"), 1, Put{IfMatch: `"` + cur.ETag + `"`}); err != nil {
		t.Fatalf("current write: %v", err)
	}
	if read(t, l, "cpy", "fence", Get{}) != "4" {
		t.Fatal("fence")
	}
}

func TestMultipart(t *testing.T) {
	ctx := context.Background()
	l, _ := newLocal(t)
	_ = l.Ensure(ctx, "mpt")
	id, err := l.Begin(ctx, "mpt", "big", Put{ContentType: "application/x-big"})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []struct {
		n int
		s string
	}{{2, "world"}, {1, "hello "}, {2, "WORLD"}} {
		link, err := l.Share(ctx, Share{Method: http.MethodPut, Bucket: "mpt", Key: "big", TTL: time.Minute, Query: url.Values{"partNumber": {string(rune('0' + p.n))}, "uploadId": {id}}})
		if err != nil {
			t.Fatal(err)
		}
		req, _ := http.NewRequest(http.MethodPut, link.URL, strings.NewReader(p.s))
		resp, err := http.DefaultClient.Do(req)
		if err != nil || resp.StatusCode != 200 || resp.Header.Get("ETag") == "" {
			t.Fatalf("part %d: %v %v", p.n, resp, err)
		}
		resp.Body.Close()
	}
	parts, err := l.Parts(ctx, "mpt", "big", id)
	if err != nil || len(parts) != 2 || parts[0].Number != 1 || parts[1].Number != 2 {
		t.Fatalf("parts = %+v, %v", parts, err)
	}
	info, err := l.Join(ctx, "mpt", "big", id, parts)
	if err != nil || info.Size != 11 || !strings.HasSuffix(info.ETag, "-2") || info.ContentType != "application/x-big" {
		t.Fatalf("join = %+v, %v", info, err)
	}
	if read(t, l, "mpt", "big", Get{}) != "hello WORLD" {
		t.Fatal("the last upload of a part must win")
	}
	if _, err := l.Join(ctx, "mpt", "big", id, parts); !NoUpload(err) {
		t.Fatalf("join twice = %v", err)
	}
	id2, _ := l.Begin(ctx, "mpt", "other", Put{})
	if err := l.Abort(ctx, "mpt", "other", id2); err != nil {
		t.Fatal(err)
	}
	if err := l.Abort(ctx, "mpt", "other", id2); !NoUpload(err) {
		t.Fatalf("abort twice = %v", err)
	}
	if _, err := l.Parts(ctx, "mpt", "wrongkey", id2); !NoUpload(err) {
		t.Fatalf("parts under another key = %v", err)
	}
}

// TestSignedLinksEndToEnd is what a browser does: GET, range GET, PUT and a form POST
// against the URLs the store signed, and every way a link can be wrong.
func TestSignedLinksEndToEnd(t *testing.T) {
	ctx := context.Background()
	l, base := newLocal(t)
	_ = l.Ensure(ctx, "web")
	do := func(method, u string, body io.Reader, hdr http.Header) (*http.Response, string) {
		t.Helper()
		req, _ := http.NewRequest(method, u, body)
		for k, v := range hdr {
			req.Header[k] = v
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, string(b)
	}

	// PUT with a signed content type, then GET with response overrides.
	put, err := l.Share(ctx, Share{Method: http.MethodPut, Bucket: "web", Key: "up/my file.txt", TTL: time.Minute, Header: http.Header{"Content-Type": {"text/plain"}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(put.URL, base+Prefix+"web/up/my%20file.txt?") {
		t.Fatalf("url = %s", put.URL)
	}
	if r, _ := do(http.MethodPut, put.URL, strings.NewReader("abc"), http.Header{"Content-Type": {"text/html"}}); r.StatusCode != 403 {
		t.Fatalf("a PUT with another content type = %d, want 403: the type is signed", r.StatusCode)
	}
	if r, _ := do(http.MethodPut, put.URL, strings.NewReader("abcdef"), http.Header{"Content-Type": {"text/plain"}}); r.StatusCode != 200 {
		t.Fatalf("put = %d", r.StatusCode)
	}
	st, _ := l.Stat(ctx, "web", "up/my file.txt")
	if st.Size != 6 || st.ContentType != "text/plain" {
		t.Fatalf("stat after browser put = %+v", st)
	}

	get, _ := l.Share(ctx, Share{Bucket: "web", Key: "up/my file.txt", TTL: time.Minute, Query: url.Values{"response-content-disposition": {`attachment; filename="x.txt"`}, "response-content-type": {"application/octet-stream"}}})
	r, body := do(http.MethodGet, get.URL, nil, nil)
	if r.StatusCode != 200 || body != "abcdef" || r.Header.Get("Content-Disposition") != `attachment; filename="x.txt"` || r.Header.Get("Content-Type") != "application/octet-stream" || r.Header.Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("get = %d %q %v", r.StatusCode, body, r.Header)
	}
	r, body = do(http.MethodGet, get.URL, nil, http.Header{"Range": {"bytes=2-3"}})
	if r.StatusCode != 206 || body != "cd" || r.Header.Get("Content-Range") != "bytes 2-3/6" {
		t.Fatalf("range = %d %q %v", r.StatusCode, body, r.Header)
	}
	if r, _ := do(http.MethodOptions, get.URL, nil, nil); r.StatusCode != 204 {
		t.Fatalf("preflight = %d", r.StatusCode)
	}
	// A link made for GET is not one for PUT, nor for another key, nor altered.
	if r, _ := do(http.MethodPut, get.URL, strings.NewReader("evil"), nil); r.StatusCode != 403 {
		t.Fatalf("PUT on a GET link = %d", r.StatusCode)
	}
	if r, _ := do(http.MethodGet, strings.Replace(get.URL, "my%20file", "other", 1), nil, nil); r.StatusCode != 403 {
		t.Fatalf("another key on a link = %d", r.StatusCode)
	}
	if r, _ := do(http.MethodGet, strings.Replace(get.URL, "attachment", "inline", 1), nil, nil); r.StatusCode != 403 {
		t.Fatalf("altered response header = %d", r.StatusCode)
	}
	// An expired link, and a missing object under a good link.
	old, _ := l.Share(ctx, Share{Bucket: "web", Key: "up/my file.txt", TTL: time.Second})
	time.Sleep(2100 * time.Millisecond)
	if r, _ := do(http.MethodGet, old.URL, nil, nil); r.StatusCode != 403 {
		t.Fatalf("expired = %d", r.StatusCode)
	}
	gone, _ := l.Share(ctx, Share{Bucket: "web", Key: "never", TTL: time.Minute})
	if r, _ := do(http.MethodGet, gone.URL, nil, nil); r.StatusCode != 404 {
		t.Fatalf("absent = %d", r.StatusCode)
	}
	// A key that lists a different signature secret is not ours.
	other := &Local{Dir: t.TempDir(), Base: l.Base}
	foreign, _ := other.Share(ctx, Share{Bucket: "web", Key: "up/my file.txt", TTL: time.Minute})
	if r, _ := do(http.MethodGet, foreign.URL, nil, nil); r.StatusCode != 403 {
		t.Fatalf("a link signed with another key = %d", r.StatusCode)
	}
}

func TestFormUpload(t *testing.T) {
	ctx := context.Background()
	l, _ := newLocal(t)
	_ = l.Ensure(ctx, "frm")
	f, err := l.Form(ctx, Form{Bucket: "frm", Prefix: "acme/run1/", TTL: time.Minute, MaxBytes: 10})
	if err != nil {
		t.Fatal(err)
	}
	post := func(key, content, ct string) int {
		var buf bytes.Buffer
		w := multipart.NewWriter(&buf)
		for k, v := range f.Fields {
			_ = w.WriteField(k, v)
		}
		_ = w.WriteField("key", key)
		if ct != "" {
			_ = w.WriteField("Content-Type", ct)
		}
		fw, _ := w.CreateFormFile("file", "f")
		_, _ = fw.Write([]byte(content))
		_ = w.Close()
		resp, err := http.Post(f.URL, w.FormDataContentType(), &buf)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if c := post("acme/run1/out/a.json", "{}", "application/json"); c != 204 {
		t.Fatalf("form post = %d", c)
	}
	st, err := l.Stat(ctx, "frm", "acme/run1/out/a.json")
	if err != nil || st.ContentType != "application/json" || st.Size != 2 {
		t.Fatalf("stat = %+v, %v", st, err)
	}
	for name, c := range map[string]int{
		"a neighbouring prefix": post("acme/run10/a", "x", ""),
		"another org's prefix":  post("other/run1/a", "x", ""),
		"a traversal":           post("acme/run1/../run2/a", "x", ""),
		"a file over the limit": post("acme/run1/big", strings.Repeat("x", 11), ""),
		"a missing key":         post("", "x", ""),
	} {
		if c < 400 {
			t.Fatalf("%s was accepted: %d", name, c)
		}
	}
	if _, err := l.Stat(ctx, "frm", "acme/run10/a"); !NoKey(err) {
		t.Fatal("a refused form left an object")
	}
	// A forged policy is refused.
	f.Fields["policy"] = f.Fields["policy"] + "A"
	if c := post("acme/run1/b", "x", ""); c != 403 {
		t.Fatalf("forged policy = %d", c)
	}
}

func TestNoLinksWithoutAPublicURL(t *testing.T) {
	l := &Local{Dir: t.TempDir()}
	if _, err := l.Share(context.Background(), Share{Bucket: "bkt", Key: "k", TTL: time.Minute}); err != ErrNoPresign {
		t.Fatalf("share = %v", err)
	}
	if _, err := l.Form(context.Background(), Form{Bucket: "bkt", Prefix: "p/", TTL: time.Minute}); err != ErrNoPresign {
		t.Fatalf("form = %v", err)
	}
}

func TestTheSigningKeySurvivesARestart(t *testing.T) {
	dir := t.TempDir()
	a := &Local{Dir: dir, Base: func() string { return "http://x" }}
	b := &Local{Dir: dir, Base: func() string { return "http://x" }}
	s := Share{Bucket: "bkt", Key: "k", TTL: time.Hour, Query: url.Values{"e": nil}}
	la, err := a.Share(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	ua, _ := url.Parse(la.URL)
	if _, err := b.mac("GET", "bkt", "k", ua.Query().Get("e"), canon(ua.Query()), ""); err != nil {
		t.Fatal(err)
	}
	ma, _ := a.mac("x")
	mb, _ := b.mac("x")
	if ma != mb {
		t.Fatal("two processes on one volume must sign with one key")
	}
}
