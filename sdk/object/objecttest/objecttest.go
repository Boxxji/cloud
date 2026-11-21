// Package objecttest is the conformance suite every object.Store must pass: the
// local engine in the SDK and each production driver run the same cases, so an app
// written against the interface behaves the same on a laptop and in production.
package objecttest

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hanzoai/cloud/sdk/object"
)

// Options says what the store under test can do beyond the contract's core.
type Options struct {
	// Conditional is true when Put.IfMatch and IfAbsent are enforced.
	Conditional bool
	// Links is true when Share and Form produce URLs this test can follow.
	Links bool
}

// bucket makes a bucket unique to one case, and removes it and what it holds at
// the end, so a store shared with other runs is left as found.
func bucket(t *testing.T, s object.Store) string {
	t.Helper()
	var b [5]byte
	_, _ = rand.Read(b[:])
	name := "cnf-" + hex.EncodeToString(b[:])
	ctx := context.Background()
	if err := s.Ensure(ctx, name); err != nil {
		t.Fatalf("ensure %s: %v", name, err)
	}
	t.Cleanup(func() {
		var keys []string
		for in, err := range s.List(ctx, name, object.List{}) {
			if err == nil {
				keys = append(keys, in.Key)
			}
		}
		_ = s.RemoveMany(ctx, name, keys)
		_ = s.Drop(ctx, name)
	})
	return name
}

func slurp(t *testing.T, s object.Store, b, k string, g object.Get) string {
	t.Helper()
	body, err := s.Open(context.Background(), b, k, g)
	if err != nil {
		t.Fatalf("open %s/%s: %v", b, k, err)
	}
	defer body.Close()
	v, err := io.ReadAll(body)
	if err != nil {
		t.Fatal(err)
	}
	return string(v)
}

// Run runs every case against s.
func Run(t *testing.T, s object.Store, o Options) {
	ctx := context.Background()

	t.Run("objects", func(t *testing.T) {
		b := bucket(t, s)
		if ok, err := s.Has(ctx, b); err != nil || !ok {
			t.Fatalf("has = %v, %v", ok, err)
		}
		if ok, err := s.Has(ctx, b+"-ghost"); err != nil || ok {
			t.Fatalf("has ghost = %v, %v", ok, err)
		}
		if err := s.Ensure(ctx, b); err != nil {
			t.Fatalf("ensure twice: %v", err)
		}
		in, err := s.Put(ctx, b, "dir/a.txt", strings.NewReader("hello"), 5, object.Put{ContentType: "text/plain", CacheControl: "no-store", Meta: map[string]string{"Owner": "z"}})
		if err != nil {
			t.Fatal(err)
		}
		if in.ETag != "5d41402abc4b2a76b9719d911017c592" {
			t.Fatalf("etag of a single-part put = %q, want the MD5 of its bytes", in.ETag)
		}
		st, err := s.Stat(ctx, b, "dir/a.txt")
		if err != nil || st.Size != 5 || st.ContentType != "text/plain" || st.CacheControl != "no-store" || st.Meta["owner"] != "z" || st.ETag != in.ETag || st.Modified.IsZero() {
			t.Fatalf("stat = %+v, %v", st, err)
		}
		if got := slurp(t, s, b, "dir/a.txt", object.Get{}); got != "hello" {
			t.Fatalf("read = %q", got)
		}
		if got := slurp(t, s, b, "dir/a.txt", object.Get{Ranged: true, First: 1, Last: 3}); got != "ell" {
			t.Fatalf("range = %q", got)
		}
		if got := slurp(t, s, b, "dir/a.txt", object.Get{Ranged: true, First: 3, Last: -1}); got != "lo" {
			t.Fatalf("open-ended range = %q", got)
		}
		// An object store holds "dir" and "dir/a.txt" as two objects. A store backed
		// by a file tree cannot, and says so; that is a limit of the store, not of
		// the contract, and it is logged rather than failed so the suite still runs.
		if _, err := s.Put(ctx, b, "dir", strings.NewReader("flat"), 4, object.Put{}); err != nil {
			t.Logf("this store cannot hold a key and the keys beneath it: %v", err)
		} else {
			if slurp(t, s, b, "dir", object.Get{}) != "flat" || slurp(t, s, b, "dir/a.txt", object.Get{}) != "hello" {
				t.Fatal("a key and the keys beneath it are separate objects")
			}
		}
		if _, err := s.Put(ctx, b, "dir/a.txt", strings.NewReader("bye"), -1, object.Put{}); err != nil {
			t.Fatal(err)
		}
		if slurp(t, s, b, "dir/a.txt", object.Get{}) != "bye" {
			t.Fatal("overwrite")
		}
		if _, err := s.Open(ctx, b, "nope", object.Get{}); !object.NoKey(err) {
			t.Fatalf("open absent = %v, want NoKey", err)
		}
		if _, err := s.Stat(ctx, b, "nope"); !object.NoKey(err) {
			t.Fatalf("stat absent = %v, want NoKey", err)
		}
		if _, err := s.Stat(ctx, b+"-ghost", "x"); !object.Absent(err) {
			t.Fatalf("stat in an absent bucket = %v", err)
		}
		// A store that makes the bucket on a write (a file tree does) is lenient where
		// an object store refuses; callers Ensure first, so either is safe.
		if _, err := s.Put(ctx, b+"-ghost", "x", strings.NewReader("x"), 1, object.Put{}); err == nil {
			t.Logf("this store made a bucket for a write into one that was not there")
			_ = s.Remove(ctx, b+"-ghost", "x")
			_ = s.Drop(ctx, b+"-ghost")
		} else if !object.NoBucket(err) {
			t.Fatalf("put into an absent bucket = %v, want NoBucket", err)
		}
		if err := s.Remove(ctx, b, "nope"); err != nil {
			t.Fatalf("remove absent key = %v, want nil", err)
		}
		if err := s.Remove(ctx, b, "dir/a.txt"); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Stat(ctx, b, "dir/a.txt"); !object.NoKey(err) {
			t.Fatalf("removed object: stat = %v", err)
		}
		if _, err := s.Put(ctx, b, "keep", strings.NewReader("k"), 1, object.Put{}); err != nil {
			t.Fatal(err)
		}
		if err := s.Drop(ctx, b); err == nil {
			// A file-tree store removes the tree; an object store refuses.
			t.Logf("this store dropped a bucket that held objects")
			_ = s.Ensure(ctx, b)
		} else if !object.NotEmpty(err) {
			t.Fatalf("drop of a bucket holding objects = %v, want NotEmpty", err)
		}
		found := false
		_, _ = s.Put(ctx, b, "keep", strings.NewReader("k"), 1, object.Put{})
		names, err := s.Buckets(ctx)
		for _, n := range names {
			found = found || n.Name == b
		}
		if err != nil || !found {
			t.Fatalf("buckets = %v, %v", names, err)
		}
	})

	t.Run("list", func(t *testing.T) {
		b := bucket(t, s)
		for _, k := range []string{"a/1", "a/2", "a/b/3", "b/1", "c"} {
			if _, err := s.Put(ctx, b, k, strings.NewReader(k), -1, object.Put{}); err != nil {
				t.Fatal(err)
			}
		}
		keys := func(l object.List) string {
			var out []string
			for in, err := range s.List(ctx, b, l) {
				if err != nil {
					t.Fatal(err)
				}
				if in.Dir {
					out = append(out, "["+in.Key+"]")
				} else {
					out = append(out, in.Key)
				}
			}
			return strings.Join(out, " ")
		}
		for want, l := range map[string]object.List{
			"a/1 a/2 a/b/3 b/1 c": {},
			"a/1 a/2 a/b/3":       {Prefix: "a/"},
			"[a/] [b/] c":         {Shallow: true},
			"a/1 a/2 [a/b/]":      {Prefix: "a/", Shallow: true},
			"a/1 a/2":             {Max: 2},
			"":                    {Prefix: "zzz"},
		} {
			if got := keys(l); got != want {
				t.Fatalf("list %+v = %q, want %q", l, got, want)
			}
		}
		n := 0
		for in, err := range s.List(ctx, b, object.List{Prefix: "c"}) {
			if err != nil || in.Size != 1 || in.ETag == "" || in.Modified.IsZero() {
				t.Fatalf("a listing entry = %+v, %v", in, err)
			}
			n++
		}
		if n != 1 {
			t.Fatalf("entries = %d", n)
		}
		for _, err := range s.List(ctx, b+"-ghost", object.List{}) {
			if !object.NoBucket(err) {
				t.Fatalf("list of an absent bucket = %v, want NoBucket", err)
			}
		}
		if err := s.RemoveMany(ctx, b, []string{"a/1", "a/2", "nothing"}); err != nil {
			t.Fatal(err)
		}
		if got := keys(object.List{}); got != "a/b/3 b/1 c" {
			t.Fatalf("after RemoveMany: %q", got)
		}
	})

	t.Run("copy", func(t *testing.T) {
		b := bucket(t, s)
		src, err := s.Put(ctx, b, "src", strings.NewReader("data"), 4, object.Put{ContentType: "text/x", CacheControl: "max-age=1", Meta: map[string]string{"k": "v"}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.Copy(ctx, object.Ref{Bucket: b, Key: "dst"}, object.Ref{Bucket: b, Key: "src"}, object.Copy{}); err != nil {
			t.Fatal(err)
		}
		st, err := s.Stat(ctx, b, "dst")
		if err != nil || st.ContentType != "text/x" || st.CacheControl != "max-age=1" || st.Meta["k"] != "v" || st.ETag != src.ETag || st.Size != 4 {
			t.Fatalf("copy keeps the source's type, policy and metadata: %+v, %v", st, err)
		}
		if _, err := s.Copy(ctx, object.Ref{Bucket: b, Key: "dst2"}, object.Ref{Bucket: b, Key: "src"}, object.Copy{Replace: true, ContentType: "text/y", CacheControl: "no-cache"}); err != nil {
			t.Fatal(err)
		}
		if st, err := s.Stat(ctx, b, "dst2"); err != nil || st.ContentType != "text/y" || st.CacheControl != "no-cache" || st.Meta["k"] != "" {
			t.Fatalf("replacing copy: %+v, %v", st, err)
		}
		// Re-stamping an object in place.
		if _, err := s.Copy(ctx, object.Ref{Bucket: b, Key: "src"}, object.Ref{Bucket: b, Key: "src"}, object.Copy{Replace: true, ContentType: "text/z"}); err != nil {
			t.Fatalf("in-place copy: %v", err)
		}
		if st, _ := s.Stat(ctx, b, "src"); st.ContentType != "text/z" {
			t.Fatalf("in-place copy: %+v", st)
		}
		if _, err := s.Copy(ctx, object.Ref{Bucket: b, Key: "z"}, object.Ref{Bucket: b, Key: "ghost"}, object.Copy{}); !object.NoKey(err) {
			t.Fatalf("copy of an absent object = %v, want NoKey", err)
		}
	})

	if o.Conditional {
		t.Run("conditional", func(t *testing.T) {
			b := bucket(t, s)
			if _, err := s.Put(ctx, b, "fence", strings.NewReader("1"), 1, object.Put{IfAbsent: true}); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Put(ctx, b, "fence", strings.NewReader("2"), 1, object.Put{IfAbsent: true}); !object.Conflict(err) {
				t.Fatalf("second create = %v, want Conflict", err)
			}
			cur, _ := s.Stat(ctx, b, "fence")
			if _, err := s.Put(ctx, b, "fence", strings.NewReader("3"), 1, object.Put{IfMatch: "0123456789abcdef0123456789abcdef"}); !object.Conflict(err) {
				t.Fatalf("stale write = %v, want Conflict", err)
			}
			if _, err := s.Put(ctx, b, "fence", strings.NewReader("4"), 1, object.Put{IfMatch: cur.ETag}); err != nil {
				t.Fatalf("current write: %v", err)
			}
			if slurp(t, s, b, "fence", object.Get{}) != "4" {
				t.Fatal("the write that held the fence must land, and the refused ones must not")
			}
			// A copy pinned to the bytes a manifest was built from.
			cur, _ = s.Stat(ctx, b, "fence")
			from, to := object.Ref{Bucket: b, Key: "fence"}, object.Ref{Bucket: b, Key: "pinned"}
			if _, err := s.Copy(ctx, to, from, object.Copy{IfMatch: "0123456789abcdef0123456789abcdef"}); !object.Conflict(err) {
				t.Fatalf("copy of a source that has moved = %v, want Conflict", err)
			}
			if _, err := s.Stat(ctx, b, "pinned"); !object.NoKey(err) {
				t.Fatal("a refused copy left an object")
			}
			if in, err := s.Copy(ctx, to, from, object.Copy{IfMatch: cur.ETag}); err != nil || in.ETag != cur.ETag {
				t.Fatalf("pinned copy = %+v, %v", in, err)
			}
		})
	}

	if !o.Links {
		return
	}

	do := func(t *testing.T, method, u string, body io.Reader, hdr http.Header) (*http.Response, string) {
		t.Helper()
		req, err := http.NewRequest(method, u, body)
		if err != nil {
			t.Fatal(err)
		}
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

	t.Run("links", func(t *testing.T) {
		b := bucket(t, s)
		put, err := s.Share(ctx, object.Share{Method: http.MethodPut, Bucket: b, Key: "up/my file.txt", TTL: time.Minute, Header: http.Header{"Content-Type": {"text/plain"}}})
		if err != nil {
			t.Fatal(err)
		}
		if r, body := do(t, http.MethodPut, put.URL, strings.NewReader("abcdef"), http.Header{"Content-Type": {"text/plain"}}); r.StatusCode != 200 {
			t.Fatalf("browser PUT = %d %s", r.StatusCode, body)
		}
		st, err := s.Stat(ctx, b, "up/my file.txt")
		if err != nil || st.Size != 6 || st.ContentType != "text/plain" {
			t.Fatalf("object after a browser PUT: %+v, %v", st, err)
		}
		get, err := s.Share(ctx, object.Share{Bucket: b, Key: "up/my file.txt", TTL: time.Minute, Query: url.Values{"response-content-disposition": {`attachment; filename="x.txt"`}, "response-content-type": {"application/octet-stream"}}})
		if err != nil {
			t.Fatal(err)
		}
		r, body := do(t, http.MethodGet, get.URL, nil, nil)
		if r.StatusCode != 200 || body != "abcdef" || r.Header.Get("Content-Disposition") != `attachment; filename="x.txt"` || r.Header.Get("Content-Type") != "application/octet-stream" {
			t.Fatalf("browser GET = %d %q %v", r.StatusCode, body, r.Header)
		}
		plain, _ := s.Share(ctx, object.Share{Bucket: b, Key: "up/my file.txt", TTL: time.Minute})
		if r, body := do(t, http.MethodGet, plain.URL, nil, http.Header{"Range": {"bytes=2-3"}}); r.StatusCode != 206 || body != "cd" {
			t.Fatalf("browser range GET = %d %q", r.StatusCode, body)
		}
		if r, _ := do(t, http.MethodGet, strings.Replace(plain.URL, "my%20file", "other", 1), nil, nil); r.StatusCode < 400 {
			t.Fatalf("a link read another object: %d", r.StatusCode)
		}
	})

	t.Run("form", func(t *testing.T) {
		b := bucket(t, s)
		f, err := s.Form(ctx, object.Form{Bucket: b, Prefix: "acme/run1/", TTL: time.Minute, MaxBytes: 10})
		if err != nil {
			t.Fatal(err)
		}
		post := func(key, content, ct string) int {
			var buf bytes.Buffer
			w := multipart.NewWriter(&buf)
			for k, v := range f.Fields {
				if k != "key" {
					_ = w.WriteField(k, v)
				}
			}
			_ = w.WriteField("key", key)
			if ct != "" {
				_ = w.WriteField("Content-Type", ct)
			}
			fw, _ := w.CreateFormFile("file", "f")
			_, _ = fw.Write([]byte(content))
			_ = w.Close()
			r, _ := do(t, http.MethodPost, f.URL, &buf, http.Header{"Content-Type": {w.FormDataContentType()}})
			return r.StatusCode
		}
		if c := post("acme/run1/out/a.json", "{}", "application/json"); c >= 300 {
			t.Fatalf("form post = %d", c)
		}
		st, err := s.Stat(ctx, b, "acme/run1/out/a.json")
		if err != nil || st.ContentType != "application/json" || st.Size != 2 {
			t.Fatalf("object after a form post: %+v, %v", st, err)
		}
		for name, key := range map[string]string{"a neighbouring prefix": "acme/run10/a", "another org": "other/run1/a"} {
			if c := post(key, "x", ""); c < 400 {
				t.Fatalf("form wrote %s: %d", name, c)
			}
			if _, err := s.Stat(ctx, b, key); !object.NoKey(err) {
				t.Fatalf("form left an object at %s", name)
			}
		}
		if c := post("acme/run1/big", strings.Repeat("x", 11), ""); c < 400 {
			t.Fatalf("a file over the limit was accepted: %d", c)
		}
	})

	t.Run("form for one key", func(t *testing.T) {
		b := bucket(t, s)
		f, err := s.Form(ctx, object.Form{Bucket: b, Key: "docs/report.pdf", ContentType: "application/pdf", TTL: time.Minute, MinBytes: 1, MaxBytes: 10})
		if err != nil {
			t.Fatal(err)
		}
		post := func(key, content, ct string) int {
			var buf bytes.Buffer
			w := multipart.NewWriter(&buf)
			for k, v := range f.Fields {
				if k != "key" && k != "Content-Type" {
					_ = w.WriteField(k, v)
				}
			}
			_ = w.WriteField("key", key)
			_ = w.WriteField("Content-Type", ct)
			fw, _ := w.CreateFormFile("file", "f")
			_, _ = fw.Write([]byte(content))
			_ = w.Close()
			r, _ := do(t, http.MethodPost, f.URL, &buf, http.Header{"Content-Type": {w.FormDataContentType()}})
			return r.StatusCode
		}
		if c := post("docs/other.pdf", "x", "application/pdf"); c < 400 {
			t.Fatalf("a form for one key wrote another: %d", c)
		}
		if c := post("docs/report.pdf", "x", "text/html"); c < 400 {
			t.Fatalf("a form for one type took another: %d", c)
		}
		if c := post("docs/report.pdf", strings.Repeat("x", 11), "application/pdf"); c < 400 {
			t.Fatalf("a file over the limit was accepted: %d", c)
		}
		if c := post("docs/report.pdf", "pdf", "application/pdf"); c >= 300 {
			t.Fatalf("the form's own key and type = %d", c)
		}
		if st, err := s.Stat(ctx, b, "docs/report.pdf"); err != nil || st.Size != 3 || st.ContentType != "application/pdf" {
			t.Fatalf("object after the form: %+v, %v", st, err)
		}
	})

	t.Run("multipart", func(t *testing.T) {
		b := bucket(t, s)
		const big = 5 << 20 // stores refuse parts under 5 MiB except the last
		first := strings.Repeat("a", big)
		id, err := s.Begin(ctx, b, "big", object.Put{ContentType: "application/x-big"})
		if err != nil {
			t.Fatal(err)
		}
		for n, content := range map[int]string{1: first, 2: "tail"} {
			link, err := s.Share(ctx, object.Share{Method: http.MethodPut, Bucket: b, Key: "big", TTL: time.Minute, Query: url.Values{"partNumber": {strconv.Itoa(n)}, "uploadId": {id}}})
			if err != nil {
				t.Fatal(err)
			}
			if r, body := do(t, http.MethodPut, link.URL, strings.NewReader(content), nil); r.StatusCode != 200 {
				t.Fatalf("part %d = %d %s", n, r.StatusCode, body)
			}
		}
		parts, err := s.Parts(ctx, b, "big", id)
		if err != nil || len(parts) != 2 || parts[0].Number != 1 || parts[1].Number != 2 || parts[0].Size != big || parts[1].Size != 4 {
			t.Fatalf("parts = %+v, %v", parts, err)
		}
		info, err := s.Join(ctx, b, "big", id, parts)
		if err != nil || info.Size != big+4 {
			t.Fatalf("join = %+v, %v", info, err)
		}
		st, err := s.Stat(ctx, b, "big")
		if err != nil || st.Size != big+4 || st.ContentType != "application/x-big" || !strings.HasSuffix(st.ETag, "-2") {
			t.Fatalf("joined object: %+v, %v", st, err)
		}
		if got := slurp(t, s, b, "big", object.Get{Ranged: true, First: big - 1, Last: big + 3}); got != "atail" {
			t.Fatalf("joined bytes = %q", got)
		}
		// A second join is refused (NoUpload) or answers the object it already made;
		// stores differ, and neither may write anything else.
		if _, err := s.Join(ctx, b, "big", id, parts); err != nil && !object.NoUpload(err) {
			t.Fatalf("join twice = %v, want NoUpload or the same object", err)
		}
		id2, err := s.Begin(ctx, b, "other", object.Put{})
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Abort(ctx, b, "other", id2); err != nil {
			t.Fatal(err)
		}
		if err := s.Abort(ctx, b, "other", id2); err != nil && !object.NoUpload(err) {
			t.Fatalf("abort twice = %v, want nil or NoUpload", err)
		}
	})
}
