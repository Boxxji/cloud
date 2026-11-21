package object

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Prefix is where a process that serves Local's signed links answers. The host
// mounts Handler here; a link is Base + Prefix + bucket + "/" + key.
const Prefix = "/v1/object/"

// secret is the key links are signed with: one minted beside the objects the first
// time it is needed. It lives on the volume rather than being derived from the
// data-plane master because every process that shares the objects must verify what
// any of them signed, and the light host holds no master; a key on the volume is
// the one fact all of them share. Whoever reads it can already read the objects.
func (l *Local) secret() ([]byte, error) {
	l.keyMu.Lock()
	defer l.keyMu.Unlock()
	if l.key != nil {
		return l.key, nil
	}
	path := filepath.Join(l.root(), ".key")
	if b, err := os.ReadFile(path); err == nil && len(b) >= 32 {
		l.key = b
		return b, nil
	}
	if err := os.MkdirAll(l.root(), 0o700); err != nil {
		return nil, err
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return nil, err
	}
	// Two processes may mint at once; whichever file the OS kept is the key.
	if kept, err := os.ReadFile(path); err == nil && len(kept) >= 32 {
		b = kept
	}
	l.key = b
	return b, nil
}

func (l *Local) base() (string, error) {
	if l.Base != nil {
		if b := strings.TrimRight(l.Base(), "/"); b != "" {
			return b, nil
		}
	}
	return "", ErrNoPresign
}

func (l *Local) mac(parts ...string) (string, error) {
	k, err := l.secret()
	if err != nil {
		return "", err
	}
	h := hmac.New(sha256.New, k)
	h.Write([]byte("hanzo-object-link-v1"))
	for _, p := range parts {
		h.Write([]byte{0})
		h.Write([]byte(p))
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// canon is the query a signature covers, sorted, without the signature's own
// parameters.
func canon(q url.Values) string {
	keys := make([]string, 0, len(q))
	for k := range q {
		if k != "e" && k != "s" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		for _, v := range q[k] {
			b.WriteString(url.QueryEscape(k) + "=" + url.QueryEscape(v) + "&")
		}
	}
	return b.String()
}

func (l *Local) Share(_ context.Context, s Share) (Link, error) {
	base, err := l.base()
	if err != nil {
		return Link{}, err
	}
	if s.Method == "" {
		s.Method = http.MethodGet
	}
	if s.Method != http.MethodGet && s.Method != http.MethodPut && s.Method != http.MethodHead {
		return Link{}, fmt.Errorf("object: cannot sign a %s", s.Method)
	}
	if !ValidBucket(s.Bucket) {
		return Link{}, fmt.Errorf("%w: %q", ErrNoBucket, s.Bucket)
	}
	if err := checkKey(s.Key); err != nil {
		return Link{}, err
	}
	if s.TTL <= 0 {
		return Link{}, errors.New("object: a link needs a lifetime")
	}
	q := url.Values{}
	for k, v := range s.Query {
		q[k] = v
	}
	exp := strconv.FormatInt(time.Now().Add(s.TTL).Unix(), 10)
	q.Set("e", exp)
	sig, err := l.mac(s.Method, s.Bucket, s.Key, exp, canon(q), s.Header.Get("Content-Type"))
	if err != nil {
		return Link{}, err
	}
	q.Set("s", sig)
	return Link{URL: base + Prefix + s.Bucket + "/" + escapePath(s.Key) + "?" + q.Encode()}, nil
}

func escapePath(key string) string {
	parts := strings.Split(key, "/")
	for i, p := range parts {
		parts[i] = url.PathEscape(p)
	}
	return strings.Join(parts, "/")
}

// policy is what a form signature covers.
type policy struct {
	Bucket string `json:"b"`
	Prefix string `json:"p,omitempty"`
	Key    string `json:"k,omitempty"`
	Type   string `json:"t,omitempty"`
	Expiry int64  `json:"e"`
	Min    int64  `json:"n,omitempty"`
	Max    int64  `json:"m,omitempty"`
}

func (l *Local) Form(_ context.Context, f Form) (Link, error) {
	base, err := l.base()
	if err != nil {
		return Link{}, err
	}
	prefixed := f.Prefix != "" && strings.HasSuffix(f.Prefix, "/") && f.Key == ""
	keyed := f.Key != "" && f.Prefix == "" && checkKey(f.Key) == nil
	if !ValidBucket(f.Bucket) || !(prefixed || keyed) || f.TTL <= 0 {
		return Link{}, errors.New("object: a form needs a bucket, a lifetime and either a prefix ending in / or a key")
	}
	raw, _ := json.Marshal(policy{Bucket: f.Bucket, Prefix: f.Prefix, Key: f.Key, Type: f.ContentType, Expiry: time.Now().Add(f.TTL).Unix(), Min: f.MinBytes, Max: f.MaxBytes})
	pol := base64.RawURLEncoding.EncodeToString(raw)
	sig, err := l.mac("form", pol)
	if err != nil {
		return Link{}, err
	}
	return Link{URL: base + Prefix + f.Bucket, Fields: map[string]string{"policy": pol, "signature": sig}}, nil
}

// Handler serves the links Share and Form made, under Prefix. It answers with CORS
// open, since a signed link is itself the credential and a browser at another
// origin is who it was made for.
func (l *Local) Handler() http.Handler {
	return http.HandlerFunc(l.serve)
}

func (l *Local) serve(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", "*")
	h.Set("Access-Control-Expose-Headers", "ETag")
	if r.Method == http.MethodOptions {
		h.Set("Access-Control-Allow-Methods", "GET, HEAD, PUT, POST, OPTIONS")
		h.Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Range")
		h.Set("Access-Control-Max-Age", "600")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	rest, ok := strings.CutPrefix(r.URL.Path, Prefix)
	if !ok {
		http.NotFound(w, r)
		return
	}
	bucket, key, hasKey := strings.Cut(rest, "/")
	switch {
	case r.Method == http.MethodPost && !hasKey:
		l.serveForm(w, r, bucket)
	case hasKey && key != "" && (r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodPut):
		l.serveLink(w, r, bucket, key)
	default:
		http.Error(w, "not a signed link", http.StatusMethodNotAllowed)
	}
}

func (l *Local) serveLink(w http.ResponseWriter, r *http.Request, bucket, key string) {
	q := r.URL.Query()
	exp, err := strconv.ParseInt(q.Get("e"), 10, 64)
	if err != nil || time.Now().Unix() > exp {
		http.Error(w, "this link has expired", http.StatusForbidden)
		return
	}
	want, err := l.mac(r.Method, bucket, key, q.Get("e"), canon(q), r.Header.Get("Content-Type"))
	if err != nil || !hmac.Equal([]byte(want), []byte(q.Get("s"))) {
		http.Error(w, "this link is not valid for this request", http.StatusForbidden)
		return
	}
	ctx := r.Context()
	if r.Method == http.MethodPut {
		l.servePut(w, r, bucket, key)
		return
	}
	body, err := l.Open(ctx, bucket, key, rangeOf(r))
	if err != nil {
		if Absent(err) {
			http.Error(w, "no such object", http.StatusNotFound)
			return
		}
		if strings.Contains(err.Error(), "range") {
			http.Error(w, err.Error(), http.StatusRequestedRangeNotSatisfiable)
			return
		}
		http.Error(w, "the store could not read this object", http.StatusInternalServerError)
		return
	}
	defer body.Close()
	info := body.Info
	h := w.Header()
	ct := info.ContentType
	if v := q.Get("response-content-type"); v != "" {
		ct = v
	}
	if ct == "" {
		ct = "application/octet-stream"
	}
	h.Set("Content-Type", ct)
	if v := q.Get("response-content-disposition"); v != "" {
		h.Set("Content-Disposition", v)
	}
	if info.CacheControl != "" {
		h.Set("Cache-Control", info.CacheControl)
	}
	h.Set("ETag", `"`+info.ETag+`"`)
	h.Set("Last-Modified", info.Modified.UTC().Format(http.TimeFormat))
	h.Set("Accept-Ranges", "bytes")
	h.Set("Content-Length", strconv.FormatInt(info.Size, 10))
	status := http.StatusOK
	if g := rangeOf(r); g.Ranged {
		total, _ := l.Stat(ctx, bucket, key)
		first := g.First
		h.Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", first, first+info.Size-1, total.Size))
		status = http.StatusPartialContent
	}
	w.WriteHeader(status)
	if r.Method != http.MethodHead {
		_, _ = io.Copy(w, body)
	}
}

// rangeOf reads a single "bytes=a-b" or "bytes=a-" range; anything else is a whole
// read, as RFC 9110 allows a server to answer.
func rangeOf(r *http.Request) Get {
	v, ok := strings.CutPrefix(r.Header.Get("Range"), "bytes=")
	if !ok || strings.Contains(v, ",") {
		return Get{}
	}
	a, b, ok := strings.Cut(v, "-")
	first, err := strconv.ParseInt(a, 10, 64)
	if !ok || err != nil {
		return Get{}
	}
	last := int64(-1)
	if b != "" {
		if last, err = strconv.ParseInt(b, 10, 64); err != nil {
			return Get{}
		}
	}
	return Get{Ranged: true, First: first, Last: last}
}

// maxSigned bounds a body a signed PUT carries when its link states no size.
const maxSigned = 5 << 30

func (l *Local) servePut(w http.ResponseWriter, r *http.Request, bucket, key string) {
	ctx := r.Context()
	body := http.MaxBytesReader(w, r.Body, maxSigned)
	q := r.URL.Query()
	if id := q.Get("uploadId"); id != "" {
		n, err := strconv.Atoi(q.Get("partNumber"))
		if err != nil {
			http.Error(w, "partNumber is not a number", http.StatusBadRequest)
			return
		}
		sum, err := l.putPart(bucket, key, id, n, ctxReader{ctx, body})
		if err != nil {
			status := http.StatusInternalServerError
			if NoUpload(err) || NoBucket(err) {
				status = http.StatusNotFound
			}
			http.Error(w, "the part was not stored", status)
			return
		}
		w.Header().Set("ETag", `"`+sum+`"`)
		w.WriteHeader(http.StatusOK)
		return
	}
	if err := l.Ensure(ctx, bucket); err != nil {
		http.Error(w, "no such bucket", http.StatusNotFound)
		return
	}
	info, err := l.Put(ctx, bucket, key, body, -1, Put{ContentType: r.Header.Get("Content-Type")})
	if err != nil {
		http.Error(w, "the object was not stored", http.StatusInternalServerError)
		return
	}
	w.Header().Set("ETag", `"`+info.ETag+`"`)
	w.WriteHeader(http.StatusOK)
}

func (l *Local) serveForm(w http.ResponseWriter, r *http.Request, bucket string) {
	mr, err := r.MultipartReader()
	if err != nil {
		http.Error(w, "this is not a form upload", http.StatusBadRequest)
		return
	}
	fields := map[string]string{}
	var pol policy
	checked := false
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			http.Error(w, "this is not a form upload", http.StatusBadRequest)
			return
		}
		name := part.FormName()
		if name != "file" {
			v, _ := io.ReadAll(io.LimitReader(part, 64<<10))
			fields[strings.ToLower(name)] = string(v)
			continue
		}
		// The file is the last field of a form, so the policy it is held to has been
		// read by now.
		if !checked {
			p, status, msg := l.checkPolicy(fields, bucket)
			if status != 0 {
				http.Error(w, msg, status)
				return
			}
			pol, checked = p, true
		}
		key, ok := Key(fields["key"])
		if pol.Key != "" {
			ok = ok && key == pol.Key
		} else {
			ok = ok && strings.HasPrefix(key, pol.Prefix)
		}
		if !ok {
			http.Error(w, "this form may not write that key", http.StatusForbidden)
			return
		}
		var src io.Reader = part
		if pol.Max > 0 {
			src = io.LimitReader(part, pol.Max+1)
		}
		ct := fields["content-type"]
		if ct == "" {
			ct = part.Header.Get("Content-Type")
		}
		if pol.Type != "" && ct != pol.Type {
			http.Error(w, "this form takes only "+pol.Type, http.StatusForbidden)
			return
		}
		if t, _, err := mime.ParseMediaType(ct); err != nil || t == "" {
			ct = ""
		}
		if err := l.Ensure(r.Context(), bucket); err != nil {
			http.Error(w, "no such bucket", http.StatusNotFound)
			return
		}
		bdir, _ := l.existing(bucket)
		tmp, n, sum, err := l.stage(bdir, ctxReader{r.Context(), src})
		if err != nil {
			http.Error(w, "the object was not stored", http.StatusInternalServerError)
			return
		}
		if pol.Max > 0 && n > pol.Max {
			_ = os.Remove(tmp)
			http.Error(w, "the file is larger than this form allows", http.StatusRequestEntityTooLarge)
			return
		}
		if n < pol.Min {
			_ = os.Remove(tmp)
			http.Error(w, "the file is smaller than this form allows", http.StatusBadRequest)
			return
		}
		if _, err := l.commit(bdir, key, tmp, n, sum, Put{ContentType: ct}); err != nil {
			http.Error(w, "the object was not stored", http.StatusInternalServerError)
			return
		}
		w.Header().Set("ETag", `"`+sum+`"`)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.Error(w, "the form has no file", http.StatusBadRequest)
}

func (l *Local) checkPolicy(fields map[string]string, bucket string) (policy, int, string) {
	var pol policy
	raw, err := base64.RawURLEncoding.DecodeString(fields["policy"])
	if err != nil || json.Unmarshal(raw, &pol) != nil {
		return pol, http.StatusForbidden, "this form's policy is not valid"
	}
	want, err := l.mac("form", fields["policy"])
	if err != nil || !hmac.Equal([]byte(want), []byte(fields["signature"])) {
		return pol, http.StatusForbidden, "this form's signature is not valid"
	}
	if time.Now().Unix() > pol.Expiry {
		return pol, http.StatusForbidden, "this form has expired"
	}
	if pol.Bucket != bucket {
		return pol, http.StatusForbidden, "this form is for another bucket"
	}
	return pol, 0, ""
}
