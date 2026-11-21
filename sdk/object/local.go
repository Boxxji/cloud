package object

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"iter"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Local is the engine on local disk: every bucket is a directory under Dir, and an
// object is a content file plus a small record beside it. It is the default, and
// the whole store of a deployment that is one pod on one volume.
//
// A key is stored under the hash of its name, so "a" and "a/b" coexist as they do
// in an object store and no key can name a path. A write lands in a temporary
// file and is renamed into place, and the record that names the content is
// renamed last, so a reader sees the old object or the new one and never a mix.
// Conditional writes (Put.IfMatch, Put.IfAbsent) are atomic within one process;
// processes that share a volume and need a fence across them use a real driver.
//
// A listing reads every record in the bucket, which is the right trade for a
// laptop and a small deployment and the reason a large one registers a driver.
type Local struct {
	// Dir is the data directory; objects live under Dir/objects.
	Dir string
	// Base is the public URL the process serving Handler answers at, with no
	// trailing slash. Empty means Share and Form refuse (ErrNoPresign): a link
	// nobody can follow is worse than an error.
	Base func() string

	mu    sync.Mutex // conditional writes
	keyMu sync.Mutex
	key   []byte
}

func (l *Local) root() string { return filepath.Join(l.Dir, "objects") }

// record is the file beside an object's content.
type record struct {
	Key     string            `json:"key"`
	Data    string            `json:"data"` // the content file's name
	Size    int64             `json:"size"`
	ETag    string            `json:"etag"`
	Type    string            `json:"type,omitempty"`
	Cache   string            `json:"cache,omitempty"`
	Meta    map[string]string `json:"meta,omitempty"`
	Mod     time.Time         `json:"mod"`
	Dir     string            `json:"-"`
	Content string            `json:"-"`
}

func (r record) info() Info {
	return Info{Key: r.Key, Size: r.Size, ETag: r.ETag, ContentType: r.Type, CacheControl: r.Cache, Meta: r.Meta, Modified: r.Mod}
}

func (l *Local) bucketDir(bucket string) (string, error) {
	if !ValidBucket(bucket) {
		return "", fmt.Errorf("%w: %q is not a bucket name", ErrNoBucket, bucket)
	}
	return filepath.Join(l.root(), bucket), nil
}

func (l *Local) existing(bucket string) (string, error) {
	d, err := l.bucketDir(bucket)
	if err != nil {
		return "", err
	}
	if st, err := os.Stat(d); err != nil || !st.IsDir() {
		return "", fmt.Errorf("%w: %s", ErrNoBucket, bucket)
	}
	return d, nil
}

func checkKey(key string) error {
	if key == "" || len(key) > 1024 || strings.ContainsRune(key, 0) {
		return fmt.Errorf("object: %q is not a key", key)
	}
	return nil
}

func hashKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

func (l *Local) recPath(bdir, key string) string {
	h := hashKey(key)
	return filepath.Join(bdir, "o", h[:2], h+".json")
}

func (l *Local) Ensure(_ context.Context, bucket string) error {
	d, err := l.bucketDir(bucket)
	if err != nil {
		return fmt.Errorf("object: %q is not a bucket name", bucket)
	}
	for _, sub := range []string{"o", "u", "t"} {
		if err := os.MkdirAll(filepath.Join(d, sub), 0o700); err != nil {
			return err
		}
	}
	return nil
}

func (l *Local) Has(_ context.Context, bucket string) (bool, error) {
	d, err := l.bucketDir(bucket)
	if err != nil {
		return false, nil
	}
	st, err := os.Stat(d)
	return err == nil && st.IsDir(), nil
}

func (l *Local) Buckets(_ context.Context) ([]Bucket, error) {
	ents, err := os.ReadDir(l.root())
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Bucket
	for _, e := range ents {
		if !e.IsDir() || !ValidBucket(e.Name()) {
			continue
		}
		// A bucket directory only changes when it is made, so its time is its birth.
		b := Bucket{Name: e.Name()}
		if fi, err := e.Info(); err == nil {
			b.Created = fi.ModTime().UTC()
		}
		out = append(out, b)
	}
	return out, nil
}

func (l *Local) Drop(ctx context.Context, bucket string) error {
	d, err := l.existing(bucket)
	if err != nil {
		return err
	}
	if len(l.records(d, "")) > 0 {
		return fmt.Errorf("%w: %s", ErrNotEmpty, bucket)
	}
	return os.RemoveAll(d)
}

// stage writes body to a temporary file in the bucket and reports its size, MD5
// and path. The caller renames or removes it.
func (l *Local) stage(bdir string, body io.Reader) (path string, size int64, sum string, err error) {
	f, err := os.CreateTemp(filepath.Join(bdir, "t"), "w-*")
	if err != nil {
		return "", 0, "", err
	}
	h := md5.New()
	n, err := io.Copy(io.MultiWriter(f, h), body)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(f.Name())
		return "", 0, "", err
	}
	return f.Name(), n, hex.EncodeToString(h.Sum(nil)), nil
}

func (l *Local) Put(ctx context.Context, bucket, key string, body io.Reader, size int64, o Put) (Info, error) {
	if err := checkKey(key); err != nil {
		return Info{}, err
	}
	bdir, err := l.existing(bucket)
	if err != nil {
		return Info{}, err
	}
	tmp, n, sum, err := l.stage(bdir, ctxReader{ctx, body})
	if err != nil {
		return Info{}, err
	}
	if size >= 0 && n != size {
		_ = os.Remove(tmp)
		return Info{}, fmt.Errorf("object: body is %d bytes, declared %d", n, size)
	}
	return l.commit(bdir, key, tmp, n, sum, o)
}

// commit installs staged content as key's object.
func (l *Local) commit(bdir, key, tmp string, size int64, etag string, o Put) (Info, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	rp := l.recPath(bdir, key)
	old, oldErr := readRecord(rp)
	if o.IfAbsent && oldErr == nil || o.IfMatch != "" && (oldErr != nil || old.ETag != strings.Trim(o.IfMatch, `"`)) {
		_ = os.Remove(tmp)
		return Info{}, fmt.Errorf("%w: %s", ErrConflict, key)
	}
	dir := filepath.Dir(rp)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		_ = os.Remove(tmp)
		return Info{}, err
	}
	data := hashKey(key) + "." + etag
	if err := os.Rename(tmp, filepath.Join(dir, data)); err != nil {
		_ = os.Remove(tmp)
		return Info{}, err
	}
	rec := record{Key: key, Data: data, Size: size, ETag: etag, Type: o.ContentType, Cache: o.CacheControl, Meta: lower(o.Meta), Mod: time.Now().UTC().Truncate(time.Second)}
	if err := writeRecord(rp, rec); err != nil {
		return Info{}, err
	}
	if oldErr == nil && old.Data != data {
		_ = os.Remove(filepath.Join(dir, old.Data))
	}
	return rec.info(), nil
}

func lower(m map[string]string) map[string]string {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[strings.ToLower(k)] = v
	}
	return out
}

func writeRecord(path string, r record) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	tmp := path + "." + strconv.FormatInt(time.Now().UnixNano(), 36) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func readRecord(path string) (record, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return record{}, err
	}
	var r record
	if err := json.Unmarshal(b, &r); err != nil {
		return record{}, err
	}
	r.Dir = filepath.Dir(path)
	return r, nil
}

func (l *Local) find(bucket, key string) (record, error) {
	if err := checkKey(key); err != nil {
		return record{}, fmt.Errorf("%w: %v", ErrNoKey, err)
	}
	bdir, err := l.existing(bucket)
	if err != nil {
		return record{}, err
	}
	r, err := readRecord(l.recPath(bdir, key))
	if err != nil || r.Key != key {
		return record{}, fmt.Errorf("%w: %s/%s", ErrNoKey, bucket, key)
	}
	return r, nil
}

func (l *Local) Stat(_ context.Context, bucket, key string) (Info, error) {
	r, err := l.find(bucket, key)
	if err != nil {
		return Info{}, err
	}
	return r.info(), nil
}

func (l *Local) Open(_ context.Context, bucket, key string, o Get) (*Body, error) {
	r, err := l.find(bucket, key)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(filepath.Join(r.Dir, r.Data))
	if err != nil {
		return nil, fmt.Errorf("%w: %s/%s", ErrNoKey, bucket, key)
	}
	info := r.info()
	if !o.Ranged {
		return &Body{ReadCloser: f, Info: info}, nil
	}
	first, last := o.First, o.Last
	if last < first || last >= r.Size {
		last = r.Size - 1
	}
	if first < 0 || first > last {
		_ = f.Close()
		return nil, fmt.Errorf("object: range %d-%d is outside %d bytes", o.First, o.Last, r.Size)
	}
	if _, err := f.Seek(first, io.SeekStart); err != nil {
		_ = f.Close()
		return nil, err
	}
	info.Size = last - first + 1
	return &Body{ReadCloser: limited{io.LimitReader(f, info.Size), f}, Info: info}, nil
}

type limited struct {
	io.Reader
	c io.Closer
}

func (l limited) Close() error { return l.c.Close() }

func (l *Local) Remove(_ context.Context, bucket, key string) error {
	bdir, err := l.existing(bucket)
	if err != nil {
		return err
	}
	if checkKey(key) != nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	rp := l.recPath(bdir, key)
	r, err := readRecord(rp)
	if err != nil {
		return nil
	}
	if err := os.Remove(rp); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	_ = os.Remove(filepath.Join(r.Dir, r.Data))
	return nil
}

func (l *Local) RemoveMany(ctx context.Context, bucket string, keys []string) error {
	if _, err := l.existing(bucket); err != nil {
		return err
	}
	for _, k := range keys {
		if err := l.Remove(ctx, bucket, k); err != nil {
			return err
		}
	}
	return nil
}

// records is every record in the bucket whose key begins with prefix, in key order.
func (l *Local) records(bdir, prefix string) []record {
	var out []record
	_ = filepath.WalkDir(filepath.Join(bdir, "o"), func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".json") {
			return nil
		}
		if r, err := readRecord(p); err == nil && strings.HasPrefix(r.Key, prefix) {
			out = append(out, r)
		}
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

func (l *Local) List(ctx context.Context, bucket string, o List) iter.Seq2[Info, error] {
	return func(yield func(Info, error) bool) {
		bdir, err := l.existing(bucket)
		if err != nil {
			yield(Info{}, err)
			return
		}
		n := 0
		seen := map[string]bool{}
		for _, r := range l.records(bdir, o.Prefix) {
			if err := ctx.Err(); err != nil {
				yield(Info{}, err)
				return
			}
			info := r.info()
			if o.Shallow {
				if i := strings.IndexByte(r.Key[len(o.Prefix):], '/'); i >= 0 {
					dir := r.Key[:len(o.Prefix)+i+1]
					if seen[dir] {
						continue
					}
					seen[dir] = true
					info = Info{Key: dir, Dir: true}
				}
			}
			if o.Max > 0 && n >= o.Max {
				return
			}
			n++
			if !yield(info, nil) {
				return
			}
		}
	}
}

func (l *Local) Copy(ctx context.Context, dst, src Ref, o Copy) (Info, error) {
	body, err := l.Open(ctx, src.Bucket, src.Key, Get{})
	if err != nil {
		return Info{}, err
	}
	defer body.Close()
	if o.IfMatch != "" && strings.Trim(o.IfMatch, `"`) != body.Info.ETag {
		return Info{}, fmt.Errorf("%w: %s/%s is not the object copied from", ErrConflict, src.Bucket, src.Key)
	}
	p := Put{ContentType: body.Info.ContentType, CacheControl: body.Info.CacheControl, Meta: body.Info.Meta}
	if o.Replace {
		p = Put{ContentType: o.ContentType, CacheControl: o.CacheControl, Meta: o.Meta}
	}
	return l.Put(ctx, dst.Bucket, dst.Key, body, body.Info.Size, p)
}

// Multipart. An upload is a directory of numbered part files and the Put that began
// it; Join concatenates the parts the caller names.

type upload struct {
	Key string `json:"key"`
	Put Put    `json:"put"`
}

func (l *Local) uploadDir(bucket, id string) (string, error) {
	bdir, err := l.existing(bucket)
	if err != nil {
		return "", err
	}
	if len(id) != 32 || strings.Trim(id, "0123456789abcdef") != "" {
		return "", fmt.Errorf("%w: %q", ErrNoUpload, id)
	}
	return filepath.Join(bdir, "u", id), nil
}

func (l *Local) Begin(_ context.Context, bucket, key string, o Put) (string, error) {
	if err := checkKey(key); err != nil {
		return "", err
	}
	bdir, err := l.existing(bucket)
	if err != nil {
		return "", err
	}
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	id := hex.EncodeToString(b[:])
	dir := filepath.Join(bdir, "u", id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	raw, _ := json.Marshal(upload{Key: key, Put: o})
	return id, os.WriteFile(filepath.Join(dir, "upload.json"), raw, 0o600)
}

func (l *Local) loadUpload(bucket, key, id string) (string, upload, error) {
	dir, err := l.uploadDir(bucket, id)
	if err != nil {
		return "", upload{}, err
	}
	raw, err := os.ReadFile(filepath.Join(dir, "upload.json"))
	var u upload
	if err != nil || json.Unmarshal(raw, &u) != nil || u.Key != key {
		return "", upload{}, fmt.Errorf("%w: %s", ErrNoUpload, id)
	}
	return dir, u, nil
}

// putPart stores one part of an upload and returns its ETag.
func (l *Local) putPart(bucket, key, id string, n int, body io.Reader) (string, error) {
	dir, _, err := l.loadUpload(bucket, key, id)
	if err != nil {
		return "", err
	}
	if n < 1 || n > 10000 {
		return "", fmt.Errorf("object: part %d is outside 1-10000", n)
	}
	bdir := filepath.Dir(filepath.Dir(dir))
	tmp, _, sum, err := l.stage(bdir, body)
	if err != nil {
		return "", err
	}
	if old, _ := filepath.Glob(filepath.Join(dir, fmt.Sprintf("p%05d.*", n))); len(old) > 0 {
		for _, f := range old { // the last upload of a part number wins
			_ = os.Remove(f)
		}
	}
	if err := os.Rename(tmp, filepath.Join(dir, fmt.Sprintf("p%05d.%s", n, sum))); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	return sum, nil
}

func (l *Local) Parts(_ context.Context, bucket, key, id string) ([]Part, error) {
	dir, _, err := l.loadUpload(bucket, key, id)
	if err != nil {
		return nil, err
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	latest := map[int]Part{}
	for _, e := range ents {
		if name := e.Name(); strings.HasPrefix(name, "p") {
			num, sum, ok := strings.Cut(name[1:], ".")
			if n, err := strconv.Atoi(num); ok && err == nil {
				p := Part{Number: n, ETag: sum}
				if fi, err := e.Info(); err == nil {
					p.Size = fi.Size()
				}
				latest[n] = p
			}
		}
	}
	out := make([]Part, 0, len(latest))
	for _, p := range latest {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Number < out[j].Number })
	return out, nil
}

func (l *Local) Join(ctx context.Context, bucket, key, id string, parts []Part) (Info, error) {
	dir, u, err := l.loadUpload(bucket, key, id)
	if err != nil {
		return Info{}, err
	}
	if len(parts) == 0 {
		return Info{}, errors.New("object: an upload joins at least one part")
	}
	var readers []io.Reader
	var files []*os.File
	defer func() {
		for _, f := range files {
			_ = f.Close()
		}
	}()
	sums := md5.New()
	for i, p := range parts {
		if i > 0 && p.Number <= parts[i-1].Number {
			return Info{}, errors.New("object: parts must ascend")
		}
		f, err := os.Open(filepath.Join(dir, fmt.Sprintf("p%05d.%s", p.Number, strings.Trim(p.ETag, `"`))))
		if err != nil {
			return Info{}, fmt.Errorf("object: part %d is not as uploaded", p.Number)
		}
		files = append(files, f)
		readers = append(readers, f)
		raw, _ := hex.DecodeString(strings.Trim(p.ETag, `"`))
		sums.Write(raw)
	}
	bdir := filepath.Dir(filepath.Dir(dir))
	tmp, n, _, err := l.stage(bdir, ctxReader{ctx, io.MultiReader(readers...)})
	if err != nil {
		return Info{}, err
	}
	etag := hex.EncodeToString(sums.Sum(nil)) + "-" + strconv.Itoa(len(parts))
	info, err := l.commit(bdir, key, tmp, n, etag, u.Put)
	if err != nil {
		return Info{}, err
	}
	_ = os.RemoveAll(dir)
	return info, nil
}

func (l *Local) Abort(_ context.Context, bucket, key, id string) error {
	dir, _, err := l.loadUpload(bucket, key, id)
	if err != nil {
		return err
	}
	return os.RemoveAll(dir)
}

// ctxReader ends a copy when its context does.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}
