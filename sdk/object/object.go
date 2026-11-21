package object

import (
	"context"
	"errors"
	"io"
	"iter"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// Store is what subsystems do with objects. Every method takes the physical bucket
// (BucketName) and the key (Key); an engine does no org scoping of its own, so the
// caller's name is the whole of the isolation.
type Store interface {
	// Ensure makes the bucket if it is not there. A bucket made concurrently is
	// not an error.
	Ensure(ctx context.Context, bucket string) error
	// Has reports whether the bucket exists.
	Has(ctx context.Context, bucket string) (bool, error)
	// Buckets lists every bucket.
	Buckets(ctx context.Context) ([]Bucket, error)
	// Drop deletes an empty bucket (ErrNotEmpty otherwise, ErrNoBucket if absent).
	Drop(ctx context.Context, bucket string) error

	// Put writes one object. size is the body's length, or -1 when unknown.
	Put(ctx context.Context, bucket, key string, body io.Reader, size int64, o Put) (Info, error)
	// Open reads an object, or the range o names; ErrNoKey / ErrNoBucket when it
	// is not there. The caller closes the body.
	Open(ctx context.Context, bucket, key string, o Get) (*Body, error)
	// Stat is an object's Info without its bytes.
	Stat(ctx context.Context, bucket, key string) (Info, error)
	// Remove deletes one object. An absent key is not an error; an absent bucket
	// is (ErrNoBucket).
	Remove(ctx context.Context, bucket, key string) error
	// RemoveMany deletes keys in one pass, stopping at the first refusal.
	RemoveMany(ctx context.Context, bucket string, keys []string) error
	// List yields the objects under o.Prefix in key order. A listing that fails
	// part-way yields its error, so a caller never takes half a listing for all
	// of it.
	List(ctx context.Context, bucket string, o List) iter.Seq2[Info, error]
	// Copy writes src's bytes at dst, keeping src's type, cache policy and
	// metadata unless o replaces them.
	Copy(ctx context.Context, dst, src Ref, o Copy) (Info, error)

	// Share signs a URL that carries one request, for a browser or another
	// process that holds no credential.
	Share(ctx context.Context, s Share) (Link, error)
	// Form signs a browser form upload that may write any key under one prefix
	// and nothing else.
	Form(ctx context.Context, f Form) (Link, error)

	// Begin opens a multipart upload; its parts are uploaded through Share (a PUT
	// carrying the partNumber and uploadId query) and joined by Join.
	Begin(ctx context.Context, bucket, key string, o Put) (string, error)
	// Parts lists the parts uploaded so far, in order.
	Parts(ctx context.Context, bucket, key, id string) ([]Part, error)
	// Join assembles the uploaded parts into the object (ErrNoUpload when id names
	// no upload).
	Join(ctx context.Context, bucket, key, id string, parts []Part) (Info, error)
	// Abort discards an upload (ErrNoUpload when id names none).
	Abort(ctx context.Context, bucket, key, id string) error
}

// Bucket is one bucket and when it was made.
type Bucket struct {
	Name    string
	Created time.Time
}

// Ref names one object.
type Ref struct{ Bucket, Key string }

// Info is what a store knows about an object.
type Info struct {
	Key string
	// Dir marks a shallow listing's common prefix: Key is the prefix, with its
	// trailing slash, and nothing else is set.
	Dir  bool
	Size int64
	// ETag has its quotes removed. For an object written in one part it is the hex
	// MD5 of the bytes; a joined upload's ends in -<parts>.
	ETag         string
	ContentType  string
	CacheControl string
	// Meta is the caller's own metadata, keys lower-cased.
	Meta     map[string]string
	Modified time.Time
}

// Body is an open object.
type Body struct {
	io.ReadCloser
	Info Info
}

// Put says how an object is written.
type Put struct {
	ContentType  string
	CacheControl string
	Meta         map[string]string
	// IfMatch writes only if the object's ETag is this; IfAbsent only if there is
	// no object. A refusal is ErrConflict and nothing is written.
	IfMatch  string
	IfAbsent bool
	// PartSize is a hint, in bytes, for a store that uploads a large body in parts;
	// a store that does not ignores it, and zero lets it choose.
	PartSize int64
}

// Get says which part of an object is read. Last is inclusive; Last < First reads
// to the end. The zero value reads the whole object.
type Get struct {
	Ranged      bool
	First, Last int64
}

// List says what a listing covers.
type List struct {
	Prefix string
	// Shallow stops at the first "/" after the prefix, reporting what lies beyond
	// as Dir entries. The default is every key under the prefix.
	Shallow bool
	// Max ends the listing after that many entries; 0 is no limit.
	Max int
}

// Copy replaces what a copy would carry over from its source. A false Replace
// keeps the source's type, cache policy and metadata.
type Copy struct {
	// IfMatch copies only if the source's ETag is this, so a copy pins itself to the
	// bytes a manifest was built from; a source that has moved is ErrConflict.
	IfMatch      string
	Replace      bool
	ContentType  string
	CacheControl string
	Meta         map[string]string
}

// Share is one signed request.
type Share struct {
	Method string // GET, PUT or HEAD
	Bucket string
	Key    string
	TTL    time.Duration
	// Query is signed with the request: response-content-type and
	// response-content-disposition on a GET, partNumber and uploadId on a part.
	Query url.Values
	// Header names headers the caller must send, and their values; the signature
	// covers them.
	Header http.Header
}

// Form is a browser upload grant. It confines the keys the form may write to Prefix
// (any key under it) or to Key (exactly that one); name one of the two.
type Form struct {
	Bucket string
	// Prefix confines every key the form may write; it must end in "/".
	Prefix string
	// Key is the one key the form may write, when it is not a prefix.
	Key string
	// ContentType, when set, is the one type the file may be sent with; empty
	// accepts the type the sender states.
	ContentType string
	TTL         time.Duration
	// MinBytes and MaxBytes bound the file; MaxBytes of zero is no bound.
	MinBytes, MaxBytes int64
}

// Link is what a signature produced: a URL, and for a Form the fields to post
// with the file.
type Link struct {
	URL    string
	Fields map[string]string
}

// Part is one uploaded piece of a multipart upload.
type Part struct {
	Number int
	ETag   string
	// Size is the part's length in bytes, as Parts reports it; Join ignores it.
	Size int64
}

// The refusals a caller maps to a status. A Store wraps them with its own detail;
// test with the predicates, never with ==.
var (
	ErrNoBucket  = errors.New("object: no such bucket")
	ErrNoKey     = errors.New("object: no such object")
	ErrNoUpload  = errors.New("object: no such upload")
	ErrNotEmpty  = errors.New("object: bucket is not empty")
	ErrConflict  = errors.New("object: precondition failed")
	ErrNoPresign = errors.New("object: this store signs no links here")
	// ErrRefused is a store turning a request down as no request it takes: a name it
	// does not hold, a bucket it will not show. It is not absence and not "try
	// again", and an edge that serves what it finds reads it as a miss.
	ErrRefused = errors.New("object: the store refused the request")
)

// NoBucket reports whether err says the bucket is not there. A caller renders it
// as 404 under whatever the bucket means to it.
func NoBucket(err error) bool { return errors.Is(err, ErrNoBucket) }

// NoKey reports whether err says the object is not there.
func NoKey(err error) bool { return errors.Is(err, ErrNoKey) }

// NoUpload reports whether err says a multipart upload id names no upload.
func NoUpload(err error) bool { return errors.Is(err, ErrNoUpload) }

// NotEmpty reports whether err is a refusal to delete a bucket that still holds
// objects; a caller renders it as 409.
func NotEmpty(err error) bool { return errors.Is(err, ErrNotEmpty) }

// Conflict reports whether err is a conditional write the store refused.
func Conflict(err error) bool { return errors.Is(err, ErrConflict) }

// Refused reports whether err is the store refusing the request itself (ErrRefused).
func Refused(err error) bool { return errors.Is(err, ErrRefused) }

// Absent reports whether err says the object or its bucket is not there.
func Absent(err error) bool { return NoKey(err) || NoBucket(err) }

// Made remembers which buckets this process has already ensured, so a hot path
// asks the store once. A failed Ensure is not remembered; the next call asks again.
// The zero value is ready to use.
type Made struct {
	mu   sync.Mutex
	seen map[string]bool
}

// Ensure makes bucket in s unless this process already has.
func (m *Made) Ensure(ctx context.Context, s Store, bucket string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.seen[bucket] {
		return nil
	}
	if err := s.Ensure(ctx, bucket); err != nil {
		return err
	}
	if m.seen == nil {
		m.seen = map[string]bool{}
	}
	m.seen[bucket] = true
	return nil
}

// Forget drops what Made remembers of bucket, for a caller that has just deleted it.
func (m *Made) Forget(bucket string) {
	m.mu.Lock()
	delete(m.seen, bucket)
	m.mu.Unlock()
}

// Signs reports whether s can make links a browser can follow here: a driver
// without a public host, and local disk without a public URL, cannot. It signs a
// throwaway link and reads only whether the store refused to.
func Signs(ctx context.Context, s Store) bool {
	_, err := s.Share(ctx, Share{Bucket: "probe-links", Key: "probe", TTL: time.Second})
	return !errors.Is(err, ErrNoPresign) && err == nil
}
