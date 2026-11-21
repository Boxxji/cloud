package object

// vfs is the REAL in-process VFSClient (deps.VFS) backing the team files plane on
// the process's object store (sdk/object): local disk by default, the shared S3
// gateway where the deployment configures it. CTO decision (.97): back deps.VFS on
// the key-based object store, NOT the content-addressed hanzoai/vfs (its
// single-block PutBlock->BlockID API does not fit the key-based VFSClient client; an
// adapter+crypto is needless complexity for small avatars).
//
// Everything lands in ONE bucket keyed by the caller-opaque key the consumer
// supplies; tenant isolation is UPSTREAM in that key (apps/team/files.go builds
// team/blobs/<verified-org>/<ws>/<blobId> via seg()). Object keys are flat opaque
// strings, and every key component is seg()-sanitized with a server-verified org,
// so a caller can only ever address keys under its own team/blobs/<its-org>/ prefix
// — the key cannot escape the bucket or another tenant's prefix.

import (
	"bytes"
	"context"
	"errors"
	"io"
)

// ErrBlobNotFound is the sentinel a WORKING blob backend returns from Get/Delete when the
// blob does not exist. It lets a consumer tell a genuine miss (→ 404 / idempotent
// delete) apart from a backend that is unavailable/disabled (any OTHER error → fail
// closed 502) — so a missing blob never masquerades as an outage and a real outage never
// masquerades as 404.
var ErrBlobNotFound = errors.New("vfs: blob not found")

// ErrDisabled is what the disabled blob client answers: the deployment configured no
// blob store, and the call fails closed.
var ErrDisabled = errors.New("cloud: dep \"vfs\" is disabled — enable the subsystem or configure its RPC endpoint")

// Blobs is the key-addressed blob store the framework hands apps (deps.VFS). Delete
// removes the blob at key; a missing key is not an error at the client.
type Blobs interface {
	Put(ctx context.Context, key string, payload []byte) error
	Get(ctx context.Context, key string) ([]byte, error)
	Delete(ctx context.Context, key string) error
}

// NoBlobs returns the fail-closed Blobs of a deployment with no blob store.
func NoBlobs() Blobs { return noBlobs{} }

type noBlobs struct{}

func (noBlobs) Put(context.Context, string, []byte) error   { return ErrDisabled }
func (noBlobs) Get(context.Context, string) ([]byte, error) { return nil, ErrDisabled }
func (noBlobs) Delete(context.Context, string) error        { return ErrDisabled }

// blobs implements Blobs over an object store.
type blobs struct {
	store  Store
	bucket string
	made   Made
}

// Compile-time proof blobs satisfies the client.
var _ Blobs = (*blobs)(nil)

// NewBlobs builds the key-addressed blob client over store, keeping every blob in bucket. NOTHING HERE TOUCHES THE
// NETWORK: the bucket is created by whichever operation first needs it (a boot
// copy of that ensure could only add a wait against a store that is merely absent).
func NewBlobs(store Store, bucket string) Blobs {
	return &blobs{store: store, bucket: bucket}
}

// Put stores payload at key. ContentType is fixed to application/octet-stream — the
// served type is re-derived from the bytes in the files download handler
// (allow-list), so the stored type is irrelevant.
func (v *blobs) Put(ctx context.Context, key string, payload []byte) error {
	if err := v.made.Ensure(ctx, v.store, v.bucket); err != nil {
		return err
	}
	_, err := v.store.Put(ctx, v.bucket, key, bytes.NewReader(payload), int64(len(payload)),
		Put{ContentType: "application/octet-stream"})
	return err
}

// Get returns the object bytes at key. A MISSING key maps to ErrBlobNotFound
// (so the consumer answers 404 / idempotent-204); any OTHER error is returned
// verbatim (so the consumer fails closed 502).
func (v *blobs) Get(ctx context.Context, key string) ([]byte, error) {
	if err := v.made.Ensure(ctx, v.store, v.bucket); err != nil {
		return nil, err
	}
	body, err := v.store.Open(ctx, v.bucket, key, Get{})
	if err != nil {
		return nil, missing(err)
	}
	defer func() { _ = body.Close() }()
	data, err := io.ReadAll(body)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// Delete removes the object at key. Removal is idempotent (a missing key is a no-op
// success); should a store surface a missing key, it maps to ErrBlobNotFound
// (which the consumer treats as an idempotent 204). Any other error is returned
// verbatim (consumer fails closed 502).
func (v *blobs) Delete(ctx context.Context, key string) error {
	if err := v.made.Ensure(ctx, v.store, v.bucket); err != nil {
		return err
	}
	return missing(v.store.Remove(ctx, v.bucket, key))
}

// missing is the load-bearing translation: an absent KEY becomes the
// ErrBlobNotFound sentinel (a genuine miss on a WORKING store → 404 /
// idempotent-204), while nil stays nil and every OTHER error (connection refused,
// no such bucket, auth, throttle, …) passes through unchanged so the consumer fails
// CLOSED with 502. This keeps apps/team/files.go's honest
// 404-vs-idempotent-204-vs-502 split intact — a missing blob never masquerades as an
// outage and an outage never masquerades as 404.
func missing(err error) error {
	if NoKey(err) {
		return ErrBlobNotFound
	}
	return err
}
