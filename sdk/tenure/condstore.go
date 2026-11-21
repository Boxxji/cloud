// Copyright 2025 Hanzo AI Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package tenure

// condstore.go is the concrete atomic-CAS object store the fence needs: the object
// store's native optimistic locking (sdk/object Put.IfMatch / IfAbsent), which the
// SERVER evaluates atomically. It satisfies github.com/hanzoai/vfs/replica.ConditionalStore,
// the client FencedStore (per-org DB ship) and CASFencer (per-org lease) compose over.
//
// WHY the object store directly and not vfs's block layer: the vfs content-addressable
// backend exposes NO conditional-write primitive — "overwriting is allowed" is its
// contract — so the fence, which is a CONDITIONAL write, cannot ride that path. It
// addresses a dedicated object per shard directly against the store.
//
// A fence is only as strong as the store's atomicity, and local disk is atomic within
// one process only; the deployment builds this over a SHARED store (the S3 driver)
// and proves it atomic first (ProbeCAS).
//
//	cs := NewConditional(object.Default(), orgBucket)
//	dbFence := replica.NewFencedStore(cs)      // per-org DB fenced ship
//	fencer  := NewCASFencer(cs, membership)    // per-org monotone lease round

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/hanzoai/cloud/sdk/object"
	"github.com/hanzoai/vfs/replica"
)

// Conditional is a replica.ConditionalStore over one bucket of an object store.
type Conditional struct {
	Store  object.Store
	Bucket string
}

// NewConditional builds a ConditionalStore over a store and bucket. The caller owns
// the store's lifecycle (credentials, TLS, endpoint) — this type adds only the
// conditional-write semantics.
func NewConditional(store object.Store, bucket string) *Conditional {
	return &Conditional{Store: store, Bucket: bucket}
}

// Get returns the object bytes and its ETag from ONE read, so the version is
// guaranteed consistent with the bytes. Absent key maps to replica.ErrNotFound.
func (s *Conditional) Get(ctx context.Context, key string) ([]byte, string, error) {
	body, err := s.Store.Open(ctx, s.Bucket, key, object.Get{})
	if err != nil {
		if object.NoKey(err) {
			return nil, "", replica.ErrNotFound
		}
		return nil, "", fmt.Errorf("condstore: get %s/%s: %w", s.Bucket, key, err)
	}
	defer body.Close()
	data, err := io.ReadAll(body)
	if err != nil {
		return nil, "", fmt.Errorf("condstore: read %s/%s: %w", s.Bucket, key, err)
	}
	return data, body.Info.ETag, nil
}

// PutIfVersion writes data at key iff the store's current ETag still equals
// expectVersion, or iff the object does not exist when expectVersion is "". A refused
// write — a failed precondition, or a concurrent conditional write — is mapped to
// replica.ErrConflict.
func (s *Conditional) PutIfVersion(ctx context.Context, key string, data []byte, expectVersion string) (string, error) {
	o := object.Put{ContentType: "application/octet-stream"}
	if expectVersion == "" {
		o.IfAbsent = true // object must not exist yet.
	} else {
		o.IfMatch = expectVersion
	}
	info, err := s.Store.Put(ctx, s.Bucket, key, bytes.NewReader(data), int64(len(data)), o)
	if err != nil {
		if object.Conflict(err) {
			return "", fmt.Errorf("condstore: %w: %v", replica.ErrConflict, err)
		}
		return "", fmt.Errorf("condstore: put %s/%s: %w", s.Bucket, key, err)
	}
	return info.ETag, nil
}

// List is every key under prefix, in key order (Lister).
func (s *Conditional) List(ctx context.Context, prefix string) ([]string, error) {
	var keys []string
	for obj, err := range s.Store.List(ctx, s.Bucket, object.List{Prefix: prefix}) {
		if err != nil {
			return nil, fmt.Errorf("condstore: list %s/%s: %w", s.Bucket, prefix, err)
		}
		keys = append(keys, obj.Key)
	}
	return keys, nil
}

var (
	_ replica.ConditionalStore = (*Conditional)(nil)
	_ Lister                   = (*Conditional)(nil)
)
