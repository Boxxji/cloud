// Copyright 2025 Hanzo AI Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cloud

// durable_proven_test.go holds provenStore to its caching rule: a verdict about
// the store (atomic, or proven non-atomic) is kept for the process life; a probe
// the store did not answer is kept only until the retry interval passes.

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hanzoai/vfs/replica"
)

// unreachableStore answers every call with a deadline while down is set, and
// otherwise delegates to a faithful in-memory CAS store. calls counts every call
// that reached it, so a cached answer is distinguishable from a fresh probe.
type unreachableStore struct {
	inner replica.ConditionalStore
	down  atomic.Bool
	calls atomic.Int64
}

func (s *unreachableStore) Get(ctx context.Context, key string) ([]byte, string, error) {
	s.calls.Add(1)
	if s.down.Load() {
		return nil, "", fmt.Errorf("get %s: %w", key, context.DeadlineExceeded)
	}
	return s.inner.Get(ctx, key)
}

func (s *unreachableStore) PutIfVersion(ctx context.Context, key string, data []byte, expect string) (string, error) {
	s.calls.Add(1)
	if s.down.Load() {
		return "", fmt.Errorf("put %s: %w", key, context.DeadlineExceeded)
	}
	return s.inner.PutIfVersion(ctx, key, data, expect)
}

// lastWriteWins admits every put regardless of its precondition — the store the
// probe exists to refuse.
type lastWriteWins struct {
	mu   sync.Mutex
	seq  int
	objs map[string]string
}

func (s *lastWriteWins) Get(_ context.Context, key string) ([]byte, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.objs[key]
	if !ok {
		return nil, "", fmt.Errorf("get %s: %w", key, replica.ErrNotFound)
	}
	return []byte("x"), v, nil
}

func (s *lastWriteWins) PutIfVersion(_ context.Context, key string, _ []byte, _ string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	v := fmt.Sprintf("v%d", s.seq)
	s.objs[key] = v
	return v, nil
}

// clock is a settable time source for provenStore.now.
type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func (c *clock) add(d time.Duration) { c.t = c.t.Add(d) }
