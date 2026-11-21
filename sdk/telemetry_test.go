// Copyright 2023-2026 Hanzo AI Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cloud

import (
	"context"
	"sync"
	"testing"
	"time"

	luxlog "github.com/luxfi/log"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

func testLogger() luxlog.Logger { return luxlog.New("cloud-test") }

// captureSink records the span names handed to a co-resident sink.
type captureSink struct {
	mu    sync.Mutex
	names []string
}

func (c *captureSink) sink(_ context.Context, spans []sdktrace.ReadOnlySpan) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, s := range spans {
		c.names = append(c.names, s.Name())
	}
	return nil
}

func (c *captureSink) got() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.names...)
}

// fakeWire is a stand-in SpanExporter for the wire fallback, so routing is
// exercised without a socket.
type fakeWire struct {
	mu sync.Mutex
	n  int
}

func (f *fakeWire) ExportSpans(context.Context, []sdktrace.ReadOnlySpan) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	return nil
}

func (f *fakeWire) Shutdown(context.Context) error { return nil }

func (f *fakeWire) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.n
}

// makeSpans produces one finished ReadOnlySpan, with no dependency on the
// exporter under test.
func makeSpans(t *testing.T) []sdktrace.ReadOnlySpan {
	t.Helper()
	rec := &recorder{}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithSyncer(rec),
	)
	_, span := tp.Tracer("t").Start(context.Background(), "unit")
	span.End()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = tp.Shutdown(ctx)
	if len(rec.spans) == 0 {
		t.Fatal("no span recorded")
	}
	return rec.spans
}

type recorder struct{ spans []sdktrace.ReadOnlySpan }

func (r *recorder) ExportSpans(_ context.Context, s []sdktrace.ReadOnlySpan) error {
	r.spans = append(r.spans, s...)
	return nil
}

func (r *recorder) Shutdown(context.Context) error { return nil }
