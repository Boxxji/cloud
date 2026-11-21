package coord

import (
	"context"
	"time"
)

// A span is a window the first call opens: it runs from that call's instant for its
// length, and the first call after it ends opens the next. A calendar window names
// its own period ("2026-10-03"), so nothing about it has to be kept; a span's period
// is its start, which only the call that opened it knew, so the start is kept, one
// per key.
//
// THE INSTANT IS THE CALLER'S. Each call states its own now and the KV keeps only
// the start, in whole seconds, so what a span is at a moment is decided the same way
// on every pod and in a test that moves its clock. The record outlives the span's end
// by SpanKeep, so a pod whose clock runs behind still finds it.
//
// A span runs at now while now is before its start plus its length. A start later
// than now — a pod whose clock runs ahead opened it — is running, never replaced, so
// two pods never hold two spans under one key.

// SpanKeep is how long a span's record outlives the span.
const SpanKeep = time.Hour

// Span answers the start of the span running under key at now, opening one that
// starts at now when none runs. It is one step on the KV, so calls that arrive
// together answer the one span the first of them opened. A KV that cannot be asked
// answers this process's span.
func (c *Coord) Span(ctx context.Context, name, key string, now time.Time, length time.Duration) time.Time {
	return c.span(ctx, name, key, now, length, true)
}

// Spanned answers the start of the span running under key at now without opening
// one: zero when none runs.
func (c *Coord) Spanned(ctx context.Context, name, key string, now time.Time, length time.Duration) time.Time {
	return c.span(ctx, name, key, now, length, false)
}

func (c *Coord) span(ctx context.Context, name, key string, now time.Time, length time.Duration, open bool) time.Time {
	full := c.Key("span:"+name, key)
	secs := int64(length / time.Second)
	start, err := c.b.Span(ctx, full, now.Unix(), secs, open)
	if err != nil {
		c.log.warn("span", "coord: the shared span is not answering; reading this process's", "span", name, "err", err)
		start, _ = c.local.Span(ctx, full, now.Unix(), secs, open)
	}
	if start == 0 {
		return time.Time{}
	}
	return time.Unix(start, 0).UTC()
}

// spanned is one span's record in this process: its start, unix seconds, and when
// the record goes.
type spanned struct {
	start int64
	until time.Time
}

// span is Span's record in this process. Records past their keep are swept at most
// once a minute, as quota's are.
func (b *mem) Span(_ context.Context, key string, now, length int64, open bool) (int64, error) {
	at := time.Now()
	b.mu.Lock()
	defer b.mu.Unlock()
	if s, ok := b.spans[key]; ok && at.Before(s.until) && now < s.start+length {
		return s.start, nil
	}
	if !open {
		return 0, nil
	}
	if at.Sub(b.spanSwept) >= time.Minute {
		b.spanSwept = at
		for k, s := range b.spans {
			if !at.Before(s.until) {
				delete(b.spans, k)
			}
		}
	}
	b.spans[key] = spanned{start: now, until: at.Add(time.Duration(length)*time.Second + SpanKeep)}
	return now, nil
}
