package coord

import (
	"context"
	"testing"
	"time"
)

// spanAt is a moment the span tests start from.
var spanAt = time.Date(2026, 11, 2, 22, 40, 0, 0, time.UTC)

// A SPAN OPENS AT THE FIRST CALL AND RUNS ITS LENGTH. A read opens nothing; the call
// that finds none opens one at its own instant; every call before the end answers
// that start; the first call at or after the end opens the next, at its own instant.
func TestASpanRunsFromTheCallThatOpenedIt(t *testing.T) {
	spans(t, Alone(), Alone())
}

// spans runs the span's contract on a and b, which share one span when they share a
// KV and are a's alone when they do not.
func spans(t *testing.T, a, b *Coord) {
	t.Helper()
	ctx := context.Background()
	const length = 5 * time.Hour
	if got := a.Spanned(ctx, "t", "s:u", spanAt, length); !got.IsZero() {
		t.Fatalf("a span runs before any call: %v", got)
	}
	if got := a.Spanned(ctx, "t", "s:u", spanAt, length); !got.IsZero() {
		t.Fatalf("a read opened a span at %v", got)
	}
	if got := a.Span(ctx, "t", "s:u", spanAt, length); !got.Equal(spanAt) {
		t.Fatalf("the first call opened %v, want its own instant %v", got, spanAt)
	}
	later := spanAt.Add(length - time.Second)
	if got := a.Span(ctx, "t", "s:u", later, length); !got.Equal(spanAt) {
		t.Fatalf("a call a second before the end answered %v, want the running span %v", got, spanAt)
	}
	if got := a.Spanned(ctx, "t", "s:u", spanAt.Add(-time.Minute), length); !got.Equal(spanAt) {
		t.Fatalf("a clock a minute behind read %v, want the running span", got)
	}
	if got := a.Spanned(ctx, "t", "s:other", later, length); !got.IsZero() {
		t.Fatalf("another key reads %v", got)
	}
	end := spanAt.Add(length)
	if got := a.Spanned(ctx, "t", "s:u", end, length); !got.IsZero() {
		t.Fatalf("at its end the span still runs: %v", got)
	}
	next := end.Add(17 * time.Minute)
	if got := a.Span(ctx, "t", "s:u", next, length); !got.Equal(next) {
		t.Fatalf("the first call after the end opened %v, want its own instant %v", got, next)
	}
	if a.Shared() {
		if got := b.Spanned(ctx, "t", "s:u", next.Add(time.Hour), length); !got.Equal(next) {
			t.Fatalf("the other pod reads %v, want the span this one opened at %v", got, next)
		}
	}
}

// A KV THAT CANNOT ANSWER keeps the span in this process.
func TestAnUnansweringKVKeepsTheSpanHere(t *testing.T) {
	c := over(down{ErrUnavailable}, newMem(), true, Config{Periods: fast, Self: Member{ID: "x"}, Secret: secret, Declared: 2})
	ctx := context.Background()
	if got := c.Span(ctx, "t", "s:u", spanAt, time.Hour); !got.Equal(spanAt) {
		t.Fatalf("opened %v, want %v", got, spanAt)
	}
	if got := c.Spanned(ctx, "t", "s:u", spanAt.Add(time.Minute), time.Hour); !got.Equal(spanAt) {
		t.Fatalf("read %v, want the span this process opened", got)
	}
}
