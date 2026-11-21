package activation

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// recorder installs a span recorder as the global provider for one test.
func recorder(t *testing.T) *tracetest.SpanRecorder {
	t.Helper()
	sr := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr))
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	t.Cleanup(func() { otel.SetTracerProvider(prev); _ = tp.Shutdown(context.Background()) })
	return sr
}

func attrs(s sdktrace.ReadOnlySpan) map[string]string {
	out := map[string]string{}
	for _, kv := range s.Attributes() {
		out[string(kv.Key)] = kv.Value.Emit()
	}
	return out
}

// An activation is one span from where the session was asked for to where it was
// ready, labelled with how it was made ready, scoped to its org — and it carries
// nothing a reader of model calls selects on, so it is never counted as one.
func TestAnActivationIsOneSpanLabelledByKind(t *testing.T) {
	sr := recorder(t)
	for _, k := range Kinds() {
		c := Start()
		time.Sleep(5 * time.Millisecond)
		c.Is(k, k != Cold)
		if !c.End(context.Background(), "sandbox", "acme", nil) {
			t.Fatalf("%s: a decided activation recorded nothing", k)
		}
	}
	ended := sr.Ended()
	if len(ended) != len(Kinds()) {
		t.Fatalf("spans = %d, want %d", len(ended), len(Kinds()))
	}
	for i, k := range Kinds() {
		s := ended[i]
		if s.Name() != Span {
			t.Errorf("span %d is named %q, want %q", i, s.Name(), Span)
		}
		if d := s.EndTime().Sub(s.StartTime()); d < 5*time.Millisecond {
			t.Errorf("%s lasted %v: the span must start where the clock did", k, d)
		}
		a := attrs(s)
		want := map[string]string{AttrKind: string(k), AttrSurface: "sandbox", attrOrg: "acme", AttrResumed: map[bool]string{true: "true", false: "false"}[k != Cold]}
		for key, v := range want {
			if a[key] != v {
				t.Errorf("%s: %s = %q, want %q", k, key, a[key], v)
			}
		}
		for key := range a {
			if strings.HasPrefix(key, "gen_ai.") {
				t.Errorf("%s carries %s: a reader of model calls would count it as one", k, key)
			}
		}
		if s.Status().Code == codes.Error {
			t.Errorf("%s: a successful activation is marked an error", k)
		}
	}
}

// A request refused before any compute was looked at never said what it was, and
// records nothing; nor does one that found it was somebody else's after all.
func TestAnUndecidedActivationRecordsNothing(t *testing.T) {
	sr := recorder(t)
	if Start().End(context.Background(), "sandbox", "acme", errors.New("payment required")) {
		t.Fatal("an activation that was never decided reported a span")
	}
	c := Start()
	c.Is(Relocated, true)
	c.Is("", false) // another call is relocating it
	if c.End(context.Background(), "sandbox", "acme", nil) {
		t.Fatal("an activation taken back reported a span")
	}
	var nilClock *Clock
	if nilClock.End(context.Background(), "sandbox", "acme", nil) || nilClock.Kind() != "" {
		t.Fatal("a nil clock is a no-op")
	}
	if n := len(sr.Ended()); n != 0 {
		t.Fatalf("%d spans recorded, want none", n)
	}
}

// An activation that was attempted and failed is recorded as a failure, so a
// reader can count it and keep it out of the latency.
func TestAFailedActivationIsAnError(t *testing.T) {
	sr := recorder(t)
	c := Start()
	c.Is(Cold, true)
	c.End(context.Background(), "sandbox", "acme", errors.New("pod did not start"))
	ended := sr.Ended()
	if len(ended) != 1 || ended[0].Status().Code != codes.Error {
		t.Fatalf("a failed activation: %d spans, want one with an error status", len(ended))
	}
}
