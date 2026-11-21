package infer

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func spanRecorder(t *testing.T) *tracetest.SpanRecorder {
	t.Helper()
	sr := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr))
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	t.Cleanup(func() { otel.SetTracerProvider(prev); _ = tp.Shutdown(context.Background()) })
	return sr
}

func spanAttr(s sdktrace.ReadOnlySpan, key string) (string, bool) {
	for _, kv := range s.Attributes() {
		if string(kv.Key) == key {
			return kv.Value.Emit(), true
		}
	}
	return "", false
}

// A streamed completion's gen_ai span says how long the model took to its first
// token, counted from the call and from the first CONTENT: a role-only opening
// frame sent at once is the connection answering, not the model, and does not
// stop the clock.
func TestAStreamedCompletionCarriesItsTimeToFirstToken(t *testing.T) {
	sr := spanRecorder(t)
	const think = 60 * time.Millisecond
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		f := w.(http.Flusher)
		fmt.Fprint(w, "data: {\"model\":\"zen5-flash\",\"choices\":[{\"delta\":{\"role\":\"assistant\"}}]}\n\n")
		f.Flush()
		time.Sleep(think)
		for range 3 {
			fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"content\":\"tok \"}}]}\n\n")
			f.Flush()
			time.Sleep(10 * time.Millisecond)
		}
		fmt.Fprint(w, "data: [DONE]\n\n")
		f.Flush()
	}))
	defer srv.Close()

	ai := HTTPAt(srv.URL, "sk-test", FixedModel("zen5-flash"))
	s, ok := ai.(StreamCompleter)
	if !ok {
		t.Fatal("the HTTP client does not stream")
	}
	if _, err := s.ChatStream(context.Background(), &ChatRequest{Prompt: "hi", Org: "acme"}, func(string) error { return nil }); err != nil {
		t.Fatalf("ChatStream: %v", err)
	}
	ended := sr.Ended()
	if len(ended) != 1 {
		t.Fatalf("gen_ai spans = %d, want 1", len(ended))
	}
	raw, ok := spanAttr(ended[0], AttrTTFT)
	if !ok {
		t.Fatalf("the streamed completion's span carries no %s", AttrTTFT)
	}
	ms, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		t.Fatalf("%s = %q: %v", AttrTTFT, raw, err)
	}
	if ms < float64(think/time.Millisecond) {
		t.Errorf("%s = %.1fms: the role-only frame stopped the clock before the model said anything (want >= %v)", AttrTTFT, ms, think)
	}
	total := float64(ended[0].EndTime().Sub(ended[0].StartTime())) / float64(time.Millisecond)
	if ms >= total {
		t.Errorf("%s = %.1fms is not inside its own call (%.1fms): it must not count the tokens after the first", AttrTTFT, ms, total)
	}
}

// A completion that is not streamed has no first token to see, so it carries no
// time to first token at all — never its whole duration under that name.
func TestABufferedCompletionCarriesNoTimeToFirstToken(t *testing.T) {
	sr := spanRecorder(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": "chatcmpl-x", "object": "chat.completion", "created": 1, "model": "zen5-flash",
			"choices": []map[string]any{{
				"index": 0, "message": map[string]string{"role": "assistant", "content": "hola"}, "finish_reason": "stop",
			}},
		})
	}))
	defer srv.Close()
	ai := HTTPAt(srv.URL, "sk-test", FixedModel("zen5-flash"))
	if _, err := ai.ChatCompletion(context.Background(), &ChatRequest{Prompt: "hi", Org: "acme"}); err != nil {
		t.Fatalf("ChatCompletion: %v", err)
	}
	ended := sr.Ended()
	if len(ended) != 1 {
		t.Fatalf("gen_ai spans = %d, want 1", len(ended))
	}
	if v, ok := spanAttr(ended[0], AttrTTFT); ok {
		t.Fatalf("a buffered completion carries %s = %s", AttrTTFT, v)
	}
}
