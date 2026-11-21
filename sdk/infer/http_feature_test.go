package infer

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// TestGenAISpanCarriesTheFeature: a completion a product surface asks for names
// that surface on its gen_ai span (hanzo.feature), beside the org it was for, and
// one no surface claims carries no such attribute at all — never an empty one.
func TestGenAISpanCarriesTheFeature(t *testing.T) {
	sr := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr))
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	t.Cleanup(func() { otel.SetTracerProvider(prev); _ = tp.Shutdown(context.Background()) })

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

	for _, feature := range []string{"translate", ""} {
		if _, err := ai.ChatCompletion(context.Background(), &ChatRequest{Prompt: "hi", Org: "acme", Feature: feature}); err != nil {
			t.Fatalf("ChatCompletion: %v", err)
		}
	}
	ended := sr.Ended()
	if len(ended) != 2 {
		t.Fatalf("gen_ai spans = %d, want 2", len(ended))
	}
	for n, want := range []string{"translate", ""} {
		got, set := "", false
		for _, kv := range ended[n].Attributes() {
			if kv.Key == "hanzo.feature" {
				got, set = kv.Value.AsString(), true
			}
		}
		if got != want || set != (want != "") {
			t.Errorf("span %d hanzo.feature = %q (set %v), want %q", n, got, set, want)
		}
	}
}
