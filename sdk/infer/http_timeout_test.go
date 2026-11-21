package infer

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A completion client must carry NO wall-clock Timeout.
//
// http.Client.Timeout covers the whole exchange including the body read, so on
// a streamed completion it is a limit on how much the model may say: the
// request dies mid-sentence and the tokens already paid for are discarded. The
// bound belongs on the caller's context, where something knows what is being
// waited for. This is a silent regression — a Timeout put back here would pass
// every other test in the tree — so it is asserted directly.
func TestCompletionClientHasNoWallClock(t *testing.T) {
	c := HTTPOn("https://api.hanzo.ai/v1", "k", nil, nil).(*httpAI)
	if c.http.Timeout != 0 {
		t.Fatalf("the completion client has Timeout %v; it caps streamed output", c.http.Timeout)
	}
}

// And the backstop has to sit clear of the work, or it becomes the deadline
// that fires — reporting a transport failure about a completion that was still
// arriving. A local model can take two minutes to its FIRST token.
func TestBackstopClearsLocalFirstToken(t *testing.T) {
	if aiHTTPTimeout < 4*time.Minute {
		t.Errorf("aiHTTPTimeout is %v; local TTFT reaches ~2m and generation follows it", aiHTTPTimeout)
	}
	// A token fetch is a different question and must not inherit that patience.
	if tokenTimeout >= aiHTTPTimeout {
		t.Errorf("tokenTimeout %v is not tighter than the completion backstop %v", tokenTimeout, aiHTTPTimeout)
	}
}

// compile-time proof the field under test is the one the client actually uses.
var _ = (&http.Client{}).Timeout

// The M2M client bounds its token fetch and nothing else. oauth2's Config.Client
// copies the minting client's Timeout onto the client it returns, so every M2M
// completion and stream — /v1/ask's answer among them — was cut at tokenTimeout
// while the model kept generating.
func TestAnM2MStreamOutlivesTheTokenTimeout(t *testing.T) {
	was := tokenTimeout
	tokenTimeout = 200 * time.Millisecond
	t.Cleanup(func() { tokenTimeout = was })
	idleGap(t, 300*time.Millisecond)
	iam := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token":"t","token_type":"Bearer","expires_in":3600}`)
	}))
	t.Cleanup(iam.Close)
	for _, rt := range []http.RoundTripper{nil, http.DefaultTransport} {
		url, _ := streaming(t, 20, 40*time.Millisecond) // 800ms, four token timeouts long
		ai := HTTPM2MOn(url, iam.URL, "id", "secret", FixedModel("m"), rt).(*httpAI)
		if ai.http.Timeout != 0 {
			t.Fatalf("the M2M client has Timeout %v; it caps streamed output", ai.http.Timeout)
		}
		resp, err := ai.ChatStream(context.Background(), &ChatRequest{Prompt: "q"}, func(string) error { return nil })
		if err != nil {
			t.Fatal(err)
		}
		if n := strings.Count(resp.Content, "tok"); n != 20 {
			t.Fatalf("an M2M stream was cut at %d of 20 tokens", n)
		}
	}
}
