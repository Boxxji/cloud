package cloud

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hanzoai/cloud/sdk/iam"
)

// happens waits for cond.
func happens(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("never happened: %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Delegate is bounded by the caller's context for the token it presents too: against the real source
// and a token endpoint that hangs it gives up when the caller's context does, not when the endpoint's
// thirty seconds do.
//
// MUTATION: read the token with actor.Token() and Delegate waits out the endpoint.
func TestDelegateGivesUpOnAHungTokenEndpointWhenItsCallerDoes(t *testing.T) {
	release := make(chan struct{})
	var hung atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.PostForm.Get("grant_type") == "client_credentials" {
			hung.Add(1)
			select {
			case <-release:
			case <-r.Context().Done():
			}
		}
		http.Error(w, "no", http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) })
	t.Setenv("IAM_URL", srv.URL)
	t.Setenv("IAM_CLIENT_ID", "hanzo-cloud")
	t.Setenv("IAM_CLIENT_SECRET", "cloud-secret")
	actor := iam.Machine()
	if actor == nil {
		t.Fatal("no machine identity")
	}
	d := Delegation{Subject: "alice", Org: "acme", Until: time.Now().Add(time.Hour)}
	var wg sync.WaitGroup
	took := make([]time.Duration, 3)
	for i := range took {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
			defer cancel()
			start := time.Now()
			_, err := Delegate(ctx, actor, d)
			took[i] = time.Since(start)
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("caller %d: %v, want its own deadline", i, err)
			}
		}()
	}
	wg.Wait()
	for i, d := range took {
		if d > 3*time.Second {
			t.Fatalf("caller %d waited %v on a hung token endpoint", i, d)
		}
	}
	happens(t, "the token endpoint was asked", func() bool { return hung.Load() >= 1 })
	if n := hung.Load(); n != 1 {
		t.Fatalf("the token endpoint was asked %d times by three callers, want one refresh among them", n)
	}
}
