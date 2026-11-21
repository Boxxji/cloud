// Copyright © 2026 Hanzo AI. MIT License.

package infer

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hanzoai/cloud/sdk/supply"
)

// A provider budget stop is its own class on the in-process path too: typed as a
// supply stop on the model_provider layer, NEVER tagged busy (a retry on the same
// model cannot help until somebody raises the cap or tops up the account), and it
// moves the route on, since another model may be served from another account.
func TestAProviderBudgetStopIsTypedNotBusy(t *testing.T) {
	for _, c := range []struct {
		name   string
		status int
		body   string
	}{
		// The model API's own class, as the fleet renders it (an RFC 9457 problem).
		{"the class itself", http.StatusServiceUnavailable, `{"status":503,"code":"budget_exhausted","error":"the model provider budget is exhausted","layer":"model_provider"}`},
		// The class in an OpenAI-compatible error body.
		{"the class, openai shape", http.StatusServiceUnavailable, `{"error":{"message":"budget exhausted","type":"budget_exhausted","code":"budget_exhausted"}}`},
		// A vendor out of quota says so with a 429 its rate limit also uses.
		{"insufficient quota", http.StatusTooManyRequests, `{"error":{"message":"You exceeded your current quota, please check your plan and billing details.","type":"insufficient_quota","code":"insufficient_quota"}}`},
		// A vendor out of credit says so with a 400.
		{"credit balance too low", http.StatusBadRequest, `{"error":{"type":"invalid_request_error","message":"Your credit balance is too low to access the API. Please go to Plans & Billing to upgrade or purchase credits."}}`},
	} {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(c.status)
				_, _ = w.Write([]byte(c.body))
			}))
			defer srv.Close()
			_, err := HTTPAt(srv.URL, "sk-test", FixedModel("zen-test")).
				ChatCompletion(context.Background(), &ChatRequest{Prompt: "x"})
			if err == nil {
				t.Fatal("expected an error")
			}
			ex, ok := supply.As(err)
			if !ok {
				t.Fatalf("err = %v, want a supply stop in its chain", err)
			}
			if ex.Layer != supply.Model || ex.Upstream != c.status {
				t.Fatalf("stop = %+v, want layer model_provider, upstream %d", ex, c.status)
			}
			if errors.Is(err, ErrUpstreamBusy) {
				t.Fatalf("a budget stop was tagged busy: %v", err)
			}
			if !routeOn(err) {
				t.Fatalf("routeOn(%v) = false, want the route to move on", err)
			}
		})
	}
}

// What is not a provider's budget keeps its old reading: the caller's OWN money is
// insufficient_balance (402, the caller's to fix), a rate limit stays busy.
func TestNotEveryRefusalIsABudgetStop(t *testing.T) {
	for _, c := range []struct {
		name   string
		status int
		body   string
		busy   bool
	}{
		{"caller out of funds", http.StatusPaymentRequired, `{"error":{"message":"Insufficient balance","type":"billing_error","code":"insufficient_balance"}}`, false},
		{"caller spend cap", http.StatusPaymentRequired, `{"error":{"message":"Spend cap reached","type":"billing_error","code":"spend_cap_exceeded"}}`, false},
		{"rate limited", http.StatusTooManyRequests, `{"error":{"message":"rate limited","type":"rate_limit_error"}}`, true},
		{"overloaded", http.StatusServiceUnavailable, `{"error":{"message":"overloaded"}}`, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(c.status)
				_, _ = w.Write([]byte(c.body))
			}))
			defer srv.Close()
			_, err := HTTPAt(srv.URL, "sk-test", FixedModel("zen-test")).
				ChatCompletion(context.Background(), &ChatRequest{Prompt: "x"})
			if err == nil {
				t.Fatal("expected an error")
			}
			if _, ok := supply.As(err); ok {
				t.Fatalf("%s read as a provider budget stop: %v", c.name, err)
			}
			if got := errors.Is(err, ErrUpstreamBusy); got != c.busy {
				t.Fatalf("busy = %v, want %v (err %v)", got, c.busy, err)
			}
		})
	}
}
