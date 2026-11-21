package meter

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A product on this middleware refuses as the zip-native gates do: the page that
// clears the refusal on the caller's own brand, in the sentence and as billingUrl.
// It said "Please add credits at console.hanzo.ai" on every brand's host.
func TestTheDefaultDenialNamesTheCallersPage(t *testing.T) {
	for _, tc := range []struct {
		host string
		err  error
		code string
		page string
	}{
		{"api.hanzo.ai", ErrInsufficientBalance, "insufficient_balance", "https://hanzo.ai/pay/amount/card"},
		{"api.hanzo.ai", ErrSpendCapExceeded, "spend_cap_exceeded", "https://platform.hanzo.ai/billing/budgets"},
		{"api.lux.cloud", ErrInsufficientBalance, "insufficient_balance", "https://console.lux.cloud/billing/credits"},
		{"api.pars.network", ErrInsufficientBalance, "insufficient_balance", ""},
	} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/v1/thing", nil)
		r.Host = tc.host
		defaultOnDenied(w, r, tc.err)
		if w.Code != http.StatusPaymentRequired {
			t.Fatalf("%s %s: status %d, want 402", tc.host, tc.code, w.Code)
		}
		var body struct {
			Error struct {
				Message, Type, Code string
				BillingURL          string `json:"billingUrl"`
			} `json:"error"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("%s: decode %s: %v", tc.host, w.Body, err)
		}
		e := body.Error
		if e.Code != tc.code || e.Type != "billing_error" || e.BillingURL != tc.page {
			t.Errorf("%s %s: %s", tc.host, tc.code, w.Body)
		}
		if tc.page != "" && e.Message[len(e.Message)-len(tc.page):] != tc.page {
			t.Errorf("%s: message %q does not end with %q", tc.host, e.Message, tc.page)
		}
		if tc.page == "" && e.Message != "Insufficient balance. Add credits" {
			t.Errorf("%s: message %q names a page the brand does not serve", tc.host, e.Message)
		}
	}
}
