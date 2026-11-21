package cloud

// The two halves of a delegation a holder needs to renew one (delegation.go): the life IAM
// granted, from when it was asked, and a refusal that says whether it is about the person.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

// delegationIAM answers a token exchange with a confined token of the life it is told to, or a refusal.
type delegationIAM struct {
	mu     sync.Mutex
	asked  []url.Values
	status int
	code   string
	life   int
}

func (d *delegationIAM) serve(t *testing.T) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		d.mu.Lock()
		d.asked = append(d.asked, r.PostForm)
		status, code, life := d.status, d.code, d.life
		d.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if status != 0 {
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": "IAM's own words"})
			return
		}
		payload, _ := json.Marshal(map[string]string{"scope": inferenceScope})
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "eyJhbGciOiJSUzI1NiJ9." + base64.RawURLEncoding.EncodeToString(payload) + ".SIG",
			"expires_in":   life, "scope": inferenceScope,
		})
	}))
	t.Cleanup(srv.Close)
	t.Setenv("IAM_URL", srv.URL)
	t.Setenv("IAM_CLIENT_ID", "hanzo-cloud")
	t.Setenv("IAM_CLIENT_SECRET", "cloud-secret")
}

func machineFor() oauth2.TokenSource {
	return oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "machine"})
}

// Delegate answers the token and the life IAM granted it for, which is what a holder arms its
// renewal by: the granted life, not the one asked for, so IAM granting a few seconds under what was
// asked shortens the renewal's timer with it.
func TestDelegateAnswersTheLifeIAMGranted(t *testing.T) {
	iam := &delegationIAM{life: 1795}
	iam.serve(t)
	got, err := Delegate(context.Background(), machineFor(), Delegation{
		Subject: "alice", Org: "acme", Until: time.Now().Add(30 * time.Minute), Run: "sess_1"})
	if err != nil {
		t.Fatalf("Delegate: %v", err)
	}
	if got.Token == "" || got.Life != 1795*time.Second {
		t.Fatalf("Delegate answered %+v, want the token and the 1795s IAM granted", got)
	}
	if asked := iam.asked[0].Get("lifetime"); asked != "1800" && asked != "1801" {
		t.Fatalf("IAM was asked for a lifetime of %q, want the half hour the holder named", asked)
	}
	// Asking again is the renewal: IAM is asked about the person again, each time.
	if _, err := Delegate(context.Background(), machineFor(), Delegation{Subject: "alice", Org: "acme", Until: time.Now().Add(30 * time.Minute)}); err != nil {
		t.Fatalf("Delegate again: %v", err)
	}
	if len(iam.asked) != 2 || iam.asked[1].Get("requested_subject") != "alice" || iam.asked[1].Get("org") != "acme" {
		t.Fatalf("IAM was asked %v, want the person and the org named afresh each time", iam.asked)
	}
}

// IAM's refusal is the caller's error as itself: its status and words, and whether it is about the
// person. Only access_denied is — a client credential it does not know, a scope or an audience it
// will not delegate, an actor token it does not take, a limit and an outage are all this deployment's
// own standing, and a person who has lost nothing is not told they have.
//
// MUTATION: read any 4xx as the person's loss and a rotated client secret ends every run as "access removed".
func TestAnIAMRefusalSaysWhetherItIsAboutThePerson(t *testing.T) {
	for name, c := range map[string]struct {
		status int
		code   string
		denied bool
	}{
		"not a member":       {http.StatusForbidden, "access_denied", true},
		"not a delegator":    {http.StatusForbidden, "unauthorized_client", false},
		"unknown client":     {http.StatusUnauthorized, "invalid_client", false},
		"actor proof":        {http.StatusBadRequest, "invalid_grant", false},
		"scope":              {http.StatusBadRequest, "invalid_scope", false},
		"audience":           {http.StatusBadRequest, "invalid_target", false},
		"unavailable":        {http.StatusServiceUnavailable, "temporarily_unavailable", false},
		"rate limited":       {http.StatusTooManyRequests, "access_denied", false},
		"the server's fault": {http.StatusInternalServerError, "server_error", false},
	} {
		t.Run(name, func(t *testing.T) {
			iam := &delegationIAM{status: c.status, code: c.code}
			iam.serve(t)
			_, err := Delegate(context.Background(), machineFor(), Delegation{Subject: "alice", Org: "acme", Until: time.Now().Add(time.Hour)})
			var refused *Refused
			if !errors.As(err, &refused) {
				t.Fatalf("Delegate answered %v, want IAM's refusal as itself", err)
			}
			if refused.Status != c.status || refused.Code != c.code || refused.Why != "IAM's own words" {
				t.Fatalf("the refusal is %+v, want IAM's status, code and words", refused)
			}
			if refused.Denied() != c.denied {
				t.Fatalf("%d %s: Denied = %v, want %v", c.status, c.code, refused.Denied(), c.denied)
			}
			if want := "delegate: IAM refused ("; !strings.HasPrefix(err.Error(), want) {
				t.Fatalf("the error reads %q, want it to say what IAM refused", err)
			}
		})
	}
}
