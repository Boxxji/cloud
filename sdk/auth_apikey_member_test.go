package cloud

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// A member's key acts in the org it was minted in. The keyed, bearer-less ingest
// and flag paths attribute a key through OrgForKey, whose contract is "the SAME
// owner org SanitizeIdentity mints when that key arrives as a bearer". For a
// member's key that org is the key's (client), not the holder's home (agency).
func TestOrgForKey_AMemberKeyAttributesToTheKeysOrg(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","data":{"owner":"agency","name":"josh","org":"client","billing_account":"org:client"}}`))
	}))
	defer srv.Close()
	sharedKeysOnce = sync.Once{}
	t.Setenv("IAM_URL", srv.URL)
	t.Setenv("IAM_MINT_CLIENT_ID", "hanzo-console")
	t.Setenv("IAM_MINT_CLIENT_SECRET", "s3cr3t")
	sharedKeysInst = nil
	t.Cleanup(func() { sharedKeysOnce = sync.Once{}; sharedKeysInst = nil })

	org, ok := OrgForKey(context.Background(), "sk-live-member")
	if !ok || org != "client" {
		t.Fatalf("a member's key minted in client was attributed to (%q,%v); want client", org, ok)
	}
}

// A home key still attributes to its holder's own org.
func TestOrgForKey_AHomeKeyAttributesToItsHoldersOrg(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","data":{"owner":"agency","name":"josh"}}`))
	}))
	defer srv.Close()
	sharedKeysOnce = sync.Once{}
	t.Setenv("IAM_URL", srv.URL)
	t.Setenv("IAM_MINT_CLIENT_ID", "hanzo-console")
	t.Setenv("IAM_MINT_CLIENT_SECRET", "s3cr3t")
	sharedKeysInst = nil
	t.Cleanup(func() { sharedKeysOnce = sync.Once{}; sharedKeysInst = nil })

	if org, ok := OrgForKey(context.Background(), "sk-live-home"); !ok || org != "agency" {
		t.Fatalf("a home key was attributed to (%q,%v); want agency", org, ok)
	}
}
