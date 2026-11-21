package object

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

// TestMissing is the load-bearing translation: a MISSING key must become
// ErrBlobNotFound (so files.go answers 404 / idempotent-204), nil stays nil,
// and EVERY other error (no such bucket, auth, throttle, connection-refused) passes
// through unchanged (so files.go fails CLOSED 502).
func TestMissing(t *testing.T) {
	cases := []struct {
		name       string
		in         error
		wantNotFnd bool
		wantNil    bool
	}{
		{"nil", nil, false, true},
		{"no such key", ErrNoKey, true, false},
		{"no such key wrapped", fmt.Errorf("get: %w", ErrNoKey), true, false},
		{"no such bucket", ErrNoBucket, false, false},
		{"refused", ErrRefused, false, false},
		{"plain conn error", fmt.Errorf("dial tcp: connection refused"), false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := missing(c.in)
			switch {
			case c.wantNil:
				if got != nil {
					t.Fatalf("missing(nil) = %v, want nil", got)
				}
			case c.wantNotFnd:
				if !errors.Is(got, ErrBlobNotFound) {
					t.Fatalf("missing(%v) = %v, want ErrBlobNotFound", c.in, got)
				}
			default:
				if errors.Is(got, ErrBlobNotFound) {
					t.Fatalf("missing(%v) mapped a non-miss error to ErrBlobNotFound (would 404 an outage)", c.in)
				}
				if got == nil {
					t.Fatalf("missing(%v) = nil, want the error passed through", c.in)
				}
			}
		})
	}
}

// The team files plane on local disk: put, get, delete, and the 404 split.
func TestVFSOnLocalDisk(t *testing.T) {
	ctx := context.Background()
	v := NewBlobs(&Local{Dir: t.TempDir()}, "team-blobs")
	if _, err := v.Get(ctx, "team/blobs/acme/ws/none"); !errors.Is(err, ErrBlobNotFound) {
		t.Fatalf("get of a blob nobody wrote = %v, want ErrBlobNotFound", err)
	}
	if err := v.Put(ctx, "team/blobs/acme/ws/a", []byte("avatar")); err != nil {
		t.Fatal(err)
	}
	got, err := v.Get(ctx, "team/blobs/acme/ws/a")
	if err != nil || string(got) != "avatar" {
		t.Fatalf("get = %q, %v", got, err)
	}
	if err := v.Delete(ctx, "team/blobs/acme/ws/a"); err != nil {
		t.Fatal(err)
	}
	if err := v.Delete(ctx, "team/blobs/acme/ws/a"); err != nil && !errors.Is(err, ErrBlobNotFound) {
		t.Fatalf("delete twice = %v: removal is idempotent", err)
	}
	if _, err := v.Get(ctx, "team/blobs/acme/ws/a"); !errors.Is(err, ErrBlobNotFound) {
		t.Fatalf("get after delete = %v", err)
	}
}

// An unopenable store fails every operation closed, and construction never waits on it.
func TestVFSFailsClosedWhenTheStoreCannotOpen(t *testing.T) {
	t.Setenv("CLOUD_ENV", "mainnet")
	t.Setenv("S3_ADMIN_ACCESS_KEY", "")
	v := NewBlobs(Default(), "team-blobs")
	if err := v.Put(context.Background(), "k", []byte("x")); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("put = %v, want ErrNotConfigured", err)
	}
	if _, err := v.Get(context.Background(), "k"); errors.Is(err, ErrBlobNotFound) || err == nil {
		t.Fatalf("get = %v: an outage must not read as a miss", err)
	}
}
