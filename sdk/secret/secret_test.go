package secret_test

import (
	"context"
	"errors"
	"testing"

	"github.com/hanzoai/cloud/sdk/secret"
)

type held map[string][]byte

func (h held) GetSecret(_ context.Context, ref string) ([]byte, error) {
	if v, ok := h[ref]; ok {
		return v, nil
	}
	return nil, secret.ErrNone
}
func (h held) PutSecret(_ context.Context, ref string, v []byte) error { h[ref] = v; return nil }
func (h held) DeleteSecret(_ context.Context, ref string) error        { delete(h, ref); return nil }
func (h held) Sign(context.Context, string, []byte) ([]byte, error)    { return nil, errors.New("no key") }

// A process given no store answers no secret, and says so: never an empty one.
func TestNoStoreIsAnErrorNotAnEmptySecret(t *testing.T) {
	v, err := secret.Get(context.Background(), nil, "orgs/acme/key")
	if !errors.Is(err, secret.ErrUnconfigured) || v != nil {
		t.Fatalf("Get with no store = %q, %v; want nil, ErrUnconfigured", v, err)
	}
	t.Setenv("SECRET_TEST_REF", "orgs/acme/key")
	if _, err := secret.Resolve(context.Background(), nil, "SECRET_TEST_REF"); !errors.Is(err, secret.ErrUnconfigured) {
		t.Fatalf("Resolve with no store: %v, want ErrUnconfigured", err)
	}
}

func TestResolveReadsTheRefTheVariableNames(t *testing.T) {
	s := held{"orgs/acme/key": []byte("k")}
	t.Setenv("SECRET_TEST_REF", " orgs/acme/key ")
	if v, err := secret.Resolve(context.Background(), s, "SECRET_TEST_REF"); err != nil || string(v) != "k" {
		t.Fatalf("Resolve = %q, %v", v, err)
	}
	t.Setenv("SECRET_TEST_REF", "orgs/acme/other")
	if _, err := secret.Resolve(context.Background(), s, "SECRET_TEST_REF"); !errors.Is(err, secret.ErrNone) {
		t.Fatalf("a ref the store does not hold: %v, want ErrNone", err)
	}
	t.Setenv("SECRET_TEST_REF", "")
	if _, err := secret.Resolve(context.Background(), s, "SECRET_TEST_REF"); err == nil {
		t.Fatal("an unset variable resolved")
	}
}
