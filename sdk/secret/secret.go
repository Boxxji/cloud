// Package secret is how an app reads and keeps a secret by reference: a Store
// answers the material a ref names, and nothing else carries it.
//
// A process with no Store configured has none: every read through Resolve fails
// and names why, never answering an empty secret as if one were held. A missing
// secret that reads as empty is how a signing key becomes "" and every signature
// verifies against it.
package secret

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
)

// ErrNone is a secret the store does not hold. GetSecret answers an error that is
// ErrNone for it — in process and across the plane alike — so a caller tells
// "never written" from "could not be read" with errors.Is rather than by the
// error's words, which are not the same on both paths. The words still say "not
// found": ai (object/kms.go isNotFound) cannot import this package and tells
// absence by them, and an absence it reads as a failure is re-read every 30
// seconds and logged as one.
var ErrNone = errors.New("kms: secret not found")

// ErrUnconfigured is a read from a process that was given no Store.
var ErrUnconfigured = errors.New("secret: no secret store is configured")

// Store reads, keeps and forgets secrets by reference, and signs with a key it
// holds without handing the key out.
type Store interface {
	// GetSecret reads one secret; one the store does not hold is ErrNone.
	GetSecret(ctx context.Context, ref string) ([]byte, error)
	PutSecret(ctx context.Context, ref string, value []byte) error
	// DeleteSecret forgets one secret; one the store does not hold is ErrNone. An
	// app that custodies a credential on a customer's behalf must be able to remove
	// it when that customer disconnects; without this, disconnecting drops the
	// connection row and leaves the material.
	DeleteSecret(ctx context.Context, ref string) error
	Sign(ctx context.Context, keyRef string, payload []byte) ([]byte, error)
}

// Get reads ref from s. A nil s is ErrUnconfigured.
func Get(ctx context.Context, s Store, ref string) ([]byte, error) {
	if s == nil {
		return nil, fmt.Errorf("%w (asked for %s)", ErrUnconfigured, ref)
	}
	return s.GetSecret(ctx, ref)
}

// Resolve reads the secret whose reference the environment variable name holds.
// An unset variable, no Store, a ref the store does not hold, and a store that
// cannot answer are each an error that says which.
func Resolve(ctx context.Context, s Store, name string) ([]byte, error) {
	ref := strings.TrimSpace(os.Getenv(name))
	if ref == "" {
		return nil, fmt.Errorf("secret: %s names no secret reference", name)
	}
	v, err := Get(ctx, s, ref)
	if err != nil {
		return nil, fmt.Errorf("secret: %s: %w", name, err)
	}
	return v, nil
}
