// Copyright © 2026 Hanzo AI. MIT License.

package cloud

import (
	"context"
	"errors"
	"fmt"
	"github.com/hanzoai/cloud/sdk/secret"
	"net/http"
	"time"

	"github.com/zap-proto/zip"
)

// KMSPeer is the KMS client for a process that does not hold the sealed store —
// which is every process but one.
//
// The org a call acts for rides the CALLER, exactly as it does for every other
// plane call (see [Ask]): the request's own identity when ctx carries
// one, or the tenant a background job stated with [For]. It is never read out
// of the ref. The store serves a tenant's ref ("orgs/<org>/…") only to a call
// acting for that same tenant, and a ref naming no tenant — the deployment's
// own material — to the custodian alone (apps/kms attest.go). Stating the org
// FROM the ref would make that check compare the ref with itself, so a plugin
// that let a request shape a ref's org segment would read whichever tenant the
// request named. A job that means to act for a tenant says so on its context.
type KMSPeer struct{}

const kmsPeerTimeout = 10 * time.Second

func (k KMSPeer) call(ctx context.Context, op KMSOp, ref string, value []byte) ([]byte, error) {
	ask := peersOf().KMS
	if ask == nil {
		return nil, fmt.Errorf("kms %s: %w", op, ErrNoPeer)
	}
	ctx, cancel := context.WithTimeout(ctx, kmsPeerTimeout)
	defer cancel()
	out, err := ask(ctx, op, ref, value)
	var he *zip.HTTPError
	switch {
	case err == nil:
	case (op == KMSGet || op == KMSDel) && errors.As(err, &he) && he.Status == http.StatusNotFound:
		// The store answers a read or a delete of a secret it does not hold as 404
		// (apps/kms secret_rpc.go); the sentinel does not survive the hop, so it is
		// restored here.
		return nil, fmt.Errorf("kms %s: %w", op, secret.ErrNone)
	default:
		return nil, fmt.Errorf("kms %s: %w", op, err)
	}
	return out, nil
}

// GetSecret reads one secret. A missing secret is an error, never empty bytes:
// callers treat empty as "not configured" and fail closed on it, so returning
// empty for a transport failure would read as a deliberate absence.
func (k KMSPeer) GetSecret(ctx context.Context, ref string) ([]byte, error) {
	return k.call(ctx, KMSGet, ref, nil)
}

// PutSecret writes one secret.
func (k KMSPeer) PutSecret(ctx context.Context, ref string, value []byte) error {
	_, err := k.call(ctx, KMSPut, ref, value)
	return err
}

// DeleteSecret asks the store to forget one secret.
func (k KMSPeer) DeleteSecret(ctx context.Context, ref string) error {
	_, err := k.call(ctx, KMSDel, ref, nil)
	return err
}

// Sign signs a payload with a key that never leaves the store's process — which
// is the reason signing is an op here rather than a key fetch.
func (k KMSPeer) Sign(ctx context.Context, keyRef string, payload []byte) ([]byte, error) {
	return k.call(ctx, KMSSign, keyRef, payload)
}
