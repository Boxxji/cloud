package cloud

import (
	"context"
	"errors"
	"fmt"

	"github.com/hanzoai/cloud/sdk/coord"
	"github.com/hanzoai/vfs/replica"
)

// LeaseStore is the object store as coord's loop leases ask it: the same register,
// with its absent-key and lost-race answers named in coord's terms. coord links no
// store, so the light host, which links coord for presence, links none either.
type LeaseStore struct{ replica.ConditionalStore }

func (s LeaseStore) Get(ctx context.Context, key string) ([]byte, string, error) {
	data, version, err := s.ConditionalStore.Get(ctx, key)
	if errors.Is(err, replica.ErrNotFound) {
		err = fmt.Errorf("%w: %w", coord.ErrMissing, err)
	}
	return data, version, err
}

func (s LeaseStore) PutIfVersion(ctx context.Context, key string, data []byte, expect string) (string, error) {
	version, err := s.ConditionalStore.PutIfVersion(ctx, key, data, expect)
	if errors.Is(err, replica.ErrConflict) {
		err = fmt.Errorf("%w: %w", coord.ErrConflict, err)
	}
	return version, err
}
