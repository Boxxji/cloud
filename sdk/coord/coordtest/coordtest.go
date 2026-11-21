package coordtest

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/hanzoai/cloud/sdk/coord"
)

// Secret is the master key every pod a test starts shares.
var Secret = bytes.Repeat([]byte{9}, 32)

// Memory is a deployment's KV in this process (coord.Memory): the pods it makes
// share every count, as pods on one KV do, and need no valkey-server — so a test that
// asks only whether pods agree on a count runs on every machine and in CI.
func Memory(t testing.TB) func(id string) *coord.Coord {
	t.Helper()
	m := coord.NewMemory()
	return func(id string) *coord.Coord {
		c := m.Pod(id)
		t.Cleanup(func() { c.Close(context.Background()) })
		return c
	}
}

// Replicas is the pods of a deployment that declares n writers: they share counts as
// Memory's do, and a store for the leases of loops, so a loop runs on the one pod that
// claims it first and ErrNotHeld is the answer on the rest, as in production. Every
// loop starts let go, so the first claim is taken at once.
func Replicas(t testing.TB, n int) func(id string) *coord.Coord {
	t.Helper()
	m, leases := coord.NewMemory(), coord.NewLeases()
	return func(id string) *coord.Coord {
		c := m.Replica(id, n, leases)
		t.Cleanup(func() { c.Close(context.Background()) })
		return c
	}
}

// Default makes c this process's Coord for the rest of the test.
func Default(t testing.TB, c *coord.Coord) {
	t.Helper()
	was := coord.Default()
	coord.SetDefault(c)
	t.Cleanup(func() { coord.SetDefault(was) })
}

// Down is a pod whose shared KV answers no question: every count falls back to this
// process's, and a single-use token is refused on a deployment of several writers.
// It is a KV that is configured and unreachable, without a server to start.
func Down(cfg coord.Config) *coord.Coord {
	if len(cfg.Secret) == 0 {
		cfg.Secret = Secret
	}
	return coord.OnBackend(down{}, cfg)
}

type down struct{}

func (down) Join(context.Context, string, coord.Record, time.Duration, bool) (*coord.Record, error) {
	return nil, coord.ErrUnavailable
}
func (down) Leave(context.Context, string, string, string) error { return coord.ErrUnavailable }
func (down) Members(context.Context, string, time.Duration) ([]coord.Record, error) {
	return nil, coord.ErrUnavailable
}
func (down) Spend(context.Context, []string, []int, int, time.Duration) (int, time.Time, error) {
	return 0, time.Time{}, coord.ErrUnavailable
}
func (down) Take(context.Context, string, int) (bool, error) { return false, coord.ErrUnavailable }
func (down) Once(context.Context, string, time.Duration) (bool, error) {
	return false, coord.ErrUnavailable
}
func (down) Commit(context.Context, string, string, int64, time.Duration) (int64, error) {
	return 0, coord.ErrUnavailable
}
func (down) Uncommit(context.Context, string, string, int64) error { return coord.ErrUnavailable }
func (down) Committed(context.Context, string) (int64, error)      { return 0, coord.ErrUnavailable }
func (down) Quota(context.Context, []string, []int, []time.Duration) ([]int, []time.Duration, bool, error) {
	return nil, nil, false, coord.ErrUnavailable
}
func (down) Counted(context.Context, []string) ([]int, error) { return nil, coord.ErrUnavailable }
func (down) Unquota(context.Context, []string) error          { return coord.ErrUnavailable }
func (down) Span(context.Context, string, int64, int64, bool) (int64, error) {
	return 0, coord.ErrUnavailable
}
