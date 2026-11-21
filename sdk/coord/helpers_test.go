package coord

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/hanzoai/vfs/replica"
)

// The periods every Coord of these tests keeps (fast), so a test sees a lease change
// hands in a second rather than a minute.
const (
	presenceTTL  = time.Second
	skew         = 500 * time.Millisecond
	refreshEvery = 50 * time.Millisecond
	term         = 600 * time.Millisecond
	effectBudget = 150 * time.Millisecond
	confirmEvery = 50 * time.Millisecond
	openFor      = 300 * time.Millisecond
)

var fast = Periods{
	Term: term, Effect: effectBudget, Confirm: confirmEvery, Watch: 10 * time.Millisecond,
	Presence: presenceTTL, Skew: skew, Refresh: refreshEvery,
	Open: openFor,
}

func staleAfter() time.Duration { return fast.staleAfter() }

var secret = bytes.Repeat([]byte{7}, 32)

// pod is one process of pod id over backend b, sharing it as a KV would, in a
// deployment that declares two writers.
func pod(t *testing.T, b Backend, id string, root bool, st replica.ConditionalStore) *Coord {
	t.Helper()
	return podOf(t, b, id, root, st, 2)
}

// solo is the root of a deployment that declares one writer.
func solo(t *testing.T, b Backend, id string, st replica.ConditionalStore) *Coord {
	t.Helper()
	return podOf(t, b, id, true, st, 1)
}

func podOf(t *testing.T, b Backend, id string, root bool, st replica.ConditionalStore, declared int) *Coord {
	t.Helper()
	c := over(b, newMem(), true, Config{Periods: fast,
		Deployment: "test",
		Self:       Member{ID: id, Addr: id + ":8443"},
		Instance:   id + "-host",
		Secret:     secret,
		Root:       root,
		Declared:   declared,
	})
	if st != nil {
		c.SetStore(st)
	}
	c.Start(context.Background())
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		c.Close(ctx)
	})
	return c
}

// eventually waits for ok, up to d.
func eventually(t *testing.T, d time.Duration, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("after %v: %s", d, what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func ids(ms []Member) []string {
	out := make([]string, len(ms))
	for i, m := range ms {
		out[i] = m.ID
	}
	return out
}

// cut is one process's view of a shared store, which can lose the store while the
// process and the store both go on.
type cut struct {
	replica.ConditionalStore
	off atomic.Bool
}

func (c *cut) Get(ctx context.Context, key string) ([]byte, string, error) {
	if c.off.Load() {
		return nil, "", errors.New("partitioned")
	}
	return c.ConditionalStore.Get(ctx, key)
}

func (c *cut) PutIfVersion(ctx context.Context, key string, data []byte, expect string) (string, error) {
	if c.off.Load() {
		return "", errors.New("partitioned")
	}
	return c.ConditionalStore.PutIfVersion(ctx, key, data, expect)
}

// casStore is an object store with compare-and-set, in memory, whose reads and
// writes can be made to fail.
type casStore struct {
	mu   sync.Mutex
	objs map[string]casObj
	down bool
}

type casObj struct {
	data    []byte
	version int
}

// The test registers answer in both vocabularies — coord's, and the replica
// package's that org reads — so one register can stand under a loop's lease and an
// org's at once, as the deployment's object store does.
var (
	errMissing  = errors.Join(ErrMissing, replica.ErrNotFound)
	errConflict = errors.Join(ErrConflict, replica.ErrConflict)
)

func newCAS() *casStore { return &casStore{objs: map[string]casObj{}} }

func (s *casStore) fail(down bool) {
	s.mu.Lock()
	s.down = down
	s.mu.Unlock()
}

func (s *casStore) Get(_ context.Context, key string) ([]byte, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.down {
		return nil, "", errors.New("store unreachable")
	}
	o, ok := s.objs[key]
	if !ok {
		return nil, "", errMissing
	}
	return append([]byte(nil), o.data...), strconv.Itoa(o.version), nil
}

func (s *casStore) PutIfVersion(_ context.Context, key string, data []byte, expect string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.down {
		return "", errors.New("store unreachable")
	}
	o, ok := s.objs[key]
	cur := ""
	if ok {
		cur = strconv.Itoa(o.version)
	}
	if cur != expect {
		return "", errConflict
	}
	o = casObj{data: append([]byte(nil), data...), version: o.version + 1}
	s.objs[key] = o
	return strconv.Itoa(o.version), nil
}

func (s *casStore) lease(name string) (uint64, string) {
	data, _, err := s.Get(context.Background(), leaseKey(name))
	if err != nil {
		return 0, ""
	}
	l, _ := decodeLease(data)
	return l.round, l.owner
}

// fileStore is compare-and-set over a directory every process on this machine
// shares, for the test that runs pods as processes.
type fileStore struct{ dir string }

func (s fileStore) locked(exclusive bool, f func() error) error {
	l, err := os.OpenFile(filepath.Join(s.dir, ".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer l.Close()
	how := syscall.LOCK_SH
	if exclusive {
		how = syscall.LOCK_EX
	}
	if err := syscall.Flock(int(l.Fd()), how); err != nil {
		return err
	}
	defer syscall.Flock(int(l.Fd()), syscall.LOCK_UN)
	return f()
}

func (s fileStore) path(key string) string {
	return filepath.Join(s.dir, fmt.Sprintf("%x", key))
}

func (s fileStore) read(key string) ([]byte, string, error) {
	b, err := os.ReadFile(s.path(key))
	if errors.Is(err, os.ErrNotExist) {
		return nil, "", errMissing
	}
	if err != nil {
		return nil, "", err
	}
	v, data, _ := bytes.Cut(b, []byte("\n"))
	return data, string(v), nil
}

func (s fileStore) Get(_ context.Context, key string) (data []byte, version string, err error) {
	err = s.locked(false, func() error {
		data, version, err = s.read(key)
		return err
	})
	return data, version, err
}

func (s fileStore) PutIfVersion(_ context.Context, key string, data []byte, expect string) (version string, err error) {
	err = s.locked(true, func() error {
		_, cur, err := s.read(key)
		if err != nil && !errors.Is(err, ErrMissing) {
			return err
		}
		if cur != expect {
			return errConflict
		}
		n, _ := strconv.Atoi(cur)
		version = strconv.Itoa(n + 1)
		tmp := s.path(key) + ".tmp"
		if err := os.WriteFile(tmp, append([]byte(version+"\n"), data...), 0o600); err != nil {
			return err
		}
		return os.Rename(tmp, s.path(key))
	})
	return version, err
}

// effects records when each process made an effect for a loop, to show no two
// processes' effects ever overlap.
type effects struct {
	mu  sync.Mutex
	all []effect
}

type effect struct {
	who        string
	start, end time.Time
}

func (e *effects) add(who string, start, end time.Time) {
	e.mu.Lock()
	e.all = append(e.all, effect{who, start, end})
	e.mu.Unlock()
}

// disjoint fails when an effect of one process overlaps an effect of another.
func (e *effects) disjoint(t *testing.T) {
	t.Helper()
	e.mu.Lock()
	defer e.mu.Unlock()
	for i, a := range e.all {
		for _, b := range e.all[i+1:] {
			if a.who != b.who && a.start.Before(b.end) && b.start.Before(a.end) {
				t.Fatalf("%s and %s acted at once: %v–%v and %v–%v", a.who, b.who,
					a.start.Format("05.000"), a.end.Format("05.000"), b.start.Format("05.000"), b.end.Format("05.000"))
			}
		}
	}
}

func (e *effects) by(who string) []effect {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []effect
	for _, x := range e.all {
		if x.who == who {
			out = append(out, x)
		}
	}
	return out
}

// work is a loop pass that makes an effect every few milliseconds, asking the fence
// before each, until its context ends.
func work(l *Leader, who string, fx *effects, each time.Duration) func(context.Context) {
	return func(ctx context.Context) {
		for ctx.Err() == nil {
			if l.Hold(ctx) != nil {
				return
			}
			start := time.Now()
			time.Sleep(each)
			fx.add(who, start, time.Now())
		}
	}
}
