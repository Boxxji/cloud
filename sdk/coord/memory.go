package coord

import (
	"context"
	"strconv"
	"strings"
	"sync"
)

// Memory is a deployment's KV held in one process. Every Coord made on one Memory
// counts on the same backend, as pods count on one shared KV, and keeps a fallback
// count of its own beside it, as a pod does. It answers every question the KV does
// with mem's answers — the same ones coord's own tests stand two pods up on.
//
// It is what a test that asks whether pods agree on a count runs on where no
// valkey-server is installed (coordtest.Memory), so that test runs everywhere
// instead of skipping wherever the server is absent.
type Memory struct{ b *mem }

// NewMemory returns an empty in-process KV.
func NewMemory() *Memory { return &Memory{b: newMem()} }

// Backend is m's shared backend, for a test that wraps it (OnBackend).
func (m *Memory) Backend() Backend { return m.b }

// Pod is the Coord of pod id on m: Shared, counting on m, falling back to its own.
func (m *Memory) Pod(id string) *Coord {
	return over(m.b, newMem(), true, Config{
		Deployment: "memory",
		Self:       Member{ID: id, Addr: id + ":8443"},
		Instance:   id,
	})
}

// Replica is the Coord of pod id on m in a deployment that declares replicas writers,
// whose loops hold their leases in st: Peered, so a loop runs only on the pod that
// holds its lease and never on a pod's word that it is alone. Pod declares no writers
// and is for counts.
func (m *Memory) Replica(id string, replicas int, st Store) *Coord {
	c := over(m.b, newMem(), true, Config{
		Deployment: "memory",
		Self:       Member{ID: id, Addr: id + ":8443"},
		Instance:   id,
		Declared:   replicas,
	})
	c.SetStore(st)
	return c
}

// Leases is the deployment's object store in one process, for the leases of loops
// (SetStore). Every loop starts let go, which the first pod to claim it takes at
// once. A store holding no object for a loop is waited on for a full term before
// anyone takes it, as production's must (the object may have been deleted from under
// a holder still in its term), which is a half a minute no test can spend.
type Leases struct {
	mu   sync.Mutex
	objs map[string]leased
}

type leased struct {
	data    []byte
	version int
}

// NewLeases returns a store in which every loop is let go.
func NewLeases() *Leases { return &Leases{objs: map[string]leased{}} }

func (s *Leases) object(key string) (leased, bool) {
	if o, ok := s.objs[key]; ok {
		return o, true
	}
	if strings.HasPrefix(key, "loops/") {
		return leased{data: encodeLease(lease{})}, true
	}
	return leased{}, false
}

// Get answers a key's bytes and its version, or ErrMissing.
func (s *Leases) Get(_ context.Context, key string) ([]byte, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.object(key)
	if !ok {
		return nil, "", ErrMissing
	}
	return append([]byte(nil), o.data...), strconv.Itoa(o.version), nil
}

// PutIfVersion writes data only while the key is still at expect ("" for an absent
// key), and answers ErrConflict when it is not.
func (s *Leases) PutIfVersion(_ context.Context, key string, data []byte, expect string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur := ""
	o, ok := s.object(key)
	if ok {
		cur = strconv.Itoa(o.version)
	}
	if expect != cur {
		return "", ErrConflict
	}
	o.data, o.version = append([]byte(nil), data...), o.version+1
	s.objs[key] = o
	return strconv.Itoa(o.version), nil
}
