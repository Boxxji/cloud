package bus

// conn.go — what an app does with the bus: say something on a subject, and hear what
// is said on one. The cluster that carries it is a driver the host registers
// (internal/driver/pubsub, hanzoai/pubsub over NATS), exactly as sdk/coord takes its
// shared backends; this package links no client library.
//
// With no driver linked a process that was not pointed at a cluster talks to itself,
// in memory, which is the whole bus when it is one process. One that was pointed at a
// cluster (CLOUD_PUBSUB_URL) and has no driver refuses: it must not publish into
// nothing and look healthy.

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"

	"github.com/zap-proto/zip"
)

// Message is one thing said on a subject.
type Message struct {
	Subject string
	Data    []byte
}

// Subscription is a live interest in a subject.
type Subscription interface {
	Unsubscribe() error
}

// Conn is this process's one connection to the bus. A message the subscriber is too
// slow to take is dropped, never queued without bound.
type Conn interface {
	// Publish sends data on subject and returns once the bus holds it.
	Publish(subject string, data []byte) error
	// Subscribe delivers what is said on subject to msgs, without ever blocking the bus.
	Subscribe(subject string, msgs chan<- Message) (Subscription, error)
}

// Driver is what a deployment's bus registers into this package.
type Driver struct {
	// Connect returns the process's connection, dialed on first use and re-dialed
	// after Disconnect.
	Connect func() (Conn, error)
	// Err maps the bus's own refusals onto zip statuses; ok is false for an error
	// that is not the driver's.
	Err func(err error) (mapped error, ok bool)
	// Disconnect releases the connection, so a remount dials the new server.
	Disconnect func()
}

// ErrNoDriver is what a process pointed at a cluster (CLOUD_PUBSUB_URL) answers when
// no driver for it is linked into the binary.
var ErrNoDriver = errors.New("bus: CLOUD_PUBSUB_URL is set but no driver for it is linked into this binary")

var (
	mu     sync.Mutex
	driver *Driver
)

// Register installs d. A nil field leaves what is installed, so a driver may arrive
// in parts (the connection, then the error mapping of a richer surface); a second
// value for a field already held is a programming error and panics, as sql.Register
// does.
func Register(d Driver) {
	mu.Lock()
	defer mu.Unlock()
	if driver == nil {
		driver = &Driver{}
	}
	if d.Connect != nil {
		if driver.Connect != nil {
			panic("bus: a connection is already registered")
		}
		driver.Connect = d.Connect
	}
	if d.Err != nil {
		if driver.Err != nil {
			panic("bus: an error mapping is already registered")
		}
		driver.Err = d.Err
	}
	if d.Disconnect != nil {
		if driver.Disconnect != nil {
			panic("bus: a disconnect is already registered")
		}
		driver.Disconnect = d.Disconnect
	}
}

func registered() *Driver {
	mu.Lock()
	defer mu.Unlock()
	if driver == nil {
		return nil
	}
	d := *driver
	return &d
}

// Open is this process's connection to the bus: the registered driver's, or memory
// when none is registered and no cluster was named. It answers 503 rather than an
// error the caller has to translate, because every caller is a typed op and there is
// one honest answer to "the bus is not reachable": the endpoint is up, the plane
// behind it is not.
func Open() (Conn, error) {
	if d := registered(); d != nil && d.Connect != nil {
		c, err := d.Connect()
		if err != nil {
			return nil, zip.Errorf(http.StatusServiceUnavailable, "bus unreachable: %v", err)
		}
		return c, nil
	}
	if Remote() {
		return nil, zip.Errorf(http.StatusServiceUnavailable, "bus unreachable: %v", ErrNoDriver)
	}
	return local, nil
}

// Publish says data on subject and returns once the bus holds it.
func Publish(subject string, data []byte) error {
	c, err := Open()
	if err != nil {
		return err
	}
	return c.Publish(subject, data)
}

// Subscribe delivers what is said on subject to msgs until the Subscription is
// released. A subject may end in ".>" to hear everything beneath it, and carry "*" for
// one token, as on the cluster.
func Subscribe(subject string, msgs chan<- Message) (Subscription, error) {
	c, err := Open()
	if err != nil {
		return nil, err
	}
	return c.Subscribe(subject, msgs)
}

// Disconnect releases the connection on shutdown, so a remount dials the new server
// instead of a dead pipe.
func Disconnect() {
	if d := registered(); d != nil && d.Disconnect != nil {
		d.Disconnect()
	}
}

// Err maps the bus's own refusals onto the wire honestly: absence is 404, a name
// already taken is 409, a config the bus refuses is the 4xx it reports, and only a
// genuinely broken bus is a 5xx.
func Err(err error) error {
	if err == nil {
		return nil
	}
	if d := registered(); d != nil && d.Err != nil {
		if mapped, ok := d.Err(err); ok {
			return mapped
		}
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return zip.Errorf(http.StatusGatewayTimeout, "bus timeout")
	case errors.Is(err, ErrNoDriver):
		return zip.Errorf(http.StatusServiceUnavailable, "bus: %v", err)
	default:
		return zip.Errorf(http.StatusInternalServerError, "bus: %v", err)
	}
}

// local is the in-process bus: the default when no cluster was named.
var local = &memory{subs: map[*memSub]struct{}{}}

type memory struct {
	mu   sync.Mutex
	subs map[*memSub]struct{}
}

type memSub struct {
	m       *memory
	pattern []string
	out     chan<- Message
}

func (m *memory) Publish(subject string, data []byte) error {
	toks := strings.Split(subject, ".")
	msg := Message{Subject: subject, Data: append([]byte(nil), data...)}
	m.mu.Lock()
	var to []chan<- Message
	for s := range m.subs {
		if matches(s.pattern, toks) {
			to = append(to, s.out)
		}
	}
	m.mu.Unlock()
	for _, out := range to {
		select {
		case out <- msg:
		default: // a subscriber too slow to take it loses it, as on the cluster
		}
	}
	return nil
}

func (m *memory) Subscribe(subject string, msgs chan<- Message) (Subscription, error) {
	s := &memSub{m: m, pattern: strings.Split(subject, "."), out: msgs}
	m.mu.Lock()
	m.subs[s] = struct{}{}
	m.mu.Unlock()
	return s, nil
}

func (s *memSub) Unsubscribe() error {
	s.m.mu.Lock()
	delete(s.m.subs, s)
	s.m.mu.Unlock()
	return nil
}

// matches reports whether subject tokens are covered by a pattern: "*" stands for one
// token and a trailing ">" for one or more.
func matches(pattern, subject []string) bool {
	for i, p := range pattern {
		if p == ">" {
			return i == len(pattern)-1 && len(subject) > i
		}
		if i >= len(subject) || (p != "*" && p != subject[i]) {
			return false
		}
	}
	return len(pattern) == len(subject)
}
