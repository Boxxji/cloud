package coord

import (
	"errors"
	"sync"
	"time"
)

// Driver is what a deployment's production backends register into this package: the
// shared KV that makes counts, tokens and the live set hold across pods, and the
// cross-pod message bus. The host registers them, once, before it calls New, and
// the SDK links neither; with nothing registered a process answers alone, in
// memory, which is the whole deployment when it is one pod.
type Driver struct {
	// Backend opens the shared backend at url (KV_URL). A backend that also
	// implements Bus carries the bus itself, as the KV does.
	Backend func(url string, p Periods) (Backend, error)
	// Bus opens the shared pubsub cluster at url (CLOUD_PUBSUB_URL); name names this
	// process's connection to it.
	Bus func(url, name string) (Bus, error)
}

var (
	driverMu sync.Mutex
	driver   Driver
)

// Register installs d. A nil field leaves what is installed; a second driver for
// a field already held is a programming error and panics, as sql.Register does.
func Register(d Driver) {
	driverMu.Lock()
	defer driverMu.Unlock()
	if d.Backend != nil {
		if driver.Backend != nil {
			panic("coord: a shared backend is already registered")
		}
		driver.Backend = d.Backend
	}
	if d.Bus != nil {
		if driver.Bus != nil {
			panic("coord: a bus is already registered")
		}
		driver.Bus = d.Bus
	}
}

func registered() Driver {
	driverMu.Lock()
	defer driverMu.Unlock()
	return driver
}

// ErrNoDriver is New's refusal when KV_URL or CLOUD_PUBSUB_URL names a shared
// service and no driver for it is linked. Pods that each believe they are alone
// double-spend every limit and each run every loop, so a process that was told to
// share never answers alone.
var ErrNoDriver = errors.New("coord: KV_URL or CLOUD_PUBSUB_URL is set but no driver for it is linked into this binary")

// OpenFor is how long a driver's breaker stays open after its backend fails to
// answer.
func (p Periods) OpenFor() time.Duration { return p.set().Open }
