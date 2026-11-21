package inflight

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/zap-proto/zip"
)

var handling atomic.Int64

// Count is middleware that counts a request while its handler runs. Install it
// ahead of what it must see: zip hands an included app the middleware stack as
// it stood at the inclusion.
func Count(c *zip.Ctx) error {
	handling.Add(1)
	defer handling.Add(-1)
	return c.Next()
}

// Drain returns a context that ends once no request is being handled — or when
// parent does. Passed to zip's ShutdownWithContext, it ends the drain at the
// moment the last handler returns, so the teardown hooks run without waiting
// out the streams.
func Drain(parent context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	go func() {
		defer cancel()
		// Idle twice in a row, a poll apart: a request accepted as the listener
		// closed has its handler running by the second look.
		for quiet := 0; quiet < 2; {
			if handling.Load() == 0 {
				quiet++
			} else {
				quiet = 0
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(poll):
			}
		}
	}()
	return ctx, cancel
}

const poll = 10 * time.Millisecond
