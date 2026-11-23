// Package retry makes a call again after a failure that passes: one policy, one backoff, one
// wait, for every call here that has another try to make.
package retry

import (
	"context"
	"math/rand/v2"
	"time"
)

// Tries is how many times a call is made, First the wait before the second try (doubling for each
// after it) and Longest its ceiling. Hold is the longest wait the other side may name: a call told
// to wait longer is answered as it was, so a caller is never held for it.
const (
	Tries   = 3
	First   = time.Second
	Longest = 20 * time.Second
	Hold    = time.Minute
)

// Pause waits d, or ends early with the context's error. A var so a test records the wait.
var Pause = func(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Backoff is the wait after try number try (from 1): doubling from First to Longest, its lower
// half fixed and its upper half random, so callers that failed together do not return together.
func Backoff(try int) time.Duration {
	d := min(First<<(try-1), Longest)
	return d/2 + rand.N(d/2+1)
}

// Do makes call until it says it need not be made again, at most Tries times, and until ctx ends.
// call answers whether another try is worth making and how long the other side asked to wait
// before it (0 for none): that wait is kept when it is within Hold, and a longer one ends the
// tries. The caller keeps what the last try answered.
func Do(ctx context.Context, call func() (again bool, named time.Duration)) {
	for try := 1; try <= Tries; try++ {
		again, named := call()
		if !again || try == Tries || named > Hold || ctx.Err() != nil {
			return
		}
		if named <= 0 {
			named = Backoff(try)
		}
		if Pause(ctx, named) != nil {
			return
		}
	}
}
