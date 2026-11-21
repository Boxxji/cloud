// Copyright © 2026 Hanzo AI. MIT License.

package cloud

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// tierCallTimeout bounds the ask. Every reader treats a tier it could not read as
// unknown, so waiting longer than this buys nothing.
const tierCallTimeout = 5 * time.Second

// Tier is the plan tier commerce derives for subject inside org — free, starter,
// pro or enterprise — asked of the process that owns the subscription store over
// the plane. When this process serves commerce the op runs in-process; otherwise
// it crosses the socket. It is the one tier read: the free-call allowance, the
// rolling spend cap and the ai module's tier gates all call it.
//
// An answer is kept for tierTTL and served while it is refreshed in the background
// after that, so a call waits on commerce only for a pair it has never asked about;
// a plan change reaches the gates within a refresh.
//
// "" with a nil error means no plan can be named: an empty subject, or a
// deployment that runs no commerce. Every other failure is returned, and each
// reader decides which way it fails.
func Tier(ctx context.Context, subject, org string) (string, error) {
	if strings.TrimSpace(subject) == "" {
		return "", nil
	}
	k := org + "\x00" + subject
	tiers.mu.Lock()
	t, ok := tiers.m[k]
	stale := ok && time.Since(t.at) > tierTTL
	if stale && !t.asking {
		t.asking = true
		tiers.m[k] = t
		go refreshTier(k, subject, org)
	}
	tiers.mu.Unlock()
	if ok {
		return t.name, nil
	}
	name, err := askTier(ctx, subject, org)
	if err == nil {
		keepTier(k, name)
	}
	return name, err
}

// tierTTL is how long a tier answer is served before it is asked again.
var tierTTL = 30 * time.Second

type tierAnswer struct {
	name   string
	at     time.Time
	asking bool
}

var tiers = struct {
	mu sync.Mutex
	m  map[string]tierAnswer
}{m: map[string]tierAnswer{}}

// tierMax bounds the pairs kept; past it the map starts again.
const tierMax = 1 << 16

func keepTier(k, name string) {
	tiers.mu.Lock()
	if len(tiers.m) >= tierMax {
		tiers.m = map[string]tierAnswer{}
	}
	tiers.m[k] = tierAnswer{name: name, at: time.Now()}
	tiers.mu.Unlock()
}

func refreshTier(k, subject, org string) {
	name, err := askTier(context.Background(), subject, org)
	if err == nil {
		keepTier(k, name)
		return
	}
	tiers.mu.Lock()
	if t, ok := tiers.m[k]; ok {
		t.asking = false
		tiers.m[k] = t
	}
	tiers.mu.Unlock()
}

func askTier(ctx context.Context, subject, org string) (string, error) {
	ask := peersOf().TierOf
	if ask == nil {
		return "", nil
	}
	ctx, cancel := context.WithTimeout(For(ctx, org), tierCallTimeout)
	defer cancel()
	name, err := ask(ctx, subject)
	switch {
	case errors.Is(err, ErrNoPeer):
		return "", nil
	case err != nil:
		return "", fmt.Errorf("tier: %w", err)
	}
	return strings.TrimSpace(name), nil
}
