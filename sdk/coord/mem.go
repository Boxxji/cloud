package coord

import (
	"context"
	"math"
	"sync"
	"time"
)

// mem answers for this process alone: every pod it knows is one that joined here,
// every count is this process's.
type mem struct {
	mu      sync.Mutex
	live    map[string]map[string]memMember // set → id → member
	windows map[string]*slot
	swept   time.Time
	buckets map[string]time.Time // key → theoretical arrival time
	used    map[string]time.Time
	quotas  map[string]*slot // Quota's counts
	// quotaSwept is when expired quota slots were last swept.
	quotaSwept time.Time
	spans      map[string]spanned // Span's records
	// spanSwept is when expired span records were last swept.
	spanSwept time.Time
	holds     map[string]map[string]heldCents // key → hold id → what it holds
	// chans are the subscriptions of the pods that share this backend (membus.go).
	chans map[string]map[*memSub]struct{}
}

// heldCents is one hold: its amount and when it lapses.
type heldCents struct {
	cents int64
	until time.Time
}

type memMember struct {
	r     Record
	until time.Time
}

// slot is one key's window: how many requests it has spent, and when it resets.
type slot struct {
	n     int
	reset time.Time
}

func newMem() *mem {
	return &mem{
		live:    map[string]map[string]memMember{},
		windows: map[string]*slot{},
		buckets: map[string]time.Time{},
		used:    map[string]time.Time{},
		quotas:  map[string]*slot{},
		spans:   map[string]spanned{},
		holds:   map[string]map[string]heldCents{},
		chans:   map[string]map[*memSub]struct{}{},
	}
}

func (b *mem) Join(_ context.Context, set string, r Record, ttl time.Duration, force bool) (*Record, error) {
	now := time.Now()
	b.mu.Lock()
	defer b.mu.Unlock()
	ms := b.live[set]
	if ms == nil {
		ms = map[string]memMember{}
		b.live[set] = ms
	}
	if cur, ok := ms[r.ID]; ok && !force && now.Before(cur.until) && cur.r.Instance != r.Instance {
		held := cur.r
		return &held, nil
	}
	ms[r.ID] = memMember{r: r, until: now.Add(ttl)}
	return nil, nil
}

func (b *mem) Leave(_ context.Context, set, id, instance string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if cur, ok := b.live[set][id]; ok && cur.r.Instance == instance {
		delete(b.live[set], id)
	}
	return nil
}

func (b *mem) Members(_ context.Context, set string, ttl time.Duration) ([]Record, error) {
	now := time.Now()
	b.mu.Lock()
	defer b.mu.Unlock()
	out := []Record{}
	for id, cur := range b.live[set] {
		switch {
		case !now.Before(cur.until):
			delete(b.live[set], id)
		case cur.until.Sub(now) <= ttl:
			out = append(out, cur.r)
		}
	}
	return out, nil
}

// spend is the fixed window cloud.Window has always counted, per key. A request
// over the limit is still charged to the key that refused it, so a caller cannot
// ride a refused request for free; a wider key is charged only for what the
// narrower admitted, so one /64 hammering past its own limit spends nothing of the
// /48 its neighbours share. Expired windows are swept at most once per period, so
// the map holds the keys seen in one window and never every key ever seen.
func (b *mem) Spend(_ context.Context, keys []string, scales []int, limit int, period time.Duration) (int, time.Time, error) {
	now := time.Now()
	b.mu.Lock()
	defer b.mu.Unlock()
	if now.Sub(b.swept) >= period {
		b.swept = now
		for k, s := range b.windows {
			if now.After(s.reset) {
				delete(b.windows, k)
			}
		}
	}
	left := math.MaxInt
	var tight, reset time.Time
	for i, k := range keys {
		refused := left < 0
		s := b.windows[k]
		if s == nil || now.After(s.reset) {
			if refused {
				continue // an empty window past a refusal holds nobody back
			}
			s = &slot{reset: now.Add(period)}
			b.windows[k] = s
		}
		room := limit*scales[i] - s.n
		if !refused {
			s.n++
			room--
			if room < left {
				left, tight = room, s.reset
			}
		}
		if room <= 0 && s.reset.After(reset) {
			reset = s.reset
		}
	}
	if reset.IsZero() {
		reset = tight
	}
	return left, reset, nil
}

// take is a token bucket of perMin tokens refilled continuously, perMin at once,
// kept as the time its next token is due (the generic cell rate algorithm): a
// request is admitted when that time is no more than a full bucket ahead of now.
func (b *mem) Take(_ context.Context, key string, perMin int) (bool, error) {
	if perMin <= 0 {
		return true, nil
	}
	now := time.Now()
	interval := time.Minute / time.Duration(perMin)
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.buckets) > 4096 {
		for k, tat := range b.buckets {
			if tat.Before(now) {
				delete(b.buckets, k)
			}
		}
	}
	tat := b.buckets[key]
	if tat.Before(now) {
		tat = now
	}
	next := tat.Add(interval)
	if next.Sub(now) > time.Minute {
		return false, nil
	}
	b.buckets[key] = next
	return true, nil
}

func (b *mem) Once(_ context.Context, key string, ttl time.Duration) (bool, error) {
	now := time.Now()
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.used) > 4096 {
		for k, until := range b.used {
			if now.After(until) {
				delete(b.used, k)
			}
		}
	}
	if until, ok := b.used[key]; ok && now.Before(until) {
		return false, nil
	}
	b.used[key] = now.Add(ttl)
	return true, nil
}

// total sweeps key's lapsed holds and answers what the rest hold. Caller holds b.mu.
func (b *mem) total(key string, now time.Time) int64 {
	var sum int64
	for id, h := range b.holds[key] {
		if !now.Before(h.until) {
			delete(b.holds[key], id)
			continue
		}
		sum += h.cents
	}
	if len(b.holds[key]) == 0 {
		delete(b.holds, key)
	}
	return sum
}

func (b *mem) Commit(_ context.Context, key, id string, cents int64, ttl time.Duration) (int64, error) {
	now := time.Now()
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.holds[key] == nil {
		b.holds[key] = map[string]heldCents{}
	}
	b.holds[key][id] = heldCents{cents: cents, until: now.Add(ttl)}
	return b.total(key, now), nil
}

func (b *mem) Uncommit(_ context.Context, key, id string, _ int64) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.holds[key], id)
	if len(b.holds[key]) == 0 {
		delete(b.holds, key)
	}
	return nil
}

func (b *mem) Committed(_ context.Context, key string) (int64, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.total(key, time.Now()), nil
}
