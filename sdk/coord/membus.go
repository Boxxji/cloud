package coord

import "context"

// memSub is one pod's subscription to a channel of the in-process backend.
type memSub struct {
	deliver func([]byte)
	gap     func()
}

// publish hands msg to every subscription of channel, this pod's included, and
// answers how many there were: the count a KV's PUBLISH answers.
func (b *mem) Publish(_ context.Context, channel string, msg []byte) (int, error) {
	b.mu.Lock()
	subs := make([]*memSub, 0, len(b.chans[channel]))
	for s := range b.chans[channel] {
		subs = append(subs, s)
	}
	b.mu.Unlock()
	for _, s := range subs {
		s.deliver(msg)
	}
	return len(subs), nil
}

// subscribe is active when it returns. It never loses a message, so gap is never
// called.
func (b *mem) Subscribe(channel string, deliver func([]byte), gap func()) (func(), error) {
	s := &memSub{deliver: deliver, gap: gap}
	b.mu.Lock()
	if b.chans[channel] == nil {
		b.chans[channel] = map[*memSub]struct{}{}
	}
	b.chans[channel][s] = struct{}{}
	b.mu.Unlock()
	return func() {
		b.mu.Lock()
		delete(b.chans[channel], s)
		if len(b.chans[channel]) == 0 {
			delete(b.chans, channel)
		}
		b.mu.Unlock()
	}, nil
}

// closeBus has nothing to close: a subscription is a map entry, and its pod
// removes it.
func (b *mem) Close() {}

func (b *mem) Exact() bool { return true }
