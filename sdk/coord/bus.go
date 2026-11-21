package coord

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// What one pod tells the others, and asks of them.
//
// The embedded message bus (apps/pubsub) is one server per pod: a message published
// on it reaches the subscribers of THAT pod and no other, and every pod dials its own
// at 127.0.0.1. The KV is the one thing every pod of a deployment shares and a
// deployment of several writers cannot run without (KV_URL), so what must cross pods
// crosses on it: a subscription is a connection the KV pushes to, never a read on a
// timer.
//
//   - Publish and Subscribe are one-way, to every OTHER pod that listens on a subject.
//     A pod keeps for itself what it already did itself.
//   - Serve, Call, CallPod and Gather are a question: Serve answers it on every pod
//     that can, and the asker hears who did.
//
// Nothing here is stored. A message reaches the pods that were listening when it was
// sent; one sent while the KV was out of reach, or while a pod was reconnecting, is
// lost, and a subscriber that may have missed some is told (gap) and asks for what it
// needs. What must not be lost is kept in the store of record and not sent.
//
// A message is sealed under a key derived from the deployment's master, as the live
// set is signed: the KV accepts a PUBLISH from anything that can reach it and shows
// every message to anything that listens, so a message is unreadable to, and
// unforgeable by, whatever does not hold the master. One nobody holding it sealed is
// dropped unread.
//
// Sealed is not fresh: whatever listens can capture a frame and publish it again, and
// it opens. So a frame also carries its sender's sequence number and the time it was
// sent, under the seal with the channel and the sender. A pod hears a frame once, and
// only within busFresh of its time: one it has heard, one more than busLate numbers
// behind the newest from its sender, and one outside the window are dropped. A sender
// that restarts is a new sender (its name carries a nonce), whose numbers start again.

const (
	// busBehind is how many messages a subscriber may be behind before it is told it
	// missed some. Its handler runs on a goroutine of its own, in order, so a slow one
	// delays only itself.
	busBehind = 1024
	// busQueued and busBytes bound what a pod holds waiting to be sent. A writer never
	// waits on the KV: past either, Publish refuses.
	busQueued = 4096
	busBytes  = 64 << 20
	// callWait is how long a question waits for its answers when its context states no
	// deadline of its own.
	callWait = 5 * time.Second
	// busFresh is how far a frame's time may be from the receiver's clock, either way. A
	// frame older than this is a replay or was held up past use; one this far ahead is
	// from a clock that cannot be trusted with the order.
	busFresh = 30 * time.Second
	// busLate is how many sequence numbers behind the newest from a sender a frame may
	// arrive and still be heard once. Frames of one sender leave on several paths (the
	// queue and a question's own send) and the KV's pool may swap two, so a strict
	// "greater than the last" would drop a message that was never replayed.
	busLate = 1024
	// busHead is the sequence number and the time a frame carries, in the clear and
	// under the seal.
	busHead = 16
)

var (
	// ErrBusy is Publish's refusal when this pod holds as much waiting to be sent as it
	// will.
	ErrBusy = errors.New("coord: the bus is carrying all it will; the message was not sent")
	// ErrNoAnswer is a question some pod that serves it did not answer in time.
	ErrNoAnswer = errors.New("coord: pods that serve the subject did not all answer in time")
)

// bus is what a backend does to carry messages: the KV, or the in-process one.
type Bus interface {
	// publish sends msg on channel and answers how many connections received it.
	Publish(ctx context.Context, channel string, msg []byte) (int, error)
	// subscribe listens on channel and answers when the subscription is active.
	// deliver must not block. gap is called when messages may have been lost.
	Subscribe(channel string, deliver func([]byte), gap func()) (cancel func(), err error)
	Close()
	// exact says whether publish answers how many connections received the message.
	// The KV and the in-process bus do; NATS does not, and a question to one that does
	// not learns who listens from the listeners (ack).
	Exact() bool
}

var (
	_ Bus = (*mem)(nil)
)

// ackWindow is how long the asker of a question on a bus that cannot count its
// listeners waits for them to say they have it. A pod that serves the subject answers
// the moment the question arrives, before it works on it, so this is a network round
// trip and not the length of anyone's work; the answers themselves are then waited for
// as long as the question's context allows.
var ackWindow = 150 * time.Millisecond

// wire is a Coord's use of its backend's bus.
type wire struct {
	c    *Coord
	b    Bus
	seal cipher.AEAD

	sm sync.Mutex // serializes subscribing and unsubscribing on the backend; before mu

	mu      sync.Mutex
	subs    map[string]*sink
	pending map[string]chan reply
	serving map[string]context.CancelFunc // questions this pod is answering, by asker and id
	replies bool                          // the subscription answers to this pod's questions is made
	cancels bool                          // the subscription to askers giving up is made
	closed  bool

	out    chan outgoing
	queued atomic.Int64
	stop   chan struct{}

	sent atomic.Uint64 // the sequence number of the last frame this pod sent

	rm    sync.Mutex
	heard map[string]*lane // what has been heard of each sender still fresh; under rm
}

// lane is what a pod has heard of one sender: the newest sequence number, and which of
// the busLate before it have arrived. Bit i of seen says that high-i has.
type lane struct {
	high uint64
	seen [busLate / 64]uint64
	at   int64 // the newest time heard, unix milliseconds
}

// take records seq and says whether it is new.
func (l *lane) take(seq uint64) bool {
	if seq > l.high {
		l.slide(seq - l.high)
		l.high = seq
		l.seen[0] |= 1
		return true
	}
	back := l.high - seq
	if back >= busLate {
		return false
	}
	word, bit := back/64, back%64
	if l.seen[word]&(1<<bit) != 0 {
		return false
	}
	l.seen[word] |= 1 << bit
	return true
}

// slide moves the newest sequence number by n: what was heard n behind it is now n
// further behind.
func (l *lane) slide(n uint64) {
	if n >= busLate {
		l.seen = [busLate / 64]uint64{}
		return
	}
	words, bits := int(n/64), n%64
	for i := len(l.seen) - 1; i >= 0; i-- {
		var v uint64
		if from := i - words; from >= 0 {
			v = l.seen[from] << bits
			if bits > 0 && from > 0 {
				v |= l.seen[from-1] >> (64 - bits)
			}
		}
		l.seen[i] = v
	}
}

// sink is the handlers of one subject on this pod: one backend subscription serves
// them all.
type sink struct {
	handlers map[*handler]struct{}
	cancel   func()
}

type packet struct {
	from    string
	payload []byte
	gap     bool
}

// handler is one Subscribe: its function, and the goroutine that calls it in order.
type handler struct {
	w    *wire
	fn   func(from string, payload []byte)
	gap  func()
	q    chan packet
	lost atomic.Bool
	stop chan struct{}
	once sync.Once
}

func (h *handler) run() {
	for {
		select {
		case p := <-h.q:
			if h.lost.Swap(false) && h.gap != nil {
				h.w.contained("gap", h.gap)
			}
			if p.gap {
				if h.gap != nil {
					h.w.contained("gap", h.gap)
				}
				continue
			}
			h.w.contained("handler", func() { h.fn(p.from, p.payload) })
		case <-h.stop:
			return
		}
	}
}

// push queues p for the handler, or notes that it fell behind.
func (h *handler) push(p packet) {
	select {
	case h.q <- p:
	default:
		h.lost.Store(true)
	}
}

type outgoing struct {
	subject string
	payload []byte
	size    int64
}

func (c *Coord) wireOf() *wire {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.wire == nil {
		block, _ := aes.NewCipher(derive(c.secret, "hanzo cloud bus v2")) // a 32-byte key: cannot fail
		seal, _ := cipher.NewGCM(block)
		w := &wire{
			c:       c,
			seal:    seal,
			subs:    map[string]*sink{},
			pending: map[string]chan reply{},
			serving: map[string]context.CancelFunc{},
			out:     make(chan outgoing, busQueued),
			stop:    make(chan struct{}),
			heard:   map[string]*lane{},
		}
		w.b, _ = c.b.(Bus)
		if c.bus != nil {
			w.b = c.bus
		}
		c.wire = w
		go w.run()
	}
	return c.wire
}

func (w *wire) channel(subject string) string { return w.c.prefix + "bus:" + subject }

// frame seals payload as sent on subject by this pod, now: the pod, a newline, the next
// sequence number and the time, a nonce and the sealed payload. The pod, the subject,
// the number and the time are under the seal, so a message captured from one subject,
// or one pod, is not accepted as another's, and one captured and sent again is heard
// only if it is still fresh and new (arrive).
func (w *wire) frame(subject string, payload []byte) []byte {
	return w.frameAt(subject, payload, w.sent.Add(1), time.Now().UnixMilli())
}

func (w *wire) frameAt(subject string, payload []byte, seq uint64, stamp int64) []byte {
	owner := w.c.owner
	var head [busHead]byte
	binary.BigEndian.PutUint64(head[:8], seq)
	binary.BigEndian.PutUint64(head[8:], uint64(stamp))
	nonce := make([]byte, w.seal.NonceSize())
	_, _ = rand.Read(nonce)
	out := make([]byte, 0, len(owner)+1+busHead+len(nonce)+len(payload)+w.seal.Overhead())
	out = append(out, owner...)
	out = append(out, '\n')
	out = append(out, head[:]...)
	out = append(out, nonce...)
	return w.seal.Seal(out, nonce, payload, w.bound(w.channel(subject), owner, head[:]))
}

func (w *wire) bound(channel, owner string, head []byte) []byte {
	return append([]byte(channel+"\x00"+owner+"\x00"), head...)
}

// hear says whether a frame from owner, numbered seq and sent at stamp (unix
// milliseconds), is one to deliver at now: within busFresh of now, and not a number
// already heard from owner. Only frames that opened are asked, so a sender is a
// member of the deployment, and what is kept is a few words for each member that
// sent within busFresh: a sender none of whose frames could still be fresh is
// forgotten, and its frames, if sent again, are refused for their time.
func (w *wire) hear(owner string, seq uint64, stamp int64, now time.Time) bool {
	ms, fresh := now.UnixMilli(), busFresh.Milliseconds()
	if age := ms - stamp; age > fresh || -age > fresh {
		return false
	}
	w.rm.Lock()
	defer w.rm.Unlock()
	for o, l := range w.heard {
		if ms-l.at > fresh {
			delete(w.heard, o)
		}
	}
	l := w.heard[owner]
	if l == nil {
		l = &lane{}
		w.heard[owner] = l
	}
	l.at = max(l.at, stamp)
	return l.take(seq)
}

// arrive opens a message and hands it to the subject's handlers. A message from this
// pod is dropped: a pod does for itself what it publishes. So is one that is not
// fresh, or that this pod has heard.
func (w *wire) arrive(subject string, msg []byte) {
	i := bytes.IndexByte(msg, '\n')
	if i < 0 || len(msg) < i+1+busHead+w.seal.NonceSize()+w.seal.Overhead() {
		return
	}
	owner := string(msg[:i])
	if owner == w.c.owner {
		return
	}
	head := msg[i+1 : i+1+busHead]
	rest := msg[i+1+busHead:]
	payload, err := w.seal.Open(nil, rest[:w.seal.NonceSize()], rest[w.seal.NonceSize():], w.bound(w.channel(subject), owner, head))
	if err != nil {
		w.c.log.warn("bus-forged", "coord: a message on the bus is not sealed by this deployment; dropped", "subject", subject)
		return
	}
	if !w.hear(owner, binary.BigEndian.Uint64(head[:8]), int64(binary.BigEndian.Uint64(head[8:])), time.Now()) {
		w.c.log.warn("bus-replayed", "coord: a message on the bus is not fresh or was heard before; dropped", "subject", subject, "from", owner)
		return
	}
	w.mu.Lock()
	var hs []*handler
	if s := w.subs[subject]; s != nil {
		hs = make([]*handler, 0, len(s.handlers))
		for h := range s.handlers {
			hs = append(hs, h)
		}
	}
	w.mu.Unlock()
	for _, h := range hs {
		h.push(packet{from: owner, payload: payload})
	}
}

// lose tells a subject's handlers they may have missed messages.
func (w *wire) lose(subject string) {
	w.mu.Lock()
	var hs []*handler
	if s := w.subs[subject]; s != nil {
		for h := range s.handlers {
			hs = append(hs, h)
		}
	}
	w.mu.Unlock()
	for _, h := range hs {
		select {
		case h.q <- packet{gap: true}:
		default:
			h.lost.Store(true)
		}
	}
}

// send publishes payload now and answers how many OTHER pods received it.
func (w *wire) send(ctx context.Context, subject string, payload []byte) (int, error) {
	if w.b == nil {
		return 0, ErrUnavailable
	}
	n, err := w.b.Publish(ctx, w.channel(subject), w.frame(subject, payload))
	if err != nil {
		return 0, err
	}
	w.mu.Lock()
	_, mine := w.subs[subject]
	w.mu.Unlock()
	if mine && n > 0 {
		n-- // this pod's own subscription received it and dropped it
	}
	return n, nil
}

// run publishes what is queued, in order.
func (w *wire) run() {
	for {
		select {
		case o := <-w.out:
			ctx, cancel := context.WithTimeout(context.Background(), callWait)
			if w.b == nil {
				cancel()
				w.queued.Add(-o.size)
				continue
			}
			if _, err := w.b.Publish(ctx, w.channel(o.subject), w.frame(o.subject, o.payload)); err != nil {
				w.c.log.warn("bus-publish", "coord: the bus is not taking messages; what other pods should have heard is lost", "err", err)
			}
			cancel()
			w.queued.Add(-o.size)
		case <-w.stop:
			return
		}
	}
}

// Publish tells every other pod that Subscribes to subject. It queues the message and
// returns: the pod that wrote does not wait on the KV, and messages leave in the order
// they were queued. Payload is copied.
func (c *Coord) Publish(subject string, payload []byte) error {
	w := c.wireOf()
	w.mu.Lock()
	closed := w.closed
	w.mu.Unlock()
	if closed {
		return ErrUnavailable
	}
	size := int64(len(payload))
	if w.queued.Add(size) > busBytes {
		w.queued.Add(-size)
		return ErrBusy
	}
	select {
	case w.out <- outgoing{subject: subject, payload: bytes.Clone(payload), size: size}:
		return nil
	default:
		w.queued.Add(-size)
		return ErrBusy
	}
}

// Subscribe calls fn with each message another pod publishes on subject, in the order
// they arrived, on a goroutine of its own. payload is shared with other subscribers
// of the subject: fn must not change it. gap, if not nil, is called when messages may
// have been lost: the KV dropped this pod's connection, or fn fell busBehind. It
// answers the function that stops listening.
//
// It answers when the subscription is active, so a message published after it
// returns is received.
func (c *Coord) Subscribe(subject string, fn func(from string, payload []byte), gap func()) func() {
	w := c.wireOf()
	h := &handler{w: w, fn: fn, gap: gap, q: make(chan packet, busBehind), stop: make(chan struct{})}
	w.sm.Lock()
	defer w.sm.Unlock()
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return func() {}
	}
	s := w.subs[subject]
	if s == nil {
		s = &sink{handlers: map[*handler]struct{}{}}
		w.subs[subject] = s
	}
	first := len(s.handlers) == 0
	s.handlers[h] = struct{}{}
	w.mu.Unlock()
	go h.run()
	if first && w.b != nil {
		cancel, err := w.b.Subscribe(w.channel(subject), func(m []byte) { w.arrive(subject, m) }, func() { w.lose(subject) })
		if err != nil {
			c.log.warn("bus-subscribe", "coord: cannot listen on the bus", "subject", subject, "err", err)
		} else {
			w.mu.Lock()
			s.cancel = cancel
			w.mu.Unlock()
		}
	}
	return func() { w.remove(subject, h) }
}

func (w *wire) remove(subject string, h *handler) {
	w.sm.Lock()
	defer w.sm.Unlock()
	w.mu.Lock()
	s := w.subs[subject]
	if s == nil {
		w.mu.Unlock()
		return
	}
	if _, ok := s.handlers[h]; !ok {
		w.mu.Unlock()
		return
	}
	delete(s.handlers, h)
	last := len(s.handlers) == 0
	cancel := s.cancel
	if last {
		delete(w.subs, subject)
	}
	w.mu.Unlock()
	h.once.Do(func() { close(h.stop) })
	if last && cancel != nil {
		cancel()
	}
}

// contained runs f and keeps a panic in it from taking the pod down: a handler is
// app code answering a message another pod chose to send.
func (w *wire) contained(what string, f func()) {
	defer func() {
		if r := recover(); r != nil {
			w.c.log.warn("bus-panic:"+what, "coord: a handler of the bus panicked; the message is dropped", "handler", what, "panic", fmt.Sprint(r))
		}
	}()
	f()
}

// closeWire ends everything this pod listens on and sends.
func (c *Coord) closeWire() {
	c.mu.Lock()
	w := c.wire
	c.mu.Unlock()
	if w == nil {
		return
	}
	w.sm.Lock()
	defer w.sm.Unlock()
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return
	}
	w.closed = true
	var cancels []func()
	for _, s := range w.subs {
		if s.cancel != nil {
			cancels = append(cancels, s.cancel)
		}
		for h := range s.handlers {
			h.once.Do(func() { close(h.stop) })
		}
	}
	w.subs = map[string]*sink{}
	w.mu.Unlock()
	close(w.stop)
	for _, cancel := range cancels {
		cancel()
	}
	if w.b != nil {
		w.b.Close()
	}
}

// ----- questions ------------------------------------------------------------

// Answer is one pod's yes to a question.
type Answer struct {
	// From names the pod, for CallPod.
	From string
	Body []byte
}

type reply struct {
	from string
	yes  bool
	ack  bool // the pod has the question and is working on it; no answer yet
	body []byte
}

// Serve answers the question subject on this pod: h is called with the asker and the
// question, and says whether this pod can answer and what. A pod that cannot says
// no, which is how the asker learns it has heard from everyone. Serve a subject once
// per pod; the caller of Call asks the OTHER pods, so it tries its own first.
//
// ctx ends when the asker gives up (its context ended) or this pod closes, so a
// question that waits on something, a person or a tool, stops waiting with the one
// who asked it. An answer to an asker that has gone is not sent.
func (c *Coord) Serve(subject string, h func(ctx context.Context, from string, body []byte) (answer []byte, yes bool)) func() {
	w := c.wireOf()
	w.hearCancels()
	fn := func(from string, req []byte) {
		id, to, body, ok := splitRequest(req)
		if !ok {
			return
		}
		if wantsAck(id) {
			_ = w.enqueue(to, joinAck(id))
		}
		ctx, cancel := context.WithCancel(context.Background())
		key := from + "/" + id
		w.mu.Lock()
		w.serving[key] = cancel
		w.mu.Unlock()
		go func() {
			defer func() {
				cancel()
				w.mu.Lock()
				delete(w.serving, key)
				w.mu.Unlock()
			}()
			var out []byte
			yes := false
			w.contained("serve", func() { out, yes = h(ctx, from, body) })
			if ctx.Err() == nil {
				_ = w.enqueue(to, joinReply(id, yes, out))
			}
		}()
	}
	one := c.Subscribe("call/"+subject, fn, nil)
	two := c.Subscribe("call/"+subject+"/"+c.owner, fn, nil)
	return func() { one(); two() }
}

// hearCancels listens, once, for askers that gave up.
func (w *wire) hearCancels() {
	w.mu.Lock()
	done := w.cancels
	w.cancels = true
	w.mu.Unlock()
	if done {
		return
	}
	w.c.Subscribe("cancel", func(from string, id []byte) {
		w.mu.Lock()
		cancel := w.serving[from+"/"+string(id)]
		w.mu.Unlock()
		if cancel != nil {
			cancel()
		}
	}, nil)
}

// enqueue is Publish for a caller that holds the wire.
func (w *wire) enqueue(subject string, payload []byte) error { return w.c.Publish(subject, payload) }

// Call asks every other pod that Serves subject and answers the first yes, or false
// when every one of them said no (or none serves it). It does not wait for the rest
// once it has a yes.
func (c *Coord) Call(ctx context.Context, subject string, body []byte) (Answer, bool, error) {
	as, err := c.exchange(ctx, "call/"+subject, body, true)
	if len(as) == 0 {
		return Answer{}, false, err
	}
	return as[0], true, nil
}

// CallPod asks one pod, named by an Answer's From or a subscriber's from.
func (c *Coord) CallPod(ctx context.Context, pod, subject string, body []byte) (Answer, bool, error) {
	as, err := c.exchange(ctx, "call/"+subject+"/"+pod, body, true)
	if len(as) == 0 {
		return Answer{}, false, err
	}
	return as[0], true, nil
}

// Gather asks every other pod that Serves subject and answers every yes. When some
// pod did not answer in time it answers the yeses it has and ErrNoAnswer.
func (c *Coord) Gather(ctx context.Context, subject string, body []byte) ([]Answer, error) {
	return c.exchange(ctx, "call/"+subject, body, false)
}

func (c *Coord) exchange(ctx context.Context, subject string, body []byte, first bool) ([]Answer, error) {
	w := c.wireOf()
	if err := w.listen(); err != nil {
		return nil, err
	}
	var raw [8]byte
	_, _ = rand.Read(raw[:])
	id := hex.EncodeToString(raw[:])
	// A bus that cannot count its listeners is asked to have them say so: the id
	// carries the request, and every pod that serves the subject answers with an ack
	// before it works.
	acks := w.b != nil && !w.b.Exact()
	if acks {
		id += ackMark
	}
	ch := make(chan reply, 64)
	w.mu.Lock()
	w.pending[id] = ch
	w.mu.Unlock()
	defer func() {
		w.mu.Lock()
		delete(w.pending, id)
		w.mu.Unlock()
	}()
	if _, has := ctx.Deadline(); !has {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, callWait)
		defer cancel()
	}
	n, err := w.send(ctx, subject, joinRequest(id, "reply/"+c.owner, body))
	if err != nil {
		return nil, err
	}
	var (
		out    []Answer
		window <-chan time.Time
		heard  map[string]bool // pods that acked inside the window
		got    int             // answers from those pods
	)
	if acks {
		t := time.NewTimer(ackWindow)
		defer t.Stop()
		window, heard, n = t.C, map[string]bool{}, -1
	}
	for n < 0 || got < n {
		select {
		case r := <-ch:
			if r.ack {
				if window != nil {
					heard[r.from] = true
				}
				continue
			}
			if acks && !heard[r.from] {
				// Not counted among those the question waits for, but an answer is an
				// answer.
				if r.yes {
					out = append(out, Answer{From: r.from, Body: r.body})
					if first {
						return out, nil
					}
				}
				continue
			}
			got++
			if !r.yes {
				continue
			}
			out = append(out, Answer{From: r.from, Body: r.body})
			if first {
				return out, nil
			}
		case <-window:
			// The listeners have said so: that many are waited for, and no more.
			n, window = len(heard), nil
		case <-ctx.Done():
			// The asker gave up: the pods still working on the question are told, so a
			// question that waits does not wait for nobody.
			_ = w.enqueue("cancel", []byte(id))
			return out, ErrNoAnswer
		}
	}
	return out, nil
}

// listen subscribes to the answers to this pod's questions, once.
func (w *wire) listen() error {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return ErrUnavailable
	}
	done := w.replies
	w.replies = true
	w.mu.Unlock()
	if done {
		return nil
	}
	w.c.Subscribe("reply/"+w.c.owner, func(from string, p []byte) {
		id, yes, ack, body, ok := splitReply(p)
		if !ok {
			return
		}
		w.mu.Lock()
		ch := w.pending[id]
		w.mu.Unlock()
		if ch != nil {
			select {
			case ch <- reply{from: from, yes: yes, ack: ack, body: body}:
			default:
			}
		}
	}, nil)
	return nil
}

// A request is its id, where to answer and the question, each ended by a zero byte
// but the last; a reply is the id, 1 for yes or 0 for no, and the answer.
func joinRequest(id, to string, body []byte) []byte {
	out := make([]byte, 0, len(id)+len(to)+2+len(body))
	out = append(out, id...)
	out = append(out, 0)
	out = append(out, to...)
	out = append(out, 0)
	return append(out, body...)
}

func splitRequest(p []byte) (id, to string, body []byte, ok bool) {
	i := bytes.IndexByte(p, 0)
	if i < 0 {
		return "", "", nil, false
	}
	j := bytes.IndexByte(p[i+1:], 0)
	if j < 0 {
		return "", "", nil, false
	}
	return string(p[:i]), string(p[i+1 : i+1+j]), p[i+j+2:], true
}

func joinReply(id string, yes bool, body []byte) []byte {
	out := make([]byte, 0, len(id)+2+len(body))
	out = append(out, id...)
	out = append(out, 0)
	if yes {
		out = append(out, 1)
	} else {
		out = append(out, 0)
	}
	return append(out, body...)
}

func splitReply(p []byte) (id string, yes, ack bool, body []byte, ok bool) {
	i := bytes.IndexByte(p, 0)
	if i < 0 || len(p) < i+2 {
		return "", false, false, nil, false
	}
	return string(p[:i]), p[i+1] == 1, p[i+1] == 2, p[i+2:], true
}

// ackMark ends the id of a question that asks its listeners to say they have it.
const ackMark = "!"

func wantsAck(id string) bool { return strings.HasSuffix(id, ackMark) }

// joinAck is a reply that is neither yes nor no: this pod has the question.
func joinAck(id string) []byte {
	out := make([]byte, 0, len(id)+2)
	out = append(out, id...)
	return append(out, 0, 2)
}
