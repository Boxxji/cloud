package coord

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// THE BUS ON BOTH BACKENDS. Pods share a KV (a real server's protocol, in process) or
// the in-process one; a message sent by one reaches the others and never its sender.

// deployment is a set of pods on one backend.
type deployment struct {
	name string
	pod  func(id string) *Coord
	// rogue is a pod that shares the backend but not the deployment's master key.
	rogue func(id string) *Coord
	// restart drops every connection to the backend and brings it back; nil when the
	// backend has none.
	restart func()
	// listeners is how many connections listen on a subject, as the backend counts.
	listeners func(c *Coord, subject string) int
}

func deployments(t *testing.T) []deployment {
	t.Helper()
	m := NewMemory()
	mem := deployment{
		name: "in process",
		pod: func(id string) *Coord {
			c := m.Pod(id)
			t.Cleanup(func() { c.Close(context.Background()) })
			return c
		},
		rogue: func(id string) *Coord {
			c := over(m.b, newMem(), true, Config{Periods: fast, Deployment: "memory", Self: Member{ID: id}, Instance: id, Secret: []byte("not the master key, but long enough")})
			t.Cleanup(func() { c.Close(context.Background()) })
			return c
		},
		listeners: func(c *Coord, subject string) int {
			m.b.mu.Lock()
			defer m.b.mu.Unlock()
			return len(m.b.chans[c.wireOf().channel(subject)])
		},
	}
	return []deployment{mem}
}

func each(t *testing.T, f func(t *testing.T, d deployment)) {
	t.Helper()
	for _, d := range deployments(t) {
		t.Run(d.name, func(t *testing.T) { f(t, d) })
	}
}

type heard struct {
	mu   sync.Mutex
	from []string
	got  []string
}

func (h *heard) hear(from string, p []byte) {
	h.mu.Lock()
	h.from = append(h.from, from)
	h.got = append(h.got, string(p))
	h.mu.Unlock()
}

func (h *heard) n() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.got)
}

func (h *heard) all() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.got...)
}

// Every other pod that listens hears every message, in the order it was sent, and
// the pod that sent it hears none of its own.
func TestPublishReachesTheOtherPodsInOrder(t *testing.T) {
	each(t, func(t *testing.T, d deployment) {
		a, b, c := d.pod("cloud-0"), d.pod("cloud-1"), d.pod("cloud-2")
		var hb, hc, ha heard
		defer a.Subscribe("room", ha.hear, nil)()
		defer b.Subscribe("room", hb.hear, nil)()
		defer c.Subscribe("room", hc.hear, nil)()
		const n = 300
		for i := range n {
			if err := a.Publish("room", fmt.Appendf(nil, "m%d", i)); err != nil {
				t.Fatal(err)
			}
		}
		eventually(t, 5*time.Second, "both other pods hear all 300", func() bool { return hb.n() == n && hc.n() == n })
		for i, got := range hb.all() {
			if want := fmt.Sprintf("m%d", i); got != want {
				t.Fatalf("pod b heard %q at %d, want %q: order is lost", got, i, want)
			}
		}
		if hb.from[0] != a.owner || hc.from[0] != a.owner {
			t.Fatalf("heard from %q and %q, want the sender %q", hb.from[0], hc.from[0], a.owner)
		}
		time.Sleep(50 * time.Millisecond)
		if got := ha.n(); got != 0 {
			t.Fatalf("the sender heard %d of its own messages", got)
		}
	})
}

// A subject is its own: a pod listening on one hears nothing sent on another.
func TestAPodHearsOnlyWhatItListensTo(t *testing.T) {
	each(t, func(t *testing.T, d deployment) {
		a, b := d.pod("cloud-0"), d.pod("cloud-1")
		var one, two heard
		defer b.Subscribe("one", one.hear, nil)()
		defer b.Subscribe("two", two.hear, nil)()
		_ = a.Publish("one", []byte("x"))
		eventually(t, 3*time.Second, "one hears x", func() bool { return one.n() == 1 })
		time.Sleep(50 * time.Millisecond)
		if two.n() != 0 {
			t.Fatalf("a listener on two heard %v", two.all())
		}
	})
}

// A message nobody holding the master key signed is dropped unread: not one signed
// under another key, not raw bytes, and not a real one moved to another subject.
func TestAForgedMessageIsDropped(t *testing.T) {
	each(t, func(t *testing.T, d deployment) {
		a, b, evil := d.pod("cloud-0"), d.pod("cloud-1"), d.rogue("evil")
		var hb, other heard
		defer b.Subscribe("room", hb.hear, nil)()
		defer b.Subscribe("elsewhere", other.hear, nil)()
		ctx := context.Background()

		// Signed under another master key.
		if _, err := evil.wireOf().send(ctx, "room", []byte("planted")); err != nil {
			t.Fatal(err)
		}
		// Raw bytes on the channel.
		if _, err := a.wireOf().b.Publish(ctx, a.wireOf().channel("room"), []byte("not a frame at all, but longer than a signature plus a name")); err != nil {
			t.Fatal(err)
		}
		// A genuine frame for "room" replayed on "elsewhere".
		if _, err := a.wireOf().b.Publish(ctx, a.wireOf().channel("elsewhere"), a.wireOf().frame("room", []byte("moved"))); err != nil {
			t.Fatal(err)
		}
		// A genuine frame of a's, claimed by b.
		stolen := append([]byte(b.owner+"\n"), a.wireOf().frame("room", []byte("as b"))[len(a.owner)+1:]...)
		if _, err := a.wireOf().b.Publish(ctx, a.wireOf().channel("room"), stolen); err != nil {
			t.Fatal(err)
		}
		// A genuine one, to prove the listener was there to hear.
		_ = a.Publish("room", []byte("real"))
		eventually(t, 3*time.Second, "the real message arrives", func() bool { return hb.n() >= 1 })
		time.Sleep(50 * time.Millisecond)
		if got := hb.all(); len(got) != 1 || got[0] != "real" {
			t.Fatalf("room heard %q, want only the real message", got)
		}
		if other.n() != 0 {
			t.Fatalf("a message signed for another subject was accepted: %q", other.all())
		}
	})
}

// A question goes to every other pod that serves it, and the first yes comes back; a
// pod that says no is how the asker learns it has heard from everyone, so a question
// nobody can answer is answered at once and not when a timer runs out.
func TestAQuestionIsAnsweredByThePodThatCan(t *testing.T) {
	each(t, func(t *testing.T, d deployment) {
		a, b, c := d.pod("cloud-0"), d.pod("cloud-1"), d.pod("cloud-2")
		var asked atomic.Int32
		defer b.Serve("run", func(_ context.Context, from string, q []byte) ([]byte, bool) {
			asked.Add(1)
			return []byte("b has " + string(q)), string(q) == "r1"
		})()
		defer c.Serve("run", func(_ context.Context, from string, q []byte) ([]byte, bool) {
			asked.Add(1)
			return []byte("c has " + string(q)), string(q) == "r2"
		})()
		ctx := context.Background()

		ans, ok, err := a.Call(ctx, "run", []byte("r2"))
		if err != nil || !ok || string(ans.Body) != "c has r2" || ans.From != c.owner {
			t.Fatalf("r2 is on c: got %q from %q ok %v err %v", ans.Body, ans.From, ok, err)
		}
		ans, ok, err = a.Call(ctx, "run", []byte("r1"))
		if err != nil || !ok || string(ans.Body) != "b has r1" || ans.From != b.owner {
			t.Fatalf("r1 is on b: got %q from %q ok %v err %v", ans.Body, ans.From, ok, err)
		}

		start := time.Now()
		_, ok, err = a.Call(ctx, "run", []byte("r3"))
		if err != nil || ok {
			t.Fatalf("r3 is nowhere: ok %v err %v", ok, err)
		}
		if took := time.Since(start); took > time.Second {
			t.Fatalf("a question nobody can answer took %v: it waited for a timer", took)
		}
		_, ok, err = a.Call(ctx, "nobody serves this", nil)
		if err != nil || ok {
			t.Fatalf("a subject nobody serves: ok %v err %v", ok, err)
		}

		// One pod, by name: the pod that answered earlier is asked again, and no other.
		before := asked.Load()
		ans, ok, err = a.CallPod(ctx, b.owner, "run", []byte("r1"))
		if err != nil || !ok || string(ans.Body) != "b has r1" {
			t.Fatalf("calling b by name: %q ok %v err %v", ans.Body, ok, err)
		}
		if asked.Load() != before+1 {
			t.Fatalf("calling one pod asked %d", asked.Load()-before)
		}
		if _, ok, _ := a.CallPod(ctx, "a pod that is not there", "run", []byte("r1")); ok {
			t.Fatal("a pod that is not there answered")
		}

		// Everyone who can answer does.
		all, err := a.Gather(ctx, "run", []byte("r1"))
		if err != nil || len(all) != 1 || all[0].From != b.owner {
			t.Fatalf("gather r1: %v %v", all, err)
		}
	})
}

// Gather is every yes.
func TestGatherAnswersEveryYes(t *testing.T) {
	each(t, func(t *testing.T, d deployment) {
		a, b, c := d.pod("cloud-0"), d.pod("cloud-1"), d.pod("cloud-2")
		defer b.Serve("who", func(context.Context, string, []byte) ([]byte, bool) { return []byte("b"), true })()
		defer c.Serve("who", func(context.Context, string, []byte) ([]byte, bool) { return []byte("c"), true })()
		got, err := a.Gather(context.Background(), "who", nil)
		if err != nil || len(got) != 2 {
			t.Fatalf("gather: %v %v", got, err)
		}
		names := string(got[0].Body) + string(got[1].Body)
		if names != "bc" && names != "cb" {
			t.Fatalf("gather answered %q", names)
		}
	})
}

// A pod that listens through a reconnect is told it was deaf, and hears again.
func TestAReconnectIsAGap(t *testing.T) {
	for _, d := range deployments(t) {
		if d.restart == nil {
			continue
		}
		t.Run(d.name, func(t *testing.T) {
			a, b := d.pod("cloud-0"), d.pod("cloud-1")
			var hb heard
			var gaps atomic.Int32
			defer b.Subscribe("room", hb.hear, func() { gaps.Add(1) })()
			_ = a.Publish("room", []byte("before"))
			eventually(t, 3*time.Second, "before is heard", func() bool { return hb.n() == 1 })
			if gaps.Load() != 0 {
				t.Fatalf("a first subscription is no gap, got %d", gaps.Load())
			}
			d.restart()
			eventually(t, 10*time.Second, "the listener is told it was deaf", func() bool { return gaps.Load() >= 1 })
			eventually(t, 10*time.Second, "messages flow again", func() bool {
				_ = a.Publish("room", []byte("after"))
				return hb.n() >= 2
			})
		})
	}
}

// A handler that cannot keep up does not hold up the pod, and is told it missed some.
func TestASlowHandlerIsToldItFellBehind(t *testing.T) {
	each(t, func(t *testing.T, d deployment) {
		a, b := d.pod("cloud-0"), d.pod("cloud-1")
		release := make(chan struct{})
		var got atomic.Int32
		var gaps atomic.Int32
		stop := b.Subscribe("room", func(string, []byte) {
			<-release
			got.Add(1)
		}, func() { gaps.Add(1) })
		defer stop()
		var fast heard
		defer b.Subscribe("room", fast.hear, nil)()
		const n = busBehind + 100
		for i := range n {
			if err := a.Publish("room", fmt.Appendf(nil, "%d", i)); err != nil {
				t.Fatal(err)
			}
			// Keep the fast handler within reach: a burst faster than any handler is
			// exactly what is being told it fell behind.
			for i-fast.n() > busBehind/2 {
				time.Sleep(time.Millisecond)
			}
		}
		eventually(t, 5*time.Second, "the fast handler on the same subject hears all of it", func() bool { return fast.n() == n })
		close(release)
		eventually(t, 5*time.Second, "the slow one is told it missed some", func() bool { return gaps.Load() >= 1 })
	})
}

// A pod that stops listening is no longer a listener, and one listener leaving does
// not take the other's subscription with it.
func TestStoppingListeningLeavesTheOthersAlone(t *testing.T) {
	each(t, func(t *testing.T, d deployment) {
		a, b := d.pod("cloud-0"), d.pod("cloud-1")
		var one, two heard
		stopOne := b.Subscribe("room", one.hear, nil)
		stopTwo := b.Subscribe("room", two.hear, nil)
		if n := d.listeners(b, "room"); n != 1 {
			t.Fatalf("two handlers on one subject use %d subscriptions, want 1", n)
		}
		stopOne()
		_ = a.Publish("room", []byte("x"))
		eventually(t, 3*time.Second, "the remaining handler hears", func() bool { return two.n() == 1 })
		if one.n() != 0 {
			t.Fatal("a stopped handler heard")
		}
		stopTwo()
		stopTwo() // idempotent
		eventually(t, 3*time.Second, "no subscription is left", func() bool { return d.listeners(b, "room") == 0 })
	})
}

// A pod that has more waiting to go than it will hold refuses, instead of growing.
func TestPublishRefusesPastWhatItWillHold(t *testing.T) {
	each(t, func(t *testing.T, d deployment) {
		a := d.pod("cloud-0")
		if err := a.Publish("room", make([]byte, busBytes+1)); err != ErrBusy {
			t.Fatalf("a message past the limit: %v, want ErrBusy", err)
		}
	})
}

// A pod that is alone has no one to tell or ask, and says so at once.
func TestAlonePodHasNoOneToAsk(t *testing.T) {
	a := Alone()
	t.Cleanup(func() { a.Close(context.Background()) })
	if err := a.Publish("room", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := a.Call(context.Background(), "run", nil); ok || err != nil {
		t.Fatalf("a call with no one else: ok %v err %v", ok, err)
	}
}

// The payload a subscriber is given is the sender's bytes, whatever they hold.
func TestPayloadsCrossIntact(t *testing.T) {
	each(t, func(t *testing.T, d deployment) {
		a, b := d.pod("cloud-0"), d.pod("cloud-1")
		var got [][]byte
		var mu sync.Mutex
		defer b.Subscribe("room", func(_ string, p []byte) {
			mu.Lock()
			got = append(got, append([]byte(nil), p...))
			mu.Unlock()
		}, nil)()
		want := [][]byte{{}, {0}, {'\n', 0, '\n'}, bytes.Repeat([]byte{0xff, 0}, 1<<19)}
		for _, w := range want {
			_ = a.Publish("room", w)
		}
		eventually(t, 5*time.Second, "four messages", func() bool { mu.Lock(); defer mu.Unlock(); return len(got) == len(want) })
		for i := range want {
			if !bytes.Equal(got[i], want[i]) {
				t.Fatalf("message %d changed on the way: %d bytes in, %d out", i, len(want[i]), len(got[i]))
			}
		}
	})
}

// What the KV carries is unreadable to whatever listens to it but a pod of the
// deployment: a message is a chat line or a run's prompt.
func TestTheKVCarriesNoPlaintext(t *testing.T) {
	each(t, func(t *testing.T, d deployment) {
		a := d.pod("cloud-0")
		var mu sync.Mutex
		var raw [][]byte
		cancel, err := a.wireOf().b.Subscribe(a.wireOf().channel("room"), func(m []byte) {
			mu.Lock()
			raw = append(raw, append([]byte(nil), m...))
			mu.Unlock()
		}, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer cancel()
		secret := []byte("the chat line nobody else may read")
		_ = a.Publish("room", secret)
		eventually(t, 3*time.Second, "the message crosses", func() bool { mu.Lock(); defer mu.Unlock(); return len(raw) == 1 })
		mu.Lock()
		defer mu.Unlock()
		if bytes.Contains(raw[0], secret) {
			t.Fatal("the payload crossed the KV in the clear")
		}
	})
}

// A handler that panics on a message does not take the pod down, nor the handlers
// after it, nor a question it was asked: the asker hears no.
func TestAPanickingHandlerIsContained(t *testing.T) {
	each(t, func(t *testing.T, d deployment) {
		a, b := d.pod("cloud-0"), d.pod("cloud-1")
		var after heard
		defer b.Subscribe("room", func(_ string, p []byte) {
			if string(p) == "boom" {
				panic("a malformed message")
			}
			after.hear("", p)
		}, nil)()
		defer b.Serve("ask", func(context.Context, string, []byte) ([]byte, bool) { panic("a malformed question") })()
		_ = a.Publish("room", []byte("boom"))
		_ = a.Publish("room", []byte("fine"))
		eventually(t, 3*time.Second, "the handler goes on after a panic", func() bool { return after.n() == 1 })
		start := time.Now()
		_, ok, err := a.Call(context.Background(), "ask", nil)
		if ok || err != nil || time.Since(start) > time.Second {
			t.Fatalf("a question whose handler panicked: ok %v err %v after %v, want an immediate no", ok, err, time.Since(start))
		}
	})
}

// A question that waits on something (a person, a tool) stops waiting with the one
// who asked it: when the asker gives up, the pod answering is told, and no answer is
// sent to nobody.
func TestAnAskerThatGivesUpCancelsTheQuestion(t *testing.T) {
	each(t, func(t *testing.T, d deployment) {
		a, b := d.pod("cloud-0"), d.pod("cloud-1")
		started, cancelled := make(chan struct{}), make(chan struct{})
		defer b.Serve("wait", func(ctx context.Context, _ string, _ []byte) ([]byte, bool) {
			close(started)
			<-ctx.Done()
			close(cancelled)
			return []byte("too late"), true
		})()
		ctx, cancel := context.WithCancel(context.Background())
		gone := make(chan error, 1)
		go func() {
			_, _, err := a.Call(ctx, "wait", nil)
			gone <- err
		}()
		select {
		case <-started:
		case <-time.After(3 * time.Second):
			t.Fatal("the question never reached the pod that serves it")
		}
		cancel()
		select {
		case <-cancelled:
		case <-time.After(3 * time.Second):
			t.Fatal("the pod answering was never told the asker gave up")
		}
		if err := <-gone; err != ErrNoAnswer {
			t.Fatalf("the asker that gave up got %v, want ErrNoAnswer", err)
		}

		// A question whose deadline passes is given up the same way.
		again := make(chan struct{})
		defer b.Serve("slow", func(ctx context.Context, _ string, _ []byte) ([]byte, bool) {
			<-ctx.Done()
			close(again)
			return nil, true
		})()
		short, stop := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer stop()
		if _, _, err := a.Call(short, "slow", nil); err != ErrNoAnswer {
			t.Fatalf("a question past its deadline: %v", err)
		}
		select {
		case <-again:
		case <-time.After(3 * time.Second):
			t.Fatal("a question past its deadline kept the pod waiting")
		}
	})
}
