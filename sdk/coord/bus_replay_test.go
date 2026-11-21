package coord

import (
	"context"
	"sync"
	"testing"
	"time"
)

// A frame is sealed, and sealed is not fresh: whatever listens on the KV can publish
// what it captured again, and it opens. A pod hears a frame once.

// capture records the frames published on subject, as the KV carries them.
type capture struct {
	mu     sync.Mutex
	frames [][]byte
}

func (c *capture) all() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([][]byte(nil), c.frames...)
}

func listen(t *testing.T, c *Coord, subject string) *capture {
	t.Helper()
	var got capture
	cancel, err := c.wireOf().b.Subscribe(c.wireOf().channel(subject), func(m []byte) {
		got.mu.Lock()
		got.frames = append(got.frames, append([]byte(nil), m...))
		got.mu.Unlock()
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cancel)
	return &got
}

// A frame captured off the bus and published again is refused, and the real message
// after it is not.
func TestAReplayedFrameIsRefused(t *testing.T) {
	each(t, func(t *testing.T, d deployment) {
		a, b := d.pod("cloud-0"), d.pod("cloud-1")
		var hb heard
		defer b.Subscribe("room", hb.hear, nil)()
		tap := listen(t, a, "room")
		ctx := context.Background()

		if err := a.Publish("room", []byte("once")); err != nil {
			t.Fatal(err)
		}
		eventually(t, 3*time.Second, "the message crosses", func() bool { return hb.n() == 1 && len(tap.all()) == 1 })

		for range 3 {
			if _, err := a.wireOf().b.Publish(ctx, a.wireOf().channel("room"), tap.all()[0]); err != nil {
				t.Fatal(err)
			}
		}
		if err := a.Publish("room", []byte("twice")); err != nil {
			t.Fatal(err)
		}
		eventually(t, 3*time.Second, "the next real message arrives", func() bool { return hb.n() >= 2 })
		time.Sleep(50 * time.Millisecond)
		if got := hb.all(); len(got) != 2 || got[0] != "once" || got[1] != "twice" {
			t.Fatalf("room heard %q, want once and twice, each once", got)
		}
	})
}

// A frame outside the window is refused whatever its number: an old capture, and one
// from a clock that is ahead.
func TestAFrameOutsideTheWindowIsRefused(t *testing.T) {
	each(t, func(t *testing.T, d deployment) {
		a, b := d.pod("cloud-0"), d.pod("cloud-1")
		var hb heard
		defer b.Subscribe("room", hb.hear, nil)()
		w, ctx := a.wireOf(), context.Background()
		now := time.Now()
		for i, stamp := range []time.Time{now.Add(-busFresh - 5*time.Second), now.Add(busFresh + 5*time.Second)} {
			if _, err := w.b.Publish(ctx, w.channel("room"), w.frameAt("room", []byte("stale"), uint64(100+i), stamp.UnixMilli())); err != nil {
				t.Fatal(err)
			}
		}
		// Just inside, both ways, is heard.
		for i, stamp := range []time.Time{now.Add(-busFresh + 5*time.Second), now.Add(busFresh - 5*time.Second)} {
			if _, err := w.b.Publish(ctx, w.channel("room"), w.frameAt("room", []byte("fresh"), uint64(200+i), stamp.UnixMilli())); err != nil {
				t.Fatal(err)
			}
		}
		eventually(t, 3*time.Second, "the fresh frames arrive", func() bool { return hb.n() >= 2 })
		time.Sleep(50 * time.Millisecond)
		if got := hb.all(); len(got) != 2 || got[0] != "fresh" || got[1] != "fresh" {
			t.Fatalf("room heard %q, want the two fresh frames and neither stale one", got)
		}
	})
}

// Frames of one sender may arrive out of order, each is heard once, and one too far
// behind the newest is not heard at all.
func TestFramesOutOfOrderAreEachHeardOnce(t *testing.T) {
	each(t, func(t *testing.T, d deployment) {
		a, b := d.pod("cloud-0"), d.pod("cloud-1")
		var hb heard
		defer b.Subscribe("room", hb.hear, nil)()
		w, ctx := a.wireOf(), context.Background()
		send := func(seq uint64, body string) {
			t.Helper()
			if _, err := w.b.Publish(ctx, w.channel("room"), w.frameAt("room", []byte(body), seq, time.Now().UnixMilli())); err != nil {
				t.Fatal(err)
			}
		}
		send(10, "ten")
		send(8, "eight")
		send(9, "nine")
		send(10, "ten again")
		send(8, "eight again")
		send(10+busLate, "far ahead") // the window slides: ten is now busLate behind and gone
		send(10, "ten, late")
		send(11+busLate, "end")
		eventually(t, 3*time.Second, "the last frame arrives", func() bool { return hb.n() >= 5 })
		time.Sleep(50 * time.Millisecond)
		want := []string{"ten", "eight", "nine", "far ahead", "end"}
		got := hb.all()
		if len(got) != len(want) {
			t.Fatalf("room heard %q, want %q", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("room heard %q, want %q", got, want)
			}
		}
	})
}

// A pod that restarts is a new sender: its numbers start again and are heard, while
// the old sender's last frame, sent again, is not.
func TestARestartedSenderIsANewSender(t *testing.T) {
	each(t, func(t *testing.T, d deployment) {
		b := d.pod("cloud-1")
		var hb heard
		defer b.Subscribe("room", hb.hear, nil)()
		first := d.pod("cloud-0")
		tap := listen(t, first, "room")
		for i := range 3 {
			if err := first.Publish("room", []byte{byte('a' + i)}); err != nil {
				t.Fatal(err)
			}
		}
		eventually(t, 3*time.Second, "the first run is heard", func() bool { return hb.n() == 3 && len(tap.all()) == 3 })
		first.Close(context.Background())

		second := d.pod("cloud-0")
		if second.owner == first.owner {
			t.Fatal("a restarted pod kept its sender name")
		}
		if err := second.Publish("room", []byte("z")); err != nil {
			t.Fatal(err)
		}
		eventually(t, 3*time.Second, "the restarted pod is heard from its first number", func() bool { return hb.n() == 4 })
		if _, err := second.wireOf().b.Publish(context.Background(), second.wireOf().channel("room"), tap.all()[2]); err != nil {
			t.Fatal(err)
		}
		time.Sleep(50 * time.Millisecond)
		if got := hb.all(); len(got) != 4 || got[3] != "z" {
			t.Fatalf("room heard %q, want the first run once and the restart", got)
		}
	})
}

// What a pod keeps of its senders is bounded by the senders that spoke within the
// window: a sender that has been quiet longer is forgotten, and a flood of numbers from
// one sender is a few words.
func TestWhatIsHeardOfSendersIsBounded(t *testing.T) {
	m := NewMemory()
	b := m.Pod("cloud-1")
	t.Cleanup(func() { b.Close(context.Background()) })
	w := b.wireOf()
	t0 := time.Now()
	for i := range 200 {
		owner := "cloud-" + string(rune('A'+i%26)) + string(rune('a'+i/26)) + "#x"
		if !w.hear(owner, 1, t0.UnixMilli(), t0) {
			t.Fatalf("the first frame of %s was refused", owner)
		}
	}
	if got := len(w.heard); got != 200 {
		t.Fatalf("%d senders kept, want 200 that spoke just now", got)
	}
	later := t0.Add(busFresh + time.Second)
	if !w.hear("cloud-new#y", 1, later.UnixMilli(), later) {
		t.Fatal("a new sender's first frame was refused")
	}
	if got := len(w.heard); got != 1 {
		t.Fatalf("%d senders kept after the others fell quiet for the window, want only the new one", got)
	}
	for seq := uint64(1); seq <= 100000; seq++ {
		if !w.hear("cloud-new#y", seq+1, later.UnixMilli(), later) {
			t.Fatalf("number %d of a steady sender was refused", seq+1)
		}
	}
	if w.hear("cloud-new#y", 5, later.UnixMilli(), later) {
		t.Fatal("a number from far behind the newest was heard")
	}
}
