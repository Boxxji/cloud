package bus

import (
	"strings"
	"testing"
	"time"
)

// No driver is linked into this test binary: these pin what a process does without
// one.

func TestWithNoClusterNamedTheBusIsThisProcess(t *testing.T) {
	t.Setenv(urlEnv, "")
	msgs := make(chan Message, 4)
	all := make(chan Message, 4)
	sub, err := Subscribe(Phys("acme", "feed"), msgs)
	if err != nil {
		t.Fatal(err)
	}
	other, err := Subscribe("coord.>", all)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Unsubscribe()
	if err := Publish(Phys("acme", "feed"), []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := Publish("coord.one", []byte("a")); err != nil {
		t.Fatal(err)
	}
	if err := Publish("coord.two.deep", []byte("b")); err != nil {
		t.Fatal(err)
	}
	if err := Publish(Phys("beta", "feed"), []byte("two")); err != nil {
		t.Fatal(err)
	}
	select {
	case m := <-msgs:
		if string(m.Data) != "one" {
			t.Fatalf("heard %q", m.Data)
		}
	case <-time.After(time.Second):
		t.Fatal("nothing heard on the subject")
	}
	select {
	case m := <-msgs:
		t.Fatalf("heard %q from another org's subject", m.Data)
	default:
	}
	if len(all) != 2 {
		t.Fatalf("a wildcard heard %d of 2", len(all))
	}
	_ = sub.Unsubscribe()
	_ = Publish(Phys("acme", "feed"), []byte("three"))
	if len(msgs) != 0 {
		t.Fatal("heard after Unsubscribe")
	}
}

func TestAnAnnouncedPulseIsHeardInProcess(t *testing.T) {
	t.Setenv(urlEnv, "")
	msgs := make(chan Message, 1)
	if _, err := Subscribe(PulseSubject(), msgs); err != nil {
		t.Fatal(err)
	}
	if err := Announce(Pulse{Kind: "signup", Key: "u1"}); err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 {
		t.Fatal("the pulse was not heard")
	}
}

// A process told where the cluster is and given no way to reach it must not publish
// into nothing and look healthy.
func TestAClusterNamedWithNoDriverRefusesLoudly(t *testing.T) {
	t.Setenv(urlEnv, "nats://127.0.0.1:1")
	if err := Publish("x", nil); err == nil || !strings.Contains(err.Error(), ErrNoDriver.Error()) {
		t.Fatalf("Publish = %v, want a refusal naming the missing driver", err)
	}
	if _, err := Subscribe("x", make(chan Message, 1)); err == nil {
		t.Fatal("Subscribe on a named cluster with no driver succeeded")
	}
	if err := Announce(Pulse{Kind: "paid"}); err == nil {
		t.Fatal("a pulse was announced into nothing")
	}
}

func TestMatches(t *testing.T) {
	for _, c := range []struct {
		p, s string
		want bool
	}{
		{"a.b", "a.b", true}, {"a.b", "a.c", false}, {"a.*", "a.b", true}, {"a.*", "a.b.c", false},
		{"a.>", "a.b.c", true}, {"a.>", "a", false}, {">", "a", true}, {"a.b", "a", false},
	} {
		if got := matches(split(c.p), split(c.s)); got != c.want {
			t.Errorf("matches(%q, %q) = %v", c.p, c.s, got)
		}
	}
}

func split(s string) []string { return strings.Split(s, ".") }
