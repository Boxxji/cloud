package audit

import (
	"context"
	"errors"
	"testing"
	"time"
)

// holder is the process that keeps the trail, as a Remote recorder reaches it: a
// real chain behind the Owner interface.
type holder struct{ chain *Recorder }

func (h holder) Append(ctx context.Context, r Record) (Record, error) { return h.chain.Append(ctx, r) }
func (h holder) Query(ctx context.Context, f Filter) ([]Record, int, error) {
	return h.chain.Query(ctx, f)
}

// gone is a holder that cannot be reached.
type gone struct{}

func (gone) Append(context.Context, Record) (Record, error) {
	return Record{}, errors.New("admin is not running")
}
func (gone) Query(context.Context, Filter) ([]Record, int, error) {
	return nil, 0, errors.New("admin is not running")
}

// A Remote recorder writes into the holder's chain and reads back out of it: the
// record keeps everything the emitter said, and the holder seals it.
func TestRemoteAppendsToTheHoldersChain(t *testing.T) {
	chain, err := Open(t.TempDir(), "audit-admin", nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = chain.Close() })
	rec := Remote("admin", holder{chain})

	at := time.Date(2026, 10, 4, 9, 30, 0, 0, time.UTC)
	sealed, err := rec.Append(context.Background(), Record{
		Time:     at,
		Actor:    Actor{Org: "acme", Sub: "u-7", Email: "u7@acme.ai"},
		Action:   "ai.limits.credits",
		Resource: Resource{Type: "ai_limits", ID: "acme/u-7"},
		Outcome:  Outcome{Result: "success", Status: 200},
		Before:   []byte(`{"creditsAfterAllowance":false}`),
		After:    []byte(`{"creditsAfterAllowance":true}`),
	})
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if sealed.Hash == "" || sealed.PrevHash == "" {
		t.Fatalf("the holder did not seal the record: %+v", sealed)
	}

	rows, total, err := rec.Query(context.Background(), Filter{Org: "acme", Action: "ai.limits.credits"})
	if err != nil || total != 1 {
		t.Fatalf("Query through the remote: total=%d err=%v", total, err)
	}
	r := rows[0]
	if !r.Time.Equal(at) || r.Actor.Sub != "u-7" || r.Resource.ID != "acme/u-7" ||
		string(r.Before) != `{"creditsAfterAllowance":false}` || string(r.After) != `{"creditsAfterAllowance":true}` {
		t.Fatalf("record read back: %+v", r)
	}
	if iv, err := chain.Verify(context.Background()); err != nil || iv.Verdict != Intact || iv.Count != 1 {
		t.Fatalf("holder chain after a remote append: %+v %v", iv, err)
	}
}

// An append the holder did not take is an error at the call site, which is what a
// caller fails closed on. A Remote recorder never pretends a record landed.
func TestRemoteAppendThatDoesNotLandIsAnError(t *testing.T) {
	rec := Remote("admin", gone{})
	if _, err := rec.Append(context.Background(), Record{Action: "flag.stage.put"}); err == nil {
		t.Fatal("an append the holder never took succeeded")
	}
}

// A Remote recorder holds no chain, so anything that needs the chain itself
// refuses and names the holder, and it arms no checkpoint: a zero count on the
// AU-9 stream would read as a truncated chain.
func TestRemoteHoldsNoChain(t *testing.T) {
	rec := Remote("admin", gone{})
	if _, err := rec.Verify(context.Background()); err == nil {
		t.Fatal("Verify on a recorder with no chain answered")
	}
	if _, err := rec.Trail(context.Background()); err == nil {
		t.Fatal("Trail on a recorder with no chain answered")
	}
	rec.StartCheckpoints(time.Millisecond, func(Checkpoint) { t.Error("a recorder with no chain emitted a checkpoint") })
	time.Sleep(10 * time.Millisecond)
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
