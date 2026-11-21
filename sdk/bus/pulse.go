package bus

import (
	"encoding/json"
	"time"
)

// Pulse is one fleet fact: a person signed up, an org was created, money was paid.
// Kind is "signup", "org", "paid", "model", or one the public board states
// (apps/leaderboard feed.go): "referral" (an org joined through a referral link),
// "bounty" (an award, Detail its points) and "expert" (an expert listed). Key names
// the thing it is about so a reader can fold repeats; Cents is set for "paid".
//
// Pulses ride the reserved admin org's own subject, so the readers that subscribe
// there are in-process: GET /v1/admin/feed (SuperAdmin only) and the public board's
// hub, which republishes nothing but masked lines.
type Pulse struct {
	Kind   string `json:"kind"`
	Key    string `json:"key"`
	At     string `json:"at"`
	Title  string `json:"title"`
	Detail string `json:"detail"`
	Org    string `json:"org"`
	Cents  int64  `json:"cents,omitempty"`
}

// PulseSubject is where every pulse is published and read.
func PulseSubject() string { return Phys("admin", "pulse") }

// Announce publishes one pulse. Best effort: the write that produced the fact has
// already happened, so a bus that is down loses a feed line and nothing else.
func Announce(p Pulse) error {
	if p.At == "" {
		p.At = time.Now().UTC().Format(time.RFC3339)
	}
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return Publish(PulseSubject(), b)
}
