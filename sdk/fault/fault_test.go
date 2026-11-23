package fault

import (
	"errors"
	"fmt"
	"net/http"
	"testing"
)

type sited struct{ at string }

func (e sited) Error() string { return "boom" }
func (e sited) Site() string  { return e.at }

// ONE FAULT, ONE KEY. The fingerprint is a function of the code, the place and the
// site, and of nothing a caller or a clock can vary: the sentence a handler wraps it
// in, the ids its message quotes, the status text, the request that carried it.
func TestAFaultHasOneKeyWhateverSaysIt(t *testing.T) {
	a := Request("post", "/v1/x/:id", 500, "", fmt.Errorf("create 41: %w", errors.New("row 41 is gone")))
	b := Request("POST", "/v1/x/:id", 500, "", fmt.Errorf("billing: %w", errors.New("row 907 is gone")))
	if a.Fingerprint() != b.Fingerprint() {
		t.Fatalf("two occurrences of one fault have two keys: %s (%q) vs %s (%q)",
			a.Fingerprint(), a.Frame, b.Fingerprint(), b.Frame)
	}
	if len(a.Fingerprint()) != 16 {
		t.Fatalf("a fingerprint is sixteen hex digits, got %q", a.Fingerprint())
	}
	b.Request, b.Reason = "req_1", "other words"
	if a.Fingerprint() != b.Fingerprint() {
		t.Fatal("the request id or the reason changed the key")
	}
}

// Each of the three inputs separates two faults, and a mutation that drops one of
// them from the hash fails here.
func TestEveryInputOfTheKeySeparatesFaults(t *testing.T) {
	base := Request("GET", "/v1/x", 500, "", errors.New("nope"))
	for name, other := range map[string]Fault{
		"route":  Request("GET", "/v1/y", 500, "", errors.New("nope")),
		"method": Request("POST", "/v1/x", 500, "", errors.New("nope")),
		"code":   Request("GET", "/v1/x", 500, "custom", errors.New("nope")),
		"root":   Request("GET", "/v1/x", 500, "", errors.New("different")),
		"type":   Request("GET", "/v1/x", 500, "", sited{"a.go:1"}),
	} {
		if other.Fingerprint() == base.Fingerprint() {
			t.Errorf("%s did not change the fingerprint", name)
		}
	}
}

// A request no route matched is one fault however many addresses a scanner tries.
func TestAnUnroutedRequestIsOneFault(t *testing.T) {
	if got := Op("get", ""); got != "GET (unrouted)" {
		t.Fatalf("op = %q", got)
	}
}

// An error that knows where it was made names its own site, ahead of its text.
func TestASitedErrorNamesItsOwnFrame(t *testing.T) {
	err := fmt.Errorf("wrapped: %w", sited{"apps/x/y.go:41"})
	if got := Frame(err); got != "apps/x/y.go:41" {
		t.Fatalf("frame = %q", got)
	}
}

// The frame is the ROOT cause, through both kinds of wrap, and is bounded.
func TestTheFrameIsTheRootCause(t *testing.T) {
	root := errors.New("disk 12 full")
	if got, want := Frame(fmt.Errorf("a: %w", fmt.Errorf("b: %w", root))), "*errors.errorString:disk 0 full"; got != want {
		t.Fatalf("frame = %q, want %q", got, want)
	}
	if got, want := Frame(errors.Join(root, errors.New("second"))), "*errors.errorString:disk 0 full"; got != want {
		t.Fatalf("joined frame = %q, want %q", got, want)
	}
	long := errors.New(string(make([]byte, 4000)))
	if got := Frame(long); len(got) > maxFrame {
		t.Fatalf("frame is %d bytes, bound is %d", len(got), maxFrame)
	}
	if Frame(nil) != "" {
		t.Fatal("no error has no frame")
	}
}

// The class follows the status: a dependency being away is not the same rate as a
// fault of ours.
func TestTheClassFollowsTheStatus(t *testing.T) {
	for status, want := range map[int]Class{
		500: Server, 501: Server,
		http.StatusBadGateway: Dependency, http.StatusServiceUnavailable: Dependency, http.StatusGatewayTimeout: Dependency,
	} {
		if got := Request("GET", "/v1/x", status, "", errors.New("x")).Class; got != want {
			t.Errorf("status %d class %q, want %q", status, got, want)
		}
	}
}

// EVERY STATUS NAMES A CODE: a fault with no word is a key that hashes an empty
// string, which is how two unrelated refusals share one.
func TestEveryErrorStatusNamesACode(t *testing.T) {
	for status := 400; status < 600; status++ {
		if CodeOf(status) == "" {
			t.Fatalf("status %d names no code", status)
		}
	}
}

// A run that ends in error has a key made of the agent and the shape of its reason,
// and a run with no reason is its own fault rather than an empty one.
func TestARunAndAJobAreFaultsToo(t *testing.T) {
	a := Ended("dev", "workspace has no repository named \"x\" (41)")
	b := Ended("dev", "workspace has no repository named \"x\" (907)")
	if a.Fingerprint() != b.Fingerprint() || a.Class != Run || a.Op != "run:dev" {
		t.Fatalf("run faults: %+v %+v", a, b)
	}
	if none := Ended("dev", "  "); none.Frame != "(no reason)" || none.Fingerprint() == a.Fingerprint() {
		t.Fatalf("a reasonless run: %+v", none)
	}
	j := Failed("billing_recharge", errors.New("timeout after 30s"))
	if j.Class != Cron || j.Op != "cron:billing_recharge" || j.Code != "cron_failed" || j.Reason == "" {
		t.Fatalf("cron fault: %+v", j)
	}
}

// Regression test for duplicate auto-filed cron issues (#934, #935, #936, #903, #916-#922, #929):
// hex/alnum job IDs starting with hex letters a-f used to preserve their leading letters in Shape(),
// splitting one cron failure into dozens of distinct fingerprints.
func TestCronJobIDsShareOneFingerprint(t *testing.T) {
	ids := []string{
		"dc52e4715f", // #934
		"dd3e46820e", // #935
		"a1b2c3d4e5",
		"f9e8d7c6b5",
		"0123456789",
		"deadbeef12",
		"abcdef0123",
		"abcdefabcd", // all hex letters, len 10
		"9k2m8x7q1p", // mixed base36/alnum
		"7f8b9c4d50",
	}
	var wantFP, wantFrame string
	for _, id := range ids {
		msg := fmt.Sprintf(`job cloud-release-lag-%s failed: BackoffLimitExceeded: Job has reached the specified backoff limit; container lag: Error, exit 1; urllib.error.HTTPError: HTTP Error 401: Unauthorized`, id)
		f := Failed("cloud-release-lag", errors.New(msg))
		if wantFP == "" {
			wantFP, wantFrame = f.Fingerprint(), f.Frame
		} else if f.Fingerprint() != wantFP {
			t.Fatalf("job id %q produced fingerprint %s (frame %q), want %s (frame %q)",
				id, f.Fingerprint(), f.Frame, wantFP, wantFrame)
		}
	}
}

func TestShapeNormalizesVariableTokensAndPreservesWords(t *testing.T) {
	same := [][]string{
		// UUIDs with different leading hex digits/letters
		{
			"session 550e8400-e29b-41d4-a716-446655440000 expired",
			"session deadbeef-cafe-41d4-b716-abcdefabcdef expired",
			"session 0196a3f2-b4c1-7def-8901-23456789abcd expired",
		},
		// Kubernetes Deployment/Pod names (replicaset hash + 5-char pod suffix)
		{
			"pod cloud-7f8b9c4d5-xk9p2 OOMKilled",
			"pod cloud-6a2e1f8c3-4m8n2 OOMKilled",
			"pod cloud-5c8f9d6b7-abcde OOMKilled",
		},
		// Kubernetes CronJob pod names (8-digit epoch + 5-char suffix)
		{
			"pod sync-29481020-xk9p2 failed",
			"pod sync-29481025-abcde failed",
		},
		// Prefixed IDs and 0x hex literals
		{
			"request req_a1b2c3d4e5 failed at 0xdeadbeef",
			"request req_0192837465 failed at 0x1a2b",
		},
		// ISO-8601 timestamps with/without fractional seconds and tz offsets
		{
			"deadline exceeded at 2026-11-22T19:15:03Z",
			"deadline exceeded at 2026-11-22T19:15:03.456789Z",
			"deadline exceeded at 2026-11-22T11:15:03-08:00",
		},
	}
	for _, group := range same {
		want := Shape(group[0])
		for _, s := range group[1:] {
			if got := Shape(s); got != want {
				t.Errorf("Shape(%q) = %q, want %q (same as %q)", s, got, want, group[0])
			}
		}
	}

	// Ordinary words (including 8-letter English words made solely of [a-f] like "feedback")
	// and meaningful short tokens must not be collapsed into 'x'.
	if got := Shape("user feedback cascaded on v1beta1"); got != "user feedback cascaded on v0beta0" {
		t.Fatalf("Shape altered ordinary words: got %q", got)
	}
}
