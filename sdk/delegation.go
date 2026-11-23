package cloud

// delegation.go — this deployment's half of IAM's delegation (iam LLM.md
// "Delegation"): asking IAM for a person's delegated token, and reading the key
// that verifies one.
//
// A delegated token is signed by a key IAM never publishes. Every other verifier
// in the estate reads the public JWKS and would read the person off any token it
// verifies, so the delegation key is kept out of that document and they refuse a
// delegated token without knowing what it is. This deployment is the one that
// serves what such a token is for, so it reads the key from IAM's authenticated
// address (PathDelegationKeys there) with the same client credential it delegates
// with, and verifies a confined token against that key and nothing else.

import (
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
	"github.com/hanzoai/cloud/sdk/iam"
	"golang.org/x/oauth2"
)

// Delegation is one person's work this deployment runs where it cannot trust the
// code: who it is for, the org it bills, when it ends, and the run, for IAM's trail.
type Delegation struct {
	// Subject is the person: their IAM `sub`, or `<owner>/<name>`.
	Subject string
	// Org is the org the work bills. IAM refuses one the person is not a member of.
	Org string
	// Until is when the token ends: the work's end, or a shorter life the holder renews within.
	// IAM caps it at four hours.
	Until time.Time
	// Run names the work in IAM's audit row. It is never signed into the token.
	Run string
	// Scopes lists optional bounded sub-scopes alongside ai:inference (e.g. "research",
	// "workflow:gpu") for autonomous science runs. Empty requests ai:inference only.
	Scopes []string
}

func delegationScope(extra []string) string {
	out := []string{inferenceScope}
	for _, s := range extra {
		s = strings.TrimSpace(s)
		if (s == researchScope || s == workflowGPUScope) && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return strings.Join(out, " ")
}

// Delegated is a delegated token and how long IAM granted it for, from when it was asked.
type Delegated struct {
	Token string
	Life  time.Duration
	// Capped says IAM granted less than was asked for, by more than the seconds between asking and
	// stamping (delegationSlack): it clipped the delegation to its own four hours.
	Capped bool
}

// Delegate asks IAM for a DELEGATED token: the person's, in d.Org, for model calls
// only (confined.go), until d.Until, naming this deployment as its actor. actor is
// this deployment's own token source (Machine); its token is the RFC 8693
// actor_token, and IAM checks it is this client's own.
//
// Every call is a fresh check of the person at IAM: they exist, are not forbidden or
// deleted, and are a member of d.Org. So asking again is how a delegation is renewed —
// IAM has no refresh and no extension, and needs none: a token that is not renewed
// ends at its own deadline, and a person who may no longer act is refused (Refused).
//
// It is what a sandbox running a model's output is handed instead of the machine
// token: the person pays for their own run, and the most a leaked one buys is the
// rest of that run's model calls on that person's account, from a key no verifier
// but this one holds.
//
// It FAILS CLOSED three ways. IAM's refusal is the caller's error, never a cue to
// fall back to the machine token; a token IAM answers that does not name the
// inference scope is refused here, because a box must never hold an unconfined
// one; and a token that would die before the work does is refused, because a
// harness that loses its model mid-run fails somewhere far from the reason.
func Delegate(ctx context.Context, actor oauth2.TokenSource, d Delegation) (Delegated, error) {
	if actor == nil {
		return Delegated{}, errors.New("delegate: this deployment holds no IAM identity")
	}
	life := int(math.Ceil(time.Until(d.Until).Seconds()))
	if life <= 0 {
		return Delegated{}, errors.New("delegate: the work's deadline has passed")
	}
	own, err := iam.TokenWithin(ctx, actor)
	if err != nil {
		return Delegated{}, fmt.Errorf("delegate: this deployment's own token: %w", err)
	}
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	status, err := iamOAuth(ctx, "/v1/iam/oauth/token", url.Values{
		"grant_type":        {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"actor_token":       {own.AccessToken},
		"actor_token_type":  {"urn:ietf:params:oauth:token-type:access_token"},
		"requested_subject": {d.Subject},
		"org":               {d.Org},
		"scope":             {delegationScope(d.Scopes)},
		"resource":          {delegatedAudience()},
		"lifetime":          {strconv.Itoa(life)},
		"run":               {d.Run},
	}, &out)
	if err != nil {
		return Delegated{}, fmt.Errorf("delegate: %w", err)
	}
	if status != http.StatusOK || out.AccessToken == "" {
		return Delegated{}, fmt.Errorf("delegate: IAM answered %d with no token", status)
	}
	if !presentsConfined(out.AccessToken) {
		return Delegated{}, errors.New("delegate: IAM answered a token that is not confined to model calls")
	}
	// What IAM granted: IAM caps a delegation at four hours (14400s).
	// A token that dies abnormally short is refused.
	maxDelegation := 4 * 3600
	needed := min(life-delegationSlack, maxDelegation-delegationSlack)
	if out.ExpiresIn < needed {
		return Delegated{}, fmt.Errorf("delegate: IAM granted %ds of the %ds this work needs", out.ExpiresIn, needed)
	}
	return Delegated{
		Token: out.AccessToken, Life: time.Duration(out.ExpiresIn) * time.Second,
		Capped: out.ExpiresIn+delegationSlack < life,
	}, nil
}

// delegationSlack is how far short of the work's deadline a granted lifetime may
// fall: the seconds between asking IAM and IAM stamping the token.
const delegationSlack = 10

// delegatedAudience is the one audience a delegated token is addressed to and the
// one a confined token must carry here: this deployment's API origin. Asked for
// at the mint and required at the boundary, from the same function.
func delegatedAudience() string { return "https://" + Domain() }

// iamOAuth posts form to IAM's OAuth address path as this deployment's client
// (client_secret_post) and decodes a 200's JSON into out. A non-200 answer is
// returned as an error carrying IAM's own `error` and `error_description`; the
// status is returned beside it for a caller that tells refusals apart.
func iamOAuth(ctx context.Context, path string, form url.Values, out any) (int, error) {
	id, secret, endpoint, ok := iam.MachineClient()
	if !ok {
		return 0, errors.New("this deployment holds no IAM identity")
	}
	form.Set("client_id", id)
	form.Set("client_secret", secret)
	endpoint = strings.TrimSuffix(endpoint, "/v1/iam/oauth/token") + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := iam.Client.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return resp.StatusCode, err
	}
	if resp.StatusCode != http.StatusOK {
		var refusal struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
		}
		_ = json.Unmarshal(body, &refusal)
		return resp.StatusCode, &Refused{Status: resp.StatusCode, Code: refusal.Error, Why: refusal.Description}
	}
	if out != nil && len(body) > 0 {
		if err := json.Unmarshal(body, out); err != nil {
			return resp.StatusCode, fmt.Errorf("IAM answered %d unreadably: %w", resp.StatusCode, err)
		}
	}
	return resp.StatusCode, nil
}

// Refused is IAM answering a request and declining it: the status and its own words.
type Refused struct {
	Status int
	Code   string
	Why    string
}

func (r *Refused) Error() string {
	return fmt.Sprintf("IAM refused (%d %s): %s", r.Status, r.Code, r.Why)
}

// Denied is IAM saying the person may not be acted for in that org, which asking
// again does not change: access_denied, its answer for one who is not a member, does
// not act there, or is a reserved identity. Every other refusal is a fault of the
// request or of this deployment's own standing with IAM (a client credential, a
// scope, an audience), and a person who has lost nothing is not told they have.
func (r *Refused) Denied() bool { return r.Status == http.StatusForbidden && r.Code == "access_denied" }

// delegationKeysPath is where IAM serves the delegation key, to a client allowed
// to delegate (iam internal/oidc PathDelegationKeys).
const delegationKeysPath = "/v1/iam/oauth/delegation/keys"

// errDelegationKeys is the delegation key being unreadable: IAM unreachable or
// refusing this deployment's credential, with no key already held.
var errDelegationKeys = errors.New("IAM's delegation keys are unreachable")

// delegationKeys holds IAM's delegation key set, read with this deployment's own
// client credential, keyed by kid.
//
// HELD FOR A TTL AND RE-READ FOR A KID IT HAS NOT SEEN — a rotation adds a key
// before it signs — but no more than once per delegationRetry, so a token naming
// a made-up kid cannot turn every request into a read of IAM. STALE ON ERROR, like
// the edge's public key cache: a key IAM served stays good through a blip.
type delegationKeys struct {
	mu    sync.Mutex
	byKid map[string][]crypto.PublicKey
	at    time.Time // when the held set was read
	tried time.Time // when a read was last attempted
}

const (
	delegationTTL       = 15 * time.Minute
	delegationRetry     = 30 * time.Second
	delegationColdRetry = 2 * time.Second
)

// resolve returns the delegation keys named kid. errDelegationKeys means there is
// nothing to verify against at all — a different answer from a kid IAM does not
// serve, which is a token that does not verify.
func (k *delegationKeys) resolve(kid string) ([]crypto.PublicKey, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	held := k.byKid != nil
	fresh := held && time.Since(k.at) < delegationTTL
	if found := k.byKid[kid]; fresh && len(found) > 0 {
		return found, nil
	}
	// Never held, IAM is asked again after a short floor rather than on every
	// request: until the first answer, every confined call would otherwise queue
	// behind its own read of IAM.
	retry := delegationRetry
	if !held {
		retry = delegationColdRetry
	}
	if k.tried.IsZero() || time.Since(k.tried) >= retry {
		k.tried = time.Now()
		if set, err := fetchDelegationKeys(); err == nil {
			k.byKid, k.at, held = set, time.Now(), true
		}
	}
	if !held {
		return nil, errDelegationKeys
	}
	return k.byKid[kid], nil
}

// fetchDelegationKeys reads the set from IAM with this deployment's client
// credential (client_secret_basic, as IAM reads a GET).
func fetchDelegationKeys() (map[string][]crypto.PublicKey, error) {
	id, secret, endpoint, ok := iam.MachineClient()
	if !ok {
		return nil, errDelegationKeys
	}
	endpoint = strings.TrimSuffix(endpoint, "/v1/iam/oauth/token") + delegationKeysPath
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(url.QueryEscape(id), url.QueryEscape(secret))
	resp, err := iam.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("delegation keys: status %d", resp.StatusCode)
	}
	var set jose.JSONWebKeySet
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&set); err != nil {
		return nil, err
	}
	out := make(map[string][]crypto.PublicKey, len(set.Keys))
	for _, key := range set.Keys {
		if key.KeyID == "" || (key.Use != "" && key.Use != "sig") || !key.Valid() || !key.IsPublic() {
			continue
		}
		out[key.KeyID] = append(out[key.KeyID], key.Key)
	}
	if len(out) == 0 {
		return nil, errors.New("delegation keys: IAM served no usable key")
	}
	return out, nil
}

// Revoke ends a delegated token at IAM (RFC 7009) as the client it was delegated
// to — the one client IAM lets end it. From then IAM's introspection answers it
// dead, and the boundary, which asks (liveness), refuses it within livenessTTL.
func Revoke(ctx context.Context, token string) error {
	_, err := iamOAuth(ctx, "/v1/iam/oauth/revoke", url.Values{
		"token": {token}, "token_type_hint": {"access_token"},
	}, nil)
	return err
}

// The kill switch. A confined token is verified here, offline, against a key, so
// nothing IAM does to its grant would reach it before its deadline: a copy lifted
// from a sandbox would spend until then. So the boundary also asks IAM whether
// the grant still stands (RFC 7662 introspection, as this deployment's client),
// and remembers each answer for livenessTTL — a revoked token is refused within
// that, a live one costs IAM one question per token per window.
var (
	errRevoked        = errors.New("the delegated token was revoked")
	errLivenessUnsure = errors.New("IAM cannot say whether the delegated token is live")
)

const (
	livenessTTL = 30 * time.Second
	livenessMax = 4096
)

// liveness holds IAM's last answer about each confined token, by digest.
type liveness struct {
	mu   sync.Mutex
	seen map[[32]byte]liveAt
}

type liveAt struct {
	alive bool
	at    time.Time
}

// check is nil for a token IAM says is live, errRevoked for one it says is not,
// and errLivenessUnsure when IAM could not be asked — which refuses too: a
// credential handed to model output is spent only while its grant is known to
// stand.
func (l *liveness) check(ctx context.Context, token string, exp *jwt.NumericDate) error {
	k := sha256.Sum256([]byte(token))
	l.mu.Lock()
	e, ok := l.seen[k]
	l.mu.Unlock()
	if !ok || time.Since(e.at) >= livenessTTL {
		var out struct {
			Active bool `json:"active"`
		}
		if _, err := iamOAuth(ctx, "/v1/iam/oauth/introspect", url.Values{"token": {token}}, &out); err != nil {
			return errLivenessUnsure
		}
		e = liveAt{alive: out.Active, at: time.Now()}
		// Cache positive liveness for livenessTTL to avoid per-request IAM calls,
		// but never negative-cache inactive answers: a revoked token still fails
		// closed on every request, while a transient IAM DB blip or read-after-write
		// lag right after minting will not poison the cache for 30s.
		if e.alive {
			l.remember(k, e)
		} else {
			l.forget(k)
		}
	}
	if !e.alive {
		// IAM answers an expired token inactive too, and with no clock leeway; the
		// verifier allows two minutes of it. A token past its own expiry was not
		// revoked, it ran out, and the refusal says that.
		if exp != nil && time.Now().After(exp.Time) {
			return fmt.Errorf("delegated token: %w", jwt.ErrTokenExpired)
		}
		return errRevoked
	}
	return nil
}

// remember records an answer, keeping the map bounded: expired answers go first,
// and a map full of live ones starts over rather than growing — each is one
// question to IAM away.
func (l *liveness) remember(k [32]byte, e liveAt) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.seen == nil {
		l.seen = make(map[[32]byte]liveAt)
	}
	if len(l.seen) >= livenessMax {
		for key, old := range l.seen {
			if time.Since(old.at) >= livenessTTL {
				delete(l.seen, key)
			}
		}
		if len(l.seen) >= livenessMax {
			clear(l.seen)
		}
	}
	l.seen[k] = e
}

// forget drops any cached liveness entry for k so a newly-revoked token is never
// served from a prior positive entry.
func (l *liveness) forget(k [32]byte) {
	l.mu.Lock()
	delete(l.seen, k)
	l.mu.Unlock()
}
