package coord

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"strconv"
	"time"
)

const membersSet = "members"

// record is one member as the live set holds it: who, where, which instance, when it
// last said so, and the signature that says a holder of the deployment's master put
// it there for this deployment. The time is signed, so a record lifted from the KV
// can be replayed for one heartbeat's worth of time and no longer, and the
// deployment's key prefix is signed, so a record lifted from one deployment names
// nobody in another that shares the master.
type Record struct {
	ID, Addr, Instance string
	At                 int64 // unix milliseconds, the writer's clock
	Sig                string
}

func (c *Coord) sign(r Record) string {
	mac := hmac.New(sha256.New, c.key)
	mac.Write([]byte(c.prefix + "\x00" + r.ID + "\x00" + r.Addr + "\x00" + r.Instance + "\x00" + strconv.FormatInt(r.At, 10)))
	return hex.EncodeToString(mac.Sum(nil))
}

func (c *Coord) record() Record {
	r := Record{ID: c.self.ID, Addr: c.self.Addr, Instance: c.instance, At: time.Now().UnixMilli()}
	r.Sig = c.sign(r)
	return r
}

// live reports whether r is a record this deployment signed within a heartbeat of
// now.
func (c *Coord) live(r Record, now time.Time) bool {
	if !hmac.Equal([]byte(r.Sig), []byte(c.sign(r))) {
		return false
	}
	return c.p.fresh(time.UnixMilli(r.At), now)
}

func (p Periods) fresh(at, now time.Time) bool {
	age := now.Sub(at)
	return age <= p.Presence+p.Skew && age >= -p.Skew
}

// join writes this pod's record into the live set. Another instance under the same
// id refuses it only when that instance is real — a record this deployment signed
// within a heartbeat. Anything else under this id (a planted entry, with no
// signature or an expiry no pod writes, or the last record of an instance that
// has stopped) is overwritten, so a value anyone can write to an unauthenticated KV
// cannot take a live pod down.
func (c *Coord) join(ctx context.Context, set string) error {
	held, err := c.b.Join(ctx, set, c.record(), c.p.Presence, false)
	if err != nil || held == nil {
		return err
	}
	if c.live(*held, time.Now()) {
		return ErrDuplicate
	}
	c.log.warn("planted", "coord: overwriting an entry under this pod's id that no live instance signed", "id", c.self.ID, "instance", held.Instance)
	_, err = c.b.Join(ctx, set, c.record(), c.p.Presence, true)
	return err
}

// Start takes this process's place in the deployment: the pod's root joins the live
// set and keeps it there, and every process reads the set now and every
// Refresh after. A KV that does not answer is not a refusal: the root keeps
// trying on every heartbeat and the pod is a member once the KV answers. Another
// live pod under this pod's id is, and Err says so.
func (c *Coord) Start(ctx context.Context) {
	c.mu.Lock()
	if c.started {
		c.mu.Unlock()
		return
	}
	c.started = true
	c.mu.Unlock()
	if !c.shared {
		return
	}
	set := c.Key("set", membersSet)
	if c.root {
		err := c.join(ctx, set)
		switch {
		case errors.Is(err, ErrDuplicate):
			c.fail(err)
			c.log.log.Error("coord: another live pod holds this pod's id; this one will not serve", "id", c.self.ID)
			return
		case err != nil:
			c.log.warn("join", "coord: the KV did not answer; this pod joins the live set when it does", "id", c.self.ID, "err", err)
		default:
			c.log.log.Info("coord: joined the live set", "id", c.self.ID, "addr", c.self.Addr)
		}
		p := &presence{c: c, set: set, stop: make(chan struct{}), done: make(chan struct{})}
		c.mu.Lock()
		c.presence = p
		c.mu.Unlock()
		go p.beat()
	}
	first, cancel := context.WithTimeout(ctx, time.Second)
	c.refresh(first)
	cancel()
	go func() {
		t := time.NewTicker(c.p.Refresh)
		defer t.Stop()
		for {
			select {
			case <-c.stop:
				return
			case <-t.C:
				r, cancel := context.WithTimeout(context.Background(), time.Second)
				c.refresh(r)
				cancel()
			}
		}
	}()
}

// refresh reads the live set, keeping only members this deployment signed within a
// heartbeat. A read that fails keeps the last good one as it was: the set holds
// still through a KV outage rather than emptying, because two pods that each saw
// only themselves would each elect themselves owner of every org.
//
// A READ IS ONLY AS GOOD AS THIS POD'S PLACE IN IT. One that holds no live record at
// all — this pod's included — is a KV that answers reads and refuses writes
// (READONLY after a failover, OOM), where every heartbeat lapses while every read
// succeeds; it is kept as a failed read is, and the set holds still. One that holds
// live peers but not this pod, while this pod's last record is still within its
// lifetime, is a KV that lost its data and has not had this pod's next heartbeat
// yet; it is kept too. Past that, it is the set those peers see: their heartbeats
// land and this pod's does not, so they have dropped it, and this pod takes the same
// view — it owns nothing until its own record is back — rather than electing itself
// for orgs a peer has already taken. A deployment that declares one writer takes
// neither view: no peer can have replaced its pod, so it counts itself beside what
// the read holds — a predecessor's records, until they lapse.
func (c *Coord) refresh(ctx context.Context) {
	rs, err := c.b.Members(ctx, c.Key("set", membersSet), c.p.Presence)
	if err != nil {
		c.log.warn("members", "coord: the live set cannot be read; keeping the last one", "err", err)
		return
	}
	now := time.Now()
	out := make([]Member, 0, len(rs))
	var self time.Time
	for _, r := range rs {
		if !c.live(r, now) {
			c.log.warn("unsigned", "coord: ignoring a member this deployment did not sign within a heartbeat", "id", r.ID, "addr", r.Addr)
			continue
		}
		if r.ID == c.self.ID {
			self = time.UnixMilli(r.At)
		}
		out = append(out, Member{ID: r.ID, Addr: r.Addr})
	}
	prev := c.view.Load()
	switch {
	case !self.IsZero():
		c.view.Store(&snapshot{members: out, at: now, self: self})
	case !c.Peered():
		// The deployment declares one writer, so no peer can have taken this pod's
		// place: the records beside it are a predecessor's that have not lapsed, and
		// they lapse here as they would in a KV that takes writes. It counts itself
		// beside them, since dropping itself would hand every org to a pod that is
		// gone, and holds none of them still.
		c.log.warn("missing", "coord: this pod's heartbeat is not in the live set; it is the one writer declared, so it counts itself", "id", c.self.ID)
		c.view.Store(&snapshot{members: out, at: now, self: prev.self})
	case len(out) > 0 && !prev.self.IsZero() && now.Sub(prev.self) < c.p.Presence-c.p.Skew:
		c.log.warn("missing", "coord: this pod's heartbeat is not in the live set yet; keeping the last one", "id", c.self.ID)
	case len(out) > 0:
		c.log.warn("dropped", "coord: this pod's heartbeat is not in the live set its peers see; it owns nothing until it is", "id", c.self.ID)
		c.view.Store(&snapshot{members: out, at: now, self: prev.self, dropped: true})
	default:
		c.log.warn("empty", "coord: the live set holds no live Record, this pod's included; keeping the last one")
	}
}

// Live reports whether this pod's own heartbeat is fresh in the live set: its record
// was in the last read, written recently enough that no peer can yet have dropped
// it. A deployment with no KV has no peers to drop it.
func (c *Coord) Live() bool {
	if !c.shared {
		return true
	}
	v := c.view.Load()
	return !v.dropped && !v.self.IsZero() && time.Since(v.self) < c.p.Presence-c.p.Skew
}

// Members is the deployment's live set as last read, ordered by id. It holds this
// pod unless it is leaving or its peers have dropped it, and it holds still while
// the KV cannot be read: a pod that died during an outage keeps its orgs until the
// KV answers again, which costs those orgs' requests, where emptying the set would
// let two live pods each own everything. The object store's rounds, not this list,
// keep two owners apart.
func (c *Coord) Members() []Member {
	v := c.view.Load()
	read := v.members
	seen := make(map[string]Member, len(read)+1)
	for _, m := range read {
		if m.ID != "" {
			seen[m.ID] = m
		}
	}
	if c.draining.Load() || v.dropped {
		delete(seen, c.self.ID)
	} else if c.self.ID != "" {
		seen[c.self.ID] = c.self
	}
	out := make([]Member, 0, len(seen))
	for _, m := range seen {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Self is this pod.
func (c *Coord) Self() string { return c.self.ID }

// Owner names this process: the pod and a nonce no other process of the pod shares, so
// a record that carries it names this incarnation and not the pod, and CallPod asks
// exactly it. A process that restarted under the same pod id has another.
func (c *Coord) Owner() string { return c.owner }

// Peered reports whether this deployment may run more than one writer: the count
// it declares (CLOUD_REPLICAS, the Deployment's own, or CLOUD_PEERS) is above one.
// It is never read off the live set. A pod's view of that set can be wrong — a KV
// that refuses writes, a heartbeat that does not land, a boot before the set was
// read — and a pod that took a view of itself alone for proof it was alone would run
// every loop, redeem every token and acknowledge every write beside a peer doing the
// same; the live set routes requests and elects org owners, and the object store
// fences them. KV_URL being set says nothing either way.
func (c *Coord) Peered() bool {
	return c.declared > 1
}

// Leave takes the pod out of the live set now, so its peers stop electing it for
// orgs at their next read. Only the root leaves; it is the first thing a draining
// pod does, and the loops it runs stay fenced by their leases until their passes
// end (Close).
func (c *Coord) Leave(ctx context.Context) {
	c.draining.Store(true)
	c.mu.Lock()
	p := c.presence
	c.presence = nil
	c.mu.Unlock()
	if p == nil {
		return
	}
	close(p.stop)
	<-p.done
	if err := c.b.Leave(ctx, p.set, c.self.ID, c.instance); err != nil {
		c.log.warn("leave", "coord: leave failed; the heartbeat will lapse instead", "id", c.self.ID, "err", err)
	}
}

// presence keeps the pod's root in the live set while it runs.
type presence struct {
	c    *Coord
	set  string
	stop chan struct{}
	done chan struct{}
}

func (p *presence) beat() {
	defer close(p.done)
	t := time.NewTicker(p.c.p.Presence / 3)
	defer t.Stop()
	for {
		select {
		case <-p.stop:
			return
		case <-t.C:
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			err := p.c.join(ctx, p.set)
			cancel()
			switch {
			case errors.Is(err, ErrDuplicate):
				p.c.fail(err)
				p.c.log.log.Error("coord: another live pod took this pod's id; leaving the live set", "id", p.c.self.ID)
				return
			case err != nil:
				p.c.log.warn("heartbeat", "coord: heartbeat failed", "id", p.c.self.ID, "err", err)
			}
		}
	}
}
