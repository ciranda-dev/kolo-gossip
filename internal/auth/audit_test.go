package auth

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/ciranda-dev/kolo-gossip/internal/core"
	"github.com/ciranda-dev/kolo-gossip/internal/wire"
	koloid "github.com/ciranda-dev/kolo-id"
)

// authPaths are the author paths with their most expensive frames: each readies a node and returns the frame from
// peer 1 and the least work the Resolver must report for it, counted from what the path does.
var authPaths = map[string]func(t *testing.T) (*node, func(), core.Ops){
	"CERTWANT of MaxCertWants entries, all unknown": func(t *testing.T) (*node, func(), core.Ops) {
		n := openNode(t, 1)
		var ws []wire.CertWant
		for i := range 20 {
			ws = append(ws, wantFor(newPerson(t, byte(100+i))))
		}
		var min core.Ops
		min[core.OpLookup] = 10 * 3
		min[core.OpAlloc] = 10
		return n, func() { n.control(1, &wire.Control{CertWant: ws}) }, min
	},
	"CERT of 10 chains matching nothing": func(t *testing.T) (*node, func(), core.Ops) {
		var ps []*person
		for i := range 10 {
			ps = append(ps, newPerson(t, byte(100+i)))
		}
		n := newNode(t, nil, newOpener(ps...).open, 1, func(c *Config) { c.MaxCertWants, c.MaxCertAnswers = 20, 10 }, nil)
		for i, p := range ps {
			n.message(1, p.sign(t, uint64(i), t0, ""))
		}
		var certs [][]byte
		for range 10 {
			certs = append(certs, newPerson(t, 50).deviceCert.Encode())
		}
		var min core.Ops
		min[core.OpBytes] = 10 * chunks(len(certs[0]))
		min[core.OpAlloc] = 10
		min[core.OpLookup] = 10
		min[core.OpCert] = 10
		return n, func() { n.control(1, &wire.Control{Cert: certs}) }, min
	},
	"CERT of 10 forged chains for our requests": func(t *testing.T) (*node, func(), core.Ops) {
		var ps []*person
		for i := range 10 {
			ps = append(ps, newPerson(t, byte(100+i)))
		}
		n := newNode(t, nil, newOpener(ps...).open, 1, func(c *Config) { c.MaxCertWants, c.MaxCertAnswers = 20, 10 }, nil)
		var certs [][]byte
		for i, p := range ps {
			n.message(1, p.sign(t, uint64(i), t0, ""))
			// A byte of the issuer's signature changed: the structure holds, the signatures do not.
			b := p.deviceCert.Encode()
			b[110] ^= 1
			certs = append(certs, b)
		}
		var min core.Ops
		min[core.OpChain] = 10
		return n, func() { n.control(1, &wire.Control{Cert: certs}) }, min
	},
	"message of an open-mode author with a cached chain": func(t *testing.T) (*node, func(), core.Ops) {
		q := newPerson(t, 20)
		n := openNode(t, 1, q)
		n.message(1, q.sign(t, 1, t0, ""))
		n.control(1, &wire.Control{Cert: [][]byte{q.deviceCert.Encode()}})
		raw := q.sign(t, 2, t0, "")
		var min core.Ops
		min[core.OpCallback] = 1
		min[core.OpLookup] = 2
		return n, func() { n.message(1, raw) }, min
	},
	"message of a roster author with a new chain": func(t *testing.T) (*node, func(), core.Ops) {
		p := newPerson(t, 10)
		n := newNode(t, newRoster(p), nil, 1, nil, nil)
		raw := p.sign(t, 1, t0, "")
		var min core.Ops
		min[core.OpCallback] = 1
		min[core.OpChain] = 1
		min[core.OpBytes] = 3 * chunks(len(p.deviceCert.Encode())) // its content key and its encoding for the cache
		return n, func() { n.message(1, raw) }, min
	},
}

// TestUnitAuditAuthors: for each author path, the router charges its peer at least every operation done, the
// Resolver's included, and the Resolver reports at least the operations the path is known to do.
func TestUnitAuditAuthors(t *testing.T) {
	for name, path := range authPaths {
		n, send, min := path(t)
		n.res.Work()
		n.r.AuditPeer(peerKey(1))
		send()
		done, charged := n.r.Audit()
		for op, k := range done {
			if charged[op] < k {
				t.Errorf("%s: op %d done %d times, charged %d", name, op, k, charged[op])
			}
		}
		for op, k := range min {
			if done[core.Op(op)] < int64(k) {
				t.Errorf("%s: op %d reported %d times, at least %d done", name, op, done[core.Op(op)], k)
			}
		}
	}
}

// TestExpiredChainCost: a cached chain that expired is not checked again at every message: its error is kept.
func TestExpiredChainCost(t *testing.T) {
	p := newPerson(t, 10)
	expiring := certify(t, p.approver, p.device, &koloid.IssueOptions{Parent: p.approverCert, Serial: 2, IssuedAt: issued, ExpiresAt: t0.Add(time.Second)})
	ros := newRoster()
	ros.add(p.pub(), p.device.PublicKey(), &Author{Person: p.pub(), Cert: expiring})
	c := &clock{t0.Add(2 * time.Second)}
	r := newResolver(t, c, ros, nil, nil)
	env, signed := decode(t, p.sign(t, 1, t0, ""))
	r.Verify(env, signed)
	r.Work()
	for range 10 {
		r.Verify(env, signed)
	}
	if w := r.Work(); w[core.OpChain] != 0 {
		t.Fatalf("an expired chain was checked %d more times", w[core.OpChain])
	}
}

// TestOpenPerTopic: a fetched chain releases each waiting message with the open mode's answer for that message's
// own topic, not the first one's.
func TestOpenPerTopic(t *testing.T) {
	q := newPerson(t, 20)
	other := wire.Topic{0x70, 2}
	open := func(tp wire.Topic, person ed25519.PublicKey) ([]*koloid.Revocation, bool) { return nil, tp == topic }
	r := newResolver(t, &clock{t0}, nil, open, nil)
	for i, tp := range []wire.Topic{topic, other} {
		raw := q.sign(t, uint64(i), t0, "")
		env, signed := decode(t, raw)
		env.Topic = tp
		if _, err := r.Resolve(t0, wire.ID{byte(i)}, env, signed, peerKey(1)); err != nil {
			t.Fatal(err)
		}
	}
	res := r.Cert(t0, peerKey(1), [][]byte{q.deviceCert.Encode()}, 1<<40)
	if len(res.Done) != 2 || res.Done[0].Err != nil || res.Done[1].Err == nil {
		t.Fatalf("results %+v", res.Done)
	}
}

// TestThrottledBeforeAuthor: a copy over its sender's share is dropped before its author is looked up, so a
// sender cannot make us check chains for messages we would not hold.
func TestThrottledBeforeAuthor(t *testing.T) {
	p := newPerson(t, 10)
	ros := newRoster(p)
	n := newNode(t, ros, nil, 1, nil, func(c *core.Config) { c.MaxPeerValidating = 1 })
	n.message(1, p.sign(t, 1, t0, ""))
	n.message(1, p.sign(t, 2, t0, ""))
	if ros.lookups != 1 || n.r.Stats().Throttled != 1 {
		t.Fatalf("%d roster lookups, %+v", ros.lookups, n.r.Stats())
	}
}

// TestCertAnswersHalfOfWants: a requester may send at most half of what a responder answers per heartbeat, so two
// of its heartbeats in one of the responder's never ask more; any other setting is refused.
func TestCertAnswersHalfOfWants(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Authors, cfg.MaxCertAnswers = newRoster(), 6
	if _, err := New(cfg); !errors.Is(err, core.ErrInvalidConfig) {
		t.Fatalf("MaxCertAnswers 6 with MaxCertWants 10: %v", err)
	}
}

// TestCertStopsAtBudget: a CERT frame whose chain checks its sender cannot pay runs none of them past the budget;
// the sender's requests end without a penalty.
func TestCertStopsAtBudget(t *testing.T) {
	var ps []*person
	for i := range 3 {
		ps = append(ps, newPerson(t, byte(100+i)))
	}
	r := newResolver(t, &clock{t0}, nil, newOpener(ps...).open, nil)
	var certs [][]byte
	for i, p := range ps {
		env, signed := decode(t, p.sign(t, uint64(i), t0, ""))
		if _, err := r.Resolve(t0, wire.ID{byte(i)}, env, signed, peerKey(1)); err != nil {
			t.Fatal(err)
		}
		certs = append(certs, p.deviceCert.Encode())
	}
	r.Work()
	out := r.Cert(t0, peerKey(1), certs, core.Cost(core.OpChain, 1))
	if w := r.Work(); w[core.OpChain] > 2 || len(out.Broken) != 0 || r.Stats().Outstanding != 0 {
		t.Fatalf("%d chain checks past a budget of one, %d broken, %d outstanding", w[core.OpChain], len(out.Broken), r.Stats().Outstanding)
	}
}

// TestChainObjectsNotPinned: a roster that returns new objects at every lookup has no more than its first objects
// kept by the chain cache.
func TestChainObjectsNotPinned(t *testing.T) {
	p := newPerson(t, 10)
	r := newResolver(t, &clock{t0}, decodingRoster{p: p, cert: p.deviceCert.Encode()}, nil, nil)
	env, signed := decode(t, p.sign(t, 1, t0, ""))
	for range 10 {
		if err := r.Verify(env, signed); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(r.chains.m); n != 2 {
		t.Fatalf("%d chain cache entries for one chain, want its content and its first objects", n)
	}
}

// TestRosterTimed: with a clock, a roster lookup is charged by the time it takes.
func TestRosterTimed(t *testing.T) {
	p := newPerson(t, 10)
	var clock time.Duration
	slow := slowRoster{inner: newRoster(p), clock: &clock}
	r := newResolver(t, &clock0, slow, nil, func(c *Config) { c.Elapsed = func() time.Duration { return clock } })
	env, signed := decode(t, p.sign(t, 1, t0, ""))
	r.Verify(env, signed)
	if w := r.Work(); core.Cost(core.OpCallback, w[core.OpCallback]) < int64(time.Millisecond/core.Unit) {
		t.Fatalf("a 1 ms lookup charged %d callback operations", w[core.OpCallback])
	}
}

var clock0 = clock{t0}

// slowRoster is a roster whose lookups take 1 ms of a test clock.
type slowRoster struct {
	inner Authors
	clock *time.Duration
}

func (s slowRoster) Lookup(tp wire.Topic, person, device ed25519.PublicKey) (*Author, error) {
	*s.clock += time.Millisecond
	return s.inner.Lookup(tp, person, device)
}
