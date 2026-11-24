package core

import (
	"testing"
	"time"

	"github.com/ciranda-dev/kolo-gossip/internal/wire"
)

// auditPaths are the router's handler paths, each with its most expensive frame. Each builds its own router,
// readies it, and returns the peer whose frames it sends and the frames to send.
var auditPaths = map[string]func(t *testing.T) (*fixture, func()){
	"duplicate message": func(t *testing.T) (*fixture, func()) {
		f := meshFixture(t, nil, 2, 0)
		raw := envelope(T, key(9), 1, f.now, 1000)
		f.receive(2, raw, Accept)
		return f, f.driverMessage(1, raw, Ignore)
	},
	"copy of a message 63 peers sent": func(t *testing.T) (*fixture, func()) {
		f := meshFixture(t, nil, 64, 0)
		raw := envelope(T, key(900), 1, f.now, 100)
		f.r.Message(f.now, key(64), raw)
		for i := 2; i < 64; i++ {
			f.r.Message(f.now, key(i), raw)
		}
		return f, f.driverMessage(1, raw, Ignore)
	},
	"copy of an ignored message": func(t *testing.T) (*fixture, func()) {
		f := meshFixture(t, nil, 2, 0)
		raw := markedEnvelope(1, f.now, unknownSig)
		f.r.Message(f.now, key(2), raw)
		return f, f.driverMessage(1, raw, Ignore)
	},
	"message for a topic not joined": func(t *testing.T) (*fixture, func()) {
		f := meshFixture(t, nil, 1, 0)
		raw := envelope(wire.Topic{0xee}, key(9), 1, f.now, 1<<20-200)
		return f, f.driverMessage(1, raw, Ignore)
	},
	"message out of the window": func(t *testing.T) (*fixture, func()) {
		f := meshFixture(t, nil, 1, 0)
		raw := envelope(T, key(9), 1, f.now.Add(-time.Hour), 1<<20-200)
		return f, f.driverMessage(1, raw, Ignore)
	},
	"bad signature": func(t *testing.T) (*fixture, func()) {
		f := meshFixture(t, nil, 1, 0)
		raw := badEnvelope(T, key(9), 1, f.now)
		return f, f.driverMessage(1, raw, Ignore)
	},
	"unknown author with IDONTWANT to the mesh": func(t *testing.T) (*fixture, func()) {
		f := meshFixture(t, nil, 13, 12)
		e := &wire.Envelope{Topic: T, Device: wire.Key(key(9)), Seq: 1, Time: uint64(f.now.UnixMilli()), Body: make([]byte, 4000)}
		e.Sig[0] = unknownSig
		raw := e.Encode()
		return f, f.driverMessage(1, raw, Ignore)
	},
	"throttled message": func(t *testing.T) (*fixture, func()) {
		cfg := DefaultConfig()
		cfg.MaxPeerValidating = 1
		f := meshFixture(t, cfg, 1, 0)
		f.r.Message(f.now, key(1), envelope(T, key(9), 1, f.now, 1))
		raw := envelope(T, key(9), 2, f.now, 1000)
		return f, f.driverMessage(1, raw, Ignore)
	},
	"new message accepted and forwarded to Dhi peers": func(t *testing.T) (*fixture, func()) {
		f := meshFixture(t, nil, 13, 12)
		raw := envelope(T, key(9), 1, f.now, 4000)
		return f, f.driverMessage(1, raw, Accept)
	},
	"message waiting for its author's chain": func(t *testing.T) (*fixture, func()) {
		res := &stubResolver{want: &wire.CertWant{}}
		f := resolverFixture(t, nil, res)
		f.join(T, nil)
		f.addPeers(1, T)
		raw := markedEnvelope(1, f.now, unresolvedSig)
		return f, f.driverMessage(1, raw, Ignore)
	},
	"new message evicting from a cache full of other topics": func(t *testing.T) (*fixture, func()) {
		cfg := DefaultConfig()
		cfg.MaxCacheMessages = 10
		f := newFixture(t, cfg)
		topics := []wire.Topic{T}
		for i := range 15 {
			topics = append(topics, topicID(20+i))
		}
		for _, tp := range topics {
			f.join(tp, nil)
		}
		f.addPeers(2, topics...)
		for _, tp := range topics[1:] {
			for i := range 10 {
				f.receive(2, envelope(tp, key(9), uint64(i), f.now, 100), Accept)
			}
		}
		for i := range 10 {
			f.receive(2, envelope(T, key(9), uint64(1000+i), f.now, 100), Accept)
		}
		raw := envelope(T, key(9), 5000, f.now, 100)
		return f, f.driverMessage(1, raw, Accept)
	},
	"PRUNE into full backoff tables": func(t *testing.T) (*fixture, func()) {
		cfg := DefaultConfig()
		cfg.MaxBackoff = 1000
		f := newFixture(t, cfg)
		var c wire.Control
		for i := range 16 {
			f.join(topicID(i), nil)
			for k := range 1000 {
				f.r.backoff.add(f.now, topicID(i), key(5000+k), time.Minute, false, 1000, f.r.byID)
			}
			c.Prune = append(c.Prune, wire.Prune{Topic: topicID(i)})
		}
		f.addPeers(1)
		return f, func() { f.control(1, &c) }
	},
	"a peer that waits with askCap ids asked of it": func(t *testing.T) (*fixture, func()) {
		f := meshFixture(t, nil, 2, 0)
		f.control(1, &wire.Control{IHave: []wire.IHave{{Topic: T, IDs: ids(7, 5000)}}})
		f.control(2, &wire.Control{IHave: []wire.IHave{{Topic: T, IDs: ids(7, 5000)}}})
		return f, func() {
			f.r.byID[key(1)].lock.level = -1 << 40
			f.r.Wait(f.now, key(1))
		}
	},
	"unknown author of 1 MiB, signed": func(t *testing.T) (*fixture, func()) {
		f := meshFixture(t, nil, 13, 12)
		e := &wire.Envelope{Topic: T, Device: wire.Key(key(9)), Seq: 1, Time: uint64(f.now.UnixMilli()), Body: make([]byte, 1<<20-200)}
		e.Sig[0] = unknownSig
		raw := e.Encode()
		return f, f.driverMessage(1, raw, Ignore)
	},
	"15,887 subscriptions alternating on one topic": func(t *testing.T) (*fixture, func()) {
		f := meshFixture(t, nil, 1, 0)
		c := &wire.Control{}
		for i := range 15887 {
			c.Subs = append(c.Subs, wire.Sub{Topic: topicID(50), Subscribe: i%2 == 0})
		}
		return f, func() { f.control(1, c) }
	},
	"15,887 distinct subscriptions to other topics with the list full": func(t *testing.T) (*fixture, func()) {
		f := meshFixture(t, nil, 1, 0)
		f.control(1, topicsFrame(0, 1024))
		c := topicsFrame(2000, 15887)
		return f, func() { f.control(1, c) }
	},
	"50 subscriptions to joined topics": func(t *testing.T) (*fixture, func()) {
		f := newFixture(t, nil)
		c := &wire.Control{}
		for i := range 50 {
			f.join(topicID(i), nil)
			c.Subs = append(c.Subs, wire.Sub{Topic: topicID(i), Subscribe: true})
		}
		f.addPeers(1)
		return f, func() { f.control(1, c) }
	},
	"GRAFT of 32 joined topics at 1,000 peers": func(t *testing.T) (*fixture, func()) {
		f := newFixture(t, nil)
		var subs, c wire.Control
		for i := range 32 {
			f.join(topicID(i), nil)
			subs.Subs = append(subs.Subs, wire.Sub{Topic: topicID(i), Subscribe: true})
			c.Graft = append(c.Graft, topicID(i))
		}
		f.addPeers(1000)
		for i := 1; i <= 1000; i++ {
			f.control(i, &subs)
		}
		return f, func() { f.control(1, &c) }
	},
	"empty control frame": func(t *testing.T) (*fixture, func()) {
		f := meshFixture(t, nil, 1, 0)
		return f, func() { f.control(1, &wire.Control{}) }
	},
	"IHAVE of 15,900 groups for topics not joined": func(t *testing.T) (*fixture, func()) {
		f := meshFixture(t, nil, 1, 0)
		c := &wire.Control{}
		for i := range 15900 {
			c.IHave = append(c.IHave, wire.IHave{Topic: wire.Topic{0xee, byte(i), byte(i >> 8)}})
		}
		return f, func() { f.control(1, c) }
	},
	"IHAVE of MaxIHaveLength unseen ids": func(t *testing.T) (*fixture, func()) {
		f := meshFixture(t, nil, 1, 0)
		c := &wire.Control{IHave: []wire.IHave{{Topic: T, IDs: ids(7, 8000)}}}
		return f, func() { f.control(1, c) }
	},
	"IHAVE past MaxIHaveMessages": func(t *testing.T) (*fixture, func()) {
		f := meshFixture(t, nil, 1, 0)
		for range DefaultConfig().MaxIHaveMessages {
			f.control(1, &wire.Control{IHave: []wire.IHave{{Topic: T}}})
		}
		c := &wire.Control{IHave: []wire.IHave{{Topic: T, IDs: ids(7, 5000)}}}
		return f, func() { f.control(1, c) }
	},
	"IWANT of MaxIHaveLength cached ids": func(t *testing.T) (*fixture, func()) {
		f := meshFixture(t, nil, 2, 0)
		var want []wire.ID
		for i := range 5000 {
			raw := envelope(T, key(9), uint64(i), f.now, 100)
			f.receive(2, raw, Accept)
			want = append(want, wire.NewID(raw))
		}
		c := &wire.Control{IWant: append(want, ids(3, 3000)...)}
		return f, func() { f.control(1, c) }
	},
	"IDONTWANT of one id": func(t *testing.T) (*fixture, func()) {
		f := meshFixture(t, nil, 1, 0)
		return f, func() { f.control(1, &wire.Control{IDontWant: ids(4, 1)}) }
	},
	"IDONTWANT past MaxIDontWantMessages": func(t *testing.T) (*fixture, func()) {
		f := meshFixture(t, nil, 1, 0)
		for range DefaultConfig().MaxIDontWantMessages {
			f.control(1, &wire.Control{IDontWant: ids(4, 1)})
		}
		c := &wire.Control{IDontWant: ids(5, 100)}
		return f, func() { f.control(1, c) }
	},
	"GRAFT of 32 topics in backoff": func(t *testing.T) (*fixture, func()) {
		f := newFixture(t, nil)
		var c wire.Control
		for i := range 16 {
			f.join(topicID(i), nil)
		}
		f.addPeers(1)
		for i := range 32 {
			tp := topicID(i % 16)
			if i >= 16 {
				tp = topicID(100 + i)
			}
			c.Graft = append(c.Graft, tp)
			f.r.backoff.add(f.now, tp, key(1), time.Minute, false, 1024, f.r.byID)
		}
		return f, func() { f.control(1, &c) }
	},
	"PRUNE of 32 topics in the mesh": func(t *testing.T) (*fixture, func()) {
		f := newFixture(t, nil)
		var c wire.Control
		var subs wire.Control
		for i := range 16 {
			f.join(topicID(i), nil)
			subs.Subs = append(subs.Subs, wire.Sub{Topic: topicID(i), Subscribe: true})
			c.Prune = append(c.Prune, wire.Prune{Topic: topicID(i)}, wire.Prune{Topic: topicID(100 + i)})
		}
		f.addPeers(1)
		f.control(1, &subs)
		f.control(1, &wire.Control{Graft: subs.Graft})
		return f, func() { f.control(1, &c) }
	},
	"PRUNE of 32 topics with 40 peer exchange records each, from a vouched peer": func(t *testing.T) (*fixture, func()) {
		cfg := DefaultConfig()
		cfg.Score.AppScore = func(p PeerID) float64 { return 20 }
		f := newFixture(t, cfg)
		var c, subs wire.Control
		for i := range 16 {
			f.join(topicID(i), nil)
			subs.Subs = append(subs.Subs, wire.Sub{Topic: topicID(i), Subscribe: true})
			c.Prune = append(c.Prune, wire.Prune{Topic: topicID(i), PX: pxRecs(1000+100*i, 40)},
				wire.Prune{Topic: topicID(100 + i), PX: pxRecs(5000+100*i, 40)})
		}
		f.addPeers(1)
		f.control(1, &subs)
		return f, func() { f.control(1, &c) }
	},
	"GRAFT of 16 topics refused for full meshes, with peer exchange": func(t *testing.T) (*fixture, func()) {
		cfg := DefaultConfig()
		cfg.PeerExchange = true
		f := newFixture(t, cfg)
		var g, subs wire.Control
		for i := range 16 {
			f.join(topicID(i), nil)
			subs.Subs = append(subs.Subs, wire.Sub{Topic: topicID(i), Subscribe: true})
			g.Graft = append(g.Graft, topicID(i))
		}
		for i := 2; i <= 64; i++ {
			f.addPeer(i, true)
			f.control(i, &subs)
			if i <= 1+cfg.Params.Dhi {
				f.control(i, &wire.Control{Graft: g.Graft})
			}
		}
		f.addPeer(1, false)
		f.control(1, &subs)
		return f, func() { f.control(1, &g) }
	},
	"31 subscriptions, the most a mesh peer can add": func(t *testing.T) (*fixture, func()) {
		f := meshFixture(t, nil, 1, 0)
		var c wire.Control
		for i := range 31 {
			c.Subs = append(c.Subs, wire.Sub{Topic: topicID(50 + i), Subscribe: true})
		}
		return f, func() { f.control(1, &c) }
	},
}

// TestUnitAudit: every handler path charges the peer that sent the frame at least the operations it does, kind by
// kind, for its most expensive frame, so a handler that works without charging, or charges another peer, fails
// here.
func TestUnitAudit(t *testing.T) {
	for name, path := range auditPaths {
		f, send := path(t)
		f.r.AuditPeer(key(1)) // work charged to anyone else shows as unpaid
		send()
		done, charged := f.r.Audit()
		if len(done) == 0 {
			t.Errorf("%s: no operation counted", name)
		}
		var d, c int64
		for op, n := range done {
			d += Cost(op, int(n))
			if charged[op] < n {
				t.Errorf("%s: op %d done %d times, charged %d", name, op, n, charged[op])
			}
		}
		for op, n := range charged {
			c += Cost(op, int(n))
		}
		if c < d {
			t.Errorf("%s: %d units charged for %d done", name, c, d)
		}
	}
}

// driverMessage prepares raw as the driver hands it in, its id hashed and its signature checked on the peer's
// reader beforehand, and returns the frame's router calls: MessageWithID, MessageSigned if asked for, and the
// verdict v if it reaches the validator. What is timed is then the work under the lock alone.
func (f *fixture) driverMessage(i int, raw []byte, v Verdict) func() {
	id := wire.NewID(raw)
	signed := false
	if env, err := wire.DecodeEnvelope(raw, len(raw)); err == nil {
		signed = f.v.Signed(env, raw[:len(raw)-wire.SigSize])
	}
	return func() {
		n := len(f.sink.validate)
		if f.r.MessageWithID(f.now, key(i), raw, id) {
			f.r.MessageSigned(f.now, key(i), raw, id, signed)
		}
		if v != Ignore && len(f.sink.validate) > n {
			f.r.ValidationDone(f.now, f.sink.validate[n].id, f.sink.validate[n].n, v)
		}
	}
}
