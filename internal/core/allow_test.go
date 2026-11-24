package core

import (
	"slices"
	"testing"
	"time"

	"github.com/ciranda-dev/kolo-gossip/internal/wire"
)

// mentions reports whether any frame or message sent to p concerns topic t.
func (s *recSink) mentions(p PeerID, t wire.Topic) bool {
	for _, c := range s.ctrlTo(p) {
		for _, sub := range c.Subs {
			if sub.Topic == t {
				return true
			}
		}
		for _, pr := range c.Prune {
			if pr.Topic == t {
				return true
			}
		}
		for _, h := range c.IHave {
			if h.Topic == t {
				return true
			}
		}
		if count(c.Graft, t) > 0 {
			return true
		}
	}
	for _, m := range s.msgs {
		if mt, _ := wire.EnvelopeTopic(m.raw); m.to == p && mt == t {
			return true
		}
	}
	return false
}

// TestAllowPeerRefusedLearnsNothing: a peer that AllowPeer refuses for a topic, one already connected at Join and one
// that connects later, is told nothing of it and gets no message of it, whatever it announces, grafts, asks or sends;
// the open topic works for it and the admitted peer gets both.
func TestAllowPeerRefusedLearnsNothing(t *testing.T) {
	open, closed := topicID(1), topicID(2)
	refused := map[PeerID]bool{key(1): true, key(4): true}
	f := newFixture(t, nil)
	f.addPeer(1, true, open, closed)
	f.join(open, nil)
	f.join(closed, &TopicConfig{AllowPeer: func(p PeerID) bool { return !refused[p] }})
	f.addPeer(2, true, open, closed)
	f.addPeer(3, false, open, closed)
	f.addPeer(4, true, open, closed)
	f.settle()
	mine := envelope(closed, key(0), 1, f.now, 20)
	if _, err := f.r.Publish(f.now, mine); err != nil {
		t.Fatal(err)
	}
	for _, i := range []int{1, 4} {
		f.control(i, &wire.Control{Graft: []wire.Topic{open, closed}, Prune: []wire.Prune{{Topic: closed}},
			IHave: []wire.IHave{{Topic: closed, IDs: []wire.ID{{1}, {2}}}}, IWant: []wire.ID{wire.NewID(mine)}})
		f.r.Message(f.now, key(i), envelope(closed, key(9), uint64(i), f.now, 10))
	}
	f.receive(2, envelope(closed, key(9), 10, f.now, 10), Accept)
	f.receive(3, envelope(open, key(9), 11, f.now, 10), Accept)
	for range 8 {
		f.heartbeat()
	}
	for _, i := range []int{1, 4} {
		if f.r.backoff.has(closed, key(i)) {
			t.Errorf("peer %d's PRUNE of the closed topic was taken", i)
		}
	}
	f.r.Leave(f.now, closed)
	for _, i := range []int{1, 4} {
		if f.sink.mentions(key(i), closed) || slices.ContainsFunc(f.sink.ctrlTo(key(i)), func(c *wire.Control) bool { return len(c.IWant) > 0 }) {
			t.Errorf("peer %d was told about the closed topic or asked for its messages", i)
		}
		if f.inMesh(closed, i) || f.r.byID[key(i)].refuses(open) {
			t.Errorf("peer %d in the closed mesh or refused for the open topic", i)
		}
	}
	if len(f.sink.validate) != 2 || f.r.Stats().NotJoined < 2 {
		t.Fatalf("a refused peer's message reached the validator: %d validations, %+v", len(f.sink.validate), f.r.Stats())
	}
	if f.sink.graftsTo(key(1), open) != 1 || !f.sink.mentions(key(1), open) || !f.sink.mentions(key(2), closed) || f.sink.msgsTo(key(2)) == 0 {
		t.Fatal("the open topic or the admitted peer lost service")
	}
}

// TestAllowPeerRefresh: Refresh asks again: a peer refused now leaves the mesh and is told we left the topic, one
// admitted now is told we joined, and it is grafted again once the backoff has passed.
func TestAllowPeerRefresh(t *testing.T) {
	topic := topicID(3)
	no := PeerID{}
	deny := no
	f := newFixture(t, nil)
	f.join(topic, &TopicConfig{AllowPeer: func(p PeerID) bool { return p != deny }})
	f.addPeers(2, topic)
	f.control(1, &wire.Control{Graft: []wire.Topic{topic}})
	f.control(2, &wire.Control{Graft: []wire.Topic{topic}})
	if !f.inMesh(topic, 1) || !f.inMesh(topic, 2) {
		t.Fatal("setup: peers not in the mesh")
	}
	f.sink.reset()
	f.r.Refresh(f.now, topic)
	if len(f.sink.ctrl) != 0 {
		t.Fatal("Refresh with the same answers sent control")
	}
	deny = key(1)
	f.r.Refresh(f.now, topic)
	if f.inMesh(topic, 1) || !f.inMesh(topic, 2) || len(f.sink.prunesTo(key(1), topic)) != 1 || len(f.sink.ctrlTo(key(2))) != 0 {
		t.Fatalf("after the refusal: mesh %v", f.r.Mesh(topic))
	}
	subs := f.sink.ctrlTo(key(1))[0].Subs
	if len(subs) != 1 || subs[0].Subscribe {
		t.Fatalf("subscriptions sent to the refused peer: %+v", subs)
	}
	f.sink.reset()
	f.r.Publish(f.now, envelope(topic, key(0), 1, f.now, 5))
	for range 3 {
		f.heartbeat()
	}
	if f.sink.msgsTo(key(1)) != 0 || len(f.sink.ctrlTo(key(1))) != 0 {
		t.Fatal("a refused peer was served after Refresh")
	}
	deny = no
	f.r.Refresh(f.now, topic)
	if c := f.sink.ctrlTo(key(1)); len(c) != 1 || len(c[0].Subs) != 1 || !c[0].Subs[0].Subscribe {
		t.Fatalf("the admitted peer was not told: %+v", c)
	}
	for start := f.now; !f.inMesh(topic, 1); f.heartbeat() {
		if f.now.Sub(start) > time.Minute {
			t.Fatal("the admitted peer never rejoined the mesh")
		}
	}
}

// TestAllowPeerCalls: AllowPeer runs when the topic is joined for each connected peer and once for a new peer, never
// again by itself, and the new peer pays one application call.
func TestAllowPeerCalls(t *testing.T) {
	calls := 0
	f := newFixture(t, nil)
	f.addPeers(3)
	f.join(topicID(4), &TopicConfig{AllowPeer: func(PeerID) bool { calls++; return true }})
	if calls != 3 {
		t.Fatalf("%d calls at Join", calls)
	}
	f.r.AuditOps()
	f.addPeer(4, true)
	f.heartbeat()
	done, charged := f.r.Audit()
	if calls != 4 || done[OpCallback] != 1 || charged[OpCallback] != 1 {
		t.Fatalf("%d calls, callbacks done %d charged %d", calls, done[OpCallback], charged[OpCallback])
	}
}

// TestAllowPeerAfterFanout: a refused peer that announced the topic before we joined it, and sat in its fanout, is not
// moved into the mesh by Join.
func TestAllowPeerAfterFanout(t *testing.T) {
	topic := topicID(5)
	cfg := DefaultConfig()
	cfg.FloodPublish = false
	f := newFixture(t, cfg)
	f.addPeers(2, topic)
	if _, err := f.r.Publish(f.now, envelope(topic, key(0), 1, f.now, 5)); err != nil || len(f.r.Fanout(topic)) != 2 {
		t.Fatalf("setup: fanout %v, %v", f.r.Fanout(topic), err)
	}
	f.sink.reset()
	f.join(topic, &TopicConfig{AllowPeer: func(p PeerID) bool { return p != key(1) }})
	if f.inMesh(topic, 1) || !f.inMesh(topic, 2) || f.sink.mentions(key(1), topic) {
		t.Fatalf("mesh %v, the refused peer told: %v", f.r.Mesh(topic), f.sink.mentions(key(1), topic))
	}
}

// TestAllowPeerPendingSubscription: a subscription that a full queue held back is not sent as a subscribe once the peer
// is refused.
func TestAllowPeerPendingSubscription(t *testing.T) {
	topic := topicID(6)
	deny := false
	f := newFixture(t, nil)
	f.addPeers(1, topic)
	f.sink.full[key(1)] = true
	f.join(topic, &TopicConfig{AllowPeer: func(PeerID) bool { return !deny }})
	deny = true
	f.r.Refresh(f.now, topic)
	f.sink.full[key(1)] = false
	f.heartbeat()
	for _, c := range f.sink.ctrlTo(key(1)) {
		for _, s := range c.Subs {
			if s.Topic == topic && s.Subscribe {
				t.Fatal("a refused peer was told that we joined")
			}
		}
	}
}
