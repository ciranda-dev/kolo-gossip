package core

import (
	"testing"
	"time"

	"github.com/ciranda-dev/kolo-gossip/internal/wire"
)

// TestPeerBusyDropsOnlyThatCopy: a forwarder whose own request limit is full gets only its copy dropped; a copy
// from another peer is resolved at once.
func TestPeerBusyDropsOnlyThatCopy(t *testing.T) {
	res := &stubResolver{err: ErrPeerBusy}
	f := resolverFixture(t, nil, res)
	f.join(T, nil)
	f.addPeers(2, T)
	raw := markedEnvelope(1, f.now, unresolvedSig)
	f.r.Message(f.now, key(1), raw)
	res.err, res.want = nil, &wire.CertWant{}
	f.r.Message(f.now, key(2), raw)
	if s := f.r.Stats(); s.IgnoredCopies != 0 || s.Resolving != 1 || len(res.resolves) != 2 {
		t.Fatalf("an honest copy was dropped after a busy forwarder: %+v", s)
	}
}

// TestControlCaps: GRAFT or PRUNE lists longer than maxFrameTopics break the protocol; duplicate PRUNE entries are
// handled once; at most MaxIHaveLength ids of an IWANT are answered; an answer our queue drops is not counted as
// sent and ends the answers.
func TestControlCaps(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxIHaveLength = 3
	f := meshFixture(t, cfg, 1, 1)
	if err := f.r.Control(f.now, key(1), &wire.Control{Prune: make([]wire.Prune, maxFrameTopics+1)}); err == nil {
		t.Fatal("33 PRUNE entries accepted")
	}
	if err := f.r.Control(f.now, key(1), &wire.Control{Graft: make([]wire.Topic, maxFrameTopics+1)}); err == nil {
		t.Fatal("33 GRAFT entries accepted")
	}
	f.control(1, &wire.Control{Prune: []wire.Prune{{Topic: T}, {Topic: T}, {Topic: T}}})
	if f.inMesh(T, 1) || len(f.r.backoff.m[T].m) != 1 {
		t.Fatal("duplicate PRUNE entries not handled once")
	}
	var cached []wire.ID
	for i := range 5 {
		raw := envelope(T, key(9), uint64(i), f.now, 100)
		f.receive(1, raw, Accept)
		cached = append(cached, wire.NewID(raw))
	}
	f.sink.reset()
	f.control(1, &wire.Control{IWant: cached})
	if len(f.sink.msgs) != 3 {
		t.Fatalf("%d IWANT answers for MaxIHaveLength 3", len(f.sink.msgs))
	}
	g := meshFixture(t, nil, 1, 0)
	raw := envelope(T, key(9), 1, g.now, 100)
	g.receive(1, raw, Accept)
	g.sink.full[key(1)] = true
	g.control(1, &wire.Control{IWant: []wire.ID{wire.NewID(raw)}})
	if g.r.byID[key(1)].sent[wire.NewID(raw)] != 0 {
		t.Fatal("an answer the queue dropped counted against GossipRetransmission")
	}
}

// TestConcurrentCheck: two readers that bring copies of one new id at once both check its signature outside the
// router, each charged for it; the first admits it and the second is a duplicate.
func TestConcurrentCheck(t *testing.T) {
	f := meshFixture(t, nil, 2, 0)
	raw := envelope(T, key(9), 1, f.now, 1)
	id := wire.NewID(raw)
	if !f.r.MessageWithID(f.now, key(1), raw, id) || !f.r.MessageWithID(f.now, key(2), raw, id) {
		t.Fatal("a new id did not ask both readers for a check")
	}
	before := f.r.byID[key(2)].out.level
	f.r.MessageSigned(f.now, key(1), raw, id, true)
	f.r.MessageSigned(f.now, key(2), raw, id, true)
	check := Cost(OpSignature, 1) + Cost(OpSigBytes, chunks(len(raw))) + Cost(OpDecode, chunks(len(raw)))
	if s := f.r.Stats(); s.Duplicates != 1 || s.Validating != 1 || f.r.byID[key(2)].out.level != before-check {
		t.Fatalf("%+v", s)
	}
}

// TestAppScoreOncePerHeartbeat: the application score runs once per peer per heartbeat.
func TestAppScoreOncePerHeartbeat(t *testing.T) {
	cfg := scoringConfig()
	calls := 0
	cfg.Score.AppScore = func(PeerID) float64 { calls++; return 0 }
	f := newFixture(t, cfg)
	f.join(T, &TopicConfig{Score: topicScore()})
	f.addPeers(1, T)
	for range 2 {
		f.heartbeat()
		calls = 0
		for i := range 10 {
			f.r.Message(f.now, key(1), envelope(T, key(9), uint64(i), f.now, 1))
		}
		if calls > 1 {
			t.Fatalf("AppScore ran %d times in one heartbeat", calls)
		}
	}
}

// TestEdgeNotCached: a message delivered but not forwarded for the window's edge is not cached either, so no IHAVE
// announces it.
func TestEdgeNotCached(t *testing.T) {
	f := meshFixture(t, nil, 1, 1)
	f.receive(1, envelope(T, key(9), 1, f.now.Add(-time.Minute+500*time.Millisecond), 1), Accept)
	if s := f.r.Stats(); s.Delivered != 1 || s.CacheMessages != 0 {
		t.Fatalf("an edge message was cached: %+v", s)
	}
}

// TestCopiesOfAskedIDCharged: only the asked peer's answer that brings the message is given back its work; a copy
// from the asked peer that brings nothing, and every copy from another peer, are charged.
func TestCopiesOfAskedIDCharged(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxPeerValidating = 1
	f := meshFixture(t, cfg, 2, 0)
	f.r.Message(f.now, key(1), envelope(T, key(9), 1, f.now, 1))
	raw := envelope(T, key(9), 2, f.now, 1)
	f.control(1, &wire.Control{IHave: []wire.IHave{{Topic: T, IDs: []wire.ID{wire.NewID(raw)}}}})
	before := f.r.byID[key(1)].out.level
	for range 4 {
		f.r.Message(f.now, key(1), raw) // over its share: throttled each time
	}
	if f.r.byID[key(1)].out.level >= before-3*Cost(OpSignature, 1) {
		t.Fatal("throttled copies of an asked id were not charged")
	}
}

// TestIDontWantCap: past MaxIDontWantMessages frames in a heartbeat, an IDONTWANT id is not kept, and past
// MaxIDontWantLength ids a frame's other ids are not either.
func TestIDontWantCap(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxIDontWantMessages, cfg.MaxIDontWantLength = 2, 2
	f := meshFixture(t, cfg, 1, 0)
	f.heartbeat()
	f.control(1, &wire.Control{IDontWant: ids(1, 3)})
	f.control(1, &wire.Control{IDontWant: ids(2, 1)})
	f.control(1, &wire.Control{IDontWant: ids(3, 1)})
	u := f.r.byID[key(1)].unwanted
	if !u.has(ids(1, 2)[1]) || u.has(ids(1, 3)[2]) || !u.has(ids(2, 1)[0]) || u.has(ids(3, 1)[0]) {
		t.Fatal("IDONTWANT caps not applied")
	}
}

// TestShareByPeers: the lock budget is shared by the peers connected now: with two peers each refills 32 times
// faster than with 64.
func TestShareByPeers(t *testing.T) {
	refilled := func(n int) int64 {
		f := meshFixture(t, nil, n, 0)
		p := f.r.byID[key(1)]
		p.lock.level = 0
		f.r.Wait(f.now, key(1))
		f.now = f.now.Add(100 * time.Millisecond)
		f.r.Wait(f.now, key(1))
		return p.lock.level
	}
	if two, all := refilled(2), refilled(64); two < 30*all || all <= 0 {
		t.Fatalf("refilled %d units in 100 ms with 2 peers, %d with 64", two, all)
	}
}

// TestRetrySkipsWaitingPeers: a chain request is not sent to a peer we do not read now.
func TestRetrySkipsWaitingPeers(t *testing.T) {
	res := &stubResolver{want: &wire.CertWant{}}
	f := resolverFixture(t, nil, res)
	f.join(T, nil)
	f.addPeers(3, T)
	raw := markedEnvelope(1, f.now, unresolvedSig)
	for p := 1; p <= 3; p++ {
		f.r.Message(f.now, key(p), raw)
	}
	f.r.byID[key(2)].lock.level = -1 << 40
	f.r.Wait(f.now, key(2))
	res.ended = Resolutions{Done: []Resolution{{ID: wire.NewID(raw), Err: ErrUnresolved}}}
	f.r.byID[key(1)].lock.level = -1 << 40
	f.r.Wait(f.now, key(1))
	if len(res.resolves) != 2 || res.resolves[1].from != key(3) {
		t.Fatalf("requests %+v", res.resolves)
	}
}

// TestPendingSubsUrgent: subscriptions held back by a full queue and sent with the heartbeat's IHAVE go in the
// urgent lane, so they are not overtaken.
func TestPendingSubsUrgent(t *testing.T) {
	f := meshFixture(t, nil, 10, 6)
	f.receive(1, envelope(T, key(9), 1, f.now, 1), Accept)
	f.sink.full[key(8)] = true
	f.join(topicID(3), nil)
	f.sink.full[key(8)] = false
	f.sink.reset()
	f.heartbeat()
	found := false
	for _, c := range f.sink.ctrl {
		if c.to == key(8) && len(c.c.Subs) > 0 && len(c.c.IHave) > 0 {
			found = true
			if !c.urgent {
				t.Fatal("pending subscriptions with IHAVE in the normal lane")
			}
		}
	}
	if !found {
		t.Fatal("pending subscriptions not sent with the IHAVE")
	}
}

// TestAskedAgainAfterArrival: once the ids asked of a peer arrive, the peer may be asked for others at once.
func TestAskedAgainAfterArrival(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxIHaveLength = 3
	f := meshFixture(t, cfg, 1, 0)
	for round := range 3 {
		var raws [][]byte
		var announced []wire.ID
		for i := range 3 {
			raw := envelope(T, key(9), uint64(10*round+i), f.now, 1)
			raws = append(raws, raw)
			announced = append(announced, wire.NewID(raw))
		}
		f.sink.reset()
		f.control(1, &wire.Control{IHave: []wire.IHave{{Topic: T, IDs: announced}}})
		if got := iwants(f.sink, key(1)); got != 3 {
			t.Fatalf("round %d: asked %d", round, got)
		}
		for _, raw := range raws {
			f.receive(1, raw, Accept)
		}
	}
}
