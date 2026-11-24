package core

import (
	"testing"
	"time"

	"github.com/ciranda-dev/kolo-gossip/internal/wire"
)

// honestRun feeds a node with peers peers the traffic of a room at rate messages of 1 KiB a second, with
// bursts at twice the rate for 2 s if asked, the way its D mesh peers bring it: each message first from one of them in
// turn and a copy from each of the others, and an IDONTWANT from each, one frame per id. Heartbeats come late or
// early by up to 300 ms. It reports the first peer that had to wait.
func honestRun(t *testing.T, cfg *Config, peers, rate int, seconds int, bursts bool) (*fixture, int, PeerID) {
	f := meshFixture(t, cfg, peers, cfg.Params.D)
	f.settle()
	return honestRunOn(t, f, cfg, rate, seconds, bursts, false)
}

// honestRunOn is honestRun on f; with sole set, peer 1 brings every message first and the buckets are only
// charged, never refilled, so what each peer used can be read from its levels.
func honestRunOn(t *testing.T, f *fixture, cfg *Config, rate int, seconds int, bursts, sole bool) (*fixture, int, PeerID) {
	f.sink.bench = true
	d := cfg.Params.D
	sent, beat := 0, f.now.Add(time.Second)
	start := f.now
	jitter := []time.Duration{300, -200, 100, -300, 250, 0, -100, 200}
	for s := range seconds {
		n := rate
		if bursts && (s == 3 || s == 4) {
			n = 2 * rate
		}
		for i := range n {
			f.now = start.Add(time.Duration(s)*time.Second + time.Duration(i)*time.Second/time.Duration(n))
			if !f.now.Before(beat) {
				f.r.Tick(f.now)
				beat = beat.Add(time.Second + jitter[s%len(jitter)]*time.Millisecond)
			}
			tp := T
			if len(f.spread) > 0 {
				tp = f.spread[sent%len(f.spread)]
			}
			raw := envelope(tp, key(900), uint64(sent), f.now, 1024)
			id := wire.NewID(raw)
			first := 1 + sent%d
			if sole {
				first = 1
			}
			f.receive(first, raw, Accept)
			for q := 1; q <= d; q++ {
				if q != first {
					f.r.Message(f.now, key(q), raw)
				}
				f.r.ControlFrame(f.now, key(q), &wire.Control{IDontWant: []wire.ID{id}}, 41)
				if !sole && f.r.Wait(f.now, key(q)) > 0 {
					return f, sent, key(q)
				}
			}
			sent++
		}
	}
	return f, sent, PeerID{}
}

// TestHonestHeadroom: honest mesh peers of a node with every connection place taken never wait for their
// buckets, lose no message and are never penalised, at the design rate with bursts of twice the rate for 2 s and
// late heartbeats, and at twice the design rate held for 8 s: the 2x headroom the buckets are sized for.
func TestHonestHeadroom(t *testing.T) {
	design := DefaultConfig().DesignRate
	for _, c := range []struct {
		rate   int
		bursts bool
	}{{design, true}, {2 * design, false}} {
		f, sent, waited := honestRun(t, DefaultConfig(), 64, c.rate, 8, c.bursts)
		if waited != (PeerID{}) {
			t.Fatalf("rate %d: peer %x waited after %d messages", c.rate, waited[:4], sent)
		}
		if s := f.r.Stats(); s.Delivered != uint64(sent) || s.Waits != 0 {
			t.Fatalf("rate %d: %d of %d delivered, %+v", c.rate, s.Delivered, sent, s)
		}
		for q := 1; q <= DefaultConfig().Params.D; q++ {
			if f.r.Score(key(q)) < 0 {
				t.Fatalf("rate %d: mesh peer %d penalised: %v", c.rate, q, f.r.Score(key(q)))
			}
		}
	}
}

// TestHonestHeadroomMeasured reports what an honest mesh peer uses of its buckets per second at the design rate,
// on average over the D mesh peers, for limits.md.
func TestHonestHeadroomMeasured(t *testing.T) {
	for _, sole := range []bool{false, true} {
		cfg := DefaultConfig()
		cfg.WorkBurst = time.Hour // nothing waits, so the use can be read in full
		f := meshFixture(t, cfg, 64, cfg.Params.D)
		f.settle()
		f.r.AuditOps()
		start := f.r.byID[key(1)].lock.level
		f, sent, _ := honestRunOn(t, f, cfg, cfg.DesignRate, 4, false, sole)
		_, charged := f.r.Audit()
		var lock, out int64
		for op, n := range charged {
			if op.outside() {
				out += Cost(op, int(n))
			} else {
				lock += Cost(op, int(n))
			}
		}
		d := int64(cfg.Params.D) * 4
		rl, ro := rateOf(f, 1)
		if sole {
			used := (start - f.r.byID[key(1)].lock.level) / 4
			t.Logf("sole source, %d messages in 4 s: it used %d lock units/s of %d (%.2fx its share)", sent, used, rl, float64(used)/float64(rl))
			continue
		}
		t.Logf("%d messages in 4 s: a mesh peer used %d lock units/s of %d (%.1fx headroom), %d outside units/s of %d (%.1fx)",
			sent, lock/d, rl, float64(rl)/float64(lock/d), out/d, ro, float64(ro)/float64(out/d))
	}
}

// TestHonestCatchUp: after a partition, six peers announce MaxCacheMessages ids between them; each id is asked of
// at most two peers at once, and of one peer at most askCap ids; the asked peers' answers cost them nothing, no
// peer waits, every message arrives, and every promise is kept.
func TestHonestCatchUp(t *testing.T) {
	cfg := scoringConfig()
	f := newFixture(t, cfg)
	f.join(T, &TopicConfig{Score: topicScore()})
	f.addPeers(64, T)
	f.settle()
	f.sink.bench = true
	f.heartbeat()
	byID := map[wire.ID][]byte{}
	var all []wire.ID
	for i := range cfg.MaxCacheMessages {
		raw := envelope(T, key(900), uint64(i), f.now, 1024)
		byID[wire.NewID(raw)] = raw
		all = append(all, wire.NewID(raw))
	}
	got := map[wire.ID]bool{}
	for round := 0; len(got) < len(all) && round < 10; round++ {
		for p := 1; p <= 6; p++ {
			f.sink.validate = nil
			f.sink.bench = false
			f.sink.reset()
			// Each peer announces the ids it holds, MaxIHaveLength at most per IHAVE, as its heartbeat does.
			lo := (p - 1) * len(all) / 6
			part := append(append([]wire.ID{}, all[lo:]...), all[:lo]...)[:cfg.MaxIHaveLength]
			f.control(p, &wire.Control{IHave: []wire.IHave{{Topic: T, IDs: part}}})
			for _, c := range f.sink.ctrlTo(key(p)) {
				if len(c.IWant) > int(f.r.askCap()) {
					t.Fatalf("peer %d asked %d ids", p, len(c.IWant))
				}
				for _, id := range c.IWant {
					f.receive(p, byID[id], Accept)
					got[id] = true
				}
			}
			if f.r.Wait(f.now, key(p)) > 0 {
				t.Fatalf("round %d: peer %d waits for answers we asked", round, p)
			}
		}
		f.heartbeat()
	}
	if len(got) != len(all) || f.r.Stats().Delivered != uint64(len(all)) {
		t.Fatalf("%d of %d fetched", len(got), len(all))
	}
	f.tick(4 * time.Second)
	for p := 1; p <= 6; p++ {
		if bp := f.r.score.stats[key(p)].behaviourPenalty; bp != 0 {
			t.Fatalf("peer %d penalised for promises: %v", p, bp)
		}
	}
}

// TestIDontWantFloodWaits: IDONTWANT frames past MaxIDontWantMessages are charged too, so a flood of small ones
// empties the peer's bucket and it waits.
func TestIDontWantFloodWaits(t *testing.T) {
	cfg := DefaultConfig()
	f := meshFixture(t, cfg, 64, 0)
	c := &wire.Control{IDontWant: ids(4, 1)}
	lock, _ := rateOf(f, 1)
	limit := int(float64(lock)*cfg.WorkBurst.Seconds())/int(Cost(OpCall, 1)) + 1
	for i := range limit {
		f.r.ControlFrame(f.now, key(1), c, 41)
		if f.r.Wait(f.now, key(1)) > 0 {
			if i < cfg.MaxIDontWantMessages {
				t.Fatalf("waited within MaxIDontWantMessages, after %d frames", i)
			}
			return
		}
	}
	t.Fatalf("%d IDONTWANT frames never made the peer wait", limit)
}

// TestMessageWithIDNeverChecks: the driver's entry never checks a signature itself: it asks for one.
func TestMessageWithIDNeverChecks(t *testing.T) {
	f := meshFixture(t, nil, 1, 0)
	v := f.r.v.(*fakeVerifier)
	raw := envelope(T, key(9), 1, f.now, 1)
	if !f.r.MessageWithID(f.now, key(1), raw, wire.NewID(raw)) || v.calls != 0 {
		t.Fatalf("a new message: asked %v, %d checks", true, v.calls)
	}
	f.r.MessageSigned(f.now, key(1), raw, wire.NewID(raw), true)
	if f.r.MessageWithID(f.now, key(1), raw, wire.NewID(raw)) || v.calls != 0 {
		t.Fatal("a known message asked for a check")
	}
}

// TestAskedOfTwo: an id is asked of at most two peers at once, and up to two more announcers are kept; when an
// asked peer waits for its buckets, or leaves, its asks end without a penalty and its place goes to a kept
// announcer at the next heartbeat.
func TestAskedOfTwo(t *testing.T) {
	cfg := scoringConfig()
	f := newFixture(t, cfg)
	f.join(T, &TopicConfig{Score: topicScore()})
	f.addPeers(4, T)
	ihave := &wire.Control{IHave: []wire.IHave{{Topic: T, IDs: ids(7, 1)}}}
	for p := 1; p <= 3; p++ {
		f.control(p, ihave)
	}
	if iwants(f.sink, key(1)) != 1 || iwants(f.sink, key(2)) != 1 || iwants(f.sink, key(3)) != 0 {
		t.Fatal("not asked of exactly the first two peers")
	}
	f.control(4, ihave) // kept to be asked, like peer 3
	f.r.byID[key(1)].lock.level = -1 << 40
	f.r.Wait(f.now, key(1))
	f.r.RemovePeer(f.now, key(2))
	f.heartbeat()
	if iwants(f.sink, key(3)) != 1 || iwants(f.sink, key(4)) != 1 {
		t.Fatal("the places of a waiting and a departed peer did not go to the next announcers at the heartbeat")
	}
	f.tick(4 * time.Second)
	if f.r.score.stats[key(1)].behaviourPenalty != 0 {
		t.Fatal("a waiting peer was penalised for its dropped promise")
	}
	if f.r.score.stats[key(3)].behaviourPenalty == 0 && f.r.score.stats[key(4)].behaviourPenalty == 0 {
		t.Fatal("a broken promise cost nothing")
	}
}

// TestRefundOnlyAskedPeer: the work of a message is given back only to the peer we asked for it.
func TestRefundOnlyAskedPeer(t *testing.T) {
	f := meshFixture(t, nil, 2, 0)
	raw := envelope(T, key(9), 1, f.now, 1000)
	f.control(1, &wire.Control{IHave: []wire.IHave{{Topic: T, IDs: []wire.ID{wire.NewID(raw)}}}})
	before := f.r.byID[key(2)].out.level
	f.receive(2, raw, Accept)
	if f.r.byID[key(2)].out.level >= before-Cost(OpSignature, 1) {
		t.Fatal("a peer we did not ask had its work given back")
	}
	raw2 := envelope(T, key(9), 2, f.now, 1000)
	f.control(1, &wire.Control{IHave: []wire.IHave{{Topic: T, IDs: []wire.ID{wire.NewID(raw2)}}}})
	before = f.r.byID[key(1)].out.level
	f.receive(1, raw2, Accept)
	if f.r.byID[key(1)].out.level != before {
		t.Fatal("the asked peer paid for its answer")
	}
}

// TestHedgedRequests: a chain request unanswered for a heartbeat is joined by one to the next peer that sent a
// copy, every heartbeat, and a request that ends because its peer waits or leaves is asked of the next peer at once.
func TestHedgedRequests(t *testing.T) {
	res := &stubResolver{want: &wire.CertWant{}}
	f := resolverFixture(t, nil, res)
	f.join(T, nil)
	f.addPeers(4, T)
	raw := markedEnvelope(1, f.now, unresolvedSig)
	for p := 1; p <= 3; p++ {
		f.r.Message(f.now, key(p), raw)
	}
	f.heartbeat()
	f.heartbeat()
	if len(res.resolves) != 2 || res.resolves[1].from != key(2) {
		t.Fatalf("no hedged request after a heartbeat: %+v", res.resolves)
	}
	f.r.Message(f.now, key(4), raw)
	res.ended = Resolutions{Done: []Resolution{{ID: wire.NewID(raw), Err: ErrUnresolved}}}
	f.r.RemovePeer(f.now, key(2))
	if len(res.resolves) != 2 {
		t.Fatal("asked again while another request was outstanding")
	}
	res.ended = Resolutions{Done: []Resolution{{ID: wire.NewID(raw), Err: ErrUnresolved}}}
	f.r.byID[key(1)].lock.level = -1 << 40
	f.r.Wait(f.now, key(1))
	if len(res.resolves) != 3 || res.resolves[2].from != key(3) {
		t.Fatalf("the next peer was not asked at once: %+v", res.resolves)
	}
}

// TestSubscriptionFramesUrgent: subscription changes go first, so a Leave then a Join reach a peer in that order.
func TestSubscriptionFramesUrgent(t *testing.T) {
	f := meshFixture(t, nil, 1, 0)
	f.r.Leave(f.now, T)
	f.join(T, nil)
	for _, c := range f.sink.ctrl {
		if len(c.c.Subs) > 0 && !c.urgent {
			t.Fatal("a subscription frame in the normal lane")
		}
	}
}

// TestBucketsAcrossReconnect: a peer that reconnects within WorkBurst gets back the buckets it left with, so
// leaving does not refill them.
func TestBucketsAcrossReconnect(t *testing.T) {
	f := meshFixture(t, nil, 1, 0)
	f.r.byID[key(1)].lock.level = -1 << 30
	f.r.RemovePeer(f.now, key(1))
	f.addPeer(1, true, T)
	if f.r.Wait(f.now, key(1)) == 0 {
		t.Fatal("a reconnect refilled the buckets")
	}
}
