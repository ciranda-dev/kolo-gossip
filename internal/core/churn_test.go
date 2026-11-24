package core

import (
	"errors"
	"testing"
	"time"

	"github.com/ciranda-dev/kolo-gossip/internal/wire"
)

// TestFreshKeysStartEmpty: a new key's buckets hold only what the newcomer pool gives, at most one second of a
// full node's share; once the pool is spent, new keys start empty.
func TestFreshKeysStartEmpty(t *testing.T) {
	cfg := DefaultConfig()
	f := meshFixture(t, cfg, 3, 0)
	lock, _, _, _ := f.r.nodeRates()
	for i := 1; i <= 3; i++ {
		if l := f.r.byID[key(i)].lock.level; l > lock {
			t.Fatalf("peer %d starts with %d lock units, over one second of a share (%d)", i, l, lock)
		}
	}
	if l := f.r.byID[key(3)].lock.level; l > 0 {
		t.Fatalf("the third new key has %d units after the pool's two seconds were given", l)
	}
}

// TestChurnBounded: keys that connect, spend what they are given, and leave, a new key every 30 ms for 10 s, are
// charged in all no more than the newcomer pool and their shares while connected give; none is refused.
func TestChurnBounded(t *testing.T) {
	cfg := DefaultConfig()
	f := meshFixture(t, cfg, 63, 0)
	f.settle()
	lock, _, lockCap, _ := f.r.nodeRates()
	start := f.now
	var spent int64
	for i := range 333 {
		f.now = f.now.Add(30 * time.Millisecond)
		k := key(10_000 + i)
		if err := f.r.AddPeer(f.now, k, false, addr(10_000+i)); err != nil {
			t.Fatal(err)
		}
		p := f.r.byID[k]
		before := p.lock.level
		for f.r.Wait(f.now, k) == 0 {
			f.r.ControlFrame(f.now, k, &wire.Control{}, 0)
		}
		spent += before - p.lock.level
		f.r.RemovePeer(f.now, k)
	}
	elapsed := f.now.Sub(start).Seconds()
	// What churners get: the pool's capacity and refill, plus nothing of their own (they start empty).
	limit := lockCap + int64(float64(lock)*elapsed) + 333*Cost(OpCall, 64) // one frame past the bucket each
	if spent > limit {
		t.Fatalf("churners spent %d lock units in %.0f s, over %d", spent, elapsed, limit)
	}
}

// TestDepartedShare: senders that fill their shares and leave hold one share in all; past it the newly departed
// messages are dropped and canceled, their late verdicts only free their places, and a connected peer's message is
// still held.
func TestDepartedShare(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxPeers, cfg.MaxPeerValidating, cfg.MaxValidating = 8, 2, 18
	f := meshFixture(t, cfg, 8, 0)
	for k := 1; k <= 7; k++ {
		for i := range 2 {
			f.r.Message(f.now, key(k), envelope(T, key(900), uint64(10*k+i), f.now, 10))
		}
		f.r.RemovePeer(f.now, key(k))
	}
	if f.r.departed.count != 2 || len(f.sink.canceled) != 12 {
		t.Fatalf("%d departed, %d canceled: the senders that left hold more than one share", f.r.departed.count, len(f.sink.canceled))
	}
	f.done(13, Accept)
	if s := f.r.Stats(); s.Delivered != 0 || s.Validating != 13 {
		t.Fatalf("the verdict of a dropped departed message did more than free its place: %+v", s)
	}
	f.r.Message(f.now, key(8), envelope(T, key(900), 999, f.now, 10))
	if s := f.r.Stats(); s.Validating != 14 || s.Throttled != 0 {
		t.Fatalf("a connected peer's message was refused: %+v", s)
	}
}

// TestDecodeChargedPerItem: decoding is charged per list entry as well as per byte.
func TestDecodeChargedPerItem(t *testing.T) {
	f := meshFixture(t, nil, 1, 0)
	c := &wire.Control{}
	for i := range 1000 {
		c.IHave = append(c.IHave, wire.IHave{Topic: wire.Topic{0xee, byte(i), byte(i >> 8)}})
	}
	f.r.AuditPeer(key(1))
	f.r.ControlFrame(f.now, key(1), c, c.Size())
	if _, charged := f.r.Audit(); charged[OpDecode] < 1000 {
		t.Fatalf("%d decode units for 1,000 entries", charged[OpDecode])
	}
}

// TestSignatureChargedBySize: a signature check is charged by the size of what it hashes, and the reader's
// envelope decode with it.
func TestSignatureChargedBySize(t *testing.T) {
	f := meshFixture(t, nil, 1, 0)
	raw := envelope(T, key(9), 1, f.now, 1<<20-200)
	f.r.AuditPeer(key(1))
	f.r.Message(f.now, key(1), raw)
	_, charged := f.r.Audit()
	if charged[OpSigBytes] < int64(chunks(len(raw))) || charged[OpDecode] < int64(chunks(len(raw))) {
		t.Fatalf("a 1 MiB signature check charged %d hashing and %d decoding chunks", charged[OpSigBytes], charged[OpDecode])
	}
}

// TestHedgedAsks: two announcers that never answer come first; an honest announcer that comes later is asked a
// heartbeat after them, not when their asks run out.
func TestHedgedAsks(t *testing.T) {
	f := meshFixture(t, nil, 3, 0)
	raw := envelope(T, key(9), 1, f.now, 1)
	ihave := &wire.Control{IHave: []wire.IHave{{Topic: T, IDs: []wire.ID{wire.NewID(raw)}}}}
	f.control(1, ihave)
	f.control(2, ihave)
	f.control(3, ihave)
	if iwants(f.sink, key(3)) != 0 {
		t.Fatal("asked of a third peer at once")
	}
	f.heartbeat()
	f.heartbeat()
	if iwants(f.sink, key(3)) != 1 {
		t.Fatal("the third announcer was not asked a heartbeat later")
	}
	f.receive(3, raw, Accept)
	if f.r.Stats().Delivered != 1 || len(f.r.asks) != 0 {
		t.Fatal("the honest answer did not end the asking")
	}
}

// TestAnswerCountsBounded: a peer's IWANT answer counts hold at most MaxCacheMessages ids and are cleared every
// HistoryLength heartbeats.
func TestAnswerCountsBounded(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxCacheMessages = 3
	f := meshFixture(t, cfg, 2, 0)
	var cached []wire.ID
	for i := range 5 {
		raw := envelope(topicID(i), key(9), uint64(i), f.now, 1)
		f.join(topicID(i), nil)
		f.addPeer(10+i, false, topicID(i))
		f.receive(10+i, raw, Accept)
		cached = append(cached, wire.NewID(raw))
	}
	f.control(1, &wire.Control{IWant: cached})
	if n := len(f.r.byID[key(1)].sent); n > cfg.MaxCacheMessages {
		t.Fatalf("%d answer counts over MaxCacheMessages %d", n, cfg.MaxCacheMessages)
	}
	for range cfg.HistoryLength {
		f.heartbeat()
	}
	if f.r.byID[key(1)].sent != nil {
		t.Fatal("answer counts not cleared")
	}
}

// TestCallbacksTimed: with a clock, the application score is charged by the time it takes.
func TestCallbacksTimed(t *testing.T) {
	cfg := scoringConfig()
	var clock time.Duration
	cfg.Elapsed = func() time.Duration { return clock }
	cfg.Score.AppScore = func(PeerID) float64 { clock += time.Millisecond; return 0 }
	f := newFixture(t, cfg)
	f.join(T, &TopicConfig{Score: topicScore()})
	f.addPeers(1, T)
	f.heartbeat()
	f.r.score.app = nil // as at the next heartbeat, before the heartbeat's own scores
	f.r.AuditPeer(key(1))
	f.control(1, &wire.Control{})
	if _, charged := f.r.Audit(); Cost(OpCallback, int(charged[OpCallback])) < int64(time.Millisecond/Unit) {
		t.Fatalf("a 1 ms application score charged %d callback operations", charged[OpCallback])
	}
}

// TestRevalidateAfterIgnore: a validator that ignores the first copy, from a peer that relayed it first, sees the
// message again as the copy of a peer that sent it meanwhile, which it accepts; at most twice.
func TestRevalidateAfterIgnore(t *testing.T) {
	f := meshFixture(t, nil, 4, 0)
	raw := envelope(T, key(9), 1, f.now, 1)
	f.r.Message(f.now, key(1), raw)
	f.r.Message(f.now, key(2), raw)
	f.r.Message(f.now, key(3), raw)
	f.r.Message(f.now, key(4), raw)
	id := wire.NewID(raw)
	f.verdict(id, Ignore)
	if len(f.sink.validate) != 2 || f.sink.validate[1].from != key(2) {
		t.Fatalf("validations %+v", f.sink.validate)
	}
	f.verdict(id, Ignore)
	f.verdict(id, Ignore)
	if len(f.sink.validate) != 3 || f.r.Stats().Ignored != 1 {
		t.Fatalf("validated %d times, want three at most", len(f.sink.validate))
	}
}

// TestRetryKeepsPeers: asking the next copy's senders for a chain leaves the record's peers as they are, for their
// scores.
func TestRetryKeepsPeers(t *testing.T) {
	res := &stubResolver{want: &wire.CertWant{}}
	f := resolverFixture(t, nil, res)
	f.join(T, nil)
	f.addPeers(3, T)
	raw := markedEnvelope(1, f.now, unresolvedSig)
	for p := 1; p <= 3; p++ {
		f.r.Message(f.now, key(p), raw)
	}
	f.heartbeat()
	f.heartbeat()
	f.heartbeat()
	if rec := f.r.recs[wire.NewID(raw)]; rec == nil || len(rec.peers) != 2 || len(res.resolves) != 3 {
		t.Fatalf("record peers changed by the retries: %+v, %d requests", rec, len(res.resolves))
	}
}

// TestResolverWorkPaid: the work a Resolver reports for a peer leaving is paid by the leaving peer at once, not by
// the next peer whose frame comes.
func TestResolverWorkPaid(t *testing.T) {
	res := &stubResolver{}
	f := resolverFixture(t, nil, res)
	f.join(T, nil)
	f.addPeers(2, T)
	res.work[OpChain] = 10
	f.r.AuditPeer(key(2))
	f.r.RemovePeer(f.now, key(2))
	if _, charged := f.r.Audit(); charged[OpChain] != 10 {
		t.Fatalf("the leaving peer paid %d of 10 chain checks", charged[OpChain])
	}
	f.r.AuditPeer(key(1))
	f.control(1, &wire.Control{CertWant: []wire.CertWant{{}}}) // a frame that takes the Resolver's work
	if _, charged := f.r.Audit(); charged[OpChain] != 0 {
		t.Fatal("a leaving peer's resolver work was charged to the next peer")
	}
	res.expireWork[OpChain] = 10
	f.heartbeat()
	f.r.AuditPeer(key(1))
	f.control(1, &wire.Control{CertWant: []wire.CertWant{{}}})
	if _, charged := f.r.Audit(); charged[OpChain] != 0 {
		t.Fatal("the heartbeat's resolver work was charged to the next peer")
	}
	f.r.byID[key(1)].lock.level = 12345
	f.control(1, &wire.Control{Cert: [][]byte{{1}}})
	if one := Cost(OpChain, 1); res.budget > 12345+one || res.budget < 12345-1000+one {
		t.Fatalf("Cert could spend %d of a bucket of 12,345 and one answer", res.budget)
	}
}

// TestAuditAttribution: the audit counts only what the named payer pays.
func TestAuditAttribution(t *testing.T) {
	f := meshFixture(t, nil, 2, 0)
	f.r.AuditPeer(key(1))
	f.control(2, &wire.Control{})
	if done, charged := f.r.Audit(); len(done) == 0 || len(charged) != 0 {
		t.Fatalf("peer 2's frame was counted as paid by peer 1: %v", charged)
	}
}

// TestHedgeSkipsWaiting: a kept announcer that waits for its buckets is not asked.
func TestHedgeSkipsWaiting(t *testing.T) {
	f := meshFixture(t, nil, 3, 0)
	ihave := &wire.Control{IHave: []wire.IHave{{Topic: T, IDs: ids(7, 1)}}}
	for p := 1; p <= 3; p++ {
		f.control(p, ihave)
	}
	f.r.byID[key(3)].waiting = true
	f.heartbeat()
	f.heartbeat()
	if iwants(f.sink, key(3)) != 0 {
		t.Fatal("a waiting announcer was asked")
	}
}

// TestHeartbeatAppTimeNotCharged: the application score time of the heartbeat's own scores is not charged to the
// next peer.
func TestHeartbeatAppTimeNotCharged(t *testing.T) {
	cfg := scoringConfig()
	var clock time.Duration
	cfg.Elapsed = func() time.Duration { return clock }
	cfg.Score.AppScore = func(p PeerID) float64 {
		if p == key(2) {
			clock += time.Second
		}
		return 0
	}
	f := newFixture(t, cfg)
	f.join(T, &TopicConfig{Score: topicScore()})
	f.addPeers(2, T)
	f.heartbeat()
	delete(f.r.score.app, key(1))
	f.r.AuditPeer(key(1))
	f.control(1, &wire.Control{})
	if _, charged := f.r.Audit(); charged[OpCallback] != 1 {
		t.Fatalf("peer 1 charged %d callback operations, the heartbeat's time included", charged[OpCallback])
	}
}

// TestLargeLateSenderSafe: a chain that resolves after its large message's sender left is validated without the
// sender, its IDONTWANT paid by the churn bucket.
func TestLargeLateSenderSafe(t *testing.T) {
	res := &stubResolver{want: &wire.CertWant{}}
	f := resolverFixture(t, nil, res)
	f.join(T, nil)
	f.addPeers(3, T)
	f.control(2, &wire.Control{Graft: []wire.Topic{T}})
	e := &wire.Envelope{Topic: T, Device: wire.Key(key(9)), Seq: 1, Time: uint64(f.now.UnixMilli()), Body: make([]byte, 4000)}
	e.Sig[0] = unresolvedSig
	raw := e.Encode()
	f.r.Message(f.now, key(1), raw)
	f.r.RemovePeer(f.now, key(1))
	res.next = Resolutions{Done: []Resolution{{ID: wire.NewID(raw)}}}
	f.r.AuditPeer(key(1))
	f.control(3, &wire.Control{Cert: [][]byte{{1}}})
	if _, charged := f.r.Audit(); len(f.sink.validate) != 1 || charged[OpSend] < 2 {
		t.Fatalf("not validated after its sender left, or its sends paid by nobody: %v", charged)
	}
}

// TestWaitBounded: a bucket deep in debt asks for at most maxWait, and a debt is paid back by the full refill.
func TestWaitBounded(t *testing.T) {
	f := meshFixture(t, nil, 1, 0)
	p := f.r.byID[key(1)]
	p.lock.level = -1 << 50
	if w := f.r.Wait(f.now, key(1)); w != maxWait {
		t.Fatalf("wait %v", w)
	}
	lock, _ := f.r.rates(p)
	p.lock.level = -10 * lock
	f.now = f.now.Add(5 * time.Second)
	f.r.Wait(f.now, key(1))
	if p.lock.level != -5*lock {
		t.Fatalf("after 5 s a debt of 10 s of refill is %d, want %d", p.lock.level, -5*lock)
	}
}

// TestLockWorkPerPeer: a LockWork under newcomerShares units a second is refused, so no share is zero.
func TestLockWorkPerPeer(t *testing.T) {
	cfg := DefaultConfig()
	cfg.LockWork = newcomerShares - 1
	if _, err := New(t0, key(0), cfg, randFor(1), &fakeVerifier{}, newSink()); !errors.Is(err, ErrInvalidConfig) {
		t.Fatal(err)
	}
}

// TestOwedBackoffKept: a full backoff table drops a refused GRAFT's entry before a backoff we owe a peer.
func TestOwedBackoffKept(t *testing.T) {
	f := meshFixture(t, nil, 6, 0)
	b := &f.r.backoff
	b.add(f.now, T, key(500), time.Minute, false, 3, f.r.byID) // its GRAFT refused, then it pruned us and left
	b.add(f.now, T, key(500), 2*time.Minute, true, 3, f.r.byID)
	for i := 1; i <= 5; i++ {
		b.add(f.now.Add(time.Duration(i)*time.Second), T, key(i), 2*time.Minute, false, 3, f.r.byID)
	}
	if !b.has(T, key(500)) {
		t.Fatal("an owed backoff was evicted by refused GRAFTs")
	}
}

// TestBucketTimesMonotonic: bucket times are kept from the router's start, so a refill depends only on the time
// passed.
func TestBucketTimesMonotonic(t *testing.T) {
	base := time.Now()
	f := &fixture{t: t, sink: newSink(), v: &fakeVerifier{}, now: base}
	r, err := New(base, key(0), DefaultConfig(), randFor(1), f.v, f.sink)
	if err != nil {
		t.Fatal(err)
	}
	f.r = r
	f.join(T, nil)
	f.addPeers(1, T)
	p := r.byID[key(1)]
	p.lock.level = 0
	r.Wait(base.Add(time.Second), key(1))
	lock, _ := r.rates(p)
	if p.lock.level != lock || p.lock.at != int64(time.Second) {
		t.Fatalf("level %d at %d after one second", p.lock.level, p.lock.at)
	}
}

// TestNewPeerCatchUp: a new honest peer that we ask for askCap messages answers them all, waiting only as its
// bucket refills: the newcomer pool gives it one second of a share, and the answers take well under two seconds.
func TestNewPeerCatchUp(t *testing.T) {
	cfg := DefaultConfig()
	f := meshFixture(t, cfg, 63, 6)
	f.settle()
	f.sink.bench = true
	k := 64
	f.addPeer(k, true, T)
	var all []wire.ID
	byID := map[wire.ID][]byte{}
	for i := range 5000 {
		raw := envelope(T, key(900), uint64(i), f.now, 1024)
		all = append(all, wire.NewID(raw))
		byID[wire.NewID(raw)] = raw
	}
	f.sink.bench = false
	f.sink.reset()
	f.control(k, &wire.Control{IHave: []wire.IHave{{Topic: T, IDs: all}}})
	f.sink.bench = true
	start := f.now
	n := 0
	for _, c := range f.sink.ctrlTo(key(k)) {
		for _, id := range c.IWant {
			for w := f.r.Wait(f.now, key(k)); w > 0; w = f.r.Wait(f.now, key(k)) {
				f.now = f.now.Add(w)
			}
			f.receive(k, byID[id], Accept)
			n++
		}
	}
	took := f.now.Sub(start)
	t.Logf("a new peer answered %d asked messages of 1 KiB in %v", n, took)
	if n != int(f.r.askCap()) || f.r.Stats().Delivered != uint64(n) || took > 2*time.Second {
		t.Fatalf("%d answers, %d delivered, %v", n, f.r.Stats().Delivered, took)
	}
}

// TestUnitAuditChurn: the work of a peer leaving, with asks, waiting messages and a full list of retained scores,
// is all charged to it, and the work of a peer connecting to it.
func TestUnitAuditChurn(t *testing.T) {
	cfg := scoringConfig()
	cfg.MaxRetained = 50
	f := newFixture(t, cfg)
	f.join(T, &TopicConfig{Score: topicScore()})
	f.addPeers(60, T)
	for i := 2; i <= 60; i++ {
		f.r.RemovePeer(f.now, key(i))
	}
	f.control(1, &wire.Control{IHave: []wire.IHave{{Topic: T, IDs: ids(7, 1000)}}})
	f.r.Message(f.now, key(1), envelope(T, key(900), 1, f.now, 10))
	for _, step := range []struct {
		p  int
		do func()
	}{
		{1, func() { f.r.RemovePeer(f.now, key(1)) }},
		{2, func() { f.r.AddPeer(f.now, key(2), true, addr(2)) }},
	} {
		f.r.AuditPeer(key(step.p))
		step.do()
		done, charged := f.r.Audit()
		for op, n := range done {
			if charged[op] < n {
				t.Errorf("peer %d: op %d done %d times, charged %d", step.p, op, n, charged[op])
			}
		}
	}
}
