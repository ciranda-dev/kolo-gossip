package core

import (
	"testing"
	"time"

	"github.com/ciranda-dev/kolo-gossip/internal/wire"
)

// fakeIDs returns n ids that no message has.
func fakeIDs(seed, n int) []wire.ID {
	ids := make([]wire.ID, n)
	for i := range ids {
		ids[i][0], ids[i][1], ids[i][2], ids[i][3] = 0xfa, byte(seed), byte(i>>8), byte(i)
	}
	return ids
}

// inflateAsks makes peers from..to each announce cap unseen ids of their own, so the router holds many asks.
func (f *fixture) inflateAsks(from, to int) {
	f.t.Helper()
	for i := from; i <= to; i++ {
		f.control(i, &wire.Control{IHave: []wire.IHave{{Topic: T, IDs: fakeIDs(i, int(f.r.askCap()))}}})
	}
}

// done answers the k-th validation the sink saw.
func (f *fixture) done(k int, v Verdict) {
	f.r.ValidationDone(f.now, f.sink.validate[k].id, f.sink.validate[k].n, v)
}

// TestChurnNeverRefuses: keys that connect and leave as fast as they can, while the router holds many asks, are
// all taken: churn costs the keys, never a refusal of others.
func TestChurnNeverRefuses(t *testing.T) {
	f := meshFixture(t, nil, 5, 0)
	f.settle()
	f.inflateAsks(1, 5)
	for i := range 2000 {
		k := key(20_000 + i)
		if err := f.r.AddPeer(f.now, k, false, addr(20_000+i)); err != nil {
			t.Fatalf("key %d refused: %v", i, err)
		}
		f.r.RemovePeer(f.now, k)
	}
}

// TestLeaveCostOwnState: a peer that leaves pays for its own leaving, and the work depends on what it holds, not on
// the asks of other peers.
func TestLeaveCostOwnState(t *testing.T) {
	f := meshFixture(t, nil, 5, 0)
	f.settle()
	f.inflateAsks(1, 5)
	f.addPeer(6, false, T)
	f.r.AuditPeer(key(6))
	f.r.RemovePeer(f.now, key(6))
	done, charged := f.r.Audit()
	if done[OpLookup] > 2000 {
		t.Fatalf("a peer holding nothing cost %d lookups to leave, with %d asks of others", done[OpLookup], len(f.r.asks))
	}
	if charged[OpLookup] < done[OpLookup] {
		t.Fatalf("the leaving peer paid %d of %d lookups", charged[OpLookup], done[OpLookup])
	}
}

// TestReturnPaysPool: a key that leaves with full buckets and comes back gets only what the newcomer pool gives.
func TestReturnPaysPool(t *testing.T) {
	f := meshFixture(t, nil, 3, 0)
	f.settle()
	f.r.RemovePeer(f.now, key(1))
	f.now = f.now.Add(time.Second)
	lock, _, _, _ := f.r.nodeRates()
	f.addPeer(1, false, T)
	f.r.Wait(f.now, key(1))
	if l := f.r.byID[key(1)].lock.level; l > lock {
		t.Fatalf("a returning key has %d lock units, over the pool grant of %d", l, lock)
	}
}

// TestGoneKeepsDebt: a key that leaves in debt still owes it, on top of the pool grant, when it returns after a
// heartbeat, however long ago its bucket was last refilled.
func TestGoneKeepsDebt(t *testing.T) {
	f := meshFixture(t, nil, 3, 0)
	f.now = f.now.Add(10 * time.Second)
	p := f.r.byID[key(1)]
	p.lock.level = -100_000
	f.r.RemovePeer(f.now, key(1))
	f.heartbeat()
	f.addPeer(1, false, T)
	lock, _, _, _ := f.r.nodeRates()
	if l := f.r.byID[key(1)].lock.level; l > lock-100_000 {
		t.Fatalf("a key that left 100,000 units in debt came back with %d, the pool grant being %d", l, lock)
	}
}

// TestDroppedValidationCounted: messages dropped from the departed share while their validators still run keep
// their places in the global bounds until the validators answer.
func TestDroppedValidationCounted(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxPeers, cfg.MaxPeerValidating, cfg.MaxValidating = 8, 2, 18
	f := meshFixture(t, cfg, 8, 0)
	for k := 1; k <= 7; k++ {
		for i := range 2 {
			f.r.Message(f.now, key(k), envelope(T, key(900), uint64(10*k+i), f.now, 10))
		}
		f.r.RemovePeer(f.now, key(k))
	}
	if s := f.r.Stats(); s.Validating != 14 {
		t.Fatalf("%d validations counted, 14 still run", s.Validating)
	}
}

// TestDepartedKeepsOldest: past the departed share, the newly departed messages are dropped and the older ones keep
// their places, so their verdicts still apply.
func TestDepartedKeepsOldest(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxPeers, cfg.MaxPeerValidating, cfg.MaxValidating = 8, 2, 18
	f := meshFixture(t, cfg, 8, 0)
	for k := 1; k <= 3; k++ {
		for i := range 2 {
			f.r.Message(f.now, key(k), envelope(T, key(900), uint64(10*k+i), f.now, 10))
		}
		f.r.RemovePeer(f.now, key(k))
	}
	f.done(0, Accept)
	if f.r.Stats().Delivered != 1 {
		t.Fatal("the oldest departed message was dropped for a newer departure")
	}
}

// TestStaleVerdictIgnored: a verdict for a validation the router dropped does not apply to a new copy of the same id.
func TestStaleVerdictIgnored(t *testing.T) {
	f := meshFixture(t, nil, 2, 0)
	raw := envelope(T, key(900), 1, f.now, 10)
	f.r.Message(f.now, key(1), raw)
	f.r.Leave(f.now, T)
	f.join(T, nil)
	f.r.Message(f.now, key(2), raw)
	f.done(0, Reject)
	if s := f.r.Stats(); s.Rejected != 0 {
		t.Fatal("the dropped validation's Reject applied to the new copy")
	}
	f.done(1, Accept)
	if s := f.r.Stats(); s.Delivered != 1 {
		t.Fatal("the new copy's own verdict was not applied")
	}
}

// TestCertFrameCapped: no CERT frame we send carries more certificates than the receiver reads, also when answers
// a full queue dropped are sent again with a new one.
func TestCertFrameCapped(t *testing.T) {
	res := &stubResolver{answers: [][]byte{make([]byte, 100)}}
	f := resolverFixture(t, nil, res)
	f.join(T, nil)
	f.addPeers(1, T)
	f.sink.full[key(1)] = true
	for range 12 {
		f.control(1, &wire.Control{CertWant: []wire.CertWant{{}}})
	}
	f.sink.full[key(1)] = false
	f.sink.reset()
	f.control(1, &wire.Control{CertWant: []wire.CertWant{{}}})
	sent := 0
	for _, c := range f.sink.ctrlTo(key(1)) {
		if len(c.Cert) > 10 {
			t.Fatalf("a frame with %d certificates, over 10", len(c.Cert))
		}
		sent += len(c.Cert)
	}
	if sent < 11 {
		t.Fatalf("%d answers sent, want the new one and the 10 kept", sent)
	}
}

// TestLeaveClearsWaitPlaces: a peer that leaves holds no place in the asks, asked or waiting.
func TestLeaveClearsWaitPlaces(t *testing.T) {
	f := meshFixture(t, nil, 3, 0)
	ids := fakeIDs(1, 1)
	for i := 1; i <= 3; i++ {
		f.control(i, &wire.Control{IHave: []wire.IHave{{Topic: T, IDs: ids}}})
	}
	f.r.RemovePeer(f.now, key(3))
	if a := f.r.asks[ids[0]]; a.nw != 0 {
		t.Fatalf("%d wait places left after the waiting peer left", a.nw)
	}
}

// TestWaitPlacesCapped: a peer waits to be asked for at most as many ids as it may be asked for.
func TestWaitPlacesCapped(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DesignRate = 4
	f := meshFixture(t, cfg, 5, 0)
	ids := fakeIDs(1, 8)
	f.control(1, &wire.Control{IHave: []wire.IHave{{Topic: T, IDs: ids[:4]}}})
	f.control(2, &wire.Control{IHave: []wire.IHave{{Topic: T, IDs: ids[:4]}}})
	f.control(3, &wire.Control{IHave: []wire.IHave{{Topic: T, IDs: ids[4:]}}})
	f.control(4, &wire.Control{IHave: []wire.IHave{{Topic: T, IDs: ids[4:]}}})
	f.control(5, &wire.Control{IHave: []wire.IHave{{Topic: T, IDs: ids}}})
	waits := 0
	for _, a := range f.r.asks {
		for _, q := range a.wait[:a.nw] {
			if q.id == key(5) {
				waits++
			}
		}
	}
	if waits > 4 {
		t.Fatalf("peer 5 waits for %d ids, over its 4", waits)
	}
}

// TestDepartedVerdictPaid: the work of a late verdict for a message whose sender left is charged to that key.
func TestDepartedVerdictPaid(t *testing.T) {
	f := meshFixture(t, nil, 6, 5)
	f.r.Message(f.now, key(1), envelope(T, key(900), 1, f.now, 10))
	f.r.RemovePeer(f.now, key(1))
	f.r.AuditPeer(key(1))
	f.done(0, Accept)
	if _, charged := f.r.Audit(); charged[OpSend] == 0 {
		t.Fatal("forwarding a departed sender's message was charged to someone else")
	}
}

// TestLeaveRetriesPaid: chain requests a leave sends to other peers are charged to the key that left.
func TestLeaveRetriesPaid(t *testing.T) {
	res := &stubResolver{want: &wire.CertWant{}}
	f := resolverFixture(t, nil, res)
	f.join(T, nil)
	f.addPeers(2, T)
	raw := markedEnvelope(1, f.now, unresolvedSig)
	f.r.Message(f.now, key(1), raw)
	f.r.Message(f.now, key(2), raw)
	res.ended = Resolutions{Done: []Resolution{{ID: wire.NewID(raw), Err: errBadChain}}}
	f.r.AuditPeer(key(1))
	f.r.RemovePeer(f.now, key(1))
	if _, charged := f.r.Audit(); charged[OpSend] == 0 {
		t.Fatal("the chain request a leave caused was charged to someone else")
	}
	if len(res.resolves) < 2 {
		t.Fatal("no retry was asked")
	}
}

// TestCertAnswerBudget: answers to our chain requests are checked even when reading the frame took the answerer's
// bucket below zero.
func TestCertAnswerBudget(t *testing.T) {
	res := &stubResolver{}
	f := resolverFixture(t, nil, res)
	f.join(T, nil)
	f.addPeers(1, T)
	f.r.byID[key(1)].lock.level = 0
	f.control(1, &wire.Control{Cert: [][]byte{make([]byte, 100), make([]byte, 100)}})
	if res.budget < Cost(OpChain, 2) {
		t.Fatalf("a budget of %d units for two answers", res.budget)
	}
}

// TestRetainedEvictionScoresOnce: evicting a retained score does not score every retained peer again.
func TestRetainedEvictionScoresOnce(t *testing.T) {
	cfg := scoringConfig()
	cfg.MaxRetained = 8
	calls := 0
	cfg.Score.AppScore = func(PeerID) float64 { calls++; return 0 }
	f := meshFixture(t, cfg, 10, 0)
	for i := 1; i <= 8; i++ {
		f.r.RemovePeer(f.now, key(i))
	}
	f.heartbeat()
	calls = 0
	f.r.RemovePeer(f.now, key(9))
	if calls > 1 {
		t.Fatalf("one leave called the application score %d times", calls)
	}
	if n := f.r.Stats().Retained; n != 8 {
		t.Fatalf("%d scores retained, want 8", n)
	}
}

// TestRunningThrottles: validations dropped while their validators run count in the global bound, so a new message
// past it is throttled.
func TestRunningThrottles(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxPeers, cfg.MaxPeerValidating, cfg.MaxValidating = 3, 2, 8
	f := meshFixture(t, cfg, 3, 3) // mesh peers are outside the open tier, which holds half
	seq := uint64(0)
	send := func(p, n int) {
		for range n {
			seq++
			f.r.Message(f.now, key(p), envelope(T, key(900), seq, f.now, 10))
		}
	}
	send(1, 2)
	f.r.RemovePeer(f.now, key(1))
	send(2, 2)
	f.r.RemovePeer(f.now, key(2))
	f.addPeer(4, false, T)
	f.control(4, &wire.Control{Graft: []wire.Topic{T}})
	send(3, 2)
	send(4, 2)
	f.r.RemovePeer(f.now, key(3))
	f.addPeer(5, false, T)
	f.control(5, &wire.Control{Graft: []wire.Topic{T}})
	if s := f.r.Stats(); s.Validating != 8 || s.Throttled != 0 {
		t.Fatalf("%+v", s)
	}
	send(5, 1)
	if s := f.r.Stats(); s.Throttled != 1 {
		t.Fatalf("a message taken past the global bound: %+v", s)
	}
}

// TestArrivalFreesWaitPlaces: when an asked id arrives, every peer asked for it or waiting for it is free of it.
func TestArrivalFreesWaitPlaces(t *testing.T) {
	f := meshFixture(t, nil, 3, 0)
	raw := envelope(T, key(900), 1, f.now, 10)
	ids := []wire.ID{wire.NewID(raw)}
	for i := 1; i <= 3; i++ {
		f.control(i, &wire.Control{IHave: []wire.IHave{{Topic: T, IDs: ids}}})
	}
	f.receive(1, raw, Accept)
	for i := 1; i <= 3; i++ {
		if p := f.r.byID[key(i)]; p.asked != 0 || p.waits != 0 || len(p.asking) != 0 {
			t.Fatalf("peer %d still holds %d asked, %d waiting, %d indexed", i, p.asked, p.waits, len(p.asking))
		}
	}
}

// TestReleasedPromisesFree: promises of a peer that waits, or of a connection that ended, break without a penalty,
// also when the key comes back.
func TestReleasedPromisesFree(t *testing.T) {
	f := meshFixture(t, nil, 2, 0)
	f.control(1, &wire.Control{IHave: []wire.IHave{{Topic: T, IDs: fakeIDs(1, 1)}}})
	f.control(2, &wire.Control{IHave: []wire.IHave{{Topic: T, IDs: fakeIDs(2, 1)}}})
	f.r.byID[key(1)].lock.level = -1
	if f.r.Wait(f.now, key(1)) == 0 {
		t.Fatal("peer 1 does not wait")
	}
	f.r.RemovePeer(f.now, key(2))
	f.addPeer(2, false, T)
	f.tick(f.r.cfg.IWantFollowupTime + time.Second)
	f.tick(time.Second)
	for i := 1; i <= 2; i++ {
		if ps := f.r.score.stats[key(i)]; ps.behaviourPenalty != 0 {
			t.Fatalf("peer %d penalized for a released promise", i)
		}
	}
}

// TestVerdictOfEndedValidation: a verdict for a validation that already ended does not apply to the message's next
// validation.
func TestVerdictOfEndedValidation(t *testing.T) {
	f := meshFixture(t, nil, 2, 0)
	raw := envelope(T, key(900), 1, f.now, 10)
	f.r.Message(f.now, key(1), raw)
	f.r.Message(f.now, key(2), raw)
	f.done(0, Ignore)
	if len(f.sink.validate) != 2 {
		t.Fatal("not validated again for the second copy")
	}
	f.done(0, Reject)
	if s := f.r.Stats(); s.Rejected != 0 || s.Validating != 1 {
		t.Fatalf("an ended validation's verdict applied: %+v", s)
	}
}

// TestHedgeFreesWaitPlaces: a waiting peer that the heartbeat asks no longer holds a wait place.
func TestHedgeFreesWaitPlaces(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DesignRate = 4
	f := meshFixture(t, cfg, 3, 0)
	ids := fakeIDs(1, 4)
	for i := 1; i <= 3; i++ {
		f.control(i, &wire.Control{IHave: []wire.IHave{{Topic: T, IDs: ids}}})
	}
	if p := f.r.byID[key(3)]; p.waits != 4 {
		t.Fatalf("peer 3 waits for %d ids", p.waits)
	}
	f.tick(cfg.HeartbeatInterval)
	f.tick(cfg.HeartbeatInterval)
	if p := f.r.byID[key(3)]; p.waits != 0 || p.asked != 4 {
		t.Fatalf("after the hedge peer 3 waits for %d ids and is asked %d", p.waits, p.asked)
	}
}

// TestPayerKeepsDebts: work charged to a departed key with nothing kept never pushes out another key's debt.
func TestPayerKeepsDebts(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxRetained = 2
	f := meshFixture(t, cfg, 4, 3)
	f.r.Message(f.now, key(1), envelope(T, key(900), 1, f.now, 10))
	f.r.RemovePeer(f.now, key(1))
	for i := 2; i <= 3; i++ {
		f.r.byID[key(i)].lock.level = -1
		f.r.RemovePeer(f.now, key(i))
	}
	if f.r.gone.m[key(1)] != nil {
		t.Fatal("the oldest key was kept past MaxRetained")
	}
	f.done(0, Accept)
	if f.r.gone.m[key(2)] == nil || f.r.gone.m[key(3)] == nil {
		t.Fatal("a verdict's work pushed out a debt")
	}
}
