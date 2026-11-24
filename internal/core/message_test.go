package core

import (
	"errors"
	"testing"
	"time"

	"github.com/ciranda-dev/kolo-gossip/internal/wire"
)

// meshFixture joins T with peers 1..n subscribed and peers 1..m grafted into the mesh.
func meshFixture(t *testing.T, cfg *Config, n, m int) *fixture {
	f := newFixture(t, cfg)
	f.join(T, nil)
	f.addPeers(n, T)
	for i := 1; i <= m; i++ {
		f.control(i, &wire.Control{Graft: []wire.Topic{T}})
	}
	f.sink.reset()
	return f
}

// TestForwardRules: an accepted message is delivered and forwarded to the mesh minus the sender, minus the
// author's own key and minus peers that sent IDONTWANT for it (gossipsub-v1.0.md:359-364; gossipsub-v1.2.md:60-62).
func TestForwardRules(t *testing.T) {
	f := meshFixture(t, nil, 6, 5)
	raw := envelope(T, key(2), 1, f.now, 10)
	id := wire.NewID(raw)
	f.control(3, &wire.Control{IDontWant: []wire.ID{id}})
	f.receive(1, raw, Accept)
	if len(f.sink.deliver) != 1 || f.sink.deliver[0].id != id {
		t.Fatal("not delivered")
	}
	for i, want := range map[int]int{1: 0, 2: 0, 3: 0, 4: 1, 5: 1, 6: 0} {
		if got := f.sink.msgsTo(key(i)); got != want {
			t.Errorf("peer %d got %d copies, want %d", i, got, want)
		}
	}
}

// TestSeenBeforeValidation: a copy that arrives while the first is validated is a duplicate and is not
// validated again (the id hashes the signed bytes, so a copy is the same message).
func TestSeenBeforeValidation(t *testing.T) {
	f := meshFixture(t, nil, 3, 0)
	raw := envelope(T, key(9), 1, f.now, 10)
	f.r.Message(f.now, key(1), raw)
	f.r.Message(f.now, key(2), raw)
	if len(f.sink.validate) != 1 || f.v.calls != 1 || f.r.Stats().Duplicates != 1 {
		t.Fatalf("%d validations, %d verifications", len(f.sink.validate), f.v.calls)
	}
	f.r.ValidationDone(f.now, f.sink.validate[0].id, f.sink.validate[0].n, Accept)
	f.r.ValidationDone(f.now, f.sink.validate[0].id, f.sink.validate[0].n, Accept)
	if len(f.sink.deliver) != 1 {
		t.Fatal("delivered twice")
	}
}

// TestReplayWindow: times from now-MaxAge to now+MaxSkew are accepted, others ignored without penalty, so a message
// old enough to have left the seen cache is never taken again.
func TestReplayWindow(t *testing.T) {
	f := newFixture(t, scoringConfig())
	f.join(T, &TopicConfig{Score: topicScore()})
	f.addPeers(1, T)
	f.sink.reset()
	for i, c := range []struct {
		at time.Time
		ok bool
	}{
		{f.now.Add(-time.Minute), true},
		{f.now.Add(-time.Minute - time.Millisecond), false},
		{f.now.Add(time.Minute), true},
		{f.now.Add(time.Minute + time.Millisecond), false},
	} {
		n := len(f.sink.validate)
		f.r.Message(f.now, key(1), envelope(T, key(9), uint64(i), c.at, 1))
		if ok := len(f.sink.validate) > n; ok != c.ok {
			t.Errorf("case %d: validated %v, want %v", i, ok, c.ok)
		}
	}
	if f.r.Stats().OutOfWindow != 2 || f.r.Score(key(1)) != 0 {
		t.Fatal("out-of-window messages counted wrong or penalised")
	}
	f.r.Message(f.now, key(1), (&wire.Envelope{Topic: T, Time: 1 << 63}).Encode())
	if f.r.Stats().OutOfWindow != 3 {
		t.Fatal("time over int64 accepted")
	}
}

// TestReplayAfterSeenExpiry: a message replayed just after its id left the seen cache is refused by its time, at
// the tightest setting MaxAge+MaxSkew = SeenTTL, and is not seen again. The id leaves at most two heartbeat
// intervals after SeenTTL.
func TestReplayAfterSeenExpiry(t *testing.T) {
	f := meshFixture(t, nil, 1, 0)
	raw := envelope(T, key(9), 1, f.now.Add(time.Minute), 1)
	f.receive(1, raw, Accept)
	gone := 2*time.Minute + 2*time.Second + time.Nanosecond
	for _, d := range []time.Duration{2 * time.Minute, gone, 3 * time.Minute} {
		f.r.Message(t0.Add(d), key(1), raw)
	}
	if len(f.sink.deliver) != 1 || f.r.Stats().Duplicates != 1 || f.r.Stats().OutOfWindow != 2 || f.r.Stats().Seen != 0 {
		t.Fatalf("delivered %d, stats %+v", len(f.sink.deliver), f.r.Stats())
	}
}

// TestSelfOrigin: a validly signed copy of our own message, after a restart or from a second instance of our key,
// is ignored without penalty and its copies are dropped unchecked; a forged one costs P4 like any bad signature.
func TestSelfOrigin(t *testing.T) {
	f := newFixture(t, scoringConfig())
	f.join(T, &TopicConfig{Score: topicScore()})
	f.addPeers(2, T)
	raw := envelope(T, key(0), 1, f.now, 1)
	f.r.Message(f.now, key(1), raw)
	if s := f.r.Stats(); s.SelfOrigin != 1 || !f.r.skipped(wire.NewID(raw)) || len(f.sink.validate) != 0 || f.r.Score(key(1)) != 0 {
		t.Fatalf("self-origin: score %v, %+v", f.r.Score(key(1)), s)
	}
	f.r.Message(f.now, key(2), raw)
	if f.r.Score(key(2)) != 0 || f.r.Stats().IgnoredCopies != 1 {
		t.Fatalf("a copy of our own message scores %v", f.r.Score(key(2)))
	}
	f.r.Message(f.now, key(1), badEnvelope(T, key(0), 2, f.now))
	if f.r.Score(key(1)) != -1 || f.r.Stats().SelfOrigin != 1 {
		t.Fatalf("a forged message under our key scores %v", f.r.Score(key(1)))
	}
}

// TestBadSignature: a failed verification rejects the message with P4 and sends nothing (pubsub README:237-239);
// copies of the same bytes are dropped without a check.
func TestBadSignature(t *testing.T) {
	f := newFixture(t, scoringConfig())
	f.join(T, &TopicConfig{Score: topicScore()})
	f.addPeers(3, T)
	for i := 2; i <= 3; i++ {
		f.control(i, &wire.Control{Graft: []wire.Topic{T}})
	}
	f.sink.reset()
	raw := badEnvelope(T, key(9), 1, f.now)
	big := badEnvelope(T, key(9), 2, f.now)
	f.r.Message(f.now, key(1), raw)
	f.r.Message(f.now, key(1), big)
	if len(f.sink.validate) != 0 || len(f.sink.ctrl) != 0 || len(f.sink.msgs) != 0 {
		t.Fatal("forged message reached the validator or caused traffic")
	}
	if f.r.Score(key(1)) != -4 {
		t.Fatalf("score %v, want -4 for two invalid messages", f.r.Score(key(1)))
	}
	// Its copies are dropped without another check: only an attacker sends them.
	f.r.Message(f.now, key(2), raw)
	if f.r.Score(key(2)) != 0 || f.r.Stats().IgnoredCopies != 1 || f.r.Stats().SignatureChecks != 2 {
		t.Fatalf("copy of a bad signature checked again: %+v", f.r.Stats())
	}
}

// TestRejectPenalisesForwarders: Reject gives P4 to the sender and every peer that sent the message while it was
// validated (gossipsub-v1.1.md:315-317).
func TestRejectPenalisesForwarders(t *testing.T) {
	f := newFixture(t, scoringConfig())
	f.join(T, &TopicConfig{Score: topicScore()})
	f.addPeers(3, T)
	raw := envelope(T, key(9), 1, f.now, 1)
	f.r.Message(f.now, key(1), raw)
	f.r.Message(f.now, key(2), raw)
	f.r.Message(f.now, key(2), raw)
	f.verdict(wire.NewID(raw), Reject)
	if f.r.Score(key(1)) != -1 || f.r.Score(key(2)) != -1 || f.r.Score(key(3)) != 0 {
		t.Fatalf("scores %v %v", f.r.Score(key(1)), f.r.Score(key(2)))
	}
	if len(f.sink.deliver) != 0 || len(f.sink.msgs) != 0 || f.r.Stats().Rejected != 1 {
		t.Fatal("rejected message delivered or forwarded")
	}
	f.r.Message(f.now, key(3), raw)
	if f.r.Score(key(3)) != -1 {
		t.Fatal("later copy not penalised")
	}
}

// TestIgnoreVerdict: Ignore drops without penalty and later copies are not penalised either.
func TestIgnoreVerdict(t *testing.T) {
	f := newFixture(t, scoringConfig())
	f.join(T, &TopicConfig{Score: topicScore()})
	f.addPeers(2, T)
	raw := envelope(T, key(9), 1, f.now, 1)
	f.receive(1, raw, Ignore)
	f.r.Message(f.now, key(2), raw)
	if f.r.Score(key(1)) != 0 || f.r.Score(key(2)) != 0 || len(f.sink.deliver) != 0 || f.r.Stats().Ignored != 1 {
		t.Fatal("ignored message penalised or delivered")
	}
}

// TestIDontWantSent: after the signature check, a message of at least IDontWantThreshold bytes makes us send
// IDONTWANT at once to every mesh peer but the sender; smaller or forged messages do not
// (gossipsub-v1.2.md:52-58).
func TestIDontWantSent(t *testing.T) {
	f := meshFixture(t, nil, 4, 3)
	small := envelope(T, key(9), 1, f.now, 100)
	big := envelope(T, key(9), 2, f.now, 1024)
	forged := append([]byte(nil), big...)
	forged[len(forged)-wire.SigSize] = badSig
	f.r.Message(f.now, key(1), small)
	f.r.Message(f.now, key(1), forged)
	if len(f.sink.ctrl) != 0 {
		t.Fatal("IDONTWANT for a small or forged message")
	}
	f.r.Message(f.now, key(1), big)
	id := wire.NewID(big)
	for i := 1; i <= 4; i++ {
		want := map[bool]int{true: 1}[i == 2 || i == 3]
		got := 0
		for _, c := range f.sink.ctrl {
			if c.to == key(i) && len(c.c.IDontWant) == 1 && c.c.IDontWant[0] == id && c.urgent {
				got++
			}
		}
		if got != want {
			t.Errorf("peer %d got %d IDONTWANT", i, got)
		}
	}
}

// TestIDontWantLimits: at most MaxIDontWantMessages frames per heartbeat, MaxIDontWantLength ids per frame and
// MaxIDontWantIDs ids in all are kept, each for IDontWantTTL heartbeats.
func TestIDontWantLimits(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxIDontWantMessages = 2
	cfg.MaxIDontWantLength = 3
	cfg.IDontWantTTL = 2
	f := meshFixture(t, cfg, 1, 0)
	p := f.r.byID[key(1)]
	ids := func(base byte, n int) []wire.ID {
		out := make([]wire.ID, n)
		for i := range out {
			out[i][0], out[i][1] = base, byte(i)
		}
		return out
	}
	f.control(1, &wire.Control{IDontWant: ids(1, 5)})
	f.control(1, &wire.Control{IDontWant: ids(2, 1)})
	f.control(1, &wire.Control{IDontWant: ids(3, 1)})
	if len(p.unwanted.m) != 4 {
		t.Fatalf("%d ids kept, want 3 + 1", len(p.unwanted.m))
	}
	f.heartbeat()
	f.control(1, &wire.Control{IDontWant: ids(3, 1)})
	if len(p.unwanted.m) != 5 {
		t.Fatal("counter not reset by the heartbeat")
	}
	f.heartbeat()
	if len(p.unwanted.m) != 1 {
		t.Fatalf("%d ids after TTL, want 1", len(p.unwanted.m))
	}
	f.heartbeat()
	if p.unwanted != nil {
		t.Fatal("ids kept past their TTL, or an empty table kept")
	}
	cfg.MaxIDontWantIDs = 4
	f = meshFixture(t, cfg, 1, 0)
	p = f.r.byID[key(1)]
	f.control(1, &wire.Control{IDontWant: ids(1, 3)})
	f.control(1, &wire.Control{IDontWant: ids(2, 3)})
	if len(p.unwanted.m) != 4 || len(p.unwanted.q) != 4 {
		t.Fatalf("%d ids kept over MaxIDontWantIDs 4", len(p.unwanted.m))
	}
}

// TestFloodPublish: our own message goes to every topic peer at or above PublishThreshold, not only the mesh
// (gossipsub-v1.1.md:145-163, 549).
func TestFloodPublish(t *testing.T) {
	cfg := scoringConfig()
	cfg.Score.AppScore = func(p PeerID) float64 {
		if p == key(5) {
			return -30
		}
		return 0
	}
	f := newFixture(t, cfg)
	f.join(T, nil)
	f.addPeers(10, T)
	f.addPeer(11, true)
	f.sink.reset()
	id, err := f.r.Publish(f.now, envelope(T, key(0), 1, f.now, 10))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.sink.msgs) != 9 || f.sink.msgsTo(key(5)) != 0 || f.sink.msgsTo(key(11)) != 0 {
		t.Fatalf("flood publish sent %d copies", len(f.sink.msgs))
	}
	if _, err := f.r.Publish(f.now, envelope(T, key(0), 1, f.now, 10)); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("republish: %v", err)
	}
	if f.r.cache.m[id] == nil {
		t.Fatal("own message not cached for IWANT")
	}
}

// TestPublishWithoutFlood: with flood publishing off, a joined topic publishes to the mesh only, skipping peers
// that sent IDONTWANT (gossipsub-v1.0.md:390-397).
func TestPublishWithoutFlood(t *testing.T) {
	cfg := DefaultConfig()
	cfg.FloodPublish = false
	f := meshFixture(t, cfg, 8, 3)
	raw := envelope(T, key(0), 1, f.now, 10)
	f.control(2, &wire.Control{IDontWant: []wire.ID{wire.NewID(raw)}})
	if _, err := f.r.Publish(f.now, raw); err != nil {
		t.Fatal(err)
	}
	if len(f.sink.msgs) != 2 || f.sink.msgsTo(key(1)) != 1 || f.sink.msgsTo(key(3)) != 1 {
		t.Fatalf("sent %d copies", len(f.sink.msgs))
	}
}

// TestFanoutExpiry: fanout state of a topic we stopped publishing to goes after FanoutTTL; it is refilled to D and
// announced with gossip until then (gossipsub-v1.0.md:449-473).
func TestFanoutExpiry(t *testing.T) {
	cfg := DefaultConfig()
	cfg.FloodPublish = false
	f := newFixture(t, cfg)
	f.addPeers(4, T)
	if _, err := f.r.Publish(f.now, envelope(T, key(0), 1, f.now, 10)); err != nil {
		t.Fatal(err)
	}
	for i := 5; i <= 8; i++ {
		f.addPeer(i, false, T)
	}
	f.heartbeat()
	if len(f.r.Fanout(T)) != 6 {
		t.Fatalf("fanout %d, want refilled to 6", len(f.r.Fanout(T)))
	}
	ihave := 0
	for _, c := range f.sink.ctrl {
		ihave += len(c.c.IHave)
	}
	if ihave != 2 {
		t.Fatalf("%d IHAVE to non-fanout peers, want 2", ihave)
	}
	for range 61 {
		f.heartbeat()
	}
	if f.r.Stats().Topics != 0 {
		t.Fatal("fanout kept past FanoutTTL")
	}
}

// TestPublishChecks: wrong device, oversize, malformed and duplicate envelopes are refused.
func TestPublishChecks(t *testing.T) {
	f := meshFixture(t, nil, 1, 0)
	if _, err := f.r.Publish(f.now, envelope(T, key(1), 1, f.now, 1)); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("other device: %v", err)
	}
	if _, err := f.r.Publish(f.now, []byte{0, 1}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("malformed: %v", err)
	}
	if _, err := f.r.Publish(f.now, envelope(T, key(0), 1, f.now, 1<<20)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversize: %v", err)
	}
}

// TestMessageDrops: frames from graylisted peers, for topics not joined, over the topic size or malformed are
// dropped before any work.
func TestMessageDrops(t *testing.T) {
	cfg := scoringConfig()
	cfg.Score.AppScore = func(p PeerID) float64 {
		if p == key(2) {
			return -50
		}
		return 0
	}
	f := newFixture(t, cfg)
	f.join(T, &TopicConfig{MaxMessageSize: 1000, Score: topicScore()})
	f.addPeers(2, T)
	f.r.Message(f.now, key(2), envelope(T, key(9), 1, f.now, 1))
	f.control(2, &wire.Control{Graft: []wire.Topic{T}})
	f.r.Message(f.now, key(1), envelope(topicID(5), key(9), 1, f.now, 1))
	f.r.Message(f.now, key(1), envelope(T, key(9), 1, f.now, 1000))
	f.r.Message(f.now, key(1), envelope(T, key(9), 1, f.now, 10)[:50])
	s := f.r.Stats()
	if s.Graylisted != 3 || s.NotJoined != 1 || s.TooLarge != 1 || s.Malformed != 1 || f.v.calls != 0 || f.inMesh(T, 2) {
		t.Fatalf("stats %+v", s)
	}
	if f.r.Score(key(1)) != -1 {
		t.Fatal("malformed envelope not penalised")
	}
}

// TestSeenBound: a full seen cache ignores new messages instead of evicting live ids, which could then be delivered
// twice.
func TestSeenBound(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxSeen = 3
	f := meshFixture(t, cfg, 1, 0)
	for i := range 5 {
		f.receive(1, envelope(T, key(9), uint64(i), f.now, 1), Accept)
	}
	if s := f.r.Stats(); s.Seen != 3 || s.SeenFull != 2 || s.Delivered != 3 {
		t.Fatalf("stats %+v", s)
	}
	if _, err := f.r.Publish(f.now, envelope(T, key(0), 1, f.now, 1)); !errors.Is(err, ErrLimit) {
		t.Fatal("publish with a full seen cache")
	}
	f.now = f.now.Add(2*time.Minute + 2*time.Second + time.Nanosecond)
	f.receive(1, envelope(T, key(9), 9, f.now, 1), Accept)
	if s := f.r.Stats(); s.Seen != 1 || s.Delivered != 4 {
		t.Fatalf("expired ids not dropped: %+v", s)
	}
}

// TestValidationBounds: over MaxValidating messages or MaxValidatingBytes, new messages are throttled without
// penalty.
func TestValidationBounds(t *testing.T) {
	cfg := scoringConfig()
	cfg.MaxPeers = 1
	cfg.MaxValidating, cfg.MaxPeerValidating = 4, 2
	cfg.MaxPeerValidatingBytes = cfg.MaxMessageSize + 300
	cfg.MaxValidatingBytes = 2 * cfg.MaxPeerValidatingBytes
	f := newFixture(t, cfg)
	f.join(T, &TopicConfig{Score: topicScore()})
	f.addPeers(1, T)
	f.r.Message(f.now, key(1), envelope(T, key(9), 1, f.now, 10))
	f.r.Message(f.now, key(1), envelope(T, key(9), 2, f.now, 10))
	f.r.Message(f.now, key(1), envelope(T, key(9), 3, f.now, 10))
	if s := f.r.Stats(); s.Validating != 2 || s.Throttled != 1 || f.r.Score(key(1)) != 0 || len(f.r.recs) != 2 {
		t.Fatalf("count bound: %+v, %d records", s, len(f.r.recs))
	}
	f.r.ValidationDone(f.now, f.sink.validate[0].id, f.sink.validate[0].n, Accept)
	f.r.ValidationDone(f.now, f.sink.validate[1].id, f.sink.validate[1].n, Ignore)
	f.r.Message(f.now, key(1), envelope(T, key(9), 4, f.now, cfg.MaxMessageSize-200))
	f.r.Message(f.now, key(1), envelope(T, key(9), 5, f.now, 200))
	if s := f.r.Stats(); s.Validating != 1 || s.Throttled != 2 {
		t.Fatalf("byte bound: %+v", s)
	}
	// A message whose validator has not answered stays charged to its sender however long it takes; a verdict
	// after SeenTTL is an Ignore.
	f.now = f.now.Add(3 * time.Minute)
	f.r.Tick(f.now)
	if s := f.r.Stats(); s.Validating != 1 {
		t.Fatal("a message whose validator still runs was released")
	}
	f.r.ValidationDone(f.now, f.sink.validate[2].id, f.sink.validate[2].n, Accept)
	if s := f.r.Stats(); s.Validating != 0 || f.r.validatingBytes != 0 || s.Delivered != 1 {
		t.Fatalf("a late verdict: %+v", s)
	}
}

// TestValidationAfterLeave: a verdict for a topic left in the meantime delivers nothing.
func TestValidationAfterLeave(t *testing.T) {
	f := meshFixture(t, nil, 2, 2)
	raw := envelope(T, key(9), 1, f.now, 1)
	f.r.Message(f.now, key(1), raw)
	f.r.Leave(f.now, T)
	f.sink.reset()
	f.verdict(wire.NewID(raw), Accept)
	if len(f.sink.deliver)+len(f.sink.msgs) != 0 {
		t.Fatal("delivered after leave")
	}
}
