package core

import (
	"errors"
	"math"
	"net/netip"
	"testing"
	"time"

	"github.com/ciranda-dev/kolo-gossip/internal/wire"
)

// scoreFixture joins T (scored with topicScore) and connects peers 1..n from distinct addresses.
func scoreFixture(t *testing.T, cfg *Config, n int) *fixture {
	if cfg == nil {
		cfg = scoringConfig()
	}
	f := newFixture(t, cfg)
	f.join(T, &TopicConfig{Score: topicScore()})
	f.addPeers(n, T)
	f.sink.reset()
	return f
}

func (f *fixture) stats(i int) *topicStats {
	return f.r.score.topicStats(key(i), T)
}

func near(a, b float64) bool {
	return math.Abs(a-b) < 1e-9
}

// TestScoreFormula checks each term against gossipsub-v1.1.md:289-332 and 357-483.
func TestScoreFormula(t *testing.T) {
	cases := []struct {
		name string
		set  func(ts *topicStats, ps *peerStats, tp *TopicScoreParams)
		want float64
	}{
		{"zero", func(*topicStats, *peerStats, *TopicScoreParams) {}, 0},
		{"P1 whole quanta", func(ts *topicStats, _ *peerStats, _ *TopicScoreParams) {
			ts.inMesh, ts.meshTime = true, 3500*time.Millisecond
		}, 3 * 0.01},
		{"P1 capped", func(ts *topicStats, _ *peerStats, _ *TopicScoreParams) { ts.inMesh, ts.meshTime = true, time.Hour }, 10 * 0.01},
		{"P1 only in mesh", func(ts *topicStats, _ *peerStats, _ *TopicScoreParams) { ts.meshTime = time.Hour }, 0},
		{"P2", func(ts *topicStats, _ *peerStats, _ *TopicScoreParams) { ts.firstMessageDeliveries = 4 }, 4},
		{"P3 deficit squared", func(ts *topicStats, _ *peerStats, _ *TopicScoreParams) {
			ts.inMesh, ts.meshActive, ts.meshMessageDeliveries = true, true, 0.5
		}, -1.5 * 1.5},
		{"P3 inactive", func(ts *topicStats, _ *peerStats, _ *TopicScoreParams) {
			ts.inMesh, ts.meshMessageDeliveries = true, 0.5
		}, 0},
		{"P3 only in mesh", func(ts *topicStats, _ *peerStats, _ *TopicScoreParams) {
			ts.meshActive, ts.meshMessageDeliveries = true, 0.5
		}, 0},
		{"P3 met", func(ts *topicStats, _ *peerStats, _ *TopicScoreParams) {
			ts.inMesh, ts.meshActive, ts.meshMessageDeliveries = true, true, 2
		}, 0},
		{"P3b", func(ts *topicStats, _ *peerStats, _ *TopicScoreParams) { ts.meshFailurePenalty = 3 }, -3},
		{"P4 squared", func(ts *topicStats, _ *peerStats, _ *TopicScoreParams) { ts.invalidMessageDeliveries = 3 }, -9},
		{"topic weight", func(ts *topicStats, _ *peerStats, tp *TopicScoreParams) {
			ts.firstMessageDeliveries, ts.invalidMessageDeliveries, tp.TopicWeight = 6, 1, 0.5
		}, 2.5},
		{"P7 over threshold squared", func(_ *topicStats, ps *peerStats, _ *TopicScoreParams) { ps.behaviourPenalty = 3 }, -9},
		{"all terms", func(ts *topicStats, ps *peerStats, _ *TopicScoreParams) {
			ts.inMesh, ts.meshTime, ts.firstMessageDeliveries = true, 2*time.Second, 5
			ts.meshActive, ts.meshMessageDeliveries, ts.meshFailurePenalty, ts.invalidMessageDeliveries = true, 1, 2, 2
			ps.behaviourPenalty = 1
		}, 0.02 + 5 - 1 - 2 - 4 - 1},
	}
	for _, c := range cases {
		f := scoreFixture(t, nil, 1)
		ts, ps := f.stats(1), f.r.score.stats[key(1)]
		c.set(ts, ps, f.r.topics[T].score)
		if got := f.r.Score(key(1)); !near(got, c.want) {
			t.Errorf("%s: score %v, want %v", c.name, got, c.want)
		}
	}
}

// TestScoreGlobalTerms checks TopicScoreCap, P5, P6 and the P7 threshold (gossipsub-v1.1.md:318-329).
func TestScoreGlobalTerms(t *testing.T) {
	cfg := scoringConfig()
	cfg.Score.TopicScoreCap = 5
	cfg.Score.AppScore = func(p PeerID) float64 {
		if p == key(1) {
			return 2
		}
		return 0
	}
	cfg.Score.AppWeight = 1.5
	cfg.Score.IPColocationWeight = -0.5
	cfg.Score.IPColocationThreshold = 1
	cfg.Score.BehaviourPenaltyThreshold = 1
	f := newFixture(t, cfg)
	f.join(T, &TopicConfig{Score: topicScore()})
	for i := 1; i <= 3; i++ {
		if err := f.r.AddPeer(f.now, key(i), true, addr(1)); err != nil {
			t.Fatal(err)
		}
	}
	for i := 4; i <= 6; i++ {
		if err := f.r.AddPeer(f.now, key(i), true, netip.AddrPortFrom(mustAddr("127.0.0.1"), 4000)); err != nil {
			t.Fatal(err)
		}
	}
	f.r.score.topicStats(key(1), T).firstMessageDeliveries = 8
	f.r.score.stats[key(1)].behaviourPenalty = 1
	if got, want := f.r.Score(key(1)), 5+2*1.5-0.5*4; !near(got, want) {
		t.Fatalf("score %v, want %v (cap 5, P5 3, P6 -2, P7 under threshold 0)", got, want)
	}
	f.r.score.topicStats(key(2), T).invalidMessageDeliveries = 4
	if got, want := f.r.Score(key(2)), -16-0.5*4; !near(got, want) {
		t.Fatalf("negative topic score capped: %v, want %v", got, want)
	}
	if got := f.r.Score(key(4)); got != 0 {
		t.Fatalf("loopback peers counted for P6: %v", got)
	}
	f.r.score.stats[key(3)].behaviourPenalty = 3
	if got, want := f.r.Score(key(3)), -2.0-4; !near(got, want) {
		t.Fatalf("P7 %v, want %v", got, want)
	}
	f.r.RemovePeer(f.now, key(2))
	f.r.RemovePeer(f.now, key(3))
	if got := f.r.Score(key(1)); !near(got, 5+3-0.5*4) {
		t.Fatalf("retained peers stop counting for P6: %v", got)
	}
}

// TestUnscoredTopic: behaviour in a topic joined with a zero TopicScoreParams adds nothing
// (gossipsub-v1.1.md:590-594).
func TestUnscoredTopic(t *testing.T) {
	f := newFixture(t, scoringConfig())
	f.join(T, &TopicConfig{Score: &TopicScoreParams{}})
	f.addPeers(1, T)
	f.r.Message(f.now, key(1), badEnvelope(T, key(9), 1, f.now))
	if f.r.Score(key(1)) != 0 || f.r.score.topicStats(key(1), T) != nil {
		t.Fatal("unscored topic counted")
	}
	f.receive(1, envelope(T, key(9), 2, f.now, 1), Accept)
	f.tick(time.Second)
	if len(f.r.recs) != 0 {
		t.Fatalf("%d records; an accepted message of an unscored topic keeps none", len(f.r.recs))
	}
}

// TestScoringByDefault: DefaultConfig scores with DefaultScore, a topic joined without score parameters takes
// DefaultTopicScore, and a nil Config.Score turns scoring off.
func TestScoringByDefault(t *testing.T) {
	f := newFixture(t, nil)
	f.join(T, nil)
	f.addPeers(1, T)
	if f.r.score == nil || *f.r.topics[T].score != *DefaultTopicScore() {
		t.Fatal("default config does not score with the default parameters")
	}
	f.r.Message(f.now, key(1), badEnvelope(T, key(9), 1, f.now))
	if got, want := f.r.Score(key(1)), DefaultTopicScore().InvalidMessageDeliveriesWeight; got != want {
		t.Fatalf("a bad signature scores %v, want one P4 %v", got, want)
	}
	off := DefaultConfig()
	off.Score = nil
	f = newFixture(t, off)
	f.join(T, nil)
	f.addPeers(1, T)
	f.r.Message(f.now, key(1), envelope(T, key(0), 1, f.now, 1))
	if f.r.score != nil || f.r.topics[T].score != nil || f.r.Score(key(1)) != 0 {
		t.Fatal("nil Score does not turn scoring off")
	}
}

// TestDecay: counters decay by their factor each DecayInterval and become 0 under DecayToZero; mesh time and the
// P3 activation update at decay time (gossipsub-v1.1.md:334-354, 485-518).
func TestDecay(t *testing.T) {
	cfg := scoringConfig()
	cfg.Score.AppScore = func(PeerID) float64 { return 100 } // keeps the peer in the mesh through the heartbeats
	f := scoreFixture(t, cfg, 1)
	f.control(1, &wire.Control{Graft: []wire.Topic{T}})
	ts, ps := f.stats(1), f.r.score.stats[key(1)]
	ts.firstMessageDeliveries, ts.meshMessageDeliveries, ts.meshFailurePenalty, ts.invalidMessageDeliveries = 8, 4, 2, 1
	ps.behaviourPenalty = 1
	f.tick(time.Second)
	if !near(ts.firstMessageDeliveries, 4) || !near(ts.meshMessageDeliveries, 2) || !near(ts.meshFailurePenalty, 1) ||
		!near(ts.invalidMessageDeliveries, 0.5) || !near(ps.behaviourPenalty, 0.9) {
		t.Fatalf("after one decay: %+v, P7 %v", ts, ps.behaviourPenalty)
	}
	if ts.meshTime != time.Second || ts.meshActive {
		t.Fatalf("mesh time %v active %v", ts.meshTime, ts.meshActive)
	}
	for range 4 {
		f.tick(time.Second)
	}
	if ts.meshActive {
		t.Fatal("P3 active at exactly the activation time")
	}
	f.tick(time.Second)
	if !ts.meshActive {
		t.Fatalf("after 6 decays: %+v", ts)
	}
	for range 60 {
		f.tick(time.Second)
	}
	if ts.firstMessageDeliveries != 0 || ts.meshMessageDeliveries != 0 || ts.meshFailurePenalty != 0 ||
		ts.invalidMessageDeliveries != 0 || ps.behaviourPenalty != 0 {
		t.Fatalf("counters never reached zero: %+v, P7 %v", ts, ps.behaviourPenalty)
	}
}

// TestDeliveryCounters: the first valid delivery earns P2 (capped) and P3 when in the mesh; a copy from a mesh peer
// while validating or within MeshMessageDeliveriesWindow earns P3 once (gossipsub-v1.1.md:385-448).
func TestDeliveryCounters(t *testing.T) {
	f := scoreFixture(t, nil, 4)
	for i := 1; i <= 3; i++ {
		f.control(i, &wire.Control{Graft: []wire.Topic{T}})
	}
	raw := envelope(T, key(90), 1, f.now, 1)
	f.r.Message(f.now, key(1), raw)
	f.r.Message(f.now, key(2), raw)
	f.r.Message(f.now, key(2), raw)
	f.r.Message(f.now, key(4), raw)
	f.verdict(wire.NewID(raw), Accept)
	if s := f.stats(1); s.firstMessageDeliveries != 1 || s.meshMessageDeliveries != 1 {
		t.Fatalf("first sender %+v", s)
	}
	if s := f.stats(2); s.firstMessageDeliveries != 0 || s.meshMessageDeliveries != 1 {
		t.Fatalf("copy while validating %+v", s)
	}
	if s := f.stats(4); s.meshMessageDeliveries != 0 {
		t.Fatal("non-mesh peer credited")
	}
	f.r.Message(f.now.Add(5*time.Millisecond), key(3), raw)
	f.r.Message(f.now.Add(5*time.Millisecond), key(3), raw)
	if s := f.stats(3); s.meshMessageDeliveries != 1 {
		t.Fatalf("copy inside the window %+v", s)
	}
	raw2 := envelope(T, key(90), 2, f.now, 1)
	f.receive(1, raw2, Accept)
	f.r.Message(f.now.Add(20*time.Millisecond), key(3), raw2)
	if s := f.stats(3); s.meshMessageDeliveries != 1 {
		t.Fatal("copy after the window credited")
	}
	for i := range 20 {
		f.receive(4, envelope(T, key(90), uint64(10+i), f.now, 1), Accept)
	}
	if s := f.stats(4); s.firstMessageDeliveries != 10 {
		t.Fatalf("P2 not capped: %v", s.firstMessageDeliveries)
	}
	f.control(4, &wire.Control{Graft: []wire.Topic{T}})
	for i := range 20 {
		f.receive(4, envelope(T, key(90), uint64(40+i), f.now, 1), Accept)
	}
	if s := f.stats(4); s.meshMessageDeliveries != 10 {
		t.Fatalf("P3 not capped: %v", s.meshMessageDeliveries)
	}
}

// TestMeshFailurePenalty: a mesh link that ends with an active deficit adds the squared deficit to P3b, on prune
// and on disconnect (gossipsub-v1.1.md:450-466).
func TestMeshFailurePenalty(t *testing.T) {
	f := scoreFixture(t, nil, 2)
	for i := 1; i <= 2; i++ {
		f.control(i, &wire.Control{Graft: []wire.Topic{T}})
		f.stats(i).meshActive = true
		f.stats(i).meshMessageDeliveries = 0.5
	}
	f.control(1, &wire.Control{Prune: []wire.Prune{{Topic: T}}})
	if s := f.stats(1); !near(s.meshFailurePenalty, 2.25) || s.inMesh {
		t.Fatalf("prune: %+v", s)
	}
	// Once pruned, only P3b counts the deficit: P3 is for mesh peers (gossipsub-v1.1.md:303-314).
	if got := f.r.Score(key(1)); !near(got, -2.25) {
		t.Fatalf("pruned peer scores %v, want P3b alone -2.25", got)
	}
	f.control(1, &wire.Control{Prune: []wire.Prune{{Topic: T}}})
	if s := f.stats(1); !near(s.meshFailurePenalty, 2.25) {
		t.Fatal("prune of a peer not in the mesh added P3b")
	}
	f.stats(2).firstMessageDeliveries = 3
	f.r.RemovePeer(f.now, key(2))
	if s := f.r.score.stats[key(2)].topics[0]; !near(s.meshFailurePenalty, 2.25) || s.firstMessageDeliveries != 0 {
		t.Fatalf("disconnect: %+v", s)
	}
}

// TestMeshDeliveryAfterRegraft: a pruned peer pays its deficit once, through P3b; grafted again, its P3 restarts
// only after a new activation time in the mesh, while P3b keeps decaying (gossipsub-v1.1.md:303-314, 424-466).
func TestMeshDeliveryAfterRegraft(t *testing.T) {
	cfg := scoringConfig()
	cfg.Score.AppScore = func(PeerID) float64 { return 10 } // a GRAFT from a negative score would be refused
	f := scoreFixture(t, cfg, 1)
	f.control(1, &wire.Control{Graft: []wire.Topic{T}})
	ts := f.stats(1)
	ts.meshActive, ts.meshMessageDeliveries = true, 0.5
	if got := f.r.Score(key(1)); !near(got, 10-2.25) {
		t.Fatalf("active deficit in the mesh %v, want P3 -2.25", got-10)
	}
	f.control(1, &wire.Control{Prune: []wire.Prune{{Topic: T, Backoff: 1}}})
	if got := f.r.Score(key(1)); !near(got, 10-2.25) {
		t.Fatalf("after prune %v, want P3b alone -2.25", got-10)
	}
	f.now = f.now.Add(2 * time.Second)
	f.control(1, &wire.Control{Graft: []wire.Topic{T}})
	if !ts.inMesh || ts.meshActive {
		t.Fatalf("regraft: in mesh %v, P3 active %v", ts.inMesh, ts.meshActive)
	}
	if got := f.r.Score(key(1)); !near(got, 10-2.25) {
		t.Fatalf("regrafted before activation %v, want P3b alone -2.25", got-10)
	}
}

// TestRetainedScore: a disconnected peer's score is kept for RetainScore without decay, restored on reconnect and
// forgotten after (gossipsub-v1.1.md:213-216, 570).
func TestRetainedScore(t *testing.T) {
	f := scoreFixture(t, nil, 2)
	f.stats(1).invalidMessageDeliveries = 2
	f.r.RemovePeer(f.now, key(1))
	f.tick(30 * time.Minute)
	if got := f.r.Score(key(1)); got != -4 || f.r.Stats().Retained != 1 {
		t.Fatalf("retained score %v", got)
	}
	f.addPeer(1, true, T)
	if got := f.r.Score(key(1)); got != -4 || f.r.Stats().Retained != 0 {
		t.Fatal("score reset by reconnecting")
	}
	f.r.RemovePeer(f.now, key(1))
	f.tick(time.Hour)
	if f.r.Stats().Retained != 1 {
		t.Fatal("forgotten at exactly RetainScore")
	}
	f.tick(time.Second)
	if f.r.Score(key(1)) != 0 || f.r.Stats().Retained != 0 {
		t.Fatal("kept past RetainScore")
	}
}

// TestRetainedBound: over MaxRetained the highest retained score is forgotten first; RetainScore 0 keeps nothing.
func TestRetainedBound(t *testing.T) {
	cfg := scoringConfig()
	cfg.MaxRetained = 2
	f := scoreFixture(t, cfg, 3)
	for i := 1; i <= 3; i++ {
		f.stats(i).invalidMessageDeliveries = float64(i)
	}
	f.stats(2).invalidMessageDeliveries = 0
	for i := 1; i <= 3; i++ {
		f.r.RemovePeer(f.now, key(i))
	}
	if f.r.Stats().Retained != 2 || f.r.Score(key(2)) != 0 || f.r.Score(key(3)) != -9 || f.r.Score(key(1)) != -1 {
		t.Fatal("wrong retained score dropped")
	}
	cfg = scoringConfig()
	cfg.Score.RetainScore = 0
	f = scoreFixture(t, cfg, 1)
	f.stats(1).invalidMessageDeliveries = 1
	f.r.RemovePeer(f.now, key(1))
	if f.r.Stats().Retained != 0 || f.r.Score(key(1)) != 0 {
		t.Fatal("score kept with RetainScore 0")
	}
}

// TestOpportunisticGraft: every OpportunisticGraftTicks heartbeats, a mesh whose median score is under the
// threshold grafts OpportunisticGraftPeers peers scoring above the median (gossipsub-v1.1.md:260-285).
func TestOpportunisticGraft(t *testing.T) {
	cfg := scoringConfig()
	cfg.OpportunisticGraftTicks = 3
	cfg.Score.AppScore = func(p PeerID) float64 {
		if p[3] > 7 {
			return 5
		}
		return 0.5
	}
	f := scoreFixture(t, cfg, 12)
	for i := 1; i <= 6; i++ {
		f.addMeshPeer(i)
	}
	f.heartbeat()
	f.heartbeat()
	if len(f.r.Mesh(T)) != 6 {
		t.Fatal("grafted before the tick")
	}
	f.heartbeat()
	mesh := f.r.Mesh(T)
	if len(mesh) != 8 {
		t.Fatalf("mesh %d, want 6 + 2", len(mesh))
	}
	for _, p := range mesh[6:] {
		if f.r.Score(p) <= 0.5 {
			t.Fatal("grafted a peer not above the median")
		}
	}
	cfg.Score.Thresholds.OpportunisticGraft = 0.5
	f = newFixture(t, cfg) // unscored topic: every mesh score is exactly the median 0.5
	f.join(T, nil)
	f.addPeers(12, T)
	for i := 1; i <= 6; i++ {
		f.addMeshPeer(i)
	}
	for range 3 {
		f.heartbeat()
	}
	if len(f.r.Mesh(T)) != 6 {
		t.Fatal("grafted with the median at the threshold")
	}
}

// TestOpportunisticGraftStrict: only peers strictly above the median are grafted.
func TestOpportunisticGraftStrict(t *testing.T) {
	cfg := scoringConfig()
	cfg.OpportunisticGraftTicks = 1
	cfg.Score.AppScore = func(PeerID) float64 { return 0.5 }
	f := scoreFixture(t, cfg, 10)
	for i := 1; i <= 6; i++ {
		f.addMeshPeer(i)
	}
	f.heartbeat()
	if len(f.r.Mesh(T)) != 6 {
		t.Fatal("grafted peers equal to the median")
	}
}

// TestGossipThreshold: no IHAVE is emitted to, and none accepted from, a peer below GossipThreshold
// (gossipsub-v1.1.md:228-231).
func TestGossipThreshold(t *testing.T) {
	cfg := scoringConfig()
	cfg.Score.AppScore = func(p PeerID) float64 {
		if p == key(8) {
			return -15
		}
		return 0
	}
	f := newFixture(t, cfg)
	f.join(T, nil)
	f.addPeers(8, T)
	for i := 1; i <= 6; i++ {
		f.control(i, &wire.Control{Graft: []wire.Topic{T}})
	}
	f.receive(1, envelope(T, key(90), 1, f.now, 1), Accept)
	f.sink.reset()
	f.heartbeat()
	for _, c := range f.sink.ctrlTo(key(8)) {
		if len(c.IHave) > 0 {
			t.Fatal("IHAVE to a peer below the gossip threshold")
		}
	}
	if len(f.sink.ctrlTo(key(7))) == 0 {
		t.Fatal("no IHAVE to the peer above it")
	}
	f.sink.reset()
	f.control(8, &wire.Control{IHave: []wire.IHave{{Topic: T, IDs: ids(1, 1)}}})
	if len(f.sink.ctrl) != 0 {
		t.Fatal("IHAVE from a peer below the gossip threshold answered")
	}
}

// TestScoreValidation checks the constraints of gossipsub-v1.1.md:559-619.
func TestScoreValidation(t *testing.T) {
	global := map[string]func(*ScoreParams){
		"gossip zero":         func(s *ScoreParams) { s.Thresholds.Gossip = 0 },
		"publish over gossip": func(s *ScoreParams) { s.Thresholds.Publish = -5 },
		"graylist at publish": func(s *ScoreParams) { s.Thresholds.Graylist = -20 },
		"opportunistic < 0":   func(s *ScoreParams) { s.Thresholds.OpportunisticGraft = -1 },
		"NaN threshold":       func(s *ScoreParams) { s.Thresholds.Gossip = math.NaN() },
		"negative cap":        func(s *ScoreParams) { s.TopicScoreCap = -1 },
		"negative app":        func(s *ScoreParams) { s.AppWeight = -1 },
		"positive P6":         func(s *ScoreParams) { s.IPColocationWeight = 1 },
		"P6 threshold 0":      func(s *ScoreParams) { s.IPColocationWeight = -1 },
		"positive P7":         func(s *ScoreParams) { s.BehaviourPenaltyWeight = 1 },
		"P7 decay 1":          func(s *ScoreParams) { s.BehaviourPenaltyDecay = 1 },
		"P7 threshold < 0":    func(s *ScoreParams) { s.BehaviourPenaltyThreshold = -1 },
		"decay interval":      func(s *ScoreParams) { s.DecayInterval = time.Second - 1 },
		"decay to zero":       func(s *ScoreParams) { s.DecayToZero = 0 },
		"infinite":            func(s *ScoreParams) { s.AppWeight = math.Inf(1) },
		"negative retain":     func(s *ScoreParams) { s.RetainScore = -1 },
	}
	for name, mutate := range global {
		s := *scoringConfig().Score
		mutate(&s)
		if err := s.validate(); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%s: %v", name, err)
		}
	}
	topic := map[string]func(*TopicScoreParams){
		"negative weight": func(p *TopicScoreParams) { p.TopicWeight = -1 },
		"P1 negative":     func(p *TopicScoreParams) { p.TimeInMeshWeight = -1 },
		"P1 quantum":      func(p *TopicScoreParams) { p.TimeInMeshQuantum = 0 },
		"P1 cap":          func(p *TopicScoreParams) { p.TimeInMeshCap = 0 },
		"P2 negative":     func(p *TopicScoreParams) { p.FirstMessageDeliveriesWeight = -1 },
		"P2 decay":        func(p *TopicScoreParams) { p.FirstMessageDeliveriesDecay = 1 },
		"P2 cap":          func(p *TopicScoreParams) { p.FirstMessageDeliveriesCap = 0 },
		"P3 positive":     func(p *TopicScoreParams) { p.MeshMessageDeliveriesWeight = 1 },
		"P3 decay":        func(p *TopicScoreParams) { p.MeshMessageDeliveriesDecay = 0 },
		"P3 threshold":    func(p *TopicScoreParams) { p.MeshMessageDeliveriesThreshold = 0 },
		"P3 cap":          func(p *TopicScoreParams) { p.MeshMessageDeliveriesCap = 1 },
		"P3 activation":   func(p *TopicScoreParams) { p.MeshMessageDeliveriesActivation = time.Second - 1 },
		"P3 window":       func(p *TopicScoreParams) { p.MeshMessageDeliveriesWindow = -1 },
		"P3b positive":    func(p *TopicScoreParams) { p.MeshFailurePenaltyWeight = 1 },
		"P3b decay":       func(p *TopicScoreParams) { p.MeshFailurePenaltyDecay = 1 },
		"P4 positive":     func(p *TopicScoreParams) { p.InvalidMessageDeliveriesWeight = 1 },
		"P4 decay":        func(p *TopicScoreParams) { p.InvalidMessageDeliveriesDecay = 0 },
		"NaN":             func(p *TopicScoreParams) { p.TopicWeight = math.NaN() },
	}
	for name, mutate := range topic {
		p := *topicScore()
		mutate(&p)
		if err := p.validate(); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("topic %s: %v", name, err)
		}
	}
	if err := (&TopicScoreParams{InvalidMessageDeliveriesDecay: 0.5}).validate(); err != nil {
		t.Fatalf("all weights 0: %v", err)
	}
}
