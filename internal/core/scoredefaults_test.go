package core

import (
	"math"
	"testing"
	"time"
)

// TestDefaultScore: the default parameters pass validation, a router runs with them, and every decay takes a
// counter of 1 to DecayToZero in its window.
func TestDefaultScore(t *testing.T) {
	g, tp := DefaultScore(), DefaultTopicScore()
	if err := g.validate(); err != nil {
		t.Fatal(err)
	}
	if err := tp.validate(); err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	cfg.Score = g
	f := newFixture(t, cfg)
	f.join(T, &TopicConfig{Score: tp})
	f.addPeers(3, T)
	f.heartbeat()
	for _, d := range []float64{g.BehaviourPenaltyDecay, tp.FirstMessageDeliveriesDecay, tp.InvalidMessageDeliveriesDecay} {
		if v := math.Pow(d, defaultPenaltyDecay.Seconds()); math.Abs(v-g.DecayToZero) > 1e-12 {
			t.Fatalf("decay %v reaches %v after %v", d, v, defaultPenaltyDecay)
		}
	}
	if DefaultScore() == g || DefaultTopicScore() == tp {
		t.Fatal("defaults share memory between calls")
	}
	if g.RetainScore < defaultPenaltyDecay || g.DecayInterval != time.Second {
		t.Fatalf("retain %v interval %v", g.RetainScore, g.DecayInterval)
	}
}

// TestDefaultScoreGraylists: k invalid messages, or k behaviour offences over the free ones, alone reach the
// graylist threshold, and one fewer does not.
func TestDefaultScoreGraylists(t *testing.T) {
	g, tp := DefaultScore(), DefaultTopicScore()
	p4 := func(n float64) float64 { return n * n * tp.InvalidMessageDeliveriesWeight }
	p7 := func(n float64) float64 { return n * n * g.BehaviourPenaltyWeight }
	if !(p4(defaultInvalidK) <= g.Thresholds.Graylist && p4(defaultInvalidK-1) > g.Thresholds.Graylist) {
		t.Fatalf("P4: %v and %v around %v", p4(defaultInvalidK), p4(defaultInvalidK-1), g.Thresholds.Graylist)
	}
	if !(p7(defaultBehaviourK) <= g.Thresholds.Graylist && p7(defaultBehaviourK-1) > g.Thresholds.Graylist) {
		t.Fatalf("P7: %v and %v around %v", p7(defaultBehaviourK), p7(defaultBehaviourK-1), g.Thresholds.Graylist)
	}
	if c := g.TopicScoreCap; !near(c, tp.TimeInMeshCap*tp.TimeInMeshWeight+tp.FirstMessageDeliveriesCap*tp.FirstMessageDeliveriesWeight) {
		t.Fatalf("TopicScoreCap %v is not one topic's largest positive score", c)
	}
}
