package sim

import (
	"testing"
	"time"

	"github.com/ciranda-dev/kolo-gossip/internal/core"
)

// TestScenariosSmall runs every scenario but M1 at 100 nodes with the default score parameters; each must pass
// (no bound exceeded, nothing delivered twice, nothing forged delivered, no honest peer graylisted, and its own
// delivery and attack criteria).
func TestScenariosSmall(t *testing.T) {
	if testing.Short() {
		t.Skip("scenarios take about 20 s")
	}
	set, err := ScoreByName("default")
	if err != nil {
		t.Fatal(err)
	}
	for _, sc := range Scenarios {
		if sc.ID == "M1" {
			continue
		}
		for _, r := range sc.Run(Case{Nodes: 100, Seed: 1, Score: set}) {
			if !r.Pass {
				t.Errorf("%s %s: %v", r.Scenario, r.Variant, r.Failures)
			}
		}
	}
}

// TestScenariosTopics runs every scenario but M1 at 100 nodes in 50 topics, each node in all of them: a peer that
// announces more than 32 topics is no longer refused.
func TestScenariosTopics(t *testing.T) {
	if testing.Short() {
		t.Skip("scenarios take about a minute")
	}
	set, err := ScoreByName("default")
	if err != nil {
		t.Fatal(err)
	}
	o := DefaultOptions(1)
	o.Topics = 50
	for _, sc := range Scenarios {
		if sc.ID == "M1" {
			continue
		}
		for _, r := range sc.Run(Case{Nodes: 100, Seed: 1, Score: set, Opts: &o}) {
			if !r.Pass {
				t.Errorf("%s %s: %v", r.Scenario, r.Variant, r.Failures)
			}
		}
	}
}

// TestRooms: with Rooms of Topics, each honest node joins that many topics, attackers join all, and a message is
// owed only to the nodes in its topic.
func TestRooms(t *testing.T) {
	set := start().Set()
	o := DefaultOptions(1)
	o.Topics, o.Rooms = 10, 3
	nw := newNetwork(Case{Nodes: 40, Seed: 1, Score: set, Opts: &o}, nil)
	att := nw.addAttackers(Silent, 1, attackerConfig())
	for _, n := range nw.honest {
		k := 0
		for t := range n.rooms {
			k += b2i(n.rooms[t])
		}
		if k != 3 {
			t.Fatalf("node %d joins %d topics", n.Index, k)
		}
	}
	if k := len(att[0].rooms); k != 10 || !att[0].room(9) {
		t.Fatalf("an attacker joins %d topics", k)
	}
	nw.build(nw.honestDials())
	nw.run(warmup)
	pub := nw.honest[0]
	tp := 0
	for t := range pub.rooms {
		if pub.rooms[t] {
			tp = t
		}
	}
	if _, err := nw.PublishIn(pub, 100, tp); err != nil {
		t.Fatal(err)
	}
	nw.run(warmup + 3*nw.o.Settle)
	m := nw.msgs[0]
	for _, n := range nw.honest {
		if got := m.at[n.Index] >= 0; got && !n.room(tp) {
			t.Fatalf("node %d delivered a message of topic %d it did not join", n.Index, tp)
		}
	}
	if d := nw.Delivery(0, time.Hour, nil, nil); d.Messages != 1 || d.Pairs == 0 || d.Pairs >= len(nw.honest) {
		t.Fatalf("eligible nodes: %+v", d)
	}
}

// TestReachabilityPerTopic: with nodes in some of the topics, a message reaches only the nodes joined to its topic
// through links between such nodes, so a node linked only through a node outside the topic is out of reach.
func TestReachabilityPerTopic(t *testing.T) {
	o := DefaultOptions(1)
	o.Topics, o.Rooms = 2, 1
	nw := newNetwork(Case{Nodes: 4, Seed: 1, Opts: &o}, nil)
	for i, n := range nw.honest {
		n.rooms = []bool{i < 2 || i == 3, i >= 2}
	}
	nw.startAll(nw.honest)
	nw.Connect(nw.honest[0], nw.honest[2])
	nw.Connect(nw.honest[2], nw.honest[1])
	nw.Connect(nw.honest[2], nw.honest[3])
	nw.msgs = append(nw.msgs, &msgRec{author: nw.honest[0].Index, topic: 0})
	r := newReachability(nw)
	if r.reach(nw, nw.honest[1], 0) || !r.reach(nw, nw.honest[0], 0) {
		t.Fatal("a node linked only through a node outside the topic is in reach")
	}
	if all := components(nw, -1); all[1] != all[0] {
		t.Fatal("over all links the nodes are connected")
	}
}

// TestWorkHoldsFrames: with Work on, frames wait for the receiver's buckets, so a node with tiny budgets waits;
// with it off the routers never wait, as in the recorded traces.
func TestWorkHoldsFrames(t *testing.T) {
	set := start().Set()
	waits := func(work bool) uint64 {
		o := DefaultOptions(1)
		o.Work = work
		nw := newNetwork(Case{Nodes: 20, Seed: 1, Score: set, Opts: &o}, func(c *core.Config) {
			c.LockWork, c.PeerWork, c.ReaderWork = 5_000, 1_000, 20_000 // a signature check alone is 3,000 units
		})
		nw.build(nw.honestDials())
		nw.workload(warmup, warmup+20*time.Second, 5, 200, nw.pickPublisher)
		nw.run(warmup + 30*time.Second)
		var w uint64
		for _, n := range nw.honest {
			w += n.r.Stats().Waits
		}
		return w
	}
	if on, off := waits(true), waits(false); on == 0 || off != 0 {
		t.Fatalf("%d waits with Work, %d without", on, off)
	}
}

// TestAdversaryDeterminism: a run with every spam role gives the same trace twice.
func TestAdversaryDeterminism(t *testing.T) {
	set := start().Set()
	a := runS4(Case{Nodes: 30, Seed: 3, Score: set})[0]
	b := runS4(Case{Nodes: 30, Seed: 3, Score: set})[0]
	if a.Trace != b.Trace || a.Hash() != b.Hash() {
		t.Fatalf("S4 twice: %s/%s and %s/%s", a.Trace, a.Hash(), b.Trace, b.Hash())
	}
}

// TestDerive: a stage emits one row per run, then one rank per candidate, best first, the same for any worker count.
func TestDerive(t *testing.T) {
	saved := Stages
	defer func() { Stages = saved }()
	Stages = []Stage{{Name: "tiny", Candidates: func() []Knobs {
		return grid(start(), "graylist-only", "MeshThreshold=0,FirstWeight=0,MeshTimeMax=0", "start", "GraylistX=8")
	}, Scenarios: []string{"S1", "S5"}}, {Name: "tiny-overlay", Overlays: func() []Overlay {
		return overlayGrid(SpecOverlay(), "spec", "D=6", "d-2", "D=2,Dlo=2,Dhi=2,Dscore=2,Dout=1,Dlazy=2")
	}, Scenarios: []string{"S1"}}}
	run := func(workers int) []any {
		Workers = workers
		var out []any
		if err := Derive("tiny", 20, 1, 2, func(v any) { out = append(out, v) }); err != nil {
			t.Fatal(err)
		}
		return out
	}
	one, three := run(1), run(3)
	Workers = 3
	if len(one) != 2*2*2+2 || len(three) != len(one) {
		t.Fatalf("%d and %d outputs, want 10", len(one), len(three))
	}
	for i := 8; i < 10; i++ {
		if one[i].(Rank) != three[i].(Rank) {
			t.Fatalf("ranks differ with the worker count: %+v and %+v", one[i], three[i])
		}
	}
	var overlay []any
	if err := Derive("tiny-overlay", 20, 1, 1, func(v any) { overlay = append(overlay, v) }); err != nil {
		t.Fatal(err)
	}
	mesh := map[string]float64{}
	for _, v := range overlay[:2] {
		mesh[v.(Row).Candidate] = v.(Row).Result.Shape.MeshAvg
	}
	if len(overlay) != 2+2 || len(mesh) != 2 || mesh["d-2"] > 2 || mesh["spec"] <= 2 {
		t.Fatalf("overlay stage not applied: %d outputs, mesh %v", len(overlay), mesh)
	}
	if err := Derive("nope", 20, 1, 1, func(any) {}); err == nil {
		t.Fatal("unknown stage accepted")
	}
}

// TestBetter: the ranking compares failures first, then missed messages, and the clean p99 only in whole
// milliseconds, so a smaller difference falls to the bytes sent.
func TestBetter(t *testing.T) {
	a := Rank{Failures: 0, MissedShare: 0, CleanP99: 157.05, CleanB: 18.8}
	b := Rank{Failures: 0, MissedShare: 0, CleanP99: 156.92, CleanB: 23.3}
	if !better(a, b) || better(b, a) {
		t.Fatal("a p99 gain under 1 ms decided over the bytes sent")
	}
	b.CleanP99 = 155.9
	if better(a, b) {
		t.Fatal("a p99 gain of 1 ms ignored")
	}
	if c := (Rank{Failures: 1, CleanB: 1}); better(c, a) {
		t.Fatal("fewer bytes beat fewer failures")
	}
}

// TestRoomsFlood: 300 nodes in 50 topics, 5 rooms each, 256 places: every S2 variant delivers every message owed.
func TestRoomsFlood(t *testing.T) {
	if testing.Short() {
		t.Skip("takes about a minute")
	}
	set, err := ScoreByName("default")
	if err != nil {
		t.Fatal(err)
	}
	o := DefaultOptions(1)
	o.Topics, o.Rooms, o.MaxPeers, o.MaxInbound, o.Work = 50, 5, 256, 128, true
	for _, r := range runS2(Case{Nodes: 300, Seed: 1, Score: set, Opts: &o}) {
		if !r.Pass {
			t.Errorf("%s %s: %v", r.Scenario, r.Variant, r.Failures)
		}
	}
}
