package sim

import (
	"crypto/ed25519"
	"errors"
	"math"
	"reflect"
	"runtime/debug"
	"testing"
	"time"

	"github.com/ciranda-dev/kolo-gossip/internal/core"
	"github.com/ciranda-dev/kolo-gossip/internal/wire"
)

// quiet returns options without latency spread, uplink limit, loss or CPU cost, for exact tests.
func quiet(seed uint64, latency time.Duration) Options {
	o := DefaultOptions(seed)
	o.LatencyBase, o.LatencyScale, o.Uplink, o.VerifyCost = latency, 0, 0, 0
	return o
}

// line builds n honest nodes connected in a line, each dialing the next, all joined at time zero.
func line(t *testing.T, o Options, n int) *Sim {
	t.Helper()
	s := New(o)
	cfg := core.DefaultConfig()
	var nodes []*Node
	for range n {
		nodes = append(nodes, s.AddNode(Honest, cfg, nil))
	}
	for _, nd := range nodes {
		if err := s.Start(nd); err != nil {
			t.Fatal(err)
		}
	}
	for i := 1; i < n; i++ {
		if !s.Connect(nodes[i-1], nodes[i]) {
			t.Fatal("connect failed")
		}
	}
	for _, nd := range nodes {
		if err := s.Join(nd); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func run(t *testing.T, s *Sim, until time.Duration) {
	t.Helper()
	if err := s.Run(until); err != nil {
		t.Fatal(err)
	}
}

func publish(t *testing.T, s *Sim, n *Node, size int) int32 {
	t.Helper()
	i, err := s.Publish(n, size)
	if err != nil {
		t.Fatal(err)
	}
	return i
}

func TestEventOrder(t *testing.T) {
	s := New(DefaultOptions(1))
	var got []int
	for i, at := range []time.Duration{3, 1, 2, 1, 0} {
		s.At(at, func() { got = append(got, i) })
	}
	run(t, s, 10)
	want := []int{4, 1, 3, 2, 0}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order %v, want %v: ties must run in insertion order", got, want)
		}
	}
	if s.Now() != 10 {
		t.Fatalf("clock %v after Run(10)", s.Now())
	}
}

// TestKnownAnswer: on a line A-B-C with 10 ms links and no other cost, B delivers A's message after 10 ms at hop 1
// and C after 20 ms at hop 2, and nobody receives a copy twice.
func TestKnownAnswer(t *testing.T) {
	s := line(t, quiet(1, 10*time.Millisecond), 3)
	run(t, s, 3*time.Second)
	i := publish(t, s, s.nodes[0], 200)
	run(t, s, 3*time.Second+s.o.Settle)
	m := s.msgs[i]
	if m.at[1] != 10_000 || m.at[2] != 20_000 || m.hop[1] != 1 || m.hop[2] != 2 {
		t.Fatalf("delays %v hops %v, want [0 10000 20000] [0 1 2]", m.at, m.hop)
	}
	if m.copies != 2 {
		t.Fatalf("%d copies, want 2", m.copies)
	}
	d := s.Delivery(0, time.Hour, nil, nil)
	if d.Messages != 1 || d.Full != 1 || d.Max != 20 || d.RMR != 0 || d.MaxHop != 2 {
		t.Fatalf("delivery %+v", d)
	}
	// Two framed copies plus the control bytes.
	env, frame := float64(len(m.raw)), float64(wire.UvarintLen(uint64(len(m.raw))))
	o := s.Overhead()
	ctl := float64(o.MeshBytes + o.IHaveBytes + o.IWantBytes + o.IDontWantBytes)
	if o.Deliveries != 2 || float64(o.MessageBytes) != 2*(env+frame) ||
		o.B != (2*(env+frame)+ctl)/(2*env) || o.BPayload != (2*(env+frame)+ctl)/400 {
		t.Fatalf("overhead %+v", o)
	}
}

// TestUplink: a frame finishes after size x 8 / rate, frames queue behind each other, and the control lane does
// not wait behind messages.
func TestUplink(t *testing.T) {
	o := quiet(1, 10*time.Millisecond)
	o.Uplink = 8e6 // one byte per microsecond
	s := line(t, o, 2)
	run(t, s, 3*time.Second)
	a, b := s.nodes[0], s.nodes[1]
	raw := make([]byte, 1000)
	start := s.now
	a.SendMessage(b.ID, raw)
	a.SendMessage(b.ID, raw)
	a.SendControl(b.ID, &wire.Control{Graft: []wire.Topic{Topic}}, true)
	var msgs, ctls []int64
	for _, e := range s.q {
		switch {
		case e.a != a.Index:
		case e.kind == evMessage:
			msgs = append(msgs, e.at-start)
		case e.kind == evControl:
			ctls = append(ctls, e.at-start)
		}
	}
	frame := int64(1002 * time.Microsecond) // 1000 bytes and a 2-byte length at one byte per microsecond
	lat := int64(10 * time.Millisecond)
	if len(msgs) != 2 || len(ctls) != 1 || min(msgs[0], msgs[1]) != frame+lat || max(msgs[0], msgs[1]) != 2*frame+lat {
		t.Fatalf("messages at %v, control at %v", msgs, ctls)
	}
	if ctls[0] >= frame+lat {
		t.Fatalf("control frame at %v waited behind a message", ctls[0])
	}
}

// TestPeerQueue: a router may queue at most PeerQueue frames for one peer; the next send fails and is counted.
func TestPeerQueue(t *testing.T) {
	o := quiet(1, 10*time.Millisecond)
	o.Uplink = 1e3
	s := line(t, o, 2)
	run(t, s, 3*time.Second)
	a, b := s.nodes[0], s.nodes[1]
	sent := 0
	for range o.PeerQueue + 5 {
		if a.SendMessage(b.ID, make([]byte, 10)) {
			sent++
		}
	}
	if sent != o.PeerQueue || s.m.queueFull != 5 {
		t.Fatalf("%d frames taken, %d refused; want %d and 5", sent, s.m.queueFull, o.PeerQueue)
	}
	var q uplinkQueue
	q.add(5, 10)
	q.add(3, 10)
	if q.fin[0] != 3 || !q.room(4, 10, 2, 100) || q.room(4, 10, 1, 100) || len(q.fin) != 1 || q.bytes != 10 {
		t.Fatalf("queue %+v", q)
	}
}

// TestLoss: every loss adds 9/8 of the round trip, the share of delayed frames follows Loss, and the same seed
// gives the same delays.
func TestLoss(t *testing.T) {
	delays := func(seed uint64) []int64 {
		o := quiet(seed, 20*time.Millisecond)
		o.Loss = 0.2
		s := line(t, o, 2)
		var out []int64
		for range 20_000 {
			out = append(out, s.delay(0, 1))
		}
		return out
	}
	a, b := delays(3), delays(3)
	lost := 0
	for i, d := range a {
		if d != b[i] {
			t.Fatal("same seed, different delays")
		}
		extra := d - int64(20*time.Millisecond)
		if extra%int64(45*time.Millisecond) != 0 {
			t.Fatalf("delay %v is not latency plus whole retransmissions", time.Duration(d))
		}
		if extra > 0 {
			lost++
		}
	}
	if share := float64(lost) / float64(len(a)); math.Abs(share-0.2) > 0.01 {
		t.Fatalf("delayed share %.3f, want about 0.2", share)
	}
}

// TestPartition: frames between sides are lost at once, the connections close after IdleTimeout, and Heal
// reopens them so messages cross again.
func TestPartition(t *testing.T) {
	s := line(t, quiet(1, 10*time.Millisecond), 4)
	run(t, s, 3*time.Second)
	side := func(n *Node) int8 { return int8(b2i(n.Index >= 2)) }
	s.Partition(side)
	i := publish(t, s, s.nodes[0], 200)
	run(t, s, 4*time.Second)
	if m := s.msgs[i]; m.at[1] < 0 || m.at[2] >= 0 || m.at[3] >= 0 {
		t.Fatalf("delivery across the cut: %v", m.at)
	}
	if s.nodes[1].r.Stats().Peers != 2 {
		t.Fatal("connection closed before IdleTimeout")
	}
	run(t, s, 3*time.Second+s.o.IdleTimeout+time.Second)
	if p := s.nodes[1].r.Stats().Peers; p != 1 || len(s.cutLinks) != 1 {
		t.Fatalf("after IdleTimeout: %d peers, %d cut links", p, len(s.cutLinks))
	}
	if s.Heal() != 1 {
		t.Fatal("heal did not reopen the link")
	}
	run(t, s, s.Now()+3*time.Second)
	j := publish(t, s, s.nodes[0], 200)
	run(t, s, s.Now()+time.Second)
	if m := s.msgs[j]; m.at[3] < 0 {
		t.Fatalf("no delivery after heal: %v", m.at)
	}
}

// TestStop: a crash is noticed by peers after IdleTimeout, a graceful stop after one latency; a restarted node
// gets a fresh router and delivers again without counting as a double delivery.
func TestStop(t *testing.T) {
	s := line(t, quiet(1, 10*time.Millisecond), 3)
	run(t, s, 3*time.Second)
	s.Stop(s.nodes[2], false)
	run(t, s, s.Now()+time.Second)
	if s.nodes[1].r.Stats().Peers != 2 {
		t.Fatal("crash noticed before IdleTimeout")
	}
	run(t, s, s.Now()+s.o.IdleTimeout)
	if s.nodes[1].r.Stats().Peers != 1 {
		t.Fatal("crash not noticed after IdleTimeout")
	}
	s.Stop(s.nodes[0], true)
	run(t, s, s.Now()+5*time.Millisecond)
	if s.nodes[1].r.Stats().Peers != 1 {
		t.Fatal("graceful close noticed before the latency")
	}
	run(t, s, s.Now()+10*time.Millisecond)
	if s.nodes[1].r.Stats().Peers != 0 {
		t.Fatal("graceful close not noticed after the latency")
	}
	n := s.nodes[2]
	if err := s.Start(n); err != nil {
		t.Fatal(err)
	}
	if !s.Connect(n, s.nodes[1]) || s.Join(n) != nil {
		t.Fatal("restart failed")
	}
	run(t, s, s.Now()+3*time.Second)
	i := publish(t, s, s.nodes[1], 200)
	run(t, s, s.Now()+time.Second)
	if s.msgs[i].at[2] < 0 || s.m.doubleDeliveries != 0 {
		t.Fatalf("restarted node: delivery %v, double %d", s.msgs[i].at, s.m.doubleDeliveries)
	}
}

var errBadTestSignature = errors.New("bad signature")

// TestVerifier: the fake accepts what the simulator signed for the roster's person and refuses a bad signature,
// a wrong person and a revoked device, charging VerifyCost of CPU for each signature check.
func TestVerifier(t *testing.T) {
	o := quiet(1, time.Millisecond)
	o.VerifyCost = time.Millisecond
	s := New(o)
	a := s.AddNode(Honest, core.DefaultConfig(), nil)
	r := s.AddNode(Revoked, nil, nil)
	v := &verifier{s: s, n: a}
	check := func(device int32, person wire.Key, sign bool) error {
		_, raw := s.envelope(device, person, 10, sign)
		env, err := wire.DecodeEnvelope(raw, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		if !v.Signed(env, raw[:len(raw)-wire.SigSize]) {
			return errBadTestSignature
		}
		return v.Verify(env, raw[:len(raw)-wire.SigSize])
	}
	if err := check(0, personKey(0), true); err != nil {
		t.Fatal(err)
	}
	for name, err := range map[string]error{
		"bad signature": check(0, personKey(0), false),
		"wrong person":  check(0, personKey(1), true),
		"revoked":       check(r.Index, personKey(r.Index), true),
	} {
		if err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if a.cpuFree != int64(4*time.Millisecond) || s.m.verifies != 4 {
		t.Fatalf("cpu %v after 4 checks", time.Duration(a.cpuFree))
	}
}

// TestDeterminism: the same seed gives the same trace and the same result hash; another seed does not.
func TestDeterminism(t *testing.T) {
	set := start().Set()
	hash := func(seed uint64) (string, string) {
		r := runS1(Case{Nodes: 40, Seed: seed, Score: set})[0]
		return r.Trace, r.Hash()
	}
	t1, h1 := hash(7)
	t2, h2 := hash(7)
	if t1 != t2 || h1 != h2 {
		t.Fatalf("seed 7 twice: %s/%s and %s/%s", t1, h1, t2, h2)
	}
	if t3, h3 := hash(8); t3 == t1 || h3 == h1 {
		t.Fatal("seeds 7 and 8 gave the same run")
	}
}

// TestDecayFactor: the factor takes a counter of 1 to DecayToZero in the given time.
func TestDecayFactor(t *testing.T) {
	f := decayFactor(10 * time.Second)
	if v := math.Pow(f, 10); math.Abs(v-decayToZero) > 1e-12 {
		t.Fatalf("after 10 decays %v, want %v", v, decayToZero)
	}
}

// TestKnobs: every candidate gives parameters the router accepts, and overrides parse.
func TestKnobs(t *testing.T) {
	for _, k := range Candidates() {
		set := k.Set()
		cfg := core.DefaultConfig()
		cfg.Score = set.Global
		s := New(DefaultOptions(1))
		n := s.AddNode(Honest, cfg, &core.TopicConfig{Score: set.Topic})
		if err := s.Start(n); err != nil {
			t.Fatalf("%s: %v", k.Name, err)
		}
		if err := s.Join(n); err != nil {
			t.Fatalf("%s: %v", k.Name, err)
		}
	}
	for _, o := range Overlays() {
		cfg := core.DefaultConfig()
		o.apply(cfg)
		s := New(DefaultOptions(1))
		n := s.AddNode(Honest, cfg, nil)
		if err := s.Start(n); err != nil {
			t.Fatalf("%s: %v", o.Name, err)
		}
		got := overlayOf(cfg)
		got.Name = o.Name
		if got != o {
			t.Fatalf("%s: read back %+v", o.Name, got)
		}
	}
	k, err := start().With("MeshThreshold=0,MeshActivation=5s,ColocationThreshold=2")
	if err != nil || k.MeshThreshold != 0 || k.MeshActivation != 5*time.Second || k.ColocationThreshold != 2 {
		t.Fatalf("With: %+v %v", k, err)
	}
	for _, bad := range []string{"Nope=1", "MeshThreshold", "MeshActivation=x", "Name=a", "Gossip=NaN", "Gossip=-Inf"} {
		if _, err := start().With(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, err := ScoreByName("nope"); err == nil {
		t.Error("unknown set accepted")
	}
}

// TestDefaultsMatchSearch: core's default score parameters and overlay are the chosen ones of the search.
func TestDefaultsMatchSearch(t *testing.T) {
	want := chosen().Set()
	got, err := ScoreByName("default")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(*got.Global, *want.Global) {
		t.Errorf("global:\n got %+v\nwant %+v", *got.Global, *want.Global)
	}
	if !reflect.DeepEqual(*got.Topic, *want.Topic) {
		t.Errorf("topic:\n got %+v\nwant %+v", *got.Topic, *want.Topic)
	}
	o := overlayOf(core.DefaultConfig())
	o.Name = "chosen"
	if o != chosenOverlay() {
		t.Errorf("overlay:\n got %+v\nwant %+v", o, chosenOverlay())
	}
}

// TestDropRouters: the measured router memory is positive and grows with the seen cache.
func TestDropRouters(t *testing.T) {
	mem := func(rate float64) int64 {
		nw := newNetwork(Case{Nodes: 30, Seed: 1}, nil)
		nw.build(nw.honestDials())
		if rate > 0 {
			nw.workload(warmup, warmup+20*time.Second, rate, 200, nw.pickPublisher)
		}
		nw.run(warmup + 21*time.Second)
		per, _ := nw.DropRouters()
		return per
	}
	idle, busy := mem(0), mem(20)
	if idle <= 0 || busy <= idle {
		t.Fatalf("idle %d, busy %d bytes per node", idle, busy)
	}
}

// BenchmarkEd25519ctxVerify measures one Ed25519ctx verification, the unit of DefaultOptions' VerifyCost.
func BenchmarkEd25519ctxVerify(b *testing.B) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		b.Fatal(err)
	}
	msg := make([]byte, 300)
	opts := &ed25519.Options{Context: "kolo-gossip/message/v0"}
	sig, err := priv.Sign(nil, msg, opts)
	if err != nil {
		b.Fatal(err)
	}
	for b.Loop() {
		if ed25519.VerifyWithOptions(pub, msg, sig, opts) != nil {
			b.Fatal("verify failed")
		}
	}
}

// FuzzKnobsWith: any override string is parsed or refused without a panic, and an accepted one gives knobs whose
// overrides read back the same.
func FuzzKnobsWith(f *testing.F) {
	f.Add("MeshThreshold=0,OpportunisticGraft=3")
	f.Add("MeshActivation=10s,ColocationThreshold=2")
	f.Add("=,=")
	f.Add("MeshThreshold=NaN")
	f.Fuzz(func(t *testing.T, spec string) {
		k, err := start().With(spec)
		if err != nil {
			return
		}
		again, err := start().With(spec)
		if err != nil || !reflect.DeepEqual(k, again) {
			t.Fatalf("%q parsed twice differently", spec)
		}
	})
}

var heapGarbage []byte

// TestHeapLimitCountsLiveHeap: garbage the collector has not swept is not counted against the limit.
func TestHeapLimitCountsLiveHeap(t *testing.T) {
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	for range 12 {
		heapGarbage = make([]byte, 64<<20)
	}
	heapGarbage = nil
	SetHeapLimit(512 << 20)
	defer SetHeapLimit(0)
	s := New(DefaultOptions(1))
	for i := range 1<<20 + 1 {
		s.At(time.Duration(i), func() {})
	}
	if err := s.Run(time.Hour); err != nil {
		t.Fatal(err)
	}
}
