package sim

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"runtime"
	"slices"
	"time"

	"github.com/ciranda-dev/kolo-gossip/internal/core"
)

// Case is the setting of one scenario run.
type Case struct {
	Nodes   int
	Seed    uint64
	Score   *ScoreSet // nil turns scoring off
	Opts    *Options  // nil: DefaultOptions(Seed)
	Memory  bool      // measure router memory at the end
	Overlay *Overlay  // overlay of the honest nodes; nil: DefaultConfig's
}

// ScoreSet is a named score parameter set.
type ScoreSet struct {
	Name   string
	Global *core.ScoreParams
	Topic  *core.TopicScoreParams
}

func (c Case) scoring() string {
	if c.Score == nil {
		return "off"
	}
	return c.Score.Name
}

// Result is the outcome of one scenario run; JSON is the simulator's only output format.
type Result struct {
	Scenario         string              `json:"scenario"`
	Variant          string              `json:"variant,omitempty"`
	Nodes            int                 `json:"nodes"`
	Attackers        int                 `json:"attackers"`
	Seed             uint64              `json:"seed"`
	Scoring          string              `json:"scoring"`
	Topics           int                 `json:"topics,omitempty"`
	Rooms            int                 `json:"rooms,omitempty"`
	Places           int                 `json:"places,omitempty"`
	Work             bool                `json:"work,omitempty"`
	Delivery         Delivery            `json:"delivery"`
	Phases           map[string]Delivery `json:"phases,omitempty"`
	Shape            Shape               `json:"shape"`
	Overhead         Overhead            `json:"overhead"`
	Honest           HonestStats         `json:"honest_scores"`
	Attack           []AttackStats       `json:"attack,omitempty"`
	Values           map[string]float64  `json:"values,omitempty"`
	Samples          []Sample            `json:"samples,omitempty"`
	MemoryPerNode    int64               `json:"memory_per_node_bytes,omitempty"`
	BoundViolations  uint64              `json:"bound_violations"`
	DoubleDeliveries uint64              `json:"double_deliveries"`
	BadDeliveries    uint64              `json:"forged_or_invalid_delivered"`
	Events           uint64              `json:"events"`
	Trace            string              `json:"trace"`
	Pass             bool                `json:"pass"`
	Failures         []string            `json:"failures,omitempty"`
	WallSeconds      float64             `json:"wall_seconds"`
	HeapSysBytes     uint64              `json:"heap_sys_bytes"`
}

// HonestStats are the worst honest-to-honest scores over every sample.
type HonestStats struct {
	MaxBelowGraylist int     `json:"max_pairs_below_graylist"`
	MaxBelowPublish  int     `json:"max_pairs_below_publish"`
	MaxBelowGossip   int     `json:"max_pairs_below_gossip"`
	MaxNegative      int     `json:"max_pairs_negative"`
	Pairs            int     `json:"pairs"`
	MinScore         float64 `json:"min_score"`
}

// AttackStats describe how honest nodes scored one attacker role, in seconds from the attack start.
type AttackStats struct {
	Role            string  `json:"role"`
	Pairs           int     `json:"pairs"`
	AllGraylisted   float64 `json:"all_graylisted_s"`
	AllNegative     float64 `json:"all_negative_s"`
	OutOfMesh       float64 `json:"out_of_mesh_s"`
	MeshSlotsMax    int     `json:"mesh_slots_max"`
	MeshSlotsLast   int     `json:"mesh_slots_last"`
	MeshSlotsTopic  float64 `json:"mesh_slots_per_topic_last,omitempty"`
	GraylistedShare float64 `json:"graylisted_share_after"`
	LastMaxScore    float64 `json:"last_max_score"`
	MessagesTo      uint64  `json:"messages_sent_to"`
}

// Hash returns a short hash of the result without its wall time, for determinism checks.
func (r Result) Hash() string {
	r.WallSeconds, r.HeapSysBytes = 0, 0
	b, err := json.Marshal(r)
	if err != nil {
		panic(err)
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:8])
}

func (r *Result) fail(format string, args ...any) {
	r.Failures = append(r.Failures, fmt.Sprintf(format, args...))
}

// KeepSamples puts every score sample into the results.
var KeepSamples bool

// network is a scenario's simulation with its honest nodes.
type network struct {
	*Sim
	c      Case
	cfg    *core.Config
	tc     *core.TopicConfig
	honest []*Node
	joined map[int32]bool
	err    error
	start  time.Time
}

const (
	warmup        = 30 * time.Second
	attackerPeers = 1024
)

func newNetwork(c Case, mutate func(*core.Config)) *network {
	o := DefaultOptions(c.Seed)
	if c.Opts != nil {
		o = *c.Opts
		o.Seed = c.Seed
	}
	cfg := core.DefaultConfig()
	cfg.Score = nil
	if c.Score != nil {
		g := *c.Score.Global
		cfg.Score = &g
	}
	if c.Overlay != nil {
		c.Overlay.apply(cfg)
	}
	if mutate != nil {
		mutate(cfg)
	}
	var tc *core.TopicConfig
	if c.Score != nil {
		t := *c.Score.Topic
		tc = &core.TopicConfig{Score: &t}
	}
	nw := &network{Sim: New(o), c: c, cfg: cfg, tc: tc, joined: map[int32]bool{}, start: time.Now()}
	for range c.Nodes {
		nw.honest = append(nw.honest, nw.AddNode(Honest, cfg, tc))
	}
	return nw
}

func (nw *network) check(err error) {
	if err != nil && nw.err == nil {
		nw.err = err
	}
}

func wide(cfg *core.Config) { cfg.MaxPeers = attackerPeers }

// attackerConfig is a router that grafts every peer it can: D, Dlo and Dhi at its connection budget, and no
// scoring, so it never prunes anyone.
func attackerConfig() *core.Config {
	cfg := core.DefaultConfig()
	cfg.Score = nil
	wide(cfg)
	cfg.Params = core.Params{D: attackerPeers, Dlo: attackerPeers, Dhi: attackerPeers, Dlazy: 6, Dscore: 4, Dout: 0,
		GossipFactor: 0.25, GossipPeers: 43}
	cfg.IDontWantThreshold = cfg.MaxMessageSize
	return cfg
}

func (nw *network) addAttackers(role Role, k int, cfg *core.Config) []*Node {
	var out []*Node
	for range k {
		out = append(out, nw.AddNode(role, cfg, nil))
	}
	return out
}

func (nw *network) startAll(nodes []*Node) {
	for _, n := range nodes {
		nw.check(nw.Start(n))
	}
}

// canDial reports whether a may open a connection to b within the honest budgets (kolo-swarm MaxPeers and
// MaxInbound); attackers have attackerPeers.
func (nw *network) canDial(a, b *Node) bool {
	if a == b || a.byPeer[b.Index] != nil || !a.up || !b.up {
		return false
	}
	budget := func(n *Node, inbound bool) bool {
		if n.Role != Honest {
			return len(n.links) < attackerPeers
		}
		total, in := n.Free(&nw.o)
		return total > 0 && (!inbound || in > 0)
	}
	return budget(a, false) && budget(b, true)
}

// wire makes each node of from dial dials random nodes of to, in a random order.
func (nw *network) wire(from, to []*Node, dials int) {
	for _, i := range nw.rnd.Perm(len(from)) {
		a := from[i]
		for made, tries := 0, 0; made < dials && tries < dials*16; tries++ {
			b := to[nw.rnd.IntN(len(to))]
			if nw.canDial(a, b) && nw.Connect(a, b) {
				made++
			}
		}
	}
}

// joinAll joins every node at a random time in [now, now+within).
func (nw *network) joinAll(nodes []*Node, within time.Duration) {
	for _, n := range nodes {
		gen := n.gen
		nw.after(time.Duration(nw.rnd.Int64N(int64(within))), func() {
			if n.up && n.gen == gen {
				nw.check(nw.Join(n))
				nw.joined[n.Index] = true
			}
		})
	}
}

// build starts the honest nodes, wires them with dials each and joins them in the first second.
func (nw *network) build(dials int) {
	nw.startAll(nw.honest)
	nw.wire(nw.honest, nw.honest, dials)
	nw.joinAll(nw.honest, time.Second)
}

// honestDials is the outbound share of an honest node's budget: MaxPeers minus MaxInbound.
func (nw *network) honestDials() int { return nw.o.MaxPeers - nw.o.MaxInbound }

// pickPublisher returns a random running, joined honest node.
func (nw *network) pickPublisher() *Node {
	for range 64 {
		n := nw.honest[nw.rnd.IntN(len(nw.honest))]
		if n.up && n.r != nil && nw.joined[n.Index] {
			return n
		}
	}
	return nil
}

// topicFor chooses the topic of a message published by n: topic 0 with probability Busy, else a topic n joins,
// all alike.
func (nw *network) topicFor(n *Node) int {
	if nw.topics() == 1 {
		return 0
	}
	if nw.o.Busy > 0 && n.room(0) && nw.rnd.Float64() < nw.o.Busy {
		return 0
	}
	var in []int
	for t := range n.rooms {
		if n.rooms[t] {
			in = append(in, t)
		}
	}
	return in[nw.rnd.IntN(len(in))]
}

// workload publishes Poisson arrivals at rate per second in [from, to), each by pick.
func (nw *network) workload(from, to time.Duration, rate float64, size int, pick func() *Node) {
	var next func()
	next = func() {
		if n := pick(); n != nil {
			_, err := nw.PublishIn(n, size, nw.topicFor(n))
			nw.check(err)
		}
		gap := time.Duration(nw.rnd.ExpFloat64() / rate * float64(time.Second))
		if nw.Now()+gap < to {
			nw.after(gap, next)
		}
	}
	nw.At(from+time.Duration(nw.rnd.ExpFloat64()/rate*float64(time.Second)), next)
}

// burst publishes k messages spread evenly over d from at.
func (nw *network) burst(at, d time.Duration, k, size int) {
	for i := range k {
		nw.At(at+d*time.Duration(i)/time.Duration(k), func() {
			if n := nw.pickPublisher(); n != nil {
				_, err := nw.PublishIn(n, size, nw.topicFor(n))
				nw.check(err)
			}
		})
	}
}

func (nw *network) run(until time.Duration) {
	if nw.err == nil {
		nw.check(nw.Run(until))
	}
}

// result summarises the run; attack is the attack start for the attacker statistics.
func (nw *network) result(id, variant string, d Delivery, attack time.Duration) Result {
	r := Result{Scenario: id, Variant: variant, Nodes: nw.c.Nodes, Seed: nw.c.Seed, Scoring: nw.c.scoring(),
		Delivery: d, Shape: nw.Shape(), Overhead: nw.Overhead(), Values: map[string]float64{}}
	r.Attackers = len(nw.nodes) - len(nw.honest)
	if k := nw.topics(); k > 1 {
		r.Topics = k
		if nw.o.Rooms > 0 && nw.o.Rooms < k {
			r.Rooms = nw.o.Rooms
		}
	}
	if nw.o.MaxPeers != DefaultOptions(0).MaxPeers {
		r.Places = nw.o.MaxPeers
	}
	if nw.o.Work {
		r.Work = true
		r.Values["honest_mesh_waits"] = float64(nw.m.meshWaits)
		r.Values["honest_nonmesh_waits"] = float64(nw.m.otherWaits)
		r.Values["honest_mesh_waits_after_warmup"] = float64(nw.m.meshWaitsSteady)
		if nw.m.meshWaits > 0 {
			r.Values["honest_mesh_wait_first_s"] = time.Duration(nw.m.meshWaitFirst).Seconds()
			r.Values["honest_mesh_wait_last_s"] = time.Duration(nw.m.meshWaitLast).Seconds()
			r.Values["honest_mesh_wait_max_ms"] = float64(nw.m.meshWaitMax.Microseconds()) / 1000
		}
	}
	if nw.o.Work || nw.topics() > 1 {
		r.Values["ihave_bytes_per_node_per_s"] = float64(nw.m.ctl[ctlIHave]) / float64(max(1, len(nw.honest))) / nw.Now().Seconds()
	}
	r.Honest = honestStats(nw.m.samples)
	r.Attack = nw.attackStats(attack)
	if KeepSamples {
		r.Samples = nw.m.samples
	}
	if nw.c.Memory {
		r.MemoryPerNode, _ = nw.DropRouters()
	}
	r.BoundViolations, r.DoubleDeliveries, r.BadDeliveries = nw.m.boundViolations, nw.m.doubleDeliveries, nw.m.badDeliveries
	r.Events, r.Trace = nw.events, fmt.Sprintf("%016x", nw.trace)
	if nw.err != nil {
		r.fail("run error: %v", nw.err)
	}
	if r.BoundViolations > 0 {
		r.fail("%d bound violations", r.BoundViolations)
	}
	if r.DoubleDeliveries > 0 {
		r.fail("%d messages delivered twice", r.DoubleDeliveries)
	}
	if r.BadDeliveries > 0 {
		r.fail("%d forged or invalid messages delivered", r.BadDeliveries)
	}
	if nw.c.Score != nil && r.Honest.MaxBelowGraylist > 0 {
		r.fail("honest peers graylisted: %d pairs", r.Honest.MaxBelowGraylist)
	}
	return r
}

func (nw *network) finish(r *Result) {
	r.Pass = len(r.Failures) == 0
	r.WallSeconds = time.Since(nw.start).Seconds()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	r.HeapSysBytes = ms.HeapSys
}

func honestStats(ss []Sample) HonestStats {
	var h HonestStats
	for _, s := range ss {
		h.MaxBelowGraylist = max(h.MaxBelowGraylist, s.BelowGraylist[Honest])
		h.MaxBelowPublish = max(h.MaxBelowPublish, s.BelowPublish[Honest])
		h.MaxBelowGossip = max(h.MaxBelowGossip, s.BelowGossip[Honest])
		h.MaxNegative = max(h.MaxNegative, s.Negative[Honest])
		h.MinScore = min(h.MinScore, s.Min[Honest])
		h.Pairs = s.Pairs[Honest]
	}
	return h
}

func (nw *network) attackStats(attack time.Duration) []AttackStats {
	var out []AttackStats
	ss := nw.m.samples
	for role := Silent; role < roleCount; role++ {
		present := false
		for _, n := range nw.nodes {
			present = present || n.Role == role
		}
		if !present {
			continue
		}
		a := AttackStats{Role: role.String(), AllGraylisted: -1, AllNegative: -1, OutOfMesh: -1,
			MessagesTo: nw.m.toAttacker[role]}
		share, count := 0.0, 0
		for i, s := range ss {
			t := s.T - attack.Seconds()
			if t < 0 {
				continue
			}
			p := s.Pairs[role]
			a.Pairs = max(a.Pairs, p)
			a.MeshSlotsMax = max(a.MeshSlotsMax, s.MeshSlots[role])
			if p > 0 && s.BelowGraylist[role] == p && a.AllGraylisted < 0 {
				a.AllGraylisted = t
			}
			if p > 0 && s.Negative[role] == p && a.AllNegative < 0 {
				a.AllNegative = t
			}
			if a.AllGraylisted >= 0 && p > 0 {
				share += float64(s.BelowGraylist[role]) / float64(p)
				count++
			}
			if s.MeshSlots[role] == 0 && a.OutOfMesh < 0 {
				a.OutOfMesh = t
			} else if s.MeshSlots[role] > 0 {
				a.OutOfMesh = -1
			}
			if i == len(ss)-1 {
				a.MeshSlotsLast = s.MeshSlots[role]
				a.LastMaxScore = s.Max[role]
				if k := nw.topics(); k > 1 {
					a.MeshSlotsTopic = float64(s.MeshSlots[role]) / float64(k)
				}
			}
		}
		if count > 0 {
			a.GraylistedShare = share / float64(count)
		}
		out = append(out, a)
	}
	return out
}

func (r *Result) attack(role Role) *AttackStats {
	for i := range r.Attack {
		if r.Attack[i].Role == role.String() {
			return &r.Attack[i]
		}
	}
	return nil
}

// noMeshWaits fails a result in which an honest node made an honest mesh peer wait for its work buckets after the
// warm-up. Before it, the nodes start together and every key is new to every other, so each waits at most a few
// milliseconds for the newcomer pool; those waits are reported, not failed.
func (r *Result) noMeshWaits(nw *network) {
	if nw.m.meshWaitsSteady > 0 {
		r.fail("%d frames of honest mesh peers waited for the receiver's work buckets after the warm-up", nw.m.meshWaitsSteady)
	}
}

func (r *Result) needFull(name string, d Delivery) {
	if d.Messages == 0 {
		r.fail("%s: no messages measured", name)
	} else if d.Full != d.Messages {
		r.fail("%s: %d of %d messages reached every eligible node (ratio %.6f)", name, d.Full, d.Messages, d.Ratio)
	}
}

// Scenario is one entry of the simulator's scenario table.
type Scenario struct {
	ID   string
	Name string
	Run  func(Case) []Result
}

// Scenarios lists S1 to S13 and the memory run M1.
var Scenarios = []Scenario{
	{"S1", "healthy network, chat load and a burst", runS1},
	{"S2", "sybil flood, silent and censoring", runS2},
	{"S3", "eclipse attempt on one target", runS3},
	{"S4", "spam: IHAVE, IWANT, IDONTWANT, invalid, rejected, GRAFT in backoff", runS4},
	{"S5", "forged messages: bad signature, wrong person, revoked device", runS5},
	{"S6", "replay before and after the seen cache", runS6},
	{"S7", "publisher churn", runS7},
	{"S8", "partition and heal", runS8},
	{"S9", "10 to 90 percent node failure", runS9},
	{"S10", "covert flash and cold boot", runS10},
	{"S11", "IP colocation sybils", runS11},
	{"S12", "large messages with and without IDONTWANT", runS12},
	{"S13", "Dlo 4 against 5", runS13},
	{"M1", "router memory at 10 messages per second", runM1},
}

// Find returns the scenario with id.
func Find(id string) (Scenario, bool) {
	for _, s := range Scenarios {
		if s.ID == id {
			return s, true
		}
	}
	return Scenario{}, false
}

func runS1(c Case) []Result {
	nw := newNetwork(c, nil)
	nw.build(nw.honestDials())
	nw.StartSampling()
	end := warmup + 60*time.Second
	nw.workload(warmup, end, 1, 200, nw.pickPublisher)
	nw.burst(warmup+30*time.Second, time.Second, 100, 200)
	nw.run(end + nw.o.Settle + time.Second)
	d := nw.Delivery(warmup, end, nil, nil)
	r := nw.result("S1", "", d, 0)
	r.needFull("all messages", d)
	r.noMeshWaits(nw)
	nw.finish(&r)
	return []Result{r}
}

// sybilNetwork builds honest nodes with a reduced honest degree and attackers of role that, at time at, fill
// the rest of each honest node's budget: ratio attacker connections per honest connection, capped by MaxPeers.
func sybilNetwork(c Case, role Role, ratio int, at time.Duration) (*network, []*Node, *reachability) {
	nw := newNetwork(c, nil)
	dials := max(1, int(math.Round(float64(nw.o.MaxPeers/2)/float64(ratio+1))))
	nw.startAll(nw.honest)
	nw.wire(nw.honest, nw.honest, dials)
	want := 0
	for _, n := range nw.honest {
		want += min(nw.o.MaxPeers-len(n.links), ratio*len(n.links))
	}
	k := max(1, (want+attackerPeers/2-1)/(attackerPeers/2))
	syb := nw.addAttackers(role, k, attackerConfig())
	nw.joinAll(nw.honest, time.Second)
	nw.At(at, func() {
		nw.startAll(syb)
		for _, n := range nw.honest {
			target := min(nw.o.MaxPeers-len(n.links), ratio*len(n.links))
			for made, tries := 0, 0; made < target && tries < target*16; tries++ {
				a := syb[nw.rnd.IntN(len(syb))]
				ok := false
				if _, in := n.Free(&nw.o); in > 0 {
					ok = nw.canDial(a, n) && nw.Connect(a, n)
				} else {
					ok = nw.canDial(n, a) && nw.Connect(n, a)
				}
				if ok {
					made++
				}
			}
		}
		nw.joinAll(syb, time.Second)
	})
	return nw, syb, newReachability(nw)
}

// reachability tells which honest nodes an honest message can reach through honest links. A message travels only
// over links between nodes that join its topic, so when nodes join some of the topics each topic has its own
// components; otherwise there is one set.
type reachability struct {
	all     []int32
	byTopic map[int][]int32
}

func newReachability(nw *network) *reachability {
	if nw.o.Rooms == 0 || nw.o.Rooms >= nw.topics() {
		return &reachability{all: components(nw, -1)}
	}
	r := &reachability{byTopic: map[int][]int32{}}
	for t := range nw.topics() {
		r.byTopic[t] = components(nw, t)
	}
	return r
}

// reach reports whether honest node n is in the component of the author of message m.
func (r *reachability) reach(nw *network, n *Node, m int32) bool {
	comp := r.all
	if comp == nil {
		comp = r.byTopic[nw.msgs[m].topic]
	}
	return comp[n.Index] == comp[nw.msgs[m].author]
}

// components labels honest nodes by their connected component over honest-to-honest links, over the links between
// nodes that join topic when it is not negative.
func components(nw *network, topic int) []int32 {
	in := func(n *Node) bool { return topic < 0 || n.room(topic) }
	comp := make([]int32, len(nw.nodes))
	for i := range comp {
		comp[i] = -1
	}
	for _, n := range nw.honest {
		if comp[n.Index] >= 0 || !in(n) {
			continue
		}
		stack := []int32{n.Index}
		comp[n.Index] = n.Index
		for len(stack) > 0 {
			x := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			for _, l := range nw.nodes[x].links {
				y := l.other(x)
				if nw.nodes[y].Role == Honest && comp[y] < 0 && in(nw.nodes[y]) {
					comp[y] = n.Index
					stack = append(stack, y)
				}
			}
		}
	}
	return comp
}

func linkRatio(nw *network) float64 {
	h, a := 0, 0
	for _, n := range nw.honest {
		for _, l := range n.links {
			if nw.nodes[l.other(n.Index)].Role == Honest {
				h++
			} else {
				a++
			}
		}
	}
	if h == 0 {
		return 0
	}
	return float64(a) / float64(h)
}

func runS2(c Case) []Result {
	var out []Result
	for _, v := range []struct {
		role  Role
		ratio int
	}{{Silent, 1}, {Silent, 5}, {Silent, 20}, {Censor, 5}} {
		attack := warmup + 30*time.Second
		nw, syb, comp := sybilNetwork(c, v.role, v.ratio, attack)
		var targets map[int32]bool
		if v.role == Censor {
			targets = map[int32]bool{}
			for _, n := range nw.honest[:max(1, len(nw.honest)/10)] {
				targets[n.Index] = true
			}
			for _, a := range syb {
				a.censored = func(author int32) bool { return targets[author] }
			}
		}
		nw.StartSampling()
		end := attack + 120*time.Second
		nw.workload(warmup, end, 1, 200, nw.pickPublisher)
		nw.run(end + nw.o.Settle + time.Second)
		reach := func(n *Node, m int32) bool { return comp.reach(nw, n, m) }
		d := nw.Delivery(attack, end, nil, reach)
		r := nw.result("S2", fmt.Sprintf("%s-%d", v.role, v.ratio), d, attack)
		r.Values["attacker_links_per_honest_link"] = linkRatio(nw)
		r.needFull("messages to honest nodes reachable through honest links", d)
		if targets != nil {
			td := nw.Delivery(attack, end, func(m int32) bool { return targets[nw.msgs[m].author] }, reach)
			r.Phases = map[string]Delivery{"censored_authors": td}
			r.needFull("censored authors", td)
		}
		late := nw.Delivery(end-60*time.Second, end, nil, reach)
		r.Phases = withPhase(r.Phases, "last_60s", late)
		nw.finish(&r)
		out = append(out, r)
	}
	return out
}

func withPhase(m map[string]Delivery, k string, d Delivery) map[string]Delivery {
	if m == nil {
		m = map[string]Delivery{}
	}
	m[k] = d
	return m
}

func runS3(c Case) []Result {
	nw := newNetwork(c, nil)
	target := nw.honest[0]
	syb := nw.addAttackers(Silent, nw.o.MaxInbound, attackerConfig())
	nw.startAll(nw.honest)
	nw.startAll(syb)
	for _, a := range syb {
		nw.Connect(a, target)
	}
	nw.wire(nw.honest, nw.honest, nw.honestDials())
	nw.joinAll(nw.honest, time.Second)
	nw.joinAll(syb, time.Second)
	nw.StartSampling()
	end := warmup + 120*time.Second
	nw.workload(warmup, end, 1, 200, nw.pickPublisher)
	nw.workload(warmup, end, 0.5, 200, func() *Node { return target })
	nw.run(end + nw.o.Settle + time.Second)
	own := nw.Delivery(warmup, end, func(m int32) bool { return nw.msgs[m].author == target.Index }, nil)
	in := nw.Delivery(warmup, end, func(m int32) bool { return nw.msgs[m].author != target.Index },
		func(n *Node, _ int32) bool { return n == target })
	r := nw.result("S3", "", nw.Delivery(warmup, end, nil, nil), 0)
	r.Phases = map[string]Delivery{"target_published": own, "target_received": in}
	r.Values["target_inbound_attackers"] = float64(len(syb))
	r.needFull("target's own messages", own)
	r.needFull("messages to the target", in)
	nw.finish(&r)
	return []Result{r}
}

// spamNetwork connects k attackers of each role to peers random honest nodes each, before the honest wiring.
func spamNetwork(c Case, roles []Role, k int) *network {
	nw := newNetwork(c, nil)
	nw.startAll(nw.honest)
	peers := min(16, max(1, len(nw.honest)/4))
	var att []*Node
	for _, role := range roles {
		att = append(att, nw.addAttackers(role, k, nil)...)
	}
	nw.startAll(att)
	nw.wire(att, nw.honest, peers)
	nw.wire(nw.honest, nw.honest, nw.honestDials())
	nw.joinAll(nw.honest, time.Second)
	return nw
}

func runS4(c Case) []Result {
	roles := []Role{IHaveSpam, IWantSpam, DontWantSpam, InvalidSpam, RejectSpam, GraftSpam}
	nw := spamNetwork(c, roles, 2)
	nw.StartSampling()
	end := warmup + 120*time.Second
	nw.workload(warmup, end, 1, 200, nw.pickPublisher)
	nw.run(end + nw.o.Settle + time.Second)
	d := nw.Delivery(warmup, end, nil, nil)
	r := nw.result("S4", "", d, 0)
	r.needFull("honest messages", d)
	if c.Score != nil {
		for _, role := range []Role{IHaveSpam, InvalidSpam, RejectSpam} {
			if a := r.attack(role); a == nil || a.AllGraylisted < 0 {
				r.fail("%s never graylisted by every peer", role)
			}
		}
		// A GRAFT spammer still in a mesh sends nothing a peer refuses. Once graylisted its GRAFTs are dropped, so
		// its score hovers at the graylist threshold; every peer that refused it must keep it below Publish.
		open := nw.graftSpamAbovePublish()
		r.Values["graft_spam_refusing_pairs_above_publish"] = float64(open)
		if open > 0 {
			r.fail("%d honest peers refused a GRAFT spammer but score it at or above the publish threshold", open)
		}
	}
	// IWANT answers per attacker connection are bounded by GossipRetransmission per cached message.
	if a := r.attack(IWantSpam); a != nil {
		r.Values["iwant_answers_per_attacker_link"] = float64(a.MessagesTo) / math.Max(1, float64(a.Pairs))
	}
	nw.finish(&r)
	return []Result{r}
}

// graftSpamAbovePublish counts honest nodes holding a GRAFT spammer outside their mesh at or above the publish
// threshold.
func (nw *network) graftSpamAbovePublish() int {
	n := 0
	for _, h := range nw.honest {
		if !h.up || h.r == nil {
			continue
		}
		var mesh []core.PeerID
		for t, in := range h.rooms {
			if in {
				mesh = append(mesh, h.r.Mesh(TopicID(t))...)
			}
		}
		for _, l := range h.links {
			p := nw.nodes[l.other(h.Index)]
			if p.Role == GraftSpam && !slices.Contains(mesh, p.ID) && h.r.Score(p.ID) >= h.cfg.Score.Thresholds.Publish {
				n++
			}
		}
	}
	return n
}

func runS5(c Case) []Result {
	nw := spamNetwork(c, []Role{ForgeSig, ForgePerson, Revoked}, 2)
	nw.StartSampling()
	end := warmup + 60*time.Second
	nw.workload(warmup, end, 1, 200, nw.pickPublisher)
	nw.run(end + nw.o.Settle + time.Second)
	d := nw.Delivery(warmup, end, nil, nil)
	r := nw.result("S5", "", d, 0)
	r.needFull("honest messages", d)
	forged, delivered := 0, 0
	for _, m := range nw.msgs {
		if m.kind != kindForged {
			continue
		}
		forged++
		for _, at := range m.at {
			delivered += b2i(at >= 0)
		}
	}
	r.Values["forged_sent"] = float64(forged)
	r.Values["forged_delivered"] = float64(delivered)
	if delivered > 0 {
		r.fail("%d deliveries of forged messages", delivered)
	}
	// A bad signature is the sender's own doing and costs P4; a wrong person or a revoked device may be a
	// forwarder's stale roster, so it is ignored without penalty.
	if c.Score != nil {
		if a := r.attack(ForgeSig); a == nil || a.AllNegative < 0 {
			r.fail("%s: P4 did not make every peer score it negative", ForgeSig)
		}
	}
	nw.finish(&r)
	return []Result{r}
}

func runS6(c Case) []Result {
	nw := spamNetwork(c, []Role{Replayer}, 2)
	nw.StartSampling()
	end := warmup + 60*time.Second
	nw.workload(warmup, end, 1, 200, nw.pickPublisher)
	nw.run(end + replayAt[len(replayAt)-1] + 2*time.Second)
	d := nw.Delivery(warmup, end, nil, nil)
	r := nw.result("S6", "", d, 0)
	r.needFull("honest messages", d)
	var window, dup uint64
	for _, n := range nw.honest {
		if n.r != nil {
			st := n.r.Stats()
			window += st.OutOfWindow
			dup += st.Duplicates
		}
	}
	r.Values["replays_sent"] = float64(nw.m.replays)
	r.Values["out_of_window_dropped"] = float64(window)
	if nw.m.replays == 0 {
		r.fail("no replays sent")
	}
	nw.finish(&r)
	return []Result{r}
}

func runS7(c Case) []Result {
	nw := newNetwork(c, nil)
	nw.build(nw.honestDials())
	nw.StartSampling()
	end := warmup + 120*time.Second
	away := 30 * time.Second
	leaves := 0
	nw.workload(warmup, end, 1, 200, func() *Node {
		n := nw.pickPublisher()
		if n == nil {
			return nil
		}
		gen := n.gen
		nw.after(time.Millisecond, func() {
			if n.gen != gen || !n.up {
				return
			}
			leaves++
			nw.Stop(n, true)
			delete(nw.joined, n.Index)
			nw.after(away, func() {
				nw.check(nw.Start(n))
				nw.wire([]*Node{n}, nw.honest, nw.honestDials())
				nw.joinAll([]*Node{n}, time.Second)
			})
		})
		return n
	})
	nw.run(end + nw.o.Settle + time.Second)
	reached := func(m int32) bool {
		for i, a := range nw.msgs[m].at {
			if a >= 0 && int32(i) != nw.msgs[m].author && nw.nodes[i].Role == Honest {
				return true
			}
		}
		return false
	}
	d := nw.Delivery(warmup, end, reached, nil)
	all := nw.Delivery(warmup, end, nil, nil)
	r := nw.result("S7", "", d, 0)
	r.Phases = map[string]Delivery{"all_messages": all}
	r.Values["publisher_leaves"] = float64(leaves)
	r.Values["messages_that_reached_no_one"] = float64(all.Messages - d.Messages)
	r.needFull("messages that reached one honest peer", d)
	r.noMeshWaits(nw)
	nw.finish(&r)
	return []Result{r}
}

func runS8(c Case) []Result {
	nw := newNetwork(c, nil)
	nw.build(nw.honestDials())
	nw.StartSampling()
	cut, heal := warmup+10*time.Second, warmup+70*time.Second
	end := warmup + 150*time.Second
	nw.workload(warmup, end, 1, 200, nw.pickPublisher)
	side := func(n *Node) int8 { return int8(b2i(n.x >= 0.5)) }
	reopened := 0
	nw.At(cut, func() { nw.Partition(side) })
	nw.At(heal, func() { reopened = nw.Heal() })
	nw.run(end + nw.o.Settle + time.Second)
	same := func(n *Node, m int32) bool { return side(n) == side(nw.nodes[nw.msgs[m].author]) }
	after := nw.Delivery(heal+2*time.Second, end, nil, nil)
	r := nw.result("S8", "", after, 0)
	r.Phases = map[string]Delivery{
		"before_cut":        nw.Delivery(warmup, cut, nil, nil),
		"during_cut_same":   nw.Delivery(cut, heal, nil, same),
		"first_2s_of_heal":  nw.Delivery(heal, heal+2*time.Second, nil, nil),
		"after_heal_plus2s": after,
	}
	r.Values["links_reopened"] = float64(reopened)
	r.Values["repair_s"] = nw.repairTime(heal, end)
	r.needFull("messages published 2 s after heal", after)
	r.noMeshWaits(nw)
	nw.finish(&r)
	return []Result{r}
}

// repairTime returns the seconds after from from which every message published until to was fully delivered.
func (nw *network) repairTime(from, to time.Duration) float64 {
	last := from
	for i, m := range nw.msgs {
		if !m.honest || m.pub < int64(from) || m.pub >= int64(to) {
			continue
		}
		d := nw.Delivery(time.Duration(m.pub), time.Duration(m.pub)+1, func(j int32) bool { return int(j) == i }, nil)
		if d.Messages > 0 && d.Full == 0 {
			last = time.Duration(m.pub) + 1
		}
	}
	return (last - from).Seconds()
}

func runS9(c Case) []Result {
	var out []Result
	for _, f := range []float64{0.1, 0.3, 0.5, 0.7, 0.9} {
		nw := newNetwork(c, nil)
		nw.build(nw.honestDials())
		nw.StartSampling()
		crash := warmup + 10*time.Second
		end := warmup + 90*time.Second
		nw.workload(warmup, end, 1, 200, nw.pickPublisher)
		nw.At(crash, func() {
			for _, i := range nw.rnd.Perm(len(nw.honest))[:int(f*float64(len(nw.honest)))] {
				nw.Stop(nw.honest[i], false)
				delete(nw.joined, int32(i))
			}
		})
		nw.run(end + nw.o.Settle + time.Second)
		detect := crash + nw.o.IdleTimeout
		before := nw.Delivery(crash, detect, nil, nil)
		after := nw.Delivery(detect+5*time.Second, end, nil, nil)
		r := nw.result("S9", fmt.Sprintf("fail-%02.0f", f*100), after, 0)
		r.Phases = map[string]Delivery{"until_detected": before, "after_detected_plus5s": after}
		r.Values["failed_fraction"] = f
		nw.finish(&r)
		out = append(out, r)
	}
	return out
}

func runS10(c Case) []Result {
	var out []Result
	for _, v := range []string{"flash", "cold"} {
		role := Flash
		attack := warmup + 60*time.Second
		if v == "cold" {
			role, attack = Silent, 0
		}
		join := time.Duration(0)
		if v == "flash" {
			join = warmup
		}
		nw, syb, comp := sybilNetwork(c, role, 5, join)
		for _, a := range syb {
			a.FlashAt = int64(attack)
		}
		nw.StartSampling()
		end := warmup + 180*time.Second
		nw.workload(warmup, end, 1, 200, nw.pickPublisher)
		nw.run(end + nw.o.Settle + time.Second)
		reach := func(n *Node, m int32) bool { return comp.reach(nw, n, m) }
		from := max(attack, warmup)
		d := nw.Delivery(from, end, nil, reach)
		r := nw.result("S10", v, d, attack)
		r.Phases = map[string]Delivery{
			"first_30s": nw.Delivery(from, from+30*time.Second, nil, reach),
			"last_60s":  nw.Delivery(end-60*time.Second, end, nil, reach),
		}
		r.Values["recovery_s"] = nw.repairTime(from, end)
		r.Values["attacker_links_per_honest_link"] = linkRatio(nw)
		r.needFull("messages in the last 60 s", r.Phases["last_60s"])
		nw.finish(&r)
		out = append(out, r)
	}
	return out
}

func runS11(c Case) []Result {
	var out []Result
	for _, perIP := range []int{4, 8} {
		nw := newNetwork(c, nil)
		nw.startAll(nw.honest)
		groups := max(1, (len(nw.honest)+attackerPeers/2-1)/(attackerPeers/2))
		cfg := core.DefaultConfig()
		cfg.Score = nil
		wide(cfg)
		var col []*Node
		for g := range groups {
			for range perIP {
				a := nw.AddNode(Colocated, cfg, nil)
				a.SetIP(netipFrom(198, 51, 100, byte(g)))
				col = append(col, a)
			}
		}
		nw.startAll(col)
		for i, n := range nw.honest {
			g := i * groups / len(nw.honest)
			for _, a := range col[g*perIP : (g+1)*perIP] {
				nw.Connect(a, n)
			}
		}
		nw.wire(nw.honest, nw.honest, nw.honestDials())
		nw.joinAll(nw.honest, time.Second)
		nw.joinAll(col, time.Second)
		nw.StartSampling()
		end := warmup + 60*time.Second
		nw.workload(warmup, end, 1, 200, nw.pickPublisher)
		nw.run(end + nw.o.Settle + time.Second)
		d := nw.Delivery(warmup, end, nil, nil)
		r := nw.result("S11", fmt.Sprintf("per-ip-%d", perIP), d, 0)
		r.needFull("honest messages", d)
		if c.Score != nil {
			if a := r.attack(Colocated); a == nil || a.MeshSlotsLast > 0 {
				r.fail("colocated peers still hold mesh slots at the end")
			}
		}
		nw.finish(&r)
		out = append(out, r)
	}
	return out
}

func runS12(c Case) []Result {
	var out []Result
	var dup [2]float64
	for i, v := range []string{"idontwant", "no-idontwant"} {
		mut := func(cfg *core.Config) {
			if v == "no-idontwant" {
				cfg.IDontWantThreshold = cfg.MaxMessageSize
			}
		}
		nw := newNetwork(c, mut)
		nw.build(nw.honestDials())
		nw.StartSampling()
		end := warmup + 60*time.Second
		nw.workload(warmup, end, 0.2, 64<<10, nw.pickPublisher)
		nw.run(end + nw.o.Settle + 5*time.Second)
		d := nw.Delivery(warmup, end, nil, nil)
		r := nw.result("S12", v, d, 0)
		r.needFull("large messages", d)
		r.noMeshWaits(nw)
		dup[i] = d.RMR
		out = append(out, r)
		nw.finish(&out[i])
	}
	if !(dup[0] < dup[1]) {
		out[0].fail("redundancy with IDONTWANT %.3f not below %.3f without", dup[0], dup[1])
		out[0].Pass = false
	}
	return out
}

func runS13(c Case) []Result {
	var out []Result
	for _, dlo := range []int{4, 5} {
		nw := newNetwork(c, func(cfg *core.Config) { cfg.Params.Dlo = dlo })
		nw.build(nw.honestDials())
		nw.StartSampling()
		end := warmup + 60*time.Second
		nw.workload(warmup, end, 1, 200, nw.pickPublisher)
		nw.run(end + nw.o.Settle + time.Second)
		r := nw.result("S13", fmt.Sprintf("dlo-%d", dlo), nw.Delivery(warmup, end, nil, nil), 0)
		nw.finish(&r)
		out = append(out, r)
	}
	return out
}

// runM1 fills the seen cache for longer than SeenTTL, then measures the router heap per node: at the
// memory workload of 10 messages per second of 200-byte bodies (target 128 KiB), and at the 1 per second chat load.
func runM1(c Case) []Result {
	c.Memory = true
	var out []Result
	for _, rate := range []float64{10, 1} {
		nw := newNetwork(c, nil)
		nw.build(nw.honestDials())
		end := warmup + nw.cfg.SeenTTL + 10*time.Second
		nw.workload(warmup, end, rate, 200, nw.pickPublisher)
		nw.run(end + time.Second)
		seen := 0
		for _, n := range nw.honest {
			seen += n.r.Stats().Seen
		}
		d := nw.Delivery(warmup, end-nw.o.Settle, nil, nil)
		r := nw.result("M1", fmt.Sprintf("rate-%g", rate), d, 0)
		r.Values["seen_ids_per_node"] = float64(seen) / float64(len(nw.honest))
		rooms := max(1, nw.o.Rooms)
		if nw.o.Rooms == 0 || nw.o.Rooms > nw.topics() {
			rooms = nw.topics()
		}
		r.Values["target_bytes"] = float64(memoryTarget * rooms)
		if rooms > 1 {
			r.Values["memory_per_topic_bytes"] = float64(r.MemoryPerNode) / float64(rooms)
		}
		if r.MemoryPerNode > int64(memoryTarget*rooms) {
			r.fail("router memory %d bytes per node over the %d target of %d topics", r.MemoryPerNode, memoryTarget*rooms, rooms)
		}
		nw.finish(&r)
		out = append(out, r)
	}
	return out
}

// memoryTarget is the router state bound per node the simulator checks: 100,000 nodes in half of a 24 GiB machine.
const memoryTarget = 128 << 10

// Run runs the scenarios with the given ids (all when empty) and returns their results in order.
func Run(ids []string, c Case) ([]Result, error) {
	var out []Result
	for _, s := range Scenarios {
		if len(ids) > 0 && !slices.Contains(ids, s.ID) {
			continue
		}
		out = append(out, s.Run(c)...)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("sim: no scenario among %v", ids)
	}
	return out, nil
}
