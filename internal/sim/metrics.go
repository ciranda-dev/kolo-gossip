package sim

import (
	"math"
	"runtime"
	"slices"
	"time"

	"github.com/ciranda-dev/kolo-gossip/internal/core"
	"github.com/ciranda-dev/kolo-gossip/internal/wire"
)

// Control byte kinds.
const (
	ctlMesh = iota // subscriptions, GRAFT, PRUNE
	ctlIHave
	ctlIWant
	ctlIDontWant
	ctlKinds
)

type metrics struct {
	connects, lost, queueFull, verifies uint64
	ctl                                 [ctlKinds]uint64
	msgBytes                            uint64
	doubleDeliveries, badDeliveries     uint64
	boundViolations, replays            uint64
	toAttacker                          [roleCount]uint64
	meshWaits, otherWaits               uint64        // honest frames that waited for the receiver's buckets, from a mesh peer or not
	meshWaitsSteady                     uint64        // of the mesh waits, those after the warm-up
	meshWaitFirst, meshWaitLast         int64         // when the first and the last of the mesh waits began
	meshWaitMax                         time.Duration // the longest of them
	samples                             []Sample
}

// waited counts a frame of from that to's work buckets held back, when both are honest.
func (m *metrics) waited(s *Sim, to, from *Node, w time.Duration) {
	if to.Role != Honest || from.Role != Honest {
		return
	}
	for t, in := range to.rooms {
		if in && slices.Contains(to.r.Mesh(TopicID(t)), from.ID) {
			if m.meshWaits == 0 {
				m.meshWaitFirst = s.now
			}
			if s.now >= int64(warmup) {
				m.meshWaitsSteady++
			}
			m.meshWaits++
			m.meshWaitLast = s.now
			m.meshWaitMax = max(m.meshWaitMax, w)
			return
		}
	}
	m.otherWaits++
}

func (m *metrics) sent(c *wire.Control, size int) {
	if c == nil {
		m.msgBytes += uint64(size)
		return
	}
	ih := 0
	for _, h := range c.IHave {
		ih += wire.IHaveSize(len(h.IDs))
	}
	iw, dw := len(c.IWant)*wire.IDSize, len(c.IDontWant)*wire.IDSize
	m.ctl[ctlIHave] += uint64(ih)
	m.ctl[ctlIWant] += uint64(iw)
	m.ctl[ctlIDontWant] += uint64(dw)
	m.ctl[ctlMesh] += uint64(max(0, size-ih-iw-dw))
}

func (m *metrics) copy(s *Sim, raw []byte) {
	if i, ok := s.msgIndex(raw); ok && s.msgs[i].honest {
		s.msgs[i].copies++
	}
}

func (m *metrics) deliver(s *Sim, n *Node, i, from int32) {
	msg := s.msgs[i]
	if n.Role == Honest && msg.kind != kindHonest {
		m.badDeliveries++
	}
	if msg.at == nil {
		return
	}
	if msg.at[n.Index] >= 0 {
		if n.Role == Honest && n.sessions[len(n.sessions)-1].from <= msg.pub+int64(msg.at[n.Index])*1000 {
			m.doubleDeliveries++
		}
		return
	}
	msg.at[n.Index] = int32(min((s.now-msg.pub)/1000, math.MaxInt32))
	hop := uint8(1)
	if from >= 0 && int(from) < len(msg.hop) && msg.at[from] >= 0 {
		hop = min(msg.hop[from], 254) + 1
	}
	msg.hop[n.Index] = hop
}

// Sample is one look at every honest node's view of its peers, by the peers' role.
type Sample struct {
	T               float64            `json:"t"`
	Pairs           [roleCount]int     `json:"pairs"`
	BelowGraylist   [roleCount]int     `json:"below_graylist"`
	BelowPublish    [roleCount]int     `json:"below_publish"`
	BelowGossip     [roleCount]int     `json:"below_gossip"`
	Negative        [roleCount]int     `json:"negative"`
	MeshSlots       [roleCount]int     `json:"mesh_slots"`
	Min             [roleCount]float64 `json:"min_score"`
	Max             [roleCount]float64 `json:"max_score"`
	BoundViolations int                `json:"bound_violations"`
}

// Sample records scores, mesh slots and bounds now.
func (s *Sim) Sample() Sample {
	sm := Sample{T: time.Duration(s.now).Seconds()}
	for i := range sm.Min {
		sm.Min[i], sm.Max[i] = math.Inf(1), math.Inf(-1)
	}
	for _, n := range s.nodes {
		if n.Role != Honest || !n.up || n.r == nil {
			continue
		}
		var th core.Thresholds
		if n.cfg.Score != nil {
			th = n.cfg.Score.Thresholds
		}
		for _, l := range n.links {
			p := s.nodes[l.other(n.Index)]
			sc, k := n.r.Score(p.ID), p.Role
			sm.Pairs[k]++
			sm.Min[k], sm.Max[k] = min(sm.Min[k], sc), max(sm.Max[k], sc)
			sm.Negative[k] += b2i(sc < 0)
			if n.cfg.Score != nil {
				sm.BelowGraylist[k] += b2i(sc < th.Graylist)
				sm.BelowPublish[k] += b2i(sc < th.Publish)
				sm.BelowGossip[k] += b2i(sc < th.Gossip)
			}
		}
		for t, in := range n.rooms {
			if !in {
				continue
			}
			for _, p := range n.r.Mesh(TopicID(t)) {
				sm.MeshSlots[s.nodes[peerIndex(p)].Role]++
			}
		}
		sm.BoundViolations += checkBounds(n)
	}
	for i := range sm.Min {
		if sm.Pairs[i] == 0 {
			sm.Min[i], sm.Max[i] = 0, 0
		}
	}
	s.m.samples = append(s.m.samples, sm)
	s.m.boundViolations += uint64(sm.BoundViolations)
	return sm
}

// checkBounds counts the configured bounds a router exceeds, from what its Stats show.
func checkBounds(n *Node) int {
	st, c := n.r.Stats(), n.cfg
	v := 0
	v += b2i(c.MaxPeers > 0 && st.Peers > c.MaxPeers)
	v += b2i(c.MaxTopics > 0 && st.Topics > c.MaxTopics)
	v += b2i(st.Topics > len(n.rooms))
	v += b2i(st.Seen > c.MaxSeen)
	v += b2i(st.CacheBytes > c.MaxCacheBytes)
	v += b2i(st.CacheMessages > c.MaxCacheMessages*max(1, st.Topics))
	v += b2i(st.Validating > c.MaxValidating)
	v += b2i(st.Retained > c.MaxRetained)
	for t, in := range n.rooms {
		if in {
			v += b2i(n.r.TopicStats(TopicID(t)).Mesh > st.Peers)
		}
	}
	return v
}

// StartSampling samples every SampleEvery from now until the run ends.
func (s *Sim) StartSampling() {
	var tick func()
	tick = func() {
		s.Sample()
		s.after(s.o.SampleEvery, tick)
	}
	s.after(s.o.SampleEvery, tick)
}

// Samples returns the samples taken so far.
func (s *Sim) Samples() []Sample { return s.m.samples }

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Delivery is the delivery of a set of honest messages to the honest nodes that should have them.
type Delivery struct {
	Messages  int     `json:"messages"`
	Pairs     int     `json:"pairs"`
	Ratio     float64 `json:"delivery_ratio"`
	MinRatio  float64 `json:"min_message_ratio"`
	Full      int     `json:"full_messages"`
	P50       float64 `json:"latency_p50_ms"`
	P90       float64 `json:"latency_p90_ms"`
	P99       float64 `json:"latency_p99_ms"`
	Max       float64 `json:"latency_max_ms"`
	RMR       float64 `json:"rmr"`
	MaxHop    int     `json:"last_delivery_hop_max"`
	HopP50    float64 `json:"last_delivery_hop_p50"`
	Copies    int     `json:"copies"`
	Delivered int     `json:"delivered"`
}

// Delivery measures the honest messages published in [from, to) that pick selects, over the honest nodes
// eligible for each: up and joined at the publish and still up Settle later (or at the end of the run).
func (s *Sim) Delivery(from, to time.Duration, pick func(m int32) bool, eligible func(n *Node, m int32) bool) Delivery {
	var d Delivery
	var lat []int32
	var hops []int
	d.MinRatio = 1
	rmr := 0.0
	for i, m := range s.msgs {
		if !m.honest || m.pub < int64(from) || m.pub >= int64(to) || (pick != nil && !pick(int32(i))) {
			continue
		}
		pairs, got, last := 0, 0, 0
		for _, n := range s.nodes {
			if n.Role != Honest || n.Index == m.author || !s.eligible(n, m) ||
				(eligible != nil && !eligible(n, int32(i))) {
				continue
			}
			pairs++
			if m.at[n.Index] >= 0 {
				got++
				lat = append(lat, m.at[n.Index])
				last = max(last, int(m.hop[n.Index]))
			}
		}
		if pairs == 0 {
			continue
		}
		d.Messages++
		d.Pairs += pairs
		d.Delivered += got
		d.Copies += m.copies
		r := float64(got) / float64(pairs)
		d.MinRatio = min(d.MinRatio, r)
		if got == pairs {
			d.Full++
		}
		if got > 0 {
			rmr += float64(m.copies)/float64(got) - 1
		}
		hops = append(hops, last)
		d.MaxHop = max(d.MaxHop, last)
	}
	if d.Messages == 0 {
		d.MinRatio = 0
		return d
	}
	d.Ratio = float64(d.Delivered) / float64(d.Pairs)
	d.RMR = rmr / float64(d.Messages)
	slices.Sort(lat)
	slices.Sort(hops)
	if len(lat) > 0 {
		d.P50, d.P90, d.P99 = pct(lat, 0.50), pct(lat, 0.90), pct(lat, 0.99)
		d.Max = float64(lat[len(lat)-1]) / 1000
	}
	d.HopP50 = float64(hops[len(hops)/2])
	return d
}

func pct(sorted []int32, p float64) float64 {
	i := int(math.Ceil(p*float64(len(sorted)))) - 1
	return float64(sorted[max(0, i)]) / 1000
}

// eligible: honest, joined at or before the publish and still up Settle after it.
func (s *Sim) eligible(n *Node, m *msgRec) bool {
	end := m.pub + int64(s.o.Settle)
	if !n.room(m.topic) {
		return false
	}
	for _, sp := range n.sessions {
		if sp.from <= m.pub && sp.to >= end && (sp.to != never || s.now >= end) {
			return true
		}
	}
	return false
}

// Overhead is the traffic of honest nodes.
type Overhead struct {
	ControlPerPayload float64 `json:"control_bytes_per_delivered_payload_byte"`
	B                 float64 `json:"b_bytes_per_useful_byte"`
	BPayload          float64 `json:"b_bytes_per_body_byte"`
	Deliveries        uint64  `json:"deliveries"`
	MeshBytes         uint64  `json:"control_mesh_bytes"`
	IHaveBytes        uint64  `json:"control_ihave_bytes"`
	IWantBytes        uint64  `json:"control_iwant_bytes"`
	IDontWantBytes    uint64  `json:"control_idontwant_bytes"`
	MessageBytes      uint64  `json:"message_bytes"`
	QueueFull         uint64  `json:"queue_full_drops"`
	Lost              uint64  `json:"frames_lost"`
	Verifies          uint64  `json:"verifies"`
}

// Overhead returns the bytes sent by honest nodes against what they delivered. B is every byte sent (messages and
// control, with frame lengths) per byte of envelope delivered to an honest node other than the author; BPayload
// divides by body bytes instead.
func (s *Sim) Overhead() Overhead {
	var payload, env, deliveries uint64
	for _, m := range s.msgs {
		if !m.honest {
			continue
		}
		for i, a := range m.at {
			if a >= 0 && int32(i) != m.author {
				deliveries++
				payload += uint64(m.body)
				env += uint64(len(m.raw))
			}
		}
	}
	o := Overhead{MeshBytes: s.m.ctl[ctlMesh], IHaveBytes: s.m.ctl[ctlIHave], IWantBytes: s.m.ctl[ctlIWant],
		IDontWantBytes: s.m.ctl[ctlIDontWant], MessageBytes: s.m.msgBytes, QueueFull: s.m.queueFull,
		Lost: s.m.lost, Verifies: s.m.verifies, Deliveries: deliveries}
	if payload == 0 {
		return o
	}
	var ctl uint64
	for _, b := range s.m.ctl {
		ctl += b
	}
	sent := float64(ctl + s.m.msgBytes)
	o.ControlPerPayload = float64(ctl) / float64(payload)
	o.B = sent / float64(env)
	o.BPayload = sent / float64(payload)
	return o
}

// Shape is the connection and mesh shape of the honest nodes now.
type Shape struct {
	ConnMin       int     `json:"connections_min"`
	ConnAvg       float64 `json:"connections_avg"`
	ConnMax       int     `json:"connections_max"`
	MeshMin       int     `json:"mesh_min"`
	MeshAvg       float64 `json:"mesh_avg"`
	MeshMax       int     `json:"mesh_max"`
	OutboundShare float64 `json:"mesh_outbound_share"`
}

// Shape measures the honest running nodes.
func (s *Sim) Shape() Shape {
	sh := Shape{ConnMin: math.MaxInt, MeshMin: math.MaxInt}
	n, mesh, out, conns, pairs := 0, 0, 0, 0, 0
	for _, nd := range s.nodes {
		if nd.Role != Honest || !nd.up || nd.r == nil {
			continue
		}
		n++
		c := len(nd.links)
		conns += c
		sh.ConnMin, sh.ConnMax = min(sh.ConnMin, c), max(sh.ConnMax, c)
		for t, in := range nd.rooms {
			if !in {
				continue
			}
			ts := nd.r.TopicStats(TopicID(t))
			pairs++
			mesh += ts.Mesh
			out += ts.Outbound
			sh.MeshMin, sh.MeshMax = min(sh.MeshMin, ts.Mesh), max(sh.MeshMax, ts.Mesh)
		}
	}
	if n == 0 {
		return Shape{}
	}
	sh.ConnAvg = float64(conns) / float64(n)
	sh.MeshAvg = float64(mesh) / float64(max(1, pairs))
	if mesh > 0 {
		sh.OutboundShare = float64(out) / float64(mesh)
	}
	return sh
}

// DropRouters measures the heap bytes held by the running routers per router, then drops them; message bytes stay
// referenced by the simulator and are not counted. The run cannot continue afterwards.
func (s *Sim) DropRouters() (perNode int64, total int64) {
	count := 0
	for _, n := range s.nodes {
		if n.r != nil {
			count++
		}
	}
	if count == 0 {
		return 0, 0
	}
	with := heap()
	for _, n := range s.nodes {
		n.r = nil
		n.up = false
	}
	without := heap()
	total = int64(with) - int64(without)
	return total / int64(count), total
}

func heap() uint64 {
	var ms runtime.MemStats
	runtime.GC()
	runtime.GC()
	runtime.ReadMemStats(&ms)
	return ms.HeapAlloc
}
