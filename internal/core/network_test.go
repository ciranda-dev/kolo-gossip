package core

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"hash"

	"slices"
	"testing"
	"time"

	"github.com/ciranda-dev/kolo-gossip/internal/wire"
)

// network runs routers connected in memory with zero latency, one frame at a time in FIFO order.
type network struct {
	t         testing.TB
	nodes     []*netNode
	byKey     map[PeerID]*netNode
	q         []netFrame
	vals      []netVal
	now       time.Time
	h         hash.Hash
	published []wire.ID
	scoring   bool
}

type netNode struct {
	n         *network
	i         int
	r         *Router
	delivered map[wire.ID]bool
}

type netFrame struct {
	from, to PeerID
	ctrl     []byte
	raw      []byte
}

type netVal struct {
	node *netNode
	id   wire.ID
	n    uint64
}

func (s *netNode) SendControl(to PeerID, c *wire.Control, urgent bool) bool {
	n := s.n
	raw, err := c.Encode()
	if err != nil {
		n.t.Fatalf("node %d encodes an invalid frame: %v", s.i, err)
	}
	if len(raw) > s.r.cfg.MaxControlSize {
		n.t.Fatalf("node %d sends %d control bytes", s.i, len(raw))
	}
	for _, tp := range c.Graft {
		if s.r.backoff.has(tp, to) {
			n.t.Fatalf("node %d grafts a backed-off peer", s.i)
		}
	}
	n.h.Write([]byte{'c', byte(s.i)})
	n.h.Write(to[:])
	n.h.Write(raw)
	n.q = append(n.q, netFrame{from: key(s.i), to: to, ctrl: raw})
	return true
}

func (s *netNode) SendMessage(to PeerID, raw []byte) bool {
	s.n.h.Write([]byte{'m', byte(s.i)})
	s.n.h.Write(to[:])
	s.n.h.Write(raw)
	s.n.q = append(s.n.q, netFrame{from: key(s.i), to: to, raw: raw})
	return true
}

func (s *netNode) Validate(id wire.ID, n uint64, env *wire.Envelope, from PeerID) {
	s.n.vals = append(s.n.vals, netVal{s, id, n})
}

func (s *netNode) Cancel(uint64) {}

func (s *netNode) Dial(wire.Topic, PeerID, []wire.PeerRecord) int { return 0 }

func (s *netNode) Deliver(id wire.ID, env *wire.Envelope, from PeerID) {
	s.n.h.Write([]byte{'d', byte(s.i)})
	s.n.h.Write(id[:])
	if s.delivered[id] {
		s.n.t.Fatalf("node %d delivered a message twice", s.i)
	}
	s.delivered[id] = true
}

func networkConfig(scoring bool) *Config {
	cfg := DefaultConfig()
	if scoring {
		cfg.Score = scoringConfig().Score
	}
	return cfg
}

func networkTopicConfig(scoring bool) *TopicConfig {
	if !scoring {
		return nil
	}
	ts := topicScore()
	ts.MeshMessageDeliveriesWeight = 0
	return &TopicConfig{Score: ts}
}

// newNetwork builds n nodes on a ring plus extra random links; each link's dialer sees it as outbound.
func newNetwork(t testing.TB, seed uint64, n int, scoring bool) *network {
	net := &network{t: t, byKey: map[PeerID]*netNode{}, now: t0, h: sha256.New(), scoring: scoring}
	for i := range n {
		node := &netNode{n: net, i: i, delivered: map[wire.ID]bool{}}
		r, err := New(t0, key(i), networkConfig(scoring), randFor(seed*1000+uint64(i)), &fakeVerifier{}, node)
		if err != nil {
			t.Fatal(err)
		}
		node.r = r
		net.nodes = append(net.nodes, node)
		net.byKey[key(i)] = node
	}
	rnd := randFor(seed)
	linked := map[[2]int]bool{}
	link := func(a, b int) {
		if a == b || linked[[2]int{a, b}] || linked[[2]int{b, a}] {
			return
		}
		linked[[2]int{a, b}] = true
		if net.nodes[a].r.AddPeer(t0, key(b), true, addr(b)) != nil || net.nodes[b].r.AddPeer(t0, key(a), false, addr(a)) != nil {
			return
		}
	}
	for i := range n {
		link(i, (i+1)%n)
	}
	for range n * 3 {
		link(rnd.IntN(n), rnd.IntN(n))
	}
	for _, node := range net.nodes {
		if err := node.r.Join(t0, T, networkTopicConfig(scoring)); err != nil {
			t.Fatal(err)
		}
	}
	net.drain()
	return net
}

func (net *network) drain() {
	for len(net.q) > 0 || len(net.vals) > 0 {
		for len(net.q) > 0 {
			f := net.q[0]
			net.q = net.q[1:]
			node := net.byKey[f.to]
			if f.ctrl != nil {
				c, err := wire.DecodeControl(f.ctrl, node.r.cfg.MaxControlSize)
				if err != nil {
					net.t.Fatal(err)
				}
				if err := node.r.Control(net.now, f.from, c); err != nil {
					net.t.Fatalf("honest frame refused: %v", err)
				}
			} else {
				node.r.Message(net.now, f.from, f.raw)
			}
			net.checkBounds(node)
		}
		vals := net.vals
		net.vals = nil
		for _, v := range vals {
			v.node.r.ValidationDone(net.now, v.id, v.n, Accept)
		}
	}
}

// round advances one heartbeat interval, ticks every node, checks the heartbeat properties, then drains.
func (net *network) round() {
	net.now = net.now.Add(time.Second)
	for _, node := range net.nodes {
		node.r.Tick(net.now)
		net.checkHeartbeat(node)
		net.checkBounds(node)
	}
	net.drain()
}

func (net *network) publish(i int, seq uint64) {
	raw := envelope(T, key(i), seq, net.now, int(seq%3)*600)
	id, err := net.nodes[i].r.Publish(net.now, raw)
	if err != nil {
		net.t.Fatal(err)
	}
	net.published = append(net.published, id)
	net.nodes[i].delivered[id] = true
	net.drain()
}

// checkHeartbeat: Dlo <= |mesh| <= Dhi when enough eligible peers exist, at least min(Dout, outbound eligible)
// outbound mesh peers, no negative score in the mesh (gossipsub-v1.0.md:421-447; gossipsub-v1.1.md:186-203, 248-250).
func (net *network) checkHeartbeat(node *netNode) {
	r := node.r
	tp := r.topics[T]
	d := tp.params
	eligible, eligibleOut := 0, 0
	for _, p := range r.peers {
		in := slices.Contains(tp.mesh, p.id)
		if (in || (p.subscribed(T) && !r.backoff.has(T, p.id))) && r.scoreOf(p.id) >= 0 {
			eligible++
			if p.outbound {
				eligibleOut++
			}
		}
	}
	m := len(tp.mesh)
	if m > d.Dhi || m < min(d.Dlo, eligible) {
		net.t.Fatalf("node %d: mesh %d outside Dlo %d to Dhi %d with %d eligible", node.i, m, d.Dlo, d.Dhi, eligible)
	}
	if m >= d.Dlo && r.countOutbound(tp.mesh) < min(d.Dout, eligibleOut) {
		net.t.Fatalf("node %d: %d outbound in mesh, %d eligible", node.i, r.countOutbound(tp.mesh), eligibleOut)
	}
	for _, p := range tp.mesh {
		if r.scoreOf(p) < 0 {
			net.t.Fatalf("node %d: negative score in mesh after heartbeat", node.i)
		}
	}
}

// checkBounds checks every configured bound of one router.
func (net *network) checkBounds(node *netNode) {
	if err := node.r.checkBounds(); err != nil {
		net.t.Fatalf("node %d: %v", node.i, err)
	}
}

// checkSymmetry: after quiescence every mesh link is known to both ends (gossipsub-v1.0.md:136-140).
func (net *network) checkSymmetry() {
	for _, a := range net.nodes {
		for _, p := range a.r.Mesh(T) {
			if !slices.Contains(net.byKey[p].r.Mesh(T), key(a.i)) {
				net.t.Fatalf("mesh link %d to %d is one-sided", a.i, net.byKey[p].i)
			}
		}
	}
}

// checkBounds reports the first configured bound the router exceeds.
func (r *Router) checkBounds() error {
	c := &r.cfg
	switch {
	case c.MaxPeers > 0 && len(r.peers) > c.MaxPeers:
		return fmt.Errorf("%d peers", len(r.peers))
	case c.MaxTopics > 0 && len(r.topics) > c.MaxTopics:
		return fmt.Errorf("%d topics", len(r.topics))
	case r.seen.len()+r.validating > c.MaxSeen || len(r.recs) > r.seen.len()+r.validating:
		return fmt.Errorf("%d seen, %d held, %d records", r.seen.len(), r.validating, len(r.recs))
	case r.skipLong.len() > c.MaxIgnoredIDs:
		return fmt.Errorf("%d ignored ids", r.skipLong.len())
	case r.cache.bytes > c.MaxCacheBytes:
		return fmt.Errorf("%d cache bytes", r.cache.bytes)
	case r.validating > c.MaxValidating || r.validatingBytes > c.MaxValidatingBytes:
		return fmt.Errorf("%d validating", r.validating)
	case len(r.backoff.left) > max(16, len(r.topics)):
		return fmt.Errorf("%d left backoff tables", len(r.backoff.left))
	case r.score != nil && len(r.score.retained) > c.MaxRetained:
		return fmt.Errorf("%d retained", len(r.score.retained))
	}
	for t, n := range r.cache.perTopic {
		if n > c.MaxCacheMessages {
			return fmt.Errorf("%d cached in topic %x", n, t[:2])
		}
	}
	for _, tb := range r.backoff.m {
		if len(tb.m) > c.MaxBackoff {
			return fmt.Errorf("%d backoff entries", len(tb.m))
		}
	}
	for _, p := range r.peers {
		switch {
		case len(p.topics) > len(r.topics):
			return fmt.Errorf("peer with %d topics, we hold %d", len(p.topics), len(r.topics))
		case len(p.other) > c.MaxPeerTopics:
			return fmt.Errorf("peer with %d other topics", len(p.other))
		case p.asked < 0 || p.asked > r.askCap():
			return fmt.Errorf("asked %d ids", p.asked)
		case p.unwanted != nil && (len(p.unwanted.m) > c.MaxIDontWantIDs || len(p.unwanted.q) != len(p.unwanted.m)):
			return fmt.Errorf("%d unwanted ids", len(p.unwanted.m))
		}
	}
	held := 0
	for _, rec := range r.recs {
		if rec.pending != nil && rec.pending.retry {
			held++
		}
	}
	if held != len(r.retrying) || held > r.validating {
		return fmt.Errorf("%d retrying messages, %d records hold one, %d held", len(r.retrying), held, r.validating)
	}
	for _, p := range r.peers {
		for t := range p.refused {
			if tp := r.topics[t]; tp == nil || !tp.joined || tp.allow == nil {
				return fmt.Errorf("a refusal for topic %x without an AllowPeer", t[:2])
			}
		}
	}
	for _, a := range r.asks {
		if a.n+a.nw < 1 || a.n > 4 || a.nw > 2 {
			return fmt.Errorf("an id asked of %d peers", a.n)
		}
	}
	return nil
}

// runNetwork plays one seeded scenario and returns the hash of every effect of every node.
func runNetwork(t testing.TB, seed uint64, scoring bool) []byte {
	rnd := randFor(seed ^ 0xabcdef)
	n := 8 + int(seed%17)
	net := newNetwork(t, seed, n, scoring)
	seq := uint64(0)
	for round := range 14 {
		net.round()
		if round < 9 {
			for range 1 + rnd.IntN(3) {
				seq++
				net.publish(rnd.IntN(n), seq)
			}
		}
		if round == 6 {
			net.leaveAndRejoin(rnd.IntN(n))
		}
	}
	net.checkSymmetry()
	for _, node := range net.nodes {
		for _, id := range net.published {
			if !node.delivered[id] {
				t.Fatalf("seed %d: node %d missed a message", seed, node.i)
			}
		}
	}
	return net.h.Sum(nil)
}

func (net *network) leaveAndRejoin(i int) {
	node := net.nodes[i]
	node.r.Leave(net.now, T)
	net.drain()
	if err := node.r.Join(net.now, T, networkTopicConfig(net.scoring)); err != nil {
		net.t.Fatal(err)
	}
	net.drain()
}

// TestNetworkProperties checks the heartbeat, bound, symmetry and delivery properties over 1,000 seeds.
func TestNetworkProperties(t *testing.T) {
	for seed := range uint64(1000) {
		runNetwork(t, seed, seed%2 == 1)
	}
}

// TestDeterminism: the same seed and inputs give the same effects, so no decision depends on map order.
func TestDeterminism(t *testing.T) {
	for seed := range uint64(20) {
		a := runNetwork(t, seed, seed%2 == 0)
		for range 3 {
			if b := runNetwork(t, seed, seed%2 == 0); !bytes.Equal(a, b) {
				t.Fatalf("seed %d: two runs differ", seed)
			}
		}
	}
	if bytes.Equal(runNetwork(t, 1, false), runNetwork(t, 2, false)) {
		t.Fatal("different seeds gave the same effects")
	}
}
