// Package sim is a deterministic discrete-event simulator for kolo-gossip routers: thousands of core.Router
// instances in one goroutine on a virtual clock, with a latency plane, an uplink model, loss, partitions,
// churn, crashes and adversaries. The same Options and seed always give the same events and metrics.
package sim

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"net/netip"
	"runtime/debug"
	rtmetrics "runtime/metrics"
	"slices"
	"time"

	"github.com/ciranda-dev/kolo-gossip/internal/core"
	"github.com/ciranda-dev/kolo-gossip/internal/wire"
)

// ErrHeapLimit aborts a run whose heap passed SetHeapLimit.
var ErrHeapLimit = errors.New("sim: heap limit passed")

var heapLimit uint64

// SetHeapLimit makes every later run stop with ErrHeapLimit once the heap passes limit bytes; 0 turns it off.
func SetHeapLimit(limit uint64) {
	heapLimit = limit
	if limit > 0 {
		debug.SetMemoryLimit(int64(limit)) // the collector runs before garbage alone passes the limit
	} else {
		debug.SetMemoryLimit(math.MaxInt64)
	}
}

// liveHeap is the heap the last collection kept.
func liveHeap() uint64 {
	s := []rtmetrics.Sample{{Name: "/gc/heap/live:bytes"}}
	rtmetrics.Read(s)
	return s[0].Value.Uint64()
}

// Topic is topic 0, the topic every simulated node joins when Options.Topics is 1.
var Topic = wire.Topic{'k', 'o', 'l', 'o', '-', 's', 'i', 'm'}

// TopicID returns topic i: Topic with i in its last two bytes.
func TopicID(i int) wire.Topic {
	t := Topic
	t[30], t[31] = byte(i>>8), byte(i)
	return t
}

// Epoch is virtual time zero.
var Epoch = time.Unix(1_800_000_000, 0)

const never = math.MaxInt64

// simPort is the port of every simulated node: the router reads ports only for peer exchange, which is off.
const simPort = 4000

// Options configure the network model; DefaultOptions gives the recorded defaults.
type Options struct {
	Seed           uint64
	LatencyBase    time.Duration // one-way latency = LatencyBase + LatencyScale x distance on the unit square
	LatencyScale   time.Duration
	Uplink         float64       // bits per second of each node's uplink
	Loss           float64       // probability that a frame needs a retransmission
	VerifyCost     time.Duration // virtual CPU time of one signature and author chain check
	ValidateCost   time.Duration // virtual CPU time of the application validator
	IdleTimeout    time.Duration // a silent connection is closed after this
	MaxPeers       int           // connection budget of an honest node
	MaxInbound     int           // connections other nodes may open to an honest node
	PeerQueue      int           // frames waiting in the uplink for one peer
	PeerQueueBytes int
	SampleEvery    time.Duration // score and bound samples
	Settle         time.Duration // a node must stay up this long after a publish to count for its delivery
	Topics         int           // topics in the network, 0 or 1 for the single topic of the recorded traces
	Rooms          int           // topics each honest node joins, a seeded random subset; 0 or Topics: all
	Busy           float64       // share of each workload published in topic 0, the rest spread over the topics
	Work           bool          // frames wait for the receiver's work buckets, as the driver makes them; false reproduces the old traces
}

// DefaultOptions returns the recorded network model.
func DefaultOptions(seed uint64) Options {
	return Options{
		Seed:           seed,
		LatencyScale:   96 * time.Millisecond, // mean one-way 50 ms on the unit square (mean distance 0.5214)
		Uplink:         20e6,                  // kolo-transport docs/limits.md: 20 Mbit/s per stream at 100 ms
		VerifyCost:     3 * ed25519Verify,     // kolo-id VerifyDevice of a root-issued device: 3 signatures
		IdleTimeout:    30 * time.Second,      // kolo-transport IdleTimeout
		MaxPeers:       64,                    // kolo-swarm MaxPeers
		MaxInbound:     32,                    // kolo-swarm MaxInbound
		PeerQueue:      32,                    // the driver's per-peer queue
		PeerQueueBytes: 1 << 20,               // the driver's default: max(1 MiB, MaxMessageSize)
		SampleEvery:    5 * time.Second,
		Settle:         10 * time.Second,
		Work:           true,
	}
}

// ed25519Verify is one Ed25519ctx verification: BenchmarkEd25519ctxVerify median 28.6 us on the recording machine.
const ed25519Verify = 29 * time.Microsecond

// Role tells what a node is; every role but Honest is an attacker.
type Role uint8

// Roles.
const (
	Honest       Role = iota
	Silent            // follows the protocol but forwards no message and sends no IHAVE
	Censor            // drops the messages of chosen authors
	Flash             // honest until FlashAt, then Silent
	Colocated         // honest behaviour from a shared IPv4 address
	IHaveSpam         // advertises bogus ids
	IWantSpam         // asks for cached messages again and again
	DontWantSpam      // floods IDONTWANT
	InvalidSpam       // sends messages with bad signatures
	RejectSpam        // sends signed messages the application validator rejects
	GraftSpam         // grafts during backoff
	ForgeSig          // claims honest authors with bad signatures
	ForgePerson       // signs with its own device but names another person
	Revoked           // signs with a revoked device
	Replayer          // replays captured messages
	roleCount
)

var roleNames = [...]string{"honest", "silent", "censor", "flash", "colocated", "ihave-spam", "iwant-spam",
	"idontwant-spam", "invalid-spam", "reject-spam", "graft-spam", "forge-sig", "forge-person", "revoked", "replayer"}

// String returns the role's name in results.
func (r Role) String() string { return roleNames[r] }

type evKind uint8

const (
	evMessage evKind = iota
	evControl
	evTick
	evValidate
	evRemove
	evFunc
)

type event struct {
	at   int64
	seq  uint64
	kind evKind
	gen  uint32
	a, b int32
	n    int32
	tx   int64 // end of the frame's transmission; for evValidate, the validation number
	l    *link
	raw  []byte
	c    *wire.Control
	fn   func()
}

// link is one connection; a dialed b.
type link struct {
	id       uint32
	a, b     int32
	closedAt int64
	qa, qb   uplinkQueue
	held     [2]heldFrames // by receiver: a, b
}

type uplinkQueue struct {
	fin   []int64
	size  []int32
	bytes int
}

func (l *link) queue(from int32) *uplinkQueue {
	if from == l.a {
		return &l.qa
	}
	return &l.qb
}

func (l *link) other(n int32) int32 {
	if n == l.a {
		return l.b
	}
	return l.a
}

// room drops finished frames and reports whether one more frame of size fits.
func (q *uplinkQueue) room(now int64, size, maxFrames, maxBytes int) bool {
	i := 0
	for i < len(q.fin) && q.fin[i] <= now {
		q.bytes -= int(q.size[i])
		i++
	}
	if i > 0 {
		q.fin, q.size = q.fin[i:], q.size[i:]
	}
	return len(q.fin) < maxFrames && q.bytes+size <= maxBytes
}

func (q *uplinkQueue) add(fin int64, size int) {
	// Two lanes share the queue, so keep it ordered by finish time.
	i := len(q.fin)
	for i > 0 && q.fin[i-1] > fin {
		i--
	}
	q.fin = slices.Insert(q.fin, i, fin)
	q.size = slices.Insert(q.size, i, int32(size))
	q.bytes += size
}

// Node is one simulated participant.
type Node struct {
	s        *Sim
	Index    int32
	ID       core.PeerID
	IP       netip.Addr
	Role     Role
	x, y     float64
	r        *core.Router
	cfg      *core.Config
	tc       *core.TopicConfig
	up       bool
	gen      uint32
	links    []*link
	byPeer   map[int32]*link
	inbound  int
	msgFree  int64
	ctlFree  int64
	cpuFree  int64
	sessions []span
	act      *actor
	FlashAt  int64
	censored func(author int32) bool
	rooms    []bool // topics the node joins
}

// heldFrames are the frames to one end of a link that wait for the receiver's work buckets, in order.
type heldFrames struct{ q []event }

func (n *Node) room(t int) bool { return t < len(n.rooms) && n.rooms[t] }

type span struct{ from, to int64 }

// Sim is one simulated network.
type Sim struct {
	o        Options
	now      int64
	seq      uint64
	q        []event
	rnd      *rand.Rand
	nodes    []*Node
	msgs     []*msgRec
	byID     map[wire.ID]int32
	nextID   uint32
	side     []int8 // partition side per node; nil when the network is whole
	cutLinks []*link
	honest   []int32
	trace    uint64
	events   uint64
	m        metrics
	bodies   map[int][]byte
	roomRnd  *rand.Rand // chooses the rooms of honest nodes, apart from rnd so one topic keeps its traces
	err      error      // the first error of a frame delivered from a timer
}

func (s *Sim) topics() int { return max(1, s.o.Topics) }

// New returns an empty network.
func New(o Options) *Sim {
	return &Sim{
		o:       o,
		rnd:     rand.New(rand.NewPCG(o.Seed, o.Seed^0x5851f42d4c957f2d)),
		byID:    map[wire.ID]int32{},
		trace:   14695981039346656037,
		bodies:  map[int][]byte{},
		roomRnd: rand.New(rand.NewPCG(o.Seed^0x2545f4914f6cdd1d, o.Seed)),
	}
}

// Now returns the virtual time since Epoch.
func (s *Sim) Now() time.Duration { return time.Duration(s.now) }

func (s *Sim) time() time.Time { return Epoch.Add(time.Duration(s.now)) }

// Nodes returns every node in index order.
func (s *Sim) Nodes() []*Node { return s.nodes }

// Rand returns the simulator's own seeded source, for scenario choices.
func (s *Sim) Rand() *rand.Rand { return s.rnd }

// Events returns how many events ran.
func (s *Sim) Events() uint64 { return s.events }

// Trace returns a hash of every event that ran, in order.
func (s *Sim) Trace() uint64 { return s.trace }

func (s *Sim) mix(vs ...uint64) {
	for _, v := range vs {
		s.trace ^= v
		s.trace *= 1099511628211
	}
}

func peerKey(i int32) core.PeerID {
	var k core.PeerID
	binary.BigEndian.PutUint32(k[:], uint32(i)+1)
	copy(k[4:], "kolo-gossip simulated node key")
	return k
}

func personKey(i int32) wire.Key {
	var k wire.Key
	binary.BigEndian.PutUint32(k[:], uint32(i)+1)
	copy(k[4:], "kolo-gossip simulated person")
	return k
}

func peerIndex(p core.PeerID) int32 { return int32(binary.BigEndian.Uint32(p[:4])) - 1 }

// AddNode adds a node with a role and a router config (nil for adversaries without a router); it starts down.
func (s *Sim) AddNode(role Role, cfg *core.Config, tc *core.TopicConfig) *Node {
	i := int32(len(s.nodes))
	n := &Node{s: s, Index: i, ID: peerKey(i), Role: role, cfg: cfg, tc: tc, byPeer: map[int32]*link{},
		x: s.rnd.Float64(), y: s.rnd.Float64(), FlashAt: never}
	n.IP = netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
	s.nodes = append(s.nodes, n)
	if role >= IHaveSpam {
		n.act = &actor{}
	}
	n.rooms = make([]bool, s.topics())
	if role == Honest && s.o.Rooms > 0 && s.o.Rooms < s.topics() {
		for _, t := range s.roomRnd.Perm(s.topics())[:s.o.Rooms] {
			n.rooms[t] = true
		}
	} else {
		for t := range n.rooms {
			n.rooms[t] = true
		}
	}
	return n
}

// SetIP gives a node a chosen IPv4 address, for colocation.
func (n *Node) SetIP(ip netip.Addr) { n.IP = ip }

// Up reports whether the node runs.
func (n *Node) Up() bool { return n.up }

// Router returns the node's router, nil for raw adversaries or a node that is down.
func (n *Node) Router() *core.Router { return n.r }

// Peers returns the indexes of the node's connected peers in connection order.
func (n *Node) Peers() []int32 {
	out := make([]int32, len(n.links))
	for i, l := range n.links {
		out[i] = l.other(n.Index)
	}
	return out
}

// Start brings a node up with a fresh router; it keeps its key.
func (s *Sim) Start(n *Node) error {
	if n.up {
		return nil
	}
	n.gen++
	n.up = true
	n.sessions = append(n.sessions, span{s.now, never})
	n.msgFree, n.ctlFree, n.cpuFree = s.now, s.now, s.now
	if n.act != nil {
		gen := n.gen
		s.after(time.Duration(s.rnd.Int64N(int64(time.Second))), func() { s.actorTick(n, gen) })
		return nil
	}
	rnd := rand.New(rand.NewPCG(s.o.Seed, uint64(n.Index)<<16|uint64(n.gen)))
	r, err := core.New(s.time(), n.ID, n.cfg, rnd, &verifier{s: s, n: n}, n)
	if err != nil {
		return err
	}
	n.r = r
	s.scheduleTick(n)
	return nil
}

// Join makes a running node join its topics.
func (s *Sim) Join(n *Node) error {
	if !n.up || n.r == nil {
		return nil
	}
	for t := range n.rooms {
		if !n.rooms[t] {
			continue
		}
		if err := n.r.Join(s.time(), TopicID(t), n.tc); err != nil {
			return err
		}
	}
	s.sessions(n).from = s.now
	return nil
}

func (s *Sim) sessions(n *Node) *span { return &n.sessions[len(n.sessions)-1] }

// Connect opens a connection that a dials to b. It returns false when either side is down, already linked or
// over its budget.
func (s *Sim) Connect(a, b *Node) bool {
	if a == b || !a.up || !b.up || a.byPeer[b.Index] != nil || b.byPeer[a.Index] != nil {
		return false
	}
	s.nextID++
	l := &link{id: s.nextID, a: a.Index, b: b.Index, closedAt: never}
	// The link exists before AddPeer, which announces the subscriptions through it.
	a.links, b.links = append(a.links, l), append(b.links, l)
	a.byPeer[b.Index], b.byPeer[a.Index] = l, l
	b.inbound++
	undo := func() {
		l.closedAt = s.now
		for _, n := range []*Node{a, b} {
			delete(n.byPeer, l.other(n.Index))
			n.links = slices.DeleteFunc(n.links, func(x *link) bool { return x == l })
		}
		b.inbound--
	}
	if a.r != nil {
		if err := a.r.AddPeer(s.time(), b.ID, true, netip.AddrPortFrom(b.IP, simPort)); err != nil {
			undo()
			return false
		}
	}
	if b.r != nil {
		if err := b.r.AddPeer(s.time(), a.ID, false, netip.AddrPortFrom(a.IP, simPort)); err != nil {
			if a.r != nil {
				a.r.RemovePeer(s.time(), b.ID)
			}
			undo()
			return false
		}
	}
	s.m.connects++
	if a.act != nil {
		s.actorConnect(a, b.Index)
	}
	if b.act != nil {
		s.actorConnect(b, a.Index)
	}
	return true
}

// Free reports how many more connections an honest node may take: total and inbound.
func (n *Node) Free(o *Options) (total, inbound int) {
	return o.MaxPeers - len(n.links), o.MaxInbound - n.inbound
}

// unlink forgets a connection at node n and tells its router.
func (s *Sim) unlink(n *Node, l *link) {
	if n.byPeer[l.other(n.Index)] != l {
		return
	}
	delete(n.byPeer, l.other(n.Index))
	n.links = slices.DeleteFunc(n.links, func(x *link) bool { return x == l })
	if l.b == n.Index {
		n.inbound--
	}
	if n.up && n.r != nil {
		n.r.RemovePeer(s.time(), s.nodes[l.other(n.Index)].ID)
	}
}

// Close ends a connection: frames not yet sent are lost, the closing side forgets it now, the other side when
// the close reaches it (graceful) or after IdleTimeout (crash or cut path).
func (s *Sim) close(l *link, closer *Node, graceful bool) {
	if l.closedAt != never {
		return
	}
	l.closedAt = s.now
	other := s.nodes[l.other(closer.Index)]
	s.unlink(closer, l)
	d := s.o.IdleTimeout
	if graceful {
		d = s.latency(closer.Index, other.Index)
	}
	s.push(event{at: s.now + int64(d), kind: evRemove, a: other.Index, gen: other.gen, l: l})
}

// Stop takes a node down. A graceful stop closes every connection at once; a crash leaves the peers to notice
// after IdleTimeout.
func (s *Sim) Stop(n *Node, graceful bool) {
	if !n.up {
		return
	}
	for _, l := range slices.Clone(n.links) {
		s.close(l, n, graceful)
	}
	n.up = false
	n.r = nil
	s.sessions(n).to = s.now
}

// At runs fn at virtual time t; times in the past run now.
func (s *Sim) At(t time.Duration, fn func()) {
	s.push(event{at: max(int64(t), s.now), kind: evFunc, fn: fn})
}

func (s *Sim) after(d time.Duration, fn func()) { s.At(time.Duration(s.now)+d, fn) }

// Partition cuts the network into two sides from now: frames between sides are lost, and connections between
// them close after IdleTimeout. side(n) chooses a node's side.
func (s *Sim) Partition(side func(*Node) int8) {
	s.side = make([]int8, len(s.nodes))
	for i, n := range s.nodes {
		s.side[i] = side(n)
	}
	s.after(s.o.IdleTimeout, func() {
		if s.side == nil {
			return
		}
		for _, n := range s.nodes {
			for _, l := range slices.Clone(n.links) {
				if l.a == n.Index && s.cut(l.a, l.b) {
					s.cutLinks = append(s.cutLinks, l)
					s.closeBoth(l)
				}
			}
		}
	})
}

// closeBoth closes a connection that both sides lost at the same time.
func (s *Sim) closeBoth(l *link) {
	if l.closedAt != never {
		return
	}
	l.closedAt = s.now
	s.unlink(s.nodes[l.a], l)
	s.unlink(s.nodes[l.b], l)
}

// Heal makes the network whole and reopens the connections the partition closed between running nodes; it
// returns how many it reopened.
func (s *Sim) Heal() int {
	s.side = nil
	n := 0
	for _, l := range s.cutLinks {
		if s.Connect(s.nodes[l.a], s.nodes[l.b]) {
			n++
		}
	}
	s.cutLinks = nil
	return n
}

func (s *Sim) cut(a, b int32) bool {
	return s.side != nil && int(a) < len(s.side) && int(b) < len(s.side) && s.side[a] != s.side[b]
}

func (s *Sim) latency(a, b int32) time.Duration {
	na, nb := s.nodes[a], s.nodes[b]
	d := math.Hypot(na.x-nb.x, na.y-nb.y)
	return s.o.LatencyBase + time.Duration(d*float64(s.o.LatencyScale))
}

// delay is the latency plus one retransmission per loss: 9/8 of the round trip (RFC 9002 time threshold).
func (s *Sim) delay(a, b int32) int64 {
	lat := s.latency(a, b)
	d := int64(lat)
	for s.o.Loss > 0 && s.rnd.Float64() < s.o.Loss {
		d += int64(lat) * 2 * 9 / 8
	}
	return d
}

func (s *Sim) txTime(size int) int64 {
	if s.o.Uplink <= 0 {
		return 0
	}
	return int64(float64(size*8) / s.o.Uplink * 1e9)
}

// send puts a frame on n's uplink to peer to. Control frames have their own lane, so they never wait behind a
// large message, which travels on its own stream.
func (s *Sim) send(n *Node, to int32, raw []byte, c *wire.Control) bool {
	l := n.byPeer[to]
	if l == nil || l.closedAt != never {
		return true
	}
	size := len(raw)
	if c != nil {
		size = c.Size()
	}
	size += wire.UvarintLen(uint64(size))
	q := l.queue(n.Index)
	if !q.room(s.now, size, s.o.PeerQueue, s.o.PeerQueueBytes) && n.r != nil {
		s.m.queueFull++
		return false
	}
	free := &n.msgFree
	kind := evMessage
	if c != nil {
		free, kind = &n.ctlFree, evControl
	}
	start := max(s.now, *free)
	fin := start + s.txTime(size)
	*free = fin
	q.add(fin, size)
	s.push(event{at: fin + s.delay(n.Index, to), kind: kind, a: n.Index, b: to, tx: fin, l: l, raw: raw, c: c})
	if n.Role == Honest {
		s.m.sent(c, size)
		if r := s.nodes[to].Role; r != Honest && c == nil {
			s.m.toAttacker[r]++
		}
	}
	return true
}

func (s *Sim) push(e event) {
	s.seq++
	e.seq = s.seq
	s.q = append(s.q, e)
	i := len(s.q) - 1
	for i > 0 {
		p := (i - 1) / 2
		if !less(&s.q[i], &s.q[p]) {
			break
		}
		s.q[i], s.q[p] = s.q[p], s.q[i]
		i = p
	}
}

func less(a, b *event) bool {
	return a.at < b.at || (a.at == b.at && a.seq < b.seq)
}

func (s *Sim) pop() event {
	e := s.q[0]
	last := len(s.q) - 1
	s.q[0] = s.q[last]
	s.q[last] = event{}
	s.q = s.q[:last]
	i := 0
	for {
		l, r, m := 2*i+1, 2*i+2, i
		if l < last && less(&s.q[l], &s.q[m]) {
			m = l
		}
		if r < last && less(&s.q[r], &s.q[m]) {
			m = r
		}
		if m == i {
			return e
		}
		s.q[i], s.q[m] = s.q[m], s.q[i]
		i = m
	}
}

// Run processes events until virtual time until; events at until run too.
func (s *Sim) Run(until time.Duration) error {
	for len(s.q) > 0 && s.q[0].at <= int64(until) {
		e := s.pop()
		s.now = e.at
		s.events++
		s.mix(uint64(e.at), uint64(e.kind), uint64(uint32(e.a))<<32|uint64(uint32(e.b)), uint64(len(e.raw)))
		if err := s.handle(&e); err != nil {
			return err
		}
		if s.err != nil {
			return s.err
		}
		if s.events%(1<<20) == 0 && heapLimit > 0 {
			if live := liveHeap(); live > heapLimit {
				return fmt.Errorf("%w: %d bytes live at %v", ErrHeapLimit, live, time.Duration(s.now))
			}
		}
	}
	s.now = max(s.now, int64(until))
	return nil
}

func (s *Sim) handle(e *event) error {
	switch e.kind {
	case evFunc:
		e.fn()
	case evTick:
		n := s.nodes[e.a]
		if !n.up || n.gen != e.gen || n.r == nil {
			return nil
		}
		n.r.Tick(s.time())
		s.scheduleTick(n)
	case evValidate:
		n := s.nodes[e.a]
		if !n.up || n.gen != e.gen || n.r == nil {
			return nil
		}
		m := s.msgs[e.n]
		v := core.Accept
		if m.kind == kindRejected {
			v = core.Reject
		}
		n.r.ValidationDone(s.time(), m.id, uint64(e.tx), v)
	case evRemove:
		n := s.nodes[e.a]
		if n.gen == e.gen {
			s.unlink(n, e.l)
		}
	case evMessage, evControl:
		return s.arrive(e)
	}
	return nil
}

func (s *Sim) arrive(e *event) error {
	to := s.nodes[e.b]
	if !to.up || to.byPeer[e.a] != e.l || e.tx > e.l.closedAt || s.cut(e.a, e.b) {
		s.m.lost++
		return nil
	}
	if to.act != nil {
		if e.kind == evMessage {
			s.actorMessage(to, e.a, e.raw)
		} else {
			s.actorControl(to, e.a, e.c)
		}
		return nil
	}
	if s.o.Work {
		h := &e.l.held[b2i(e.b == e.l.b)]
		if len(h.q) > 0 {
			h.q = append(h.q, *e)
			return nil
		}
		if w := to.r.Wait(s.time(), s.nodes[e.a].ID); w > 0 {
			s.m.waited(s, to, s.nodes[e.a], w)
			h.q = append(h.q, *e)
			gen := to.gen
			s.after(w, func() { s.drain(e.l, h, to, gen) })
			return nil
		}
	}
	return s.deliver(e)
}

// drain delivers the frames held for to, as the driver reads them once the receiver's buckets are positive.
func (s *Sim) drain(l *link, h *heldFrames, to *Node, gen uint32) {
	for len(h.q) > 0 {
		e := h.q[0]
		if !to.up || to.gen != gen || to.byPeer[e.a] != l || e.tx > l.closedAt || s.cut(e.a, e.b) {
			s.m.lost++
			h.q = h.q[1:]
			continue
		}
		if w := to.r.Wait(s.time(), s.nodes[e.a].ID); w > 0 {
			s.after(w, func() { s.drain(l, h, to, gen) })
			return
		}
		h.q = h.q[1:]
		if err := s.deliver(&e); err != nil && s.err == nil {
			s.err = err
		}
	}
	h.q = nil
}

func (s *Sim) deliver(e *event) error {
	to := s.nodes[e.b]
	from := s.nodes[e.a].ID
	if e.kind == evMessage {
		if to.Role == Honest {
			s.m.copy(s, e.raw)
		}
		to.r.Message(s.time(), from, e.raw)
		return nil
	}
	if err := to.r.Control(s.time(), from, e.c); err != nil {
		if to.Role == Honest && s.nodes[e.a].Role == Honest {
			return fmt.Errorf("sim: honest node %d refused a frame of honest node %d: %w", e.b, e.a, err)
		}
		s.close(e.l, to, true)
	}
	return nil
}

func (s *Sim) scheduleTick(n *Node) {
	s.push(event{at: int64(n.r.NextTick().Sub(Epoch)), kind: evTick, a: n.Index, gen: n.gen})
}

// SendControl implements core.Sink; silent and censoring attackers drop IHAVE they do not want to send.
func (n *Node) SendControl(to core.PeerID, c *wire.Control, urgent bool) bool {
	if len(c.IHave) > 0 && n.Role != Honest {
		if n.silent() {
			cc := *c
			cc.IHave = nil
			if cc.Empty() {
				return true
			}
			c = &cc
		} else if n.censored != nil {
			c = n.censorIHave(c)
		}
	}
	return n.s.send(n, peerIndex(to), nil, c)
}

func (n *Node) censorIHave(c *wire.Control) *wire.Control {
	cc := *c
	cc.IHave = nil
	for _, h := range c.IHave {
		var ids []wire.ID
		for _, id := range h.IDs {
			if i, ok := n.s.byID[id]; !ok || !n.censored(n.s.msgs[i].author) {
				ids = append(ids, id)
			}
		}
		if len(ids) > 0 {
			cc.IHave = append(cc.IHave, wire.IHave{Topic: h.Topic, IDs: ids})
		}
	}
	return &cc
}

func (n *Node) silent() bool {
	return n.Role == Silent || (n.Role == Flash && n.s.now >= n.FlashAt)
}

// SendMessage implements core.Sink.
func (n *Node) SendMessage(to core.PeerID, raw []byte) bool {
	if n.Role != Honest {
		if n.silent() {
			return true
		}
		if n.censored != nil {
			if i, ok := n.s.msgIndex(raw); ok && n.censored(n.s.msgs[i].author) {
				return true
			}
		}
	}
	return n.s.send(n, peerIndex(to), raw, nil)
}

// Validate implements core.Sink: the verdict comes back once the node's virtual CPU is free.
func (n *Node) Validate(id wire.ID, v uint64, env *wire.Envelope, from core.PeerID) {
	s := n.s
	i, ok := s.byID[id]
	if !ok {
		return
	}
	n.cpuFree = max(n.cpuFree, s.now) + int64(s.o.ValidateCost)
	s.push(event{at: n.cpuFree, kind: evValidate, a: n.Index, gen: n.gen, n: i, tx: int64(v)})
}

// Cancel implements core.Sink: the virtual validator runs to its verdict, which the router then ignores.
func (n *Node) Cancel(uint64) {}

// Dial implements core.Sink: the simulator models no peer exchange, which is off by default.
func (n *Node) Dial(wire.Topic, core.PeerID, []wire.PeerRecord) int { return 0 }

// Deliver implements core.Sink.
func (n *Node) Deliver(id wire.ID, env *wire.Envelope, from core.PeerID) {
	if i, ok := n.s.byID[id]; ok {
		n.s.m.deliver(n.s, n, i, peerIndex(from))
	}
}

var (
	errPerson  = errors.New("sim: device is not a device of the person")
	errRevoked = errors.New("sim: revoked device")
)

// verifier is the cost-model fake: it charges VerifyCost of virtual CPU and checks a hash in place of the
// signature, the roster's person of each device and its revocation list.
type verifier struct {
	s *Sim
	n *Node
}

// Signed implements core.Verifier; it charges the whole VerifyCost of a message, as the author check reuses the
// chain checked within the same second.
func (v *verifier) Signed(env *wire.Envelope, signed []byte) bool {
	s, n := v.s, v.n
	n.cpuFree = max(n.cpuFree, s.now) + int64(s.o.VerifyCost)
	s.m.verifies++
	return [32]byte(env.Sig[:32]) == fakeSig(signed)
}

// Verify implements core.Verifier.
func (v *verifier) Verify(env *wire.Envelope, signed []byte) error {
	s := v.s
	dev := peerIndex(core.PeerID(env.Device))
	if dev < 0 || int(dev) >= len(s.nodes) || s.nodes[dev].ID != core.PeerID(env.Device) {
		return errPerson
	}
	if personKey(dev) != env.Person {
		return errPerson
	}
	if s.nodes[dev].Role == Revoked {
		return errRevoked
	}
	return nil
}

// Work implements core.Verifier: the model's author check does nothing the router charges.
func (v *verifier) Work() core.Ops { return core.Ops{} }

func fakeSig(signed []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte("kolo-gossip/sim-signature"))
	h.Write(signed)
	var out [32]byte
	h.Sum(out[:0])
	return out
}

const (
	kindHonest = iota
	kindRejected
	kindForged
)

// msgRec is one message the simulator created.
type msgRec struct {
	id     wire.ID
	raw    []byte
	author int32
	kind   int
	pub    int64
	at     []int32 // delivery delay per node in microseconds, -1 when not delivered
	hop    []uint8
	copies int
	body   int
	honest bool // published by an honest node: counted in delivery metrics
	topic  int
}

// envelope builds a signed envelope in topic 0; sign false leaves a bad signature.
func (s *Sim) envelope(device int32, person wire.Key, size int, sign bool) (*msgRec, []byte) {
	return s.envelopeIn(0, device, person, size, sign)
}

func (s *Sim) envelopeIn(topic int, device int32, person wire.Key, size int, sign bool) (*msgRec, []byte) {
	i := int32(len(s.msgs))
	body := s.bodies[size]
	if body == nil {
		body = make([]byte, size)
		s.bodies[size] = body
	}
	e := &wire.Envelope{Topic: TopicID(topic), Person: person, Device: wire.Key(peerKey(device)), Seq: uint64(i),
		Time: uint64(s.time().UnixMilli()), Body: body}
	if sign {
		e.Sig = [64]byte(append(fakeSigSlice(e.Signed()), make([]byte, 32)...))
	} else {
		e.Sig[0] = 1
	}
	raw := e.Encode()
	m := &msgRec{id: wire.NewID(raw), raw: raw, author: device, pub: s.now, body: size, topic: topic}
	s.msgs = append(s.msgs, m)
	s.byID[m.id] = i
	return m, raw
}

func fakeSigSlice(signed []byte) []byte {
	h := fakeSig(signed)
	return h[:]
}

// msgIndex reads the message index the simulator stored as the envelope sequence number.
func (s *Sim) msgIndex(raw []byte) (int32, bool) {
	const off = 1 + 3*wire.KeySize
	if len(raw) <= off {
		return 0, false
	}
	v, k := binary.Uvarint(raw[off:])
	if k <= 0 || v >= uint64(len(s.msgs)) {
		return 0, false
	}
	return int32(v), true
}

// Publish makes an honest node publish a message of size body bytes in topic 0 and returns its index.
func (s *Sim) Publish(n *Node, size int) (int32, error) { return s.PublishIn(n, size, 0) }

// PublishIn is Publish in topic t.
func (s *Sim) PublishIn(n *Node, size, t int) (int32, error) {
	if !n.up || n.r == nil {
		return -1, nil
	}
	m, raw := s.envelopeIn(t, n.Index, personKey(n.Index), size, true)
	m.honest = n.Role == Honest
	if m.honest {
		m.at = make([]int32, len(s.nodes))
		m.hop = make([]uint8, len(s.nodes))
		for i := range m.at {
			m.at[i] = -1
		}
		m.at[n.Index] = 0
	}
	if _, err := n.r.Publish(s.time(), raw); err != nil {
		return -1, fmt.Errorf("sim: node %d publish: %w", n.Index, err)
	}
	return int32(len(s.msgs) - 1), nil
}

func netipFrom(a, b, c, d byte) netip.Addr { return netip.AddrFrom4([4]byte{a, b, c, d}) }
