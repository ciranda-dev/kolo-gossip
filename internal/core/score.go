package core

import (
	"bytes"
	"container/heap"
	"math/bits"
	"net/netip"
	"slices"
	"time"

	"github.com/ciranda-dev/kolo-gossip/internal/wire"
)

// Thresholds are the score thresholds of GossipSub v1.1; a peer below one loses what it gates.
type Thresholds struct {
	Gossip             float64 // below: no IHAVE or IWANT to or from the peer; must be < 0
	Publish            float64 // below: no flood publishing to the peer; must be <= Gossip
	Graylist           float64 // below: every frame from the peer is dropped; must be < Publish
	OpportunisticGraft float64 // a mesh median below it grafts better peers; must be >= 0
	AcceptPX           float64 // at or above: the peer exchange of a PRUNE is dialed; 0 dials none; must be >= 0
}

// ScoreParams are the score parameters that apply to every peer; the values are the caller's.
type ScoreParams struct {
	Thresholds                Thresholds
	TopicScoreCap             float64              // 0: no cap
	AppScore                  func(PeerID) float64 // P5; nil scores 0
	AppWeight                 float64
	IPColocationWeight        float64 // P6, <= 0
	IPColocationThreshold     int     // peers on one IPv4 address before P6 applies
	BehaviourPenaltyWeight    float64 // P7, <= 0
	BehaviourPenaltyThreshold float64
	BehaviourPenaltyDecay     float64
	DecayInterval             time.Duration
	DecayToZero               float64
	RetainScore               time.Duration // how long a disconnected peer's score is kept
}

// TopicScoreParams are the score parameters of one topic (P1 to P4).
type TopicScoreParams struct {
	TopicWeight float64

	TimeInMeshWeight  float64
	TimeInMeshQuantum time.Duration
	TimeInMeshCap     float64

	FirstMessageDeliveriesWeight float64
	FirstMessageDeliveriesDecay  float64
	FirstMessageDeliveriesCap    float64

	MeshMessageDeliveriesWeight     float64
	MeshMessageDeliveriesDecay      float64
	MeshMessageDeliveriesCap        float64
	MeshMessageDeliveriesThreshold  float64
	MeshMessageDeliveriesWindow     time.Duration
	MeshMessageDeliveriesActivation time.Duration

	MeshFailurePenaltyWeight float64
	MeshFailurePenaltyDecay  float64

	InvalidMessageDeliveriesWeight float64
	InvalidMessageDeliveriesDecay  float64
}

func (s *ScoreParams) validate() error {
	t := &s.Thresholds
	switch {
	case !finite(t.Gossip, t.Publish, t.Graylist, t.OpportunisticGraft, t.AcceptPX, s.TopicScoreCap, s.AppWeight,
		s.IPColocationWeight, s.BehaviourPenaltyWeight, s.BehaviourPenaltyThreshold, s.BehaviourPenaltyDecay,
		s.DecayToZero):
		return invalid("score parameters must be finite")
	case !(t.Gossip < 0 && t.Publish <= t.Gossip && t.Graylist < t.Publish):
		return invalid("need Graylist < Publish <= Gossip < 0")
	case t.OpportunisticGraft < 0 || t.AcceptPX < 0:
		return invalid("OpportunisticGraft and AcceptPX thresholds must be >= 0")
	case s.TopicScoreCap < 0 || s.AppWeight < 0:
		return invalid("TopicScoreCap and AppWeight must be >= 0")
	case s.IPColocationWeight > 0 || (s.IPColocationWeight != 0 && s.IPColocationThreshold < 1):
		return invalid("need IPColocationWeight <= 0 and a threshold of at least 1")
	case s.BehaviourPenaltyWeight > 0 || s.BehaviourPenaltyThreshold < 0 ||
		(s.BehaviourPenaltyWeight != 0 && !decay(s.BehaviourPenaltyDecay)):
		return invalid("need BehaviourPenaltyWeight <= 0, threshold >= 0 and a decay in (0, 1)")
	case s.DecayInterval < time.Second:
		return invalid("DecayInterval under 1s")
	case !decay(s.DecayToZero):
		return invalid("DecayToZero outside (0, 1)")
	case s.RetainScore < 0:
		return invalid("negative RetainScore")
	}
	return nil
}

func (p *TopicScoreParams) validate() error {
	switch {
	case !finite(p.TopicWeight, p.TimeInMeshWeight, p.TimeInMeshCap, p.FirstMessageDeliveriesWeight,
		p.FirstMessageDeliveriesDecay, p.FirstMessageDeliveriesCap, p.MeshMessageDeliveriesWeight,
		p.MeshMessageDeliveriesDecay, p.MeshMessageDeliveriesCap, p.MeshMessageDeliveriesThreshold,
		p.MeshFailurePenaltyWeight, p.MeshFailurePenaltyDecay, p.InvalidMessageDeliveriesWeight,
		p.InvalidMessageDeliveriesDecay):
		return invalid("topic score parameters must be finite")
	case p.TopicWeight < 0:
		return invalid("negative TopicWeight")
	case p.TimeInMeshWeight < 0 || (p.TimeInMeshWeight != 0 && (p.TimeInMeshQuantum <= 0 || p.TimeInMeshCap <= 0)):
		return invalid("need TimeInMeshWeight >= 0 with a positive quantum and cap")
	case p.FirstMessageDeliveriesWeight < 0 || (p.FirstMessageDeliveriesWeight != 0 &&
		(!decay(p.FirstMessageDeliveriesDecay) || p.FirstMessageDeliveriesCap <= 0)):
		return invalid("need FirstMessageDeliveriesWeight >= 0 with a decay in (0, 1) and a positive cap")
	case p.MeshMessageDeliveriesWeight > 0 || p.MeshMessageDeliveriesWindow < 0 || (p.MeshMessageDeliveriesWeight != 0 &&
		(!decay(p.MeshMessageDeliveriesDecay) || p.MeshMessageDeliveriesThreshold <= 0 ||
			p.MeshMessageDeliveriesCap < p.MeshMessageDeliveriesThreshold ||
			p.MeshMessageDeliveriesActivation < time.Second)):
		return invalid("need MeshMessageDeliveriesWeight <= 0 with a decay in (0, 1), threshold > 0, cap >= threshold and activation >= 1s")
	case p.MeshFailurePenaltyWeight > 0 || (p.MeshFailurePenaltyWeight != 0 && !decay(p.MeshFailurePenaltyDecay)):
		return invalid("need MeshFailurePenaltyWeight <= 0 with a decay in (0, 1)")
	case p.InvalidMessageDeliveriesWeight > 0 || !decay(p.InvalidMessageDeliveriesDecay):
		return invalid("need InvalidMessageDeliveriesWeight <= 0 with a decay in (0, 1)")
	}
	return nil
}

func decay(v float64) bool {
	return v > 0 && v < 1
}

type peerStats struct {
	connected        bool
	ret              *retained  // set while the peer is disconnected and its score kept
	ip               netip.Addr // counted for P6 when valid
	topics           []*topicStats
	behaviourPenalty float64
}

type topicStats struct {
	topic                    wire.Topic
	inMesh                   bool
	graftTime                time.Time
	meshTime                 time.Duration
	firstMessageDeliveries   float64
	meshMessageDeliveries    float64
	meshActive               bool
	meshFailurePenalty       float64
	invalidMessageDeliveries float64
}

// scorer is the peer score engine of GossipSub v1.1; it is nil when scoring is off.
type scorer struct {
	p        *ScoreParams
	params   func(wire.Topic) *TopicScoreParams
	stats    map[PeerID]*peerStats
	retained retainedHeap // disconnected peers, the highest score at its disconnect on top
	ips      map[netip.Addr]int
	app      map[PeerID]float64   // AppScore results of this heartbeat
	elapsed  func() time.Duration // the monotonic clock that times AppScore, nil to charge it a flat cost
	spent    time.Duration        // AppScore time not charged yet
}

func newScorer(p *ScoreParams, params func(wire.Topic) *TopicScoreParams) *scorer {
	return &scorer{p: p, params: params, stats: map[PeerID]*peerStats{}, ips: map[netip.Addr]int{}}
}

// work returns the lookups score(p) does and whether it calls the application's score.
func (s *scorer) work(p PeerID) (lookups int, callback bool) {
	if s == nil {
		return 1, false
	}
	ps := s.stats[p]
	if ps == nil {
		return 1, false
	}
	_, cached := s.app[p]
	return 4 + 2*len(ps.topics), s.p.AppScore != nil && !cached
}

// score computes Score(p) = TopicCap(sum_t w_t (w1 P1 + w2 P2 + w3 P3 + w3b P3b + w4 P4)) + w5 P5 + w6 P6 + w7 P7.
func (s *scorer) score(p PeerID) float64 {
	if s == nil {
		return 0
	}
	ps := s.stats[p]
	if ps == nil {
		return 0
	}
	var score float64
	for _, ts := range ps.topics {
		tp := s.params(ts.topic)
		if tp == nil {
			continue
		}
		var topic float64
		if ts.inMesh && tp.TimeInMeshWeight != 0 {
			p1 := min(float64(ts.meshTime/tp.TimeInMeshQuantum), tp.TimeInMeshCap)
			topic += p1 * tp.TimeInMeshWeight
		}
		topic += ts.firstMessageDeliveries * tp.FirstMessageDeliveriesWeight
		// P3 is for mesh peers only; P3b remembers the deficit of a pruned one.
		if ts.inMesh && ts.meshActive && ts.meshMessageDeliveries < tp.MeshMessageDeliveriesThreshold {
			deficit := tp.MeshMessageDeliveriesThreshold - ts.meshMessageDeliveries
			topic += deficit * deficit * tp.MeshMessageDeliveriesWeight
		}
		topic += ts.meshFailurePenalty * tp.MeshFailurePenaltyWeight
		topic += ts.invalidMessageDeliveries * ts.invalidMessageDeliveries * tp.InvalidMessageDeliveriesWeight
		score += topic * tp.TopicWeight
	}
	if s.p.TopicScoreCap > 0 && score > s.p.TopicScoreCap {
		score = s.p.TopicScoreCap
	}
	if s.p.AppScore != nil {
		// The application's score runs once per peer per heartbeat: it is application code under the router lock.
		v, ok := s.app[p]
		if !ok {
			var start time.Duration
			if s.elapsed != nil {
				start = s.elapsed()
			}
			v = s.p.AppScore(p)
			if s.elapsed != nil {
				s.spent += s.elapsed() - start
			}
			if s.app == nil {
				s.app = map[PeerID]float64{}
			}
			s.app[p] = v
		}
		score += v * s.p.AppWeight
	}
	score += s.colocation(ps) * s.p.IPColocationWeight
	if ps.behaviourPenalty > s.p.BehaviourPenaltyThreshold {
		excess := ps.behaviourPenalty - s.p.BehaviourPenaltyThreshold
		score += excess * excess * s.p.BehaviourPenaltyWeight
	}
	return score
}

func (s *scorer) colocation(ps *peerStats) float64 {
	if !ps.ip.IsValid() {
		return 0
	}
	if n := s.ips[ps.ip]; n > s.p.IPColocationThreshold {
		surplus := float64(n - s.p.IPColocationThreshold)
		return surplus * surplus
	}
	return 0
}

// connect starts or resumes a peer's stats; loopback addresses are not counted for P6. It returns the lookups it
// did.
func (s *scorer) connect(p PeerID, ip netip.Addr) int {
	if s == nil {
		return 1
	}
	n := 2
	ps := s.stats[p]
	if ps == nil {
		ps = &peerStats{}
		s.stats[p] = ps
	} else {
		if ps.ret != nil {
			n += 2 * bits.Len(uint(len(s.retained)))
			heap.Remove(&s.retained, ps.ret.at)
			ps.ret = nil
		}
		s.setIP(ps, netip.Addr{})
	}
	ps.connected = true
	if !ip.IsLoopback() {
		s.setIP(ps, ip)
	}
	return n
}

func (s *scorer) setIP(ps *peerStats, ip netip.Addr) {
	if ps.ip.IsValid() {
		if s.ips[ps.ip]--; s.ips[ps.ip] <= 0 {
			delete(s.ips, ps.ip)
		}
	}
	ps.ip = ip
	if ip.IsValid() {
		s.ips[ip]++
	}
}

// disconnect keeps a peer's score for RetainScore, so leaving and coming back does not reset a penalty. Past
// maxRetained the highest-scored retained peer is dropped: penalties matter more than credit. It returns the
// lookups it did and whether it called the application's score.
func (s *scorer) disconnect(now time.Time, p PeerID, maxRetained int) (int, bool) {
	if s == nil {
		return 1, false
	}
	ps := s.stats[p]
	if ps == nil {
		return 1, false
	}
	n := 2 + len(ps.topics)
	for _, ts := range ps.topics {
		ts.firstMessageDeliveries = 0
		if ts.inMesh {
			s.meshFailure(ts)
		}
		ts.inMesh = false
	}
	if s.p.RetainScore == 0 {
		s.forget(p)
		return n, false
	}
	w, app := s.work(p)
	n += w + 2*bits.Len(uint(len(s.retained)+1))
	ps.ret = &retained{id: p, snap: s.score(p), expire: now.Add(s.p.RetainScore)}
	ps.connected = false
	heap.Push(&s.retained, ps.ret)
	if len(s.retained) > maxRetained {
		s.forget(s.retained[0].id)
		n += 2 * bits.Len(uint(len(s.retained)))
	}
	return n, app
}

// retained is a disconnected peer whose score is kept until expire; snap is its score when it disconnected.
type retained struct {
	id     PeerID
	snap   float64
	expire time.Time
	at     int // its index in the heap
}

// retainedHeap orders retained peers by their score at disconnect, highest first, then by earlier expiry, then by
// lower key, so the choice never depends on map order.
type retainedHeap []*retained

func (h retainedHeap) Len() int { return len(h) }

func (h retainedHeap) Less(i, j int) bool {
	a, b := h[i], h[j]
	switch {
	case a.snap != b.snap:
		return a.snap > b.snap
	case !a.expire.Equal(b.expire):
		return a.expire.Before(b.expire)
	}
	return bytes.Compare(a.id[:], b.id[:]) < 0
}

func (h retainedHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].at, h[j].at = i, j
}

func (h *retainedHeap) Push(x any) {
	e := x.(*retained)
	e.at = len(*h)
	*h = append(*h, e)
}

func (h *retainedHeap) Pop() any {
	old := *h
	e := old[len(old)-1]
	old[len(old)-1] = nil
	*h = old[:len(old)-1]
	return e
}

func (s *scorer) forget(p PeerID) {
	ps := s.stats[p]
	if ps == nil {
		return
	}
	s.setIP(ps, netip.Addr{})
	if ps.ret != nil {
		heap.Remove(&s.retained, ps.ret.at)
	}
	delete(s.stats, p)
}

func (s *scorer) topicStats(p PeerID, t wire.Topic) *topicStats {
	ps := s.stats[p]
	if ps == nil || s.params(t) == nil {
		return nil
	}
	i, ok := slices.BinarySearchFunc(ps.topics, t, func(ts *topicStats, t wire.Topic) int {
		return bytes.Compare(ts.topic[:], t[:])
	})
	if !ok {
		ps.topics = slices.Insert(ps.topics, i, &topicStats{topic: t})
	}
	return ps.topics[i]
}

func (s *scorer) dropTopic(t wire.Topic) {
	if s == nil {
		return
	}
	for _, ps := range s.stats {
		ps.topics = slices.DeleteFunc(ps.topics, func(ts *topicStats) bool { return ts.topic == t })
	}
}

func (s *scorer) graft(now time.Time, p PeerID, t wire.Topic) {
	if s == nil {
		return
	}
	if ts := s.topicStats(p, t); ts != nil {
		ts.inMesh = true
		ts.graftTime = now
		ts.meshTime = 0
		ts.meshActive = false
	}
}

func (s *scorer) prune(p PeerID, t wire.Topic) {
	if s == nil {
		return
	}
	if ts := s.topicStats(p, t); ts != nil {
		s.meshFailure(ts)
		ts.inMesh = false
	}
}

// meshFailure adds the sticky P3b penalty: the squared delivery deficit at the time a mesh link ends.
func (s *scorer) meshFailure(ts *topicStats) {
	tp := s.params(ts.topic)
	if tp != nil && ts.meshActive && ts.meshMessageDeliveries < tp.MeshMessageDeliveriesThreshold {
		deficit := tp.MeshMessageDeliveriesThreshold - ts.meshMessageDeliveries
		ts.meshFailurePenalty += deficit * deficit
	}
}

func (s *scorer) penalty(p PeerID, n int) {
	if s == nil {
		return
	}
	if ps := s.stats[p]; ps != nil {
		ps.behaviourPenalty += float64(n)
	}
}

func (s *scorer) invalid(p PeerID, t wire.Topic) {
	if s == nil {
		return
	}
	if ts := s.topicStats(p, t); ts != nil {
		ts.invalidMessageDeliveries++
	}
}

// firstDelivery credits the peer that delivered a valid message first (P2, and P3 when in the mesh).
func (s *scorer) firstDelivery(p PeerID, t wire.Topic) {
	if s == nil {
		return
	}
	ts := s.topicStats(p, t)
	if ts == nil {
		return
	}
	tp := s.params(t)
	ts.firstMessageDeliveries = min(ts.firstMessageDeliveries+1, tp.FirstMessageDeliveriesCap)
	if ts.inMesh {
		ts.meshMessageDeliveries = min(ts.meshMessageDeliveries+1, tp.MeshMessageDeliveriesCap)
	}
}

// nearFirst credits a mesh peer whose copy came while validating or within MeshMessageDeliveriesWindow after it.
func (s *scorer) nearFirst(now time.Time, p PeerID, t wire.Topic, validated time.Time) {
	if s == nil {
		return
	}
	ts := s.topicStats(p, t)
	if ts == nil || !ts.inMesh {
		return
	}
	tp := s.params(t)
	if !validated.IsZero() && now.Sub(validated) > tp.MeshMessageDeliveriesWindow {
		return
	}
	ts.meshMessageDeliveries = min(ts.meshMessageDeliveries+1, tp.MeshMessageDeliveriesCap)
}

// decay runs once per DecayInterval: counters shrink, mesh time grows, expired retained scores go.
func (s *scorer) decay(now time.Time, connected []*peer) {
	for _, p := range connected {
		ps := s.stats[p.id]
		if ps == nil {
			continue
		}
		for _, ts := range ps.topics {
			tp := s.params(ts.topic)
			if tp == nil {
				continue
			}
			ts.firstMessageDeliveries = s.decayed(ts.firstMessageDeliveries, tp.FirstMessageDeliveriesDecay)
			ts.meshMessageDeliveries = s.decayed(ts.meshMessageDeliveries, tp.MeshMessageDeliveriesDecay)
			ts.meshFailurePenalty = s.decayed(ts.meshFailurePenalty, tp.MeshFailurePenaltyDecay)
			ts.invalidMessageDeliveries = s.decayed(ts.invalidMessageDeliveries, tp.InvalidMessageDeliveriesDecay)
			if ts.inMesh {
				ts.meshTime = now.Sub(ts.graftTime)
				if ts.meshTime > tp.MeshMessageDeliveriesActivation {
					ts.meshActive = true
				}
			}
		}
		ps.behaviourPenalty = s.decayed(ps.behaviourPenalty, s.p.BehaviourPenaltyDecay)
	}
	var expired []PeerID
	for _, e := range s.retained {
		if now.After(e.expire) {
			expired = append(expired, e.id)
		}
	}
	for _, p := range expired {
		s.forget(p)
	}
}

func (s *scorer) decayed(v, factor float64) float64 {
	v *= factor
	if v < s.p.DecayToZero {
		return 0
	}
	return v
}
