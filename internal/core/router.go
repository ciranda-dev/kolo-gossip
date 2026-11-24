// Package core is the deterministic GossipSub v1.1 router of kolo-gossip, with the v1.2 IDONTWANT rule.
// It has no goroutines, clock, randomness of its own or I/O: time comes with each call, randomness through
// Rand and every effect through Sink, so the same inputs always give the same effects.
package core

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/ciranda-dev/kolo-gossip/internal/wire"
)

var (
	// ErrInvalidConfig means a Config, TopicConfig or score parameter set breaks a constraint.
	ErrInvalidConfig = errors.New("kologossip: invalid config")
	// ErrInvalidArgument means a call's argument is not usable, such as a malformed envelope or a non-IPv4 address.
	ErrInvalidArgument = errors.New("kologossip: invalid argument")
	// ErrLimit means a bound is full: MaxPeers or MaxTopics when the application set one, or the seen cache.
	ErrLimit = errors.New("kologossip: limit reached")
	// ErrDuplicate means a published message was already seen.
	ErrDuplicate = errors.New("kologossip: duplicate message")
	// ErrTooLarge means a published envelope is over its topic's MaxMessageSize.
	ErrTooLarge = errors.New("kologossip: message too large")
	// ErrProtocol means a peer broke a protocol rule; the driver closes its connection.
	ErrProtocol = errors.New("kologossip: protocol violation")
)

// PeerID is a peer's kolo-id public key, proved by the secure channel.
type PeerID [32]byte

// Rand is the router's source of randomness; *math/rand/v2.Rand satisfies it.
type Rand interface {
	IntN(n int) int
}

// Verifier checks envelopes; signed is the envelope without its signature.
type Verifier interface {
	// Signed reports whether the envelope is signed by its own device key; it must not depend on any state.
	Signed(env *wire.Envelope, signed []byte) bool
	// Verify checks the author of an envelope whose signature passed Signed: nil accepts, ErrUnresolved asks
	// for the chain, and any other error ignores the message without penalty.
	Verify(env *wire.Envelope, signed []byte) error
	// Work returns the operations Verify and the Resolver methods did since the last call, which the router
	// charges to the peer that caused them.
	Work() Ops
}

// Sink receives every effect of a Router call. Its methods must not call back into the Router.
type Sink interface {
	// SendControl queues a control frame; false means the peer's queue is full and the frame was dropped.
	SendControl(to PeerID, c *wire.Control, urgent bool) bool
	// SendMessage queues an encoded envelope; false means the peer's queue is full and it was dropped.
	SendMessage(to PeerID, raw []byte) bool
	// Validate asks the application validator about a message as validation n; the answer must come back through
	// ValidationDone with the same n, also after Cancel.
	Validate(id wire.ID, n uint64, env *wire.Envelope, from PeerID)
	// Cancel tells the validator of validation n that its verdict is no longer needed.
	Cancel(n uint64)
	// Deliver hands a validated message to the application.
	Deliver(id wire.ID, env *wire.Envelope, from PeerID)
	// Dial asks for connections to peer exchange records that from sent for topic t and returns how many it took.
	Dial(t wire.Topic, from PeerID, recs []wire.PeerRecord) int
}

// Verdict is an application validator's answer.
type Verdict int

// The verdicts of GossipSub v1.1 extended validators; the zero Verdict is Ignore.
const (
	Ignore Verdict = iota // drop without penalty
	Accept                // deliver and forward
	Reject                // invalid: P4 for the sender and every peer that sent it while it was validated
	Retry                 // keep the message and validate it again, on Revalidate or after RetryInterval, until SeenTTL
)

// Router is one node's gossip state for all its topics. It is not safe for concurrent use.
type Router struct {
	self  PeerID
	start time.Time // the monotonic origin of bucket times
	cfg   Config
	rnd   Rand
	v     Verifier
	out   Sink
	now   time.Time
	ticks uint64

	nextHeartbeat, nextDecay time.Time

	peers  []*peer // in arrival order, so every iteration is deterministic
	byID   map[PeerID]*peer
	topics map[wire.Topic]*topic

	backoff  backoffs
	seen     seenCache
	skipLong seenCache // ids ignored for their author or content, kept IgnoredTTL
	asks     map[wire.ID]asking
	recs     map[wire.ID]*seenRec
	cache    msgCache
	promises promises
	score    *scorer

	gossipLoad int   // ids and topic headers this heartbeat's IHAVE announce
	meshPlaces int   // mesh places of all peers at the last heartbeat
	delivered  int64 // valid messages mesh peers delivered over the last HistoryLength heartbeats, as of the last heartbeat

	validating, validatingBytes int
	open, openBytes             int               // of those, held for senders outside the message's mesh that we did not ask
	holding                     map[PeerID]holder // messages held per sending peer
	departed                    departed          // messages held for senders that left: one share in all
	// running holds the bytes of validations dropped while their validator still runs, by validation number: they
	// count in the global bounds until ValidationDone.
	running      map[uint64]int
	runningBytes int
	validations  uint64     // the last validation number given
	retrying     []*seenRec // messages the validator answered Retry for, in the order they were held
	gone         gone
	node         node
	audit        *audit // nil unless AuditOps turned it on
	stats        Stats
}

// buckets are a peer's two work budgets: under the router lock and on its reader.
type buckets struct{ lock, out bucket }

// holder is a sender's share of the validation bounds: the messages it has waiting, newest first in a list
// through their pending records, and their bytes.
type holder struct {
	count, bytes int
	head         *seenRec
}

// departed is the share of the senders that left: their waiting messages, oldest first.
type departed struct {
	count, bytes int
	recs         []*seenRec
}

type peer struct {
	id               PeerID
	ip               [4]byte // where it connects from, zero when relayed
	port             uint16  // where it accepts connections, 0 when not known
	outbound         bool
	waiting          bool  // the driver does not read the peer until its buckets are positive
	ihaves, dontwant int32 // IHAVE and IDONTWANT frames this heartbeat
	asked, waits     int32 // ids asked of the peer that have not arrived, and ids it waits to be asked for
	buckets
	released  uint64                  // its promises up to this number end without a penalty
	meshN     int32                   // mesh places it holds, at the last heartbeat
	delivered int64                   // valid messages it delivered in a topic whose mesh held it, over the last HistoryLength heartbeats
	ring      []int32                 // those per heartbeat
	topics    []wire.Topic            // announced subscriptions to topics we hold state for, sorted
	other     []wire.Topic            // announced subscriptions to other topics, sorted, at most MaxPeerTopics
	asking    map[wire.ID]struct{}    // the ids it is asked for or waits to be
	sent      map[wire.ID]uint8       // IWANT answers sent to it, cleared every HistoryLength heartbeats
	unwanted  *unwanted               // nil until the peer sends IDONTWANT, so most peers carry none
	pend      *pending                // nil until something waits
	refused   map[wire.Topic]struct{} // topics whose AllowPeer refused it; nil for most peers
}

// pendings returns p's pending control, allocating it on first use.
func (p *peer) pendings() *pending {
	if p.pend == nil {
		p.pend = &pending{}
	}
	return p.pend
}

type topic struct {
	id         wire.Topic
	joined     bool
	params     Params
	score      *TopicScoreParams
	maxSize    int
	mesh       []PeerID
	fanout     []PeerID
	lastPub    time.Time
	lastGossip []PeerID          // the peers the last heartbeat sent this topic's IHAVE, sorted
	grafted    []PeerID          // the peers that entered the mesh since the last heartbeat's gossip
	allow      func(PeerID) bool // nil admits every peer
}

// refuses reports whether the AllowPeer of t refused p: t is then never announced to it, nor grafted, gossiped or
// sent to it, and its frames about t are ignored as if we had not joined.
func (p *peer) refuses(t wire.Topic) bool {
	_, ok := p.refused[t]
	return ok
}

// judge asks tp's AllowPeer about p and records a refusal; it reports whether p is admitted.
func (r *Router) judge(tp *topic, p *peer) bool {
	delete(p.refused, tp.id)
	if tp.allow == nil || tp.allow(p.id) {
		return true
	}
	if p.refused == nil {
		p.refused = map[wire.Topic]struct{}{}
	}
	p.refused[tp.id] = struct{}{}
	return false
}

// New returns a Router for the node whose key is self, starting at now.
func New(now time.Time, self PeerID, cfg *Config, rnd Rand, v Verifier, out Sink) (*Router, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if rnd == nil || v == nil || out == nil {
		return nil, fmt.Errorf("%w: nil Rand, Verifier or Sink", ErrInvalidArgument)
	}
	r := &Router{
		self:     self,
		cfg:      *cfg,
		rnd:      rnd,
		v:        v,
		out:      out,
		now:      now,
		byID:     map[PeerID]*peer{},
		topics:   map[wire.Topic]*topic{},
		seen:     newSeen(now, cfg.HeartbeatInterval),
		skipLong: newSeen(now, cfg.HeartbeatInterval),
		asks:     map[wire.ID]asking{},
		recs:     map[wire.ID]*seenRec{},
		cache:    newCache(cfg.HistoryLength),
		holding:  map[PeerID]holder{},
		running:  map[uint64]int{},
		start:    now,
		gone:     gone{m: map[PeerID]*peer{}},
	}
	_, _, lockCap, outCap := r.nodeRates()
	r.node.pool.level, r.node.poolOut.level = lockCap, outCap
	r.backoff.m, r.backoff.base = map[wire.Topic]*backoffTable{}, now
	r.promises.open = map[wire.ID][]promised{}
	r.nextHeartbeat = now.Add(cfg.HeartbeatInitialDelay)
	if cfg.Score != nil {
		r.score = newScorer(cfg.Score, r.topicScore)
		r.score.elapsed = cfg.Elapsed
		r.nextDecay = now.Add(cfg.Score.DecayInterval)
	}
	return r, nil
}

func (r *Router) topicScore(t wire.Topic) *TopicScoreParams {
	if tp := r.topics[t]; tp != nil && tp.joined {
		return tp.score
	}
	return nil
}

// advance moves the router's clock, an earlier time counting as the latest seen; at the end of each heartbeat
// interval it expires seen ids and delivery records. A message whose validator has not answered stays charged to
// its sender's share until it does, however long that takes.
func (r *Router) advance(now time.Time) {
	if now.After(r.now) {
		r.now = now
	}
	if r.now.Before(r.seen.until) {
		return
	}
	r.seen.roll(r.now, r.cfg.HeartbeatInterval, r.cfg.SeenTTL)
	r.skipLong.roll(r.now, r.cfg.HeartbeatInterval, r.cfg.IgnoredTTL)
	at := r.mono(r.now)
	for _, rec := range r.recs {
		if rec.expire < at && (rec.pending == nil || rec.pending.resolving || rec.pending.retry) {
			r.forget(rec, nil)
		}
	}
}

// AddPeer starts gossip with a connected peer; addr is its IPv4 address with the port it accepts connections at
// (0 if unknown), or the zero AddrPort when relayed, which leaves it out of the IP colocation score and of peer
// exchange. A positive MaxPeers is the only cap that refuses a peer.
func (r *Router) AddPeer(now time.Time, p PeerID, outbound bool, addr netip.AddrPort) error {
	r.advance(now)
	switch {
	case addr.IsValid() && !addr.Addr().Is4():
		return fmt.Errorf("%w: peer address %v is not IPv4", ErrInvalidArgument, addr.Addr())
	case p == r.self:
		return fmt.Errorf("%w: own key", ErrInvalidArgument)
	case r.byID[p] != nil:
		return fmt.Errorf("%w: peer already added", ErrInvalidArgument)
	case r.cfg.MaxPeers > 0 && len(r.peers) >= r.cfg.MaxPeers:
		return fmt.Errorf("%w: %d peers", ErrLimit, len(r.peers))
	}
	pr := &peer{id: p, outbound: outbound, released: r.promises.seq}
	if addr.Addr().Is4() {
		pr.ip, pr.port = addr.Addr().As4(), addr.Port()
	}
	// A key that left in debt keeps it; what it held besides is not given back. Every key then starts with what
	// the newcomer pool gives, at most one second of a full node's share, so keys never bring work of their own.
	if g := r.gone.take(p); g != nil {
		pr.lock.level, pr.out.level = min(g.lock.level, 0), min(g.out.level, 0)
	}
	r.refillNode()
	lock, out, _, _ := r.nodeRates()
	gl := max(0, min(r.node.pool.level, lock))
	go_ := max(0, min(r.node.poolOut.level, out))
	r.node.pool.level -= gl
	r.node.poolOut.level -= go_
	at := r.mono(r.now)
	pr.lock = bucket{level: pr.lock.level + gl, at: at}
	pr.out = bucket{level: pr.out.level + go_, at: at}
	r.peers = append(r.peers, pr)
	r.byID[p] = pr
	n := r.score.connect(p, addr.Addr())
	r.charge(pr, OpLookup, n)
	r.did(OpLookup, n)
	var c wire.Control
	for _, t := range r.joined() {
		if t.allow != nil {
			r.charge(pr, OpCallback, 1)
			r.did(OpCallback, 1)
		}
		if r.judge(t, pr) {
			c.Subs = append(c.Subs, wire.Sub{Topic: t.id, Subscribe: true})
		}
	}
	if len(c.Subs) > 0 {
		r.push(pr, pr, &c, true)
	}
	return nil
}

// RemovePeer ends gossip with a peer whose connection ended; its score is retained for RetainScore. The peer pays
// for its leaving, and a debt it leaves with is kept for its key.
func (r *Router) RemovePeer(now time.Time, p PeerID) {
	r.advance(now)
	pr := r.byID[p]
	if pr == nil {
		return
	}
	n := len(r.peers) + len(r.topics)*(2*r.cfg.Params.Dhi+1)
	for _, t := range r.sortedTopics() {
		t.mesh = remove(t.mesh, p)
		t.fanout = remove(t.fanout, p)
	}
	if r.score != nil {
		r.score.spent = 0
	}
	k, app := r.score.disconnect(r.now, p, r.cfg.MaxRetained)
	n += k
	r.charge(pr, OpLookup, n)
	r.did(OpLookup, n)
	if app {
		k := max(1, callbacks(r.score.spent))
		r.score.spent = 0
		r.charge(pr, OpCallback, k)
		r.did(OpCallback, k)
	}
	r.peers = slices.DeleteFunc(r.peers, func(q *peer) bool { return q == pr })
	delete(r.byID, p)
	r.release(pr)
	held := r.depart(pr)
	if held || pr.lock.level < 0 || pr.out.level < 0 {
		r.gone.put(pr, r.mono(r.now), r.cfg.MaxRetained)
	}
}

// depart moves the messages p has waiting into the departed share, one peer's share for all senders that left; past
// it p's newest are dropped, so keys that fill their shares and leave cannot fill the global bounds.
// It reports whether p had messages waiting.
func (r *Router) depart(p *peer) bool {
	h, ok := r.holding[p.id]
	if !ok {
		return false
	}
	delete(r.holding, p.id)
	r.charge(p, OpLookup, h.count)
	r.did(OpLookup, h.count)
	var recs []*seenRec
	for rec := h.head; rec != nil; rec = rec.pending.nextHeld {
		recs = append(recs, rec)
	}
	for i := len(recs) - 1; i >= 0; i-- { // oldest first
		recs[i].pending.departed, recs[i].pending.nextHeld = true, nil
		r.departed.recs = append(r.departed.recs, recs[i])
	}
	r.departed.count += h.count
	r.departed.bytes += h.bytes
	for r.departed.count > r.cfg.MaxPeerValidating || r.departed.bytes > r.cfg.MaxPeerValidatingBytes {
		r.forget(r.departed.recs[len(r.departed.recs)-1], p)
	}
	return true
}

// gone keeps the keys that left in debt or with messages waiting, so a returning key pays its debt: at most
// MaxRetained keys, each for RetainScore (WorkBurst when scoring is off), the oldest dropped first.
type gone struct {
	m map[PeerID]*peer
	q []goneKey // in the order they were kept; an entry no longer in m is skipped
}

// goneKey is a key kept in gone and since when.
type goneKey struct {
	p  *peer
	at int64
}

// put keeps p from at, dropping the oldest key when limit keys are kept.
func (g *gone) put(p *peer, at int64, limit int) {
	p.topics, p.other, p.ring, p.asking, p.sent, p.unwanted, p.pend, p.refused = nil, nil, nil, nil, nil, nil, nil, nil
	for len(g.m) >= limit {
		g.pop()
	}
	g.m[p.id] = p
	g.q = append(g.q, goneKey{p, at})
	if len(g.q) > 2*limit {
		g.q = slices.DeleteFunc(g.q, func(k goneKey) bool { return g.m[k.p.id] != k.p })
	}
}

// pop drops the oldest key kept.
func (g *gone) pop() {
	for len(g.q) > 0 {
		k := g.q[0]
		g.q = g.q[1:]
		if g.m[k.p.id] == k.p {
			delete(g.m, k.p.id)
			return
		}
	}
}

// take removes and returns what is kept for p, nil if nothing is.
func (g *gone) take(p PeerID) *peer {
	q := g.m[p]
	delete(g.m, p)
	return q
}

// expire drops the keys that left before at.
func (g *gone) expire(at int64) {
	for len(g.q) > 0 && (g.m[g.q[0].p.id] != g.q[0].p || g.q[0].at < at) {
		if k := g.q[0]; g.m[k.p.id] == k.p {
			delete(g.m, k.p.id)
		}
		g.q = g.q[1:]
	}
	if len(g.q) == 0 {
		g.q = nil
	}
}

// goneFor returns how long a key that left is kept: as long as its score, or WorkBurst when scoring is off.
func (r *Router) goneFor() time.Duration {
	if r.cfg.Score != nil {
		return max(r.cfg.Score.RetainScore, r.cfg.WorkBurst)
	}
	return r.cfg.WorkBurst
}

// Join subscribes to t, announces it to every peer and grafts up to D peers; joining twice does nothing.
func (r *Router) Join(now time.Time, t wire.Topic, tc *TopicConfig) error {
	r.advance(now)
	tp := r.topics[t]
	if tp != nil && tp.joined {
		return nil
	}
	params, score, maxSize, err := r.topicConfig(tc)
	if err != nil {
		return err
	}
	if tp == nil {
		if r.cfg.MaxTopics > 0 && len(r.topics) >= r.cfg.MaxTopics {
			return fmt.Errorf("%w: %d topics", ErrLimit, len(r.topics))
		}
		tp = &topic{id: t}
		r.addTopic(tp)
	}
	tp.joined, tp.params, tp.score, tp.maxSize, tp.allow = true, params, score, maxSize, nil
	if tc != nil {
		tp.allow = tc.AllowPeer
	}
	for _, p := range r.peers {
		r.judge(tp, p)
	}
	r.backoff.join(t)
	mesh := slices.DeleteFunc(tp.fanout, func(p PeerID) bool {
		return r.scoreOf(p) < 0 || r.backoff.has(t, p) || r.byID[p].refuses(t)
	})
	if need := params.D - len(mesh); need > 0 {
		mesh = append(mesh, r.pick(t, need, func(p *peer) bool {
			return !slices.Contains(mesh, p.id) && !r.backoff.has(t, p.id) && r.scoreOf(p.id) >= 0
		})...)
	}
	tp.mesh, tp.fanout, tp.lastPub = mesh, nil, time.Time{}
	for _, p := range mesh {
		r.score.graft(r.now, p, t)
	}
	for _, p := range r.peers {
		if p.refuses(t) {
			continue
		}
		c := &wire.Control{Subs: []wire.Sub{{Topic: t, Subscribe: true}}}
		if slices.Contains(mesh, p.id) {
			c.Graft = []wire.Topic{t}
		}
		r.sendControl(p, c, true)
	}
	return nil
}

func (r *Router) topicConfig(tc *TopicConfig) (Params, *TopicScoreParams, int, error) {
	params, maxSize := r.cfg.Params, r.cfg.MaxMessageSize
	var score *TopicScoreParams
	if r.score != nil {
		score = DefaultTopicScore()
	}
	if tc == nil {
		return params, score, maxSize, nil
	}
	if tc.Params != nil {
		params = *tc.Params
		if err := params.validate(); err != nil {
			return params, nil, 0, err
		}
		if err := r.cfg.checkIDontWant(&params); err != nil {
			return params, nil, 0, err
		}
	}
	if tc.MaxMessageSize != 0 {
		if tc.MaxMessageSize < minEnvelopeSize || tc.MaxMessageSize > r.cfg.MaxMessageSize {
			return params, nil, 0, invalid("topic MaxMessageSize %d outside %d to %d", tc.MaxMessageSize, minEnvelopeSize, r.cfg.MaxMessageSize)
		}
		maxSize = tc.MaxMessageSize
	}
	switch {
	case tc.Score == nil:
	case *tc.Score == TopicScoreParams{}:
		score = nil
	default:
		if r.score == nil {
			return params, nil, 0, invalid("topic score parameters while scoring is off")
		}
		if err := tc.Score.validate(); err != nil {
			return params, nil, 0, err
		}
		s := *tc.Score
		score = &s
	}
	return params, score, maxSize, nil
}

// Leave prunes t's mesh with the unsubscribe backoff and announces the leave to every peer.
func (r *Router) Leave(now time.Time, t wire.Topic) {
	r.advance(now)
	tp := r.topics[t]
	if tp == nil || !tp.joined {
		return
	}
	for _, p := range tp.mesh {
		r.score.prune(p, t)
		r.backoff.add(r.now, t, p, r.cfg.UnsubscribeBackoff, true, r.cfg.MaxBackoff, r.byID)
	}
	for _, p := range r.peers {
		if p.refuses(t) {
			continue
		}
		c := &wire.Control{Subs: []wire.Sub{{Topic: t, Subscribe: false}}}
		if slices.Contains(tp.mesh, p.id) {
			c.Prune = []wire.Prune{{Topic: t, Backoff: seconds(r.cfg.UnsubscribeBackoff), PX: r.exchange(nil, p.id, t)}}
		}
		r.sendControl(p, c, true)
	}
	// Pending validations and chain requests of t are dropped, so a verdict that arrives after a rejoin cannot
	// apply to the new room and no forwarder is charged for a request we no longer need.
	for _, rec := range r.recs {
		if rec.topic == t && rec.pending != nil {
			r.forget(rec, nil)
		}
	}
	if res := r.resolver(); res != nil {
		res.Leave(t)
		r.take(nil)
	}
	r.score.dropTopic(t)
	r.dropTopic(t)
	r.backoff.leave(t, r.now, max(16, len(r.topics)))
}

// Refresh asks t's AllowPeer about every peer again: a peer refused now is told we left the topic and leaves its
// mesh, and one admitted now is told we joined it.
func (r *Router) Refresh(now time.Time, t wire.Topic) {
	r.advance(now)
	tp := r.topics[t]
	if tp == nil || !tp.joined || tp.allow == nil {
		return
	}
	for _, p := range r.peers {
		was := p.refuses(t)
		switch ok := r.judge(tp, p); {
		case ok && was:
			r.sendControl(p, &wire.Control{Subs: []wire.Sub{{Topic: t, Subscribe: true}}}, true)
		case !ok && !was:
			c := &wire.Control{Subs: []wire.Sub{{Topic: t, Subscribe: false}}}
			if slices.Contains(tp.mesh, p.id) {
				r.score.prune(p.id, t)
				tp.mesh = remove(tp.mesh, p.id)
				r.backoff.add(r.now, t, p.id, r.cfg.UnsubscribeBackoff, true, r.cfg.MaxBackoff, r.byID)
				c.Prune = []wire.Prune{{Topic: t, Backoff: seconds(r.cfg.UnsubscribeBackoff)}}
			}
			r.sendControl(p, c, true)
		}
	}
}

// Publish sends the caller's signed envelope, which the router keeps: to every topic peer at or above the publish
// threshold with flood publishing, else to the mesh, or to fanout peers when the topic is not joined.
func (r *Router) Publish(now time.Time, raw []byte) (wire.ID, error) {
	r.advance(now)
	t, _ := wire.EnvelopeTopic(raw)
	tp := r.topics[t]
	maxSize := r.cfg.MaxMessageSize
	if tp != nil && tp.joined {
		maxSize = tp.maxSize
	}
	if len(raw) > maxSize {
		return wire.ID{}, fmt.Errorf("%w: %d bytes over %d", ErrTooLarge, len(raw), maxSize)
	}
	env, err := wire.DecodeEnvelope(raw, maxSize)
	if err != nil {
		return wire.ID{}, fmt.Errorf("%w: %w", ErrInvalidArgument, err)
	}
	if PeerID(env.Device) != r.self {
		return wire.ID{}, fmt.Errorf("%w: envelope device is not this node", ErrInvalidArgument)
	}
	id := wire.NewID(raw)
	switch {
	case r.seen.has(id):
		return id, ErrDuplicate
	case r.seen.len()+r.validating >= r.cfg.MaxSeen: // held messages become seen once validated
		return id, fmt.Errorf("%w: seen cache full", ErrLimit)
	case !r.cfg.FloodPublish && tp == nil && r.cfg.MaxTopics > 0 && len(r.topics) >= r.cfg.MaxTopics:
		return id, fmt.Errorf("%w: %d topics", ErrLimit, len(r.topics))
	}
	r.seen.add(id)
	if tp != nil && tp.joined {
		r.accepted(r.record(id, t, nil), tp)
	}
	r.cache.put(id, t, raw, r.cfg.MaxCacheMessages, r.cfg.MaxCacheBytes, &r.stats)
	r.stats.Published++
	var to []PeerID
	switch {
	case r.cfg.FloodPublish:
		for _, p := range r.peers {
			if p.knows(t) && !p.refuses(t) && r.scoreOf(p.id) >= r.thresholds().Publish {
				to = append(to, p.id)
			}
		}
	case tp != nil && tp.joined:
		to = r.wanted(nil, tp.mesh, id)
	default:
		to = r.wanted(nil, r.fanoutFor(t), id)
	}
	for _, p := range to {
		r.sendMessage(nil, p, raw)
	}
	return id, nil
}

// fanoutFor returns t's fanout peers, choosing D peers at or above the publish threshold when it has none.
func (r *Router) fanoutFor(t wire.Topic) []PeerID {
	tp := r.topics[t]
	if tp == nil {
		tp = &topic{id: t, params: r.cfg.Params, maxSize: r.cfg.MaxMessageSize}
		r.addTopic(tp)
	}
	if len(tp.fanout) == 0 {
		tp.fanout = r.pick(t, tp.params.D, func(p *peer) bool { return r.scoreOf(p.id) >= r.thresholds().Publish })
	}
	tp.lastPub = r.now
	return tp.fanout
}

// wanted filters out the peers that sent IDONTWANT for id, charged to payer.
func (r *Router) wanted(payer *peer, ps []PeerID, id wire.ID) []PeerID {
	r.charge(payer, OpLookup, len(ps))
	if payer != nil {
		r.did(OpLookup, len(ps))
	}
	var out []PeerID
	for _, p := range ps {
		if !r.byID[p].unwanted.has(id) {
			out = append(out, p)
		}
	}
	return out
}

// Tick runs the heartbeat and the score decay when they are due.
func (r *Router) Tick(now time.Time) {
	r.advance(now)
	if !r.now.Before(r.nextHeartbeat) {
		r.heartbeat()
		r.nextHeartbeat = next(r.nextHeartbeat, r.now, r.cfg.HeartbeatInterval)
	}
	if r.score != nil && !r.now.Before(r.nextDecay) {
		r.score.decay(r.now, r.peers)
		r.nextDecay = next(r.nextDecay, r.now, r.cfg.Score.DecayInterval)
	}
}

// next returns the following tick, skipping the ticks missed while the caller was late.
func next(t, now time.Time, d time.Duration) time.Time {
	t = t.Add(d)
	if !t.After(now) {
		t = now.Add(d)
	}
	return t
}

// NextTick returns when Tick has work to do next.
func (r *Router) NextTick() time.Time {
	if r.score != nil && r.nextDecay.Before(r.nextHeartbeat) {
		return r.nextDecay
	}
	return r.nextHeartbeat
}

// Score returns a peer's current score, 0 when scoring is off or the peer is unknown.
func (r *Router) Score(p PeerID) float64 {
	return r.scoreOf(p)
}

func (r *Router) scoreOf(p PeerID) float64 {
	return r.score.score(p)
}

// scoreFor is scoreOf for a peer whose frame is handled now: the computation is charged to it.
func (r *Router) scoreFor(p *peer) float64 { return r.scoreBy(p, p.id) }

// scoreBy is scoreOf(q) charged to payer.
func (r *Router) scoreBy(payer *peer, q PeerID) float64 {
	n, app := r.score.work(q)
	r.charge(payer, OpLookup, n)
	r.did(OpLookup, n)
	if r.score == nil {
		return 0
	}
	r.score.spent = 0 // time of earlier calls, the heartbeat's, is the node's own
	score := r.scoreOf(q)
	if app {
		// Application code is charged by the time it took, at least its flat cost.
		k := max(1, callbacks(r.score.spent))
		r.score.spent = 0
		r.charge(payer, OpCallback, k)
		r.did(OpCallback, k)
	}
	return score
}

// callbacks converts the time application code took into OpCallback operations, rounded up.
func callbacks(d time.Duration) int {
	per := time.Duration(units[OpCallback]) * Unit
	return int((d + per - 1) / per)
}

// Callbacks is callbacks for the Verifier, which times the roster and the open mode the same way.
func Callbacks(d time.Duration) int { return callbacks(d) }

// grayFor is graylisted for a peer whose frame is handled now.
func (r *Router) grayFor(p *peer) bool {
	return r.score != nil && r.scoreFor(p) < r.score.p.Thresholds.Graylist
}

func (r *Router) thresholds() Thresholds {
	if r.score == nil {
		return Thresholds{}
	}
	return r.score.p.Thresholds
}

// Graylisted reports whether p's score is below the graylist threshold, so its frames are dropped.
func (r *Router) Graylisted(p PeerID) bool {
	return r.graylisted(p)
}

func (r *Router) graylisted(p PeerID) bool {
	return r.score != nil && r.scoreOf(p) < r.score.p.Thresholds.Graylist
}

// Mesh returns a copy of t's mesh, in the order peers joined it.
func (r *Router) Mesh(t wire.Topic) []PeerID {
	if tp := r.topics[t]; tp != nil {
		return slices.Clone(tp.mesh)
	}
	return nil
}

// Fanout returns a copy of t's fanout peers.
func (r *Router) Fanout(t wire.Topic) []PeerID {
	if tp := r.topics[t]; tp != nil {
		return slices.Clone(tp.fanout)
	}
	return nil
}

// sortedTopics returns the topic states in topic id order, so iterations never depend on map order.
func (r *Router) sortedTopics() []*topic {
	ts := make([]*topic, 0, len(r.topics))
	for _, t := range r.topics {
		ts = append(ts, t)
	}
	slices.SortFunc(ts, func(a, b *topic) int { return bytes.Compare(a.id[:], b.id[:]) })
	return ts
}

func (r *Router) joined() []*topic {
	return slices.DeleteFunc(r.sortedTopics(), func(t *topic) bool { return !t.joined })
}

// pick returns up to n random peers subscribed to t that pass ok.
func (r *Router) pick(t wire.Topic, n int, ok func(*peer) bool) []PeerID {
	var c []PeerID
	for _, p := range r.peers {
		if p.subscribed(t) && !p.refuses(t) && ok(p) {
			c = append(c, p.id)
		}
	}
	shuffle(r.rnd, c)
	return c[:min(n, len(c))]
}

func (p *peer) subscribed(t wire.Topic) bool {
	_, ok := slices.BinarySearchFunc(p.topics, t, cmpTopic)
	return ok
}

// knows reports whether p announced t, whether we hold state for it or not.
func (p *peer) knows(t wire.Topic) bool {
	_, ok := slices.BinarySearchFunc(p.other, t, cmpTopic)
	return ok || p.subscribed(t)
}

// addTopic starts state for a topic and moves the peers' subscriptions to it from their other lists.
func (r *Router) addTopic(tp *topic) {
	r.topics[tp.id] = tp
	for _, p := range r.peers {
		if i, ok := slices.BinarySearchFunc(p.other, tp.id, cmpTopic); ok {
			p.other = slices.Delete(p.other, i, i+1)
			j, _ := slices.BinarySearchFunc(p.topics, tp.id, cmpTopic)
			p.topics = slices.Insert(p.topics, j, tp.id)
		}
	}
}

// dropTopic ends the state of a topic and moves the peers' subscriptions to their other lists, dropping and counting
// those that do not fit.
func (r *Router) dropTopic(t wire.Topic) {
	delete(r.topics, t)
	for _, p := range r.peers {
		delete(p.refused, t)
		i, ok := slices.BinarySearchFunc(p.topics, t, cmpTopic)
		if !ok {
			continue
		}
		p.topics = slices.Delete(p.topics, i, i+1)
		if len(p.other) >= r.cfg.MaxPeerTopics {
			r.stats.SubscriptionsDropped++
			continue
		}
		j, _ := slices.BinarySearchFunc(p.other, t, cmpTopic)
		p.other = slices.Insert(p.other, j, t)
	}
}

func cmpTopic(a, b wire.Topic) int {
	return bytes.Compare(a[:], b[:])
}

func shuffle[T any](rnd Rand, s []T) {
	for i := len(s) - 1; i > 0; i-- {
		j := rnd.IntN(i + 1)
		s[i], s[j] = s[j], s[i]
	}
}

func remove(s []PeerID, p PeerID) []PeerID {
	return slices.DeleteFunc(s, func(q PeerID) bool { return q == p })
}

func seconds(d time.Duration) uint64 {
	return uint64(d / time.Second)
}
