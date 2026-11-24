package kologossip

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"math"
	"time"

	"github.com/ciranda-dev/kolo-gossip/internal/auth"
	"github.com/ciranda-dev/kolo-gossip/internal/core"
	koloid "github.com/ciranda-dev/kolo-id"
	koloswarm "github.com/ciranda-dev/kolo-swarm"
)

// Config configures a Gossip. Cert is required; every other zero field takes its default, and a negative or
// inconsistent value is ErrInvalidConfig. The defaults are in docs/limits.md with their sources.
type Config struct {
	// Cert is the certificate chain of the device key passed to New; its person is the author of every message.
	Cert *koloid.DeviceCert
	// Swarm, if set, must run as the same device key; Join and Leave then also join and leave the swarm topic.
	Swarm *koloswarm.Swarm

	// Params are the overlay parameters of topics joined without their own; nil takes DefaultParams.
	Params *Params
	// Score nil takes DefaultScore.
	Score *ScoreParams
	// NoScore turns peer scoring off.
	NoScore bool
	// NoFloodPublish sends our own messages to the mesh (or to fanout peers) instead of every topic peer.
	NoFloodPublish bool
	// Now is the clock for signing, the time windows, chain checks and heartbeat times; nil is time.Now. The heartbeat
	// timer still waits in real time, so a clock that runs faster is noticed at the next timer.
	Now func() time.Time
	// PeerExchange lists other topic peers in the PRUNE we send, so a pruned peer can dial them; off by default, as
	// GossipSub v1.1 advises outside bootstrap nodes. Received peer exchange is dialed through Swarm either way,
	// from peers scored at least Thresholds.AcceptPX.
	PeerExchange bool

	HeartbeatInterval       time.Duration // default 1s
	HeartbeatInitialDelay   time.Duration // default 100ms
	FanoutTTL               time.Duration // default 1m
	HistoryLength           int           // message cache windows kept, default 5
	HistoryGossip           int           // newest windows announced in IHAVE, default 3
	SeenTTL                 time.Duration // default 2m
	MaxAge                  time.Duration // oldest accepted author time, default 1m; MaxAge + MaxSkew <= SeenTTL
	MaxSkew                 time.Duration // newest accepted author time ahead of ours, default 1m
	MaxSeen                 int           // seen message ids, default 200,000
	MaxCacheMessages        int           // cached messages per topic, default 8,333
	MaxCacheBytes           int           // cached message bytes, all topics, default 32 MiB
	GossipRetransmission    int           // IWANT answers per peer per message, default 3
	PruneBackoff            time.Duration // default 1m
	UnsubscribeBackoff      time.Duration // default 10s
	GraftFloodThreshold     time.Duration // default 10s
	OpportunisticGraftTicks int           // heartbeats between opportunistic grafts, default 60
	OpportunisticGraftPeers int           // default 2
	MaxIHaveLength          int           // ids read per IHAVE and asked per peer per heartbeat, default 5000
	MaxIHaveMessages        int           // IHAVE frames handled per peer per heartbeat, default 10
	MaxIDontWantLength      int           // ids kept per IDONTWANT frame, default 10
	MaxIDontWantMessages    int           // IDONTWANT frames handled per peer per heartbeat, default 1000
	MaxIDontWantIDs         int           // IDONTWANT ids kept per peer, default 5000
	IWantFollowupTime       time.Duration // default 3s
	IDontWantThreshold      int           // envelope bytes from which IDONTWANT is sent, default 1024
	IDontWantTTL            int           // heartbeats an IDONTWANT id is kept, default 3
	MaxMessageSize          int           // whole envelope, default 1 MiB
	MaxControlSize          int           // control frame, default 512 KiB
	MaxPeers                int           // peers served at once; default 0, no cap of its own (ServeConn's connections, which kolo-swarm bounds); a positive value is a cap (ErrLimit)
	MaxTopics               int           // joined and fanout topics; default 0, no cap; a positive value is a cap (ErrLimit)
	MaxPeerTopics           int           // topics one peer announces that we hold no state for, kept to join or publish to them later, default 1,024; past it they are not kept (Stats.Router.SubscriptionsDropped), never an error
	MaxBackoff              int           // backoff entries per topic, default 1024
	MaxRetained             int           // scores kept for disconnected peers, default 1024
	MaxValidating           int           // messages waiting for a validator or a chain, or dropped while their validator runs, default max(1,040, 65 x MaxPeerValidating)
	MaxValidatingBytes      int           // their bytes, default max(65 MiB, 65 x MaxPeerValidatingBytes)
	MaxPeerValidating       int           // of those, from one peer, default 16; at most half of MaxValidating
	MaxPeerValidatingBytes  int           // their bytes from one peer, default 1 MiB, at least MaxMessageSize; at most half of MaxValidatingBytes
	MaxIgnoredIDs           int           // ids ignored for their content or author, kept so their copies cost nothing, default 8,333
	IgnoredTTL              time.Duration // how long such an id is kept, default 5s
	RetryInterval           time.Duration // how long a message the validator answered Retry waits for its next validation, unless Room.Revalidate comes first; default HeartbeatInterval
	LockWork                time.Duration // router lock time per second for all peers' frames, default 500ms: half shared by every peer, a quarter by mesh places, a quarter by the messages mesh peers delivered
	ReaderWork              time.Duration // reader time per second for all peers (hashing, signature checks, peer exchange dials), default 64 x PeerWork, about 7.06s, shared as LockWork
	PeerWork                time.Duration // most reader time per second one peer gets, default about 110ms
	WorkBurst               time.Duration // what a peer's work buckets hold: this long of their refill, default 2s
	PrunePeers              int           // peer exchange records read from one PRUNE entry and listed in one we send, default 16

	PeerQueue       int           // control frames queued for one peer, default 32
	PeerQueueBytes  int           // bytes queued for one peer, default the largest of 1 MiB, MaxMessageSize, MaxControlSize
	RoomQueue       int           // delivered messages waiting for Room.Next, default 32
	FrameTimeout    time.Duration // how long a frame or stream header under way may go without a byte, default 30s
	ValidateTimeout time.Duration // how long a Validator may take, default and at most SeenTTL
	PXPending       int           // peer exchange records waiting for a dial, default 128; more are dropped
	PXDialers       int           // peer exchange dials at once through Swarm, default 8
	PXTimeout       time.Duration // how long one peer exchange dial may take, default 30s

	CertCacheBytes int           // verified author chains kept, from the roster and fetched, each; default 1 MiB
	CertTimeout    time.Duration // how long a CERTWANT may stay unanswered, default 3s
	MaxCertWants   int           // CERTWANT requests outstanding per peer and entries answered per peer per heartbeat, default 10
	MaxCertAnswers int           // CERTWANT requests sent to one peer per heartbeat, default 5, at most half of MaxCertWants
	MaxWaiting     int           // messages waiting for their author's chain, default MaxValidating
}

// Params are the overlay parameters of a topic: the mesh degree D with its bounds Dlo and Dhi, the lazy degree
// for gossip, the peers kept by score when a mesh is pruned, the outbound quota and the gossip factor.
type Params struct {
	D, Dlo, Dhi, Dlazy, Dscore, Dout int
	GossipFactor                     float64
	// GossipPeers is the node's gossip budget, at least Dlazy: GossipPeers IHAVE of MaxIHaveLength ids a heartbeat,
	// shared by every topic. A node that announces fewer ids gossips to more peers per topic, as the specification
	// says. 0 takes the default, max(Dlazy, 43); in a Bootstrap Params that keeps no mesh it means no cap.
	GossipPeers int
	// Bootstrap allows D, Dlo, Dhi and Dout all zero: a node that keeps no mesh, as GossipSub v1.1 lets bootstrap
	// nodes run. Without it they are refused, so a zero Params cannot turn the mesh off by mistake.
	Bootstrap bool
}

// DefaultParams returns the GossipSub specification's overlay values, except Dscore 6 and GossipFactor 0.75,
// which our simulator measured under Sybil floods.
func DefaultParams() *Params {
	return publicParams(core.DefaultConfig().Params)
}

func publicParams(c core.Params) *Params {
	return &Params{D: c.D, Dlo: c.Dlo, Dhi: c.Dhi, Dlazy: c.Dlazy, Dscore: c.Dscore, Dout: c.Dout, GossipFactor: c.GossipFactor, GossipPeers: c.GossipPeers}
}

func (p *Params) core() (core.Params, error) {
	c := core.Params{D: p.D, Dlo: p.Dlo, Dhi: p.Dhi, Dlazy: p.Dlazy, Dscore: p.Dscore, Dout: p.Dout, GossipFactor: p.GossipFactor, GossipPeers: p.GossipPeers}
	meshless := p.D == 0 && p.Dlo == 0 && p.Dhi == 0 && p.Dout == 0
	if meshless && !p.Bootstrap {
		return c, fmt.Errorf("%w: Params with D, Dlo, Dhi and Dout zero need Bootstrap", ErrInvalidConfig)
	}
	if c.GossipPeers == 0 && !meshless {
		c.GossipPeers = max(p.Dlazy, core.DefaultConfig().Params.GossipPeers)
	}
	return c, nil
}

// Thresholds are the GossipSub v1.1 score thresholds; a peer below one loses what it gates.
type Thresholds struct {
	Gossip             float64 // below: no IHAVE or IWANT to or from the peer; must be < 0
	Publish            float64 // below: our own messages are not flooded to the peer; must be <= Gossip
	Graylist           float64 // below: every frame is dropped, ServeConn ends and Allow refuses; must be < Publish
	OpportunisticGraft float64 // a mesh median below it grafts better peers; must be >= 0
	AcceptPX           float64 // at or above: the peer exchange of the peer's PRUNE is dialed; 0 dials none; must be >= 0
}

// ScoreParams are the score parameters that apply to every peer: thresholds, the application score (P5), IP
// colocation (P6), the behaviour penalty (P7), decay and retention.
type ScoreParams struct {
	Thresholds    Thresholds
	TopicScoreCap float64 // cap of the summed topic scores; 0: no cap
	// AppScore is the application's view of a peer (P5); nil, a panic or a value that is not finite scores 0. It
	// runs with the Gossip's lock held, so it must not call the Gossip.
	AppScore                  func(key ed25519.PublicKey) float64
	AppWeight                 float64
	IPColocationWeight        float64 // P6, <= 0
	IPColocationThreshold     int     // peers on one IPv4 address before P6 applies
	BehaviourPenaltyWeight    float64 // P7, <= 0
	BehaviourPenaltyThreshold float64
	BehaviourPenaltyDecay     float64
	DecayInterval             time.Duration
	DecayToZero               float64
	RetainScore               time.Duration // how long a disconnected peer's score is kept, unchanged; must be positive
}

// TopicScoreParams are the score parameters of one topic: time in mesh (P1), first deliveries (P2), mesh
// delivery rate and failures (P3, P3b) and invalid messages (P4).
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

// DefaultScore returns the score parameters our simulator found; set AppScore on the copy to use P5.
func DefaultScore() *ScoreParams {
	c := core.DefaultScore()
	return &ScoreParams{
		Thresholds:                Thresholds(c.Thresholds),
		TopicScoreCap:             c.TopicScoreCap,
		AppWeight:                 c.AppWeight,
		IPColocationWeight:        c.IPColocationWeight,
		IPColocationThreshold:     c.IPColocationThreshold,
		BehaviourPenaltyWeight:    c.BehaviourPenaltyWeight,
		BehaviourPenaltyThreshold: c.BehaviourPenaltyThreshold,
		BehaviourPenaltyDecay:     c.BehaviourPenaltyDecay,
		DecayInterval:             c.DecayInterval,
		DecayToZero:               c.DecayToZero,
		RetainScore:               c.RetainScore,
	}
}

// DefaultTopicScore returns the topic score parameters our simulator found; P3 and P3b are off.
func DefaultTopicScore() *TopicScoreParams {
	p := TopicScoreParams(*core.DefaultTopicScore())
	return &p
}

func (s *ScoreParams) core() (*core.ScoreParams, error) {
	if s.RetainScore <= 0 {
		return nil, fmt.Errorf("%w: RetainScore %v must be positive, or a peer clears its score by reconnecting", ErrInvalidConfig, s.RetainScore)
	}
	c := &core.ScoreParams{
		Thresholds:                core.Thresholds(s.Thresholds),
		TopicScoreCap:             s.TopicScoreCap,
		AppWeight:                 s.AppWeight,
		IPColocationWeight:        s.IPColocationWeight,
		IPColocationThreshold:     s.IPColocationThreshold,
		BehaviourPenaltyWeight:    s.BehaviourPenaltyWeight,
		BehaviourPenaltyThreshold: s.BehaviourPenaltyThreshold,
		BehaviourPenaltyDecay:     s.BehaviourPenaltyDecay,
		DecayInterval:             s.DecayInterval,
		DecayToZero:               s.DecayToZero,
		RetainScore:               s.RetainScore,
	}
	if f := s.AppScore; f != nil {
		c.AppScore = func(p core.PeerID) float64 { return appScore(f, p) }
	}
	return c, nil
}

func appScore(f func(ed25519.PublicKey) float64, p core.PeerID) (v float64) {
	defer func() {
		if recover() != nil {
			v = 0
		}
	}()
	v = f(bytes.Clone(p[:]))
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return 0
	}
	return v
}

// settings are a Config with its defaults applied, split into the parts each layer takes.
type settings struct {
	router          core.Config
	auth            auth.Config
	peerQueue       int
	peerQueueBytes  int
	roomQueue       int
	frameTimeout    time.Duration
	validateTimeout time.Duration
	pxPending       int
	pxDialers       int
	pxTimeout       time.Duration
	now             func() time.Time
}

// override sets *dst to v unless v is zero.
func override[T comparable](dst *T, v T) {
	var zero T
	if v != zero {
		*dst = v
	}
}

func (c *Config) settings() (*settings, error) {
	if c == nil || c.Cert == nil {
		return nil, fmt.Errorf("%w: Cert is required", ErrInvalidConfig)
	}
	r := *core.DefaultConfig()
	r.FloodPublish = !c.NoFloodPublish
	r.PeerExchange = c.PeerExchange
	if c.Params != nil {
		p, err := c.Params.core()
		if err != nil {
			return nil, err
		}
		r.Params = p
	}
	switch {
	case c.NoScore:
		r.Score = nil
	case c.Score != nil:
		s, err := c.Score.core()
		if err != nil {
			return nil, err
		}
		r.Score = s
	}
	override(&r.HeartbeatInterval, c.HeartbeatInterval)
	override(&r.HeartbeatInitialDelay, c.HeartbeatInitialDelay)
	override(&r.FanoutTTL, c.FanoutTTL)
	override(&r.HistoryLength, c.HistoryLength)
	override(&r.HistoryGossip, c.HistoryGossip)
	override(&r.SeenTTL, c.SeenTTL)
	override(&r.MaxAge, c.MaxAge)
	override(&r.MaxSkew, c.MaxSkew)
	override(&r.MaxSeen, c.MaxSeen)
	override(&r.MaxCacheMessages, c.MaxCacheMessages)
	override(&r.MaxCacheBytes, c.MaxCacheBytes)
	override(&r.GossipRetransmission, c.GossipRetransmission)
	override(&r.PruneBackoff, c.PruneBackoff)
	override(&r.UnsubscribeBackoff, c.UnsubscribeBackoff)
	override(&r.GraftFloodThreshold, c.GraftFloodThreshold)
	override(&r.OpportunisticGraftTicks, c.OpportunisticGraftTicks)
	override(&r.OpportunisticGraftPeers, c.OpportunisticGraftPeers)
	override(&r.MaxIHaveLength, c.MaxIHaveLength)
	override(&r.MaxIHaveMessages, c.MaxIHaveMessages)
	override(&r.MaxIDontWantLength, c.MaxIDontWantLength)
	override(&r.MaxIDontWantMessages, c.MaxIDontWantMessages)
	override(&r.MaxIDontWantIDs, c.MaxIDontWantIDs)
	override(&r.IWantFollowupTime, c.IWantFollowupTime)
	override(&r.IDontWantThreshold, c.IDontWantThreshold)
	override(&r.IDontWantTTL, c.IDontWantTTL)
	override(&r.MaxMessageSize, c.MaxMessageSize)
	override(&r.MaxControlSize, c.MaxControlSize)
	override(&r.MaxPeers, c.MaxPeers)
	override(&r.MaxTopics, c.MaxTopics)
	override(&r.MaxPeerTopics, c.MaxPeerTopics)
	override(&r.MaxBackoff, c.MaxBackoff)
	override(&r.MaxRetained, c.MaxRetained)
	override(&r.MaxValidating, c.MaxValidating)
	override(&r.MaxValidatingBytes, c.MaxValidatingBytes)
	override(&r.MaxPeerValidating, c.MaxPeerValidating)
	override(&r.MaxPeerValidatingBytes, c.MaxPeerValidatingBytes)
	// Unset, the validation bounds follow the sizes they must hold: a share fits one largest message, and the global
	// bounds hold 65 shares, a chosen budget (docs/limits.md).
	if c.MaxPeerValidatingBytes == 0 {
		r.MaxPeerValidatingBytes = max(r.MaxPeerValidatingBytes, r.MaxMessageSize)
	}
	if c.MaxValidating == 0 {
		r.MaxValidating = max(r.MaxValidating, 65*r.MaxPeerValidating)
	}
	if c.MaxValidatingBytes == 0 {
		r.MaxValidatingBytes = max(r.MaxValidatingBytes, 65*r.MaxPeerValidatingBytes)
	}
	override(&r.MaxIgnoredIDs, c.MaxIgnoredIDs)
	override(&r.IgnoredTTL, c.IgnoredTTL)
	r.RetryInterval = r.HeartbeatInterval
	override(&r.RetryInterval, c.RetryInterval)
	if c.LockWork != 0 {
		r.LockWork = int64(c.LockWork / core.Unit)
	}
	if c.PeerWork != 0 {
		r.PeerWork = int64(c.PeerWork / core.Unit)
	}
	r.ReaderWork = 64 * r.PeerWork // a chosen node budget, not a peer count (docs/limits.md)
	if c.ReaderWork != 0 {
		r.ReaderWork = int64(c.ReaderWork / core.Unit)
	}
	override(&r.WorkBurst, c.WorkBurst)
	override(&r.PrunePeers, c.PrunePeers)

	// Application code is timed with the monotonic clock and charged to the peer that caused it.
	origin := time.Now()
	r.Elapsed = func() time.Duration { return time.Since(origin) }
	a := *auth.DefaultConfig()
	a.Elapsed = r.Elapsed
	override(&a.CertCacheBytes, c.CertCacheBytes)
	override(&a.CertTimeout, c.CertTimeout)
	override(&a.MaxCertWants, c.MaxCertWants)
	override(&a.MaxCertAnswers, c.MaxCertAnswers)
	a.MaxWaiting = r.MaxValidating // every waiting message is held within the validation bounds
	override(&a.MaxWaiting, c.MaxWaiting)
	r.MaxCerts = a.MaxCertWants // what the receiver reads of one CERT frame

	s := &settings{router: r, auth: a,
		peerQueue:       32,                                             // the per-peer outbound queue of deployed implementations
		peerQueueBytes:  max(1<<20, r.MaxMessageSize, r.MaxControlSize), // 1 MiB per peer, or one largest frame
		roomQueue:       32,                                             // a subscription's buffer in deployed implementations
		frameTimeout:    30 * time.Second,                               // kolo-transport's IdleTimeout: a silent peer is gone by then
		validateTimeout: r.SeenTTL,                                      // the longest a message is kept in the seen window
		pxPending:       128,                                            // the pending dials of deployed implementations
		pxDialers:       8,                                              // their dialers at once
		pxTimeout:       30 * time.Second,                               // their dial timeout
	}
	override(&s.peerQueue, c.PeerQueue)
	override(&s.peerQueueBytes, c.PeerQueueBytes)
	override(&s.roomQueue, c.RoomQueue)
	override(&s.frameTimeout, c.FrameTimeout)
	override(&s.validateTimeout, c.ValidateTimeout)
	override(&s.pxPending, c.PXPending)
	override(&s.pxDialers, c.PXDialers)
	override(&s.pxTimeout, c.PXTimeout)
	s.now = time.Now
	if c.Now != nil {
		s.now = c.Now
	}
	switch {
	case s.peerQueue < 1:
		return nil, fmt.Errorf("%w: PeerQueue %d must be at least 1", ErrInvalidConfig, s.peerQueue)
	case s.roomQueue < 1:
		return nil, fmt.Errorf("%w: RoomQueue %d must be at least 1", ErrInvalidConfig, s.roomQueue)
	case s.peerQueueBytes < r.MaxMessageSize || s.peerQueueBytes < r.MaxControlSize:
		return nil, fmt.Errorf("%w: PeerQueueBytes %d must hold one largest message and control frame", ErrInvalidConfig, s.peerQueueBytes)
	case s.frameTimeout < 0:
		return nil, fmt.Errorf("%w: FrameTimeout %v must be positive", ErrInvalidConfig, s.frameTimeout)
	case s.validateTimeout < 0 || s.validateTimeout > r.SeenTTL:
		return nil, fmt.Errorf("%w: ValidateTimeout %v must be positive and at most SeenTTL %v", ErrInvalidConfig, s.validateTimeout, r.SeenTTL)
	case s.pxPending < 1 || s.pxDialers < 1 || s.pxTimeout < 0:
		return nil, fmt.Errorf("%w: PXPending %d and PXDialers %d must be at least 1 and PXTimeout %v positive", ErrInvalidConfig, s.pxPending, s.pxDialers, s.pxTimeout)
	}
	return s, nil
}
