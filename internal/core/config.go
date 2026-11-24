package core

import (
	"fmt"
	"math"
	"time"

	"github.com/ciranda-dev/kolo-gossip/internal/wire"
)

// defaultPeerWork is twice the work an honest peer causes outside the lock at the design rate: each of 1,666
// messages of 1 KiB a second brought first, decoded, its signature checked over its bytes and its id hashed, a
// copy of each hashed too, one IHAVE of 5,000 ids and 1,666 IDONTWANT frames decoded, by the byte and the entry.
const defaultPeerWork = 2 * (1666*(3000+(5+4)*chunksPerKiB+3*2*chunksPerKiB) + 4*(5000*32/64+5000) + 4*2*1666)

// chunksPerKiB is the 64-byte chunks of a 1 KiB message with its envelope.
const chunksPerKiB = (1024 + 180 + 63) / 64

// maxFrameTopics is the GRAFT and PRUNE entries one control frame holds, the receiver rule of every released
// version, so the lock time of a frame stays bounded; it does not limit topics.
const maxFrameTopics = 32

// newcomerShares is the peers one second of the newcomer pool is sized for: the share each connected peer had at the
// old default of 64 peers, which TestNewPeerCatchUp measured as enough for a new peer to answer 1,666 asked ids.
const newcomerShares = 64

// validationShares is the senders the global validation bounds were sized for: 64 peers and the departed share.
const validationShares = 65

// minControlSize fits the eight list counts and the largest single item, a certificate with its length.
const minControlSize = 8 + 2 + wire.MaxCertSize

// minEnvelopeSize is the smallest envelope: version, three keys, one-byte seq, time and body length, signature.
const minEnvelopeSize = 1 + 3*wire.KeySize + 3 + wire.SigSize

// Params are the overlay parameters of one topic.
type Params struct {
	D, Dlo, Dhi, Dlazy, Dscore, Dout int
	GossipFactor                     float64
	GossipPeers                      int // most peers one heartbeat's IHAVE goes to per topic; at least Dlazy
}

// Config holds a Router's protocol parameters and bounds; DefaultConfig gives the sourced defaults.
type Config struct {
	Params                  Params // for topics joined without their own
	HeartbeatInterval       time.Duration
	HeartbeatInitialDelay   time.Duration
	FanoutTTL               time.Duration
	HistoryLength           int // message cache windows kept
	HistoryGossip           int // newest windows announced in IHAVE
	SeenTTL                 time.Duration
	MaxAge, MaxSkew         time.Duration // accepted message times: now-MaxAge to now+MaxSkew; sum at most SeenTTL
	MaxSeen                 int
	MaxCacheMessages        int // per topic
	MaxCacheBytes           int // all topics
	GossipRetransmission    int // IWANT answers per peer per message
	PruneBackoff            time.Duration
	UnsubscribeBackoff      time.Duration
	GraftFloodThreshold     time.Duration
	OpportunisticGraftTicks int
	OpportunisticGraftPeers int
	MaxIHaveLength          int // ids read per IHAVE and asked per peer per heartbeat
	MaxIHaveMessages        int // IHAVE frames handled per peer per heartbeat
	MaxIDontWantLength      int // ids kept per IDONTWANT frame
	MaxIDontWantMessages    int // IDONTWANT frames handled per peer per heartbeat
	MaxIDontWantIDs         int // IDONTWANT ids kept per peer
	IWantFollowupTime       time.Duration
	IDontWantThreshold      int // envelope bytes from which IDONTWANT is sent
	IDontWantTTL            int // heartbeats an IDONTWANT id is kept
	MaxMessageSize          int
	MaxControlSize          int
	MaxPeers                int // 0: no cap of its own
	MaxTopics               int // joined and fanout topics; 0: no cap
	MaxPeerTopics           int // topics one peer announces that we hold no state for, kept to join or publish to them later
	MaxBackoff              int // backoff entries per topic
	MaxRetained             int // scores kept for disconnected peers
	MaxValidating           int // messages waiting for ValidationDone or their author's chain
	MaxValidatingBytes      int
	MaxPeerValidating       int                  // of those, from one peer; at most half of MaxValidating
	MaxPeerValidatingBytes  int                  // their bytes, from one peer; at least MaxMessageSize, at most half of MaxValidatingBytes
	MaxIgnoredIDs           int                  // ids of messages ignored for their content or author, kept so their copies cost nothing
	IgnoredTTL              time.Duration        // how long such an id is kept
	RetryInterval           time.Duration        // how long a message the validator answered Retry waits before its next validation
	DesignRate              int                  // new messages per second the node is sized for (MaxSeen per SeenTTL)
	LockWork                int64                // units of work under the router lock per second for all peers, shared by connection, mesh place and messages delivered
	ReaderWork              int64                // units of work outside the lock per second for all peers, shared the same way
	PeerWork                int64                // most units of work outside the lock per second one peer gets
	WorkBurst               time.Duration        // what a peer's buckets hold: this long of their refill
	Elapsed                 func() time.Duration // a monotonic clock that times application code; nil charges it a flat cost
	MaxCerts                int                  // certificates per CERT frame, the receiver's bound
	PrunePeers              int                  // peer exchange records read from one PRUNE entry and offered in one
	PeerExchange            bool                 // offer peer exchange in the PRUNE we send
	FloodPublish            bool
	Score                   *ScoreParams // DefaultScore in DefaultConfig; nil turns scoring off: every score is 0
}

// TopicConfig is the configuration of one joined topic; zero fields take the Config values.
type TopicConfig struct {
	Params *Params
	// Score nil takes DefaultTopicScore when scoring is on; a pointer to a zero TopicScoreParams leaves the topic
	// unscored.
	Score          *TopicScoreParams
	MaxMessageSize int // at most Config.MaxMessageSize
	// AllowPeer admits the peers of this topic; nil admits every peer. A peer it refuses is never told we joined
	// the topic, is never grafted, gossiped to or sent its messages, and its frames about it are ignored. It runs
	// when a peer is added, when the topic is joined and on Refresh, and must not call the Router.
	AllowPeer func(PeerID) bool
}

// DefaultConfig returns the defaults: the GossipSub v1.0 to v1.2 parameter tables, derived bounds and the score
// parameters found by the simulator.
func DefaultConfig() *Config {
	return &Config{
		Params:                  Params{D: 6, Dlo: 4, Dhi: 12, Dlazy: 6, Dscore: 6, Dout: 2, GossipFactor: 0.75, GossipPeers: 43}, // Dscore and GossipFactor measured by the simulator; 43 is 0.75 of the 58 non-mesh peers at 64 places
		HeartbeatInterval:       time.Second,
		HeartbeatInitialDelay:   100 * time.Millisecond,
		FanoutTTL:               time.Minute,
		HistoryLength:           5,
		HistoryGossip:           3,
		SeenTTL:                 2 * time.Minute,
		MaxAge:                  time.Minute,
		MaxSkew:                 time.Minute,
		MaxSeen:                 200_000,  // 1666 messages/s for SeenTTL
		MaxCacheMessages:        8333,     // 5000 ids per 3 gossip windows, times 5 windows
		MaxCacheBytes:           32 << 20, // 3.3 times the 9.6 MiB of MaxCacheMessages messages of 1 KiB with their envelopes
		GossipRetransmission:    3,
		PruneBackoff:            time.Minute,
		UnsubscribeBackoff:      10 * time.Second,
		GraftFloodThreshold:     10 * time.Second,
		OpportunisticGraftTicks: 60,
		OpportunisticGraftPeers: 2,
		MaxIHaveLength:          5000,
		MaxIHaveMessages:        10,
		MaxIDontWantLength:      10,
		MaxIDontWantMessages:    1000,
		MaxIDontWantIDs:         5000, // the ids a peer may announce or ask per heartbeat (MaxIHaveLength)
		IWantFollowupTime:       3 * time.Second,
		IDontWantThreshold:      1024,
		IDontWantTTL:            3,
		MaxMessageSize:          1 << 20,
		MaxControlSize:          512 << 10,
		MaxPeers:                0,
		MaxTopics:               0,
		MaxPeerTopics:           1024, // 32 KiB of topic ids, a thirty-second of PeerQueueBytes
		MaxBackoff:              1024,
		MaxRetained:             1024,
		MaxValidating:           1040,     // validationShares shares of 16, the implementations' validation concurrency
		MaxValidatingBytes:      65 << 20, // validationShares shares of MaxPeerValidatingBytes
		MaxPeerValidating:       16,
		MaxPeerValidatingBytes:  1 << 20,         // MaxMessageSize: one largest message fits a share
		MaxIgnoredIDs:           8333,            // as MaxCacheMessages: the ids gossip can announce over HistoryLength windows
		IgnoredTTL:              5 * time.Second, // HistoryLength heartbeats: after it no peer announces the id any more
		RetryInterval:           time.Second,     // one heartbeat, the router's finest timer
		DesignRate:              1666,            // MaxSeen per SeenTTL
		LockWork:                int64(500 * time.Millisecond / Unit),
		ReaderWork:              newcomerShares * defaultPeerWork,
		PeerWork:                defaultPeerWork,
		WorkBurst:               2 * time.Second,
		MaxCerts:                10, // MaxCertWants of the author checks
		PrunePeers:              16, // more than Dhi, as GossipSub v1.1 asks
		FloodPublish:            true,
		Score:                   DefaultScore(),
	}
}

func (p *Params) validate() error {
	bootstrap := p.D == 0 && p.Dlo == 0 && p.Dhi == 0 && p.Dout == 0
	switch {
	case p.Dlo < 0 || p.Dlo > p.D || p.D > p.Dhi:
		return invalid("need 0 <= Dlo <= D <= Dhi, got %d, %d, %d", p.Dlo, p.D, p.Dhi)
	case p.Dout < 0 || p.Dout > p.D/2 || (p.Dout >= p.Dlo && !bootstrap):
		return invalid("need 0 <= Dout < Dlo and Dout <= D/2, got Dout %d", p.Dout)
	case p.Dscore < 0 || p.Dscore > p.Dhi:
		return invalid("need 0 <= Dscore <= Dhi, got %d", p.Dscore)
	case p.Dlazy < 0:
		return invalid("negative Dlazy")
	case p.GossipPeers == 0 && !bootstrap:
		return invalid("GossipPeers 0 needs a bootstrap Params")
	case p.GossipPeers != 0 && p.GossipPeers < p.Dlazy:
		return invalid("GossipPeers %d under Dlazy %d", p.GossipPeers, p.Dlazy)
	case !(p.GossipFactor >= 0 && p.GossipFactor <= 1):
		return invalid("GossipFactor %v outside 0 to 1", p.GossipFactor)
	}
	return nil
}

func (c *Config) validate() error {
	if err := c.Params.validate(); err != nil {
		return err
	}
	for _, d := range []struct {
		name string
		v    time.Duration
	}{{"HeartbeatInterval", c.HeartbeatInterval}, {"FanoutTTL", c.FanoutTTL}, {"SeenTTL", c.SeenTTL}, {"IgnoredTTL", c.IgnoredTTL},
		{"PruneBackoff", c.PruneBackoff}, {"UnsubscribeBackoff", c.UnsubscribeBackoff}, {"IWantFollowupTime", c.IWantFollowupTime},
		{"RetryInterval", c.RetryInterval}} {
		if d.v <= 0 {
			return invalid("%s %v must be positive", d.name, d.v)
		}
	}
	for _, d := range []struct {
		name string
		v    time.Duration
	}{{"HeartbeatInitialDelay", c.HeartbeatInitialDelay}, {"MaxAge", c.MaxAge}, {"MaxSkew", c.MaxSkew},
		{"GraftFloodThreshold", c.GraftFloodThreshold}} {
		if d.v < 0 {
			return invalid("%s %v must not be negative", d.name, d.v)
		}
	}
	if c.MaxAge > c.SeenTTL-c.MaxSkew {
		return invalid("MaxAge %v plus MaxSkew %v over SeenTTL %v", c.MaxAge, c.MaxSkew, c.SeenTTL)
	}
	for _, n := range []struct {
		name string
		v    int
	}{{"HistoryGossip", c.HistoryGossip}, {"MaxSeen", c.MaxSeen}, {"MaxCacheMessages", c.MaxCacheMessages},
		{"GossipRetransmission", c.GossipRetransmission}, {"OpportunisticGraftTicks", c.OpportunisticGraftTicks},
		{"OpportunisticGraftPeers", c.OpportunisticGraftPeers}, {"MaxIHaveLength", c.MaxIHaveLength},
		{"MaxIHaveMessages", c.MaxIHaveMessages}, {"MaxIDontWantLength", c.MaxIDontWantLength},
		{"MaxIDontWantMessages", c.MaxIDontWantMessages}, {"MaxIDontWantIDs", c.MaxIDontWantIDs},
		{"IDontWantTTL", c.IDontWantTTL}, {"MaxBackoff", c.MaxBackoff}, {"MaxRetained", c.MaxRetained},
		{"MaxValidating", c.MaxValidating}, {"MaxPeerValidating", c.MaxPeerValidating},
		{"MaxPeerValidatingBytes", c.MaxPeerValidatingBytes}, {"MaxIgnoredIDs", c.MaxIgnoredIDs},
		{"DesignRate", c.DesignRate}, {"MaxCerts", c.MaxCerts}, {"PrunePeers", c.PrunePeers}} {
		if n.v < 1 {
			return invalid("%s %d must be at least 1", n.name, n.v)
		}
	}
	for _, n := range []struct {
		name string
		v    int
	}{{"MaxPeers", c.MaxPeers}, {"MaxTopics", c.MaxTopics}, {"MaxPeerTopics", c.MaxPeerTopics}} {
		if n.v < 0 {
			return invalid("%s %d must not be negative", n.name, n.v)
		}
	}
	// A bucket holds WorkBurst of refill and may go below zero by a frame's work and a leave; 2^50 units (130 days
	// of a core) keeps every sum far from overflow.
	const maxWork = 1 << 50
	switch {
	case c.LockWork < newcomerShares || c.LockWork > maxWork || c.PeerWork < newcomerShares || c.PeerWork > maxWork ||
		c.ReaderWork < newcomerShares || c.ReaderWork > maxWork:
		return invalid("LockWork %d, ReaderWork %d and PeerWork %d must be %d to %d units per second", c.LockWork, c.ReaderWork, c.PeerWork, newcomerShares, int64(maxWork))
	case c.ReaderWork < c.PeerWork:
		return invalid("ReaderWork %d under PeerWork %d", c.ReaderWork, c.PeerWork)
	case c.WorkBurst < time.Second || c.WorkBurst > time.Hour:
		return invalid("WorkBurst %v outside 1s to 1h", c.WorkBurst)
	case c.MaxPeerValidatingBytes < c.MaxMessageSize:
		return invalid("MaxPeerValidatingBytes %d under MaxMessageSize %d", c.MaxPeerValidatingBytes, c.MaxMessageSize)
	case c.MaxPeerValidating > c.MaxValidating/2 || c.MaxPeerValidatingBytes > c.MaxValidatingBytes/2:
		return invalid("MaxPeerValidating %d and MaxPeerValidatingBytes %d over half of MaxValidating %d and MaxValidatingBytes %d",
			c.MaxPeerValidating, c.MaxPeerValidatingBytes, c.MaxValidating, c.MaxValidatingBytes)
	}
	switch {
	case c.HistoryLength < c.HistoryGossip:
		return invalid("HistoryLength %d under HistoryGossip %d", c.HistoryLength, c.HistoryGossip)
	case c.MaxMessageSize < minEnvelopeSize:
		return invalid("MaxMessageSize %d under the smallest envelope, %d", c.MaxMessageSize, minEnvelopeSize)
	case c.MaxCacheBytes < c.MaxMessageSize:
		return invalid("MaxCacheBytes %d under MaxMessageSize %d", c.MaxCacheBytes, c.MaxMessageSize)
	case c.MaxValidatingBytes < c.MaxMessageSize:
		return invalid("MaxValidatingBytes %d under MaxMessageSize %d", c.MaxValidatingBytes, c.MaxMessageSize)
	case c.MaxControlSize < minControlSize:
		return invalid("MaxControlSize %d under %d", c.MaxControlSize, minControlSize)
	case c.PeerExchange && !c.pruneFits():
		return invalid("MaxControlSize %d cannot hold a PRUNE with PrunePeers %d records", c.MaxControlSize, c.PrunePeers)
	}
	if err := c.checkIDontWant(&c.Params); err != nil {
		return err
	}
	if c.Score != nil {
		return c.Score.validate()
	}
	return nil
}

// pruneFits reports whether MaxControlSize holds the largest frame of one PRUNE entry we send with peer exchange:
// the eight list counts and the entry with PrunePeers records of the longest port, counted without overflow.
func (c *Config) pruneFits() bool {
	head := 8 + 32 + wire.UvarintLen(seconds(max(c.PruneBackoff, c.UnsubscribeBackoff))) + wire.UvarintLen(uint64(c.PrunePeers))
	record := wire.KeySize + 4 + wire.UvarintLen(65535)
	return c.MaxControlSize >= head && (c.MaxControlSize-head)/record >= c.PrunePeers
}

// checkIDontWant keeps IDONTWANT cheaper than the copies it saves: the threshold must exceed Dhi ids.
func (c *Config) checkIDontWant(p *Params) error {
	if c.IDontWantThreshold <= p.Dhi*wire.IDSize {
		return invalid("IDontWantThreshold %d not over Dhi times the id size", c.IDontWantThreshold)
	}
	return nil
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrInvalidConfig}, args...)...)
}

func finite(vs ...float64) bool {
	for _, v := range vs {
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return false
		}
	}
	return true
}
