package core

import (
	"math"
	"time"
)

// The default score parameters come from the simulator's parameter search (internal/sim, Derive). The score unit is
// GossipThreshold; each penalty weight is graylist / k^2, where k is how many offences alone reach the graylist.
const (
	defaultGossip        = -10.0
	defaultGraylist      = 8 * defaultGossip
	defaultInvalidK      = 3  // invalid messages
	defaultBehaviourK    = 10 // behaviour offences over the threshold
	defaultBehaviourFree = 10 // behaviour offences without a penalty
	defaultFirstCap      = 10 // first deliveries
	defaultMeshTimeMax   = 1.0
	defaultPenaltyDecay  = 10 * time.Minute
)

// DefaultScore returns the global score parameters found by the simulator search; AppScore is the caller's.
func DefaultScore() *ScoreParams {
	return &ScoreParams{
		Thresholds: Thresholds{
			Gossip:             defaultGossip,
			Publish:            2 * defaultGossip,
			Graylist:           defaultGraylist,
			OpportunisticGraft: 3,
			AcceptPX:           defaultMeshTimeMax + defaultFirstCap + 1, // above TopicScoreCap: only a peer the application vouches for
		},
		TopicScoreCap:             defaultMeshTimeMax + defaultFirstCap,
		AppWeight:                 1,
		IPColocationWeight:        defaultGossip,
		IPColocationThreshold:     3,
		BehaviourPenaltyWeight:    defaultGraylist / (defaultBehaviourK * defaultBehaviourK),
		BehaviourPenaltyThreshold: defaultBehaviourFree,
		BehaviourPenaltyDecay:     decayOver(defaultPenaltyDecay),
		DecayInterval:             time.Second,
		DecayToZero:               0.01,
		RetainScore:               defaultPenaltyDecay,
	}
}

// DefaultTopicScore returns the topic score parameters found by the simulator search. P3 and P3b are off: the
// search found that they prune honest mesh peers in quiet rooms and slow repair under sybil floods.
func DefaultTopicScore() *TopicScoreParams {
	return &TopicScoreParams{
		TopicWeight:                    1,
		TimeInMeshWeight:               defaultMeshTimeMax / 3600,
		TimeInMeshQuantum:              time.Second,
		TimeInMeshCap:                  3600,
		FirstMessageDeliveriesWeight:   1,
		FirstMessageDeliveriesDecay:    decayOver(defaultPenaltyDecay),
		FirstMessageDeliveriesCap:      defaultFirstCap,
		InvalidMessageDeliveriesWeight: defaultGraylist / (defaultInvalidK * defaultInvalidK),
		InvalidMessageDeliveriesDecay:  decayOver(defaultPenaltyDecay),
	}
}

// decayOver returns the factor per one-second DecayInterval that takes a counter of 1 to DecayToZero 0.01 in d.
func decayOver(d time.Duration) float64 {
	return math.Pow(0.01, 1/(d.Seconds()/time.Second.Seconds()))
}
