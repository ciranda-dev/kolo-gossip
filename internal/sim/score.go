package sim

import (
	"fmt"
	"math"
	"reflect"
	"time"

	"github.com/ciranda-dev/kolo-gossip/internal/core"
)

// Knobs describe a score parameter set by what each term must do; Set turns them into parameters.
// Every penalty is sized by how many offences reach the graylist threshold on its own.
type Knobs struct {
	Name string

	Gossip    float64 // GossipThreshold, the score unit
	PublishX  float64 // PublishThreshold = PublishX x Gossip
	GraylistX float64 // GraylistThreshold = GraylistX x Gossip

	MeshTimeMax float64       // largest P1 contribution
	MeshTimeCap time.Duration // time in mesh at which P1 stops growing

	FirstWeight float64       // P2 weight
	FirstCap    float64       // P2 cap, in first deliveries
	FirstDecay  time.Duration // time for one first delivery to decay to zero

	MeshThreshold  float64       // P3 threshold in mesh deliveries; 0 turns P3 and P3b off
	MeshToNegative float64       // a full P3 deficit costs MeshToNegative x Gossip
	MeshActivation time.Duration // grace after a graft
	MeshDecay      time.Duration
	MeshWindow     time.Duration
	FailureX       float64       // P3b weight as a multiple of the P3 weight; 0 turns P3b off
	FailureDecay   time.Duration // P3b

	InvalidToGraylist float64 // invalid messages that alone reach the graylist
	InvalidDecay      time.Duration

	BehaviourThreshold float64 // P7 free offences
	BehaviourToGray    float64 // offences over the threshold that alone reach the graylist
	BehaviourDecay     time.Duration

	ColocationThreshold int     // peers on one IPv4 address without a penalty
	ColocationX         float64 // one peer over the threshold costs ColocationX x Gossip

	OpportunisticGraft float64 // threshold, in score units
}

// decayFactor is the per-DecayInterval factor that takes a counter of 1 to DecayToZero in d.
func decayFactor(d time.Duration) float64 {
	ticks := d.Seconds() / decayInterval.Seconds()
	return math.Pow(decayToZero, 1/ticks)
}

// DecayInterval and DecayToZero are the GossipSub v1.1 reference values.
const (
	decayInterval = time.Second
	decayToZero   = 0.01
)

// Set returns the parameters the knobs describe.
func (k Knobs) Set() *ScoreSet {
	g := &core.ScoreParams{
		Thresholds: core.Thresholds{
			Gossip:             k.Gossip,
			Publish:            k.PublishX * k.Gossip,
			Graylist:           k.GraylistX * k.Gossip,
			OpportunisticGraft: k.OpportunisticGraft,
		},
		TopicScoreCap: k.MeshTimeMax + k.FirstWeight*k.FirstCap,
		AppWeight:     1,
		DecayInterval: decayInterval,
		DecayToZero:   decayToZero,
	}
	g.Thresholds.AcceptPX = g.TopicScoreCap + 1 // above the topic scores: only a peer the application vouches for
	gray := -g.Thresholds.Graylist
	if k.ColocationX > 0 {
		g.IPColocationWeight = k.ColocationX * k.Gossip
		g.IPColocationThreshold = k.ColocationThreshold
	}
	if k.BehaviourToGray > 0 {
		g.BehaviourPenaltyWeight = -gray / (k.BehaviourToGray * k.BehaviourToGray)
		g.BehaviourPenaltyThreshold = k.BehaviourThreshold
		g.BehaviourPenaltyDecay = decayFactor(k.BehaviourDecay)
	}
	t := &core.TopicScoreParams{
		TopicWeight:                    1,
		InvalidMessageDeliveriesWeight: -gray / (k.InvalidToGraylist * k.InvalidToGraylist),
		InvalidMessageDeliveriesDecay:  decayFactor(k.InvalidDecay),
	}
	if k.MeshTimeMax > 0 {
		q := time.Second
		t.TimeInMeshQuantum = q
		t.TimeInMeshCap = k.MeshTimeCap.Seconds() / q.Seconds()
		t.TimeInMeshWeight = k.MeshTimeMax / t.TimeInMeshCap
	}
	if k.FirstWeight > 0 {
		t.FirstMessageDeliveriesWeight = k.FirstWeight
		t.FirstMessageDeliveriesCap = k.FirstCap
		t.FirstMessageDeliveriesDecay = decayFactor(k.FirstDecay)
	}
	if k.MeshThreshold > 0 {
		t.MeshMessageDeliveriesThreshold = k.MeshThreshold
		t.MeshMessageDeliveriesCap = 2 * k.MeshThreshold
		t.MeshMessageDeliveriesWeight = k.MeshToNegative * k.Gossip / (k.MeshThreshold * k.MeshThreshold)
		t.MeshMessageDeliveriesDecay = decayFactor(k.MeshDecay)
		t.MeshMessageDeliveriesActivation = k.MeshActivation
		t.MeshMessageDeliveriesWindow = k.MeshWindow
		if k.FailureX > 0 {
			t.MeshFailurePenaltyWeight = k.FailureX * t.MeshMessageDeliveriesWeight
			t.MeshFailurePenaltyDecay = decayFactor(k.FailureDecay)
		}
	}
	g.RetainScore = max(k.InvalidDecay, k.BehaviourDecay)
	if t.MeshFailurePenaltyWeight != 0 {
		g.RetainScore = max(g.RetainScore, k.FailureDecay)
	}
	return &ScoreSet{Name: k.Name, Global: g, Topic: t}
}

// ScoreByName returns the set named off (nil), default (the core defaults) or a candidate of Candidates.
func ScoreByName(name string) (*ScoreSet, error) {
	switch name {
	case "off":
		return nil, nil
	case "default":
		return &ScoreSet{Name: "default", Global: core.DefaultScore(), Topic: core.DefaultTopicScore()}, nil
	}
	for _, k := range Candidates() {
		if k.Name == name {
			return k.Set(), nil
		}
	}
	return nil, fmt.Errorf("sim: unknown score set %q", name)
}

// With returns k with the overrides in spec applied: comma-separated Field=value pairs, durations in Go syntax.
func (k Knobs) With(spec string) (Knobs, error) {
	if err := with(reflect.ValueOf(&k).Elem(), spec); err != nil {
		return k, err
	}
	if spec != "" {
		k.Name += "+" + spec
	}
	return k, nil
}

// KnobsByName returns a candidate's knobs.
func KnobsByName(name string) (Knobs, bool) {
	for _, k := range Candidates() {
		if k.Name == name {
			return k, true
		}
	}
	return Knobs{}, false
}
