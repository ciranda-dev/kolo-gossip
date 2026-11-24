package sim

import (
	"fmt"
	"math"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/ciranda-dev/kolo-gossip/internal/core"
)

// Overlay is the mesh family of the search: the overlay degrees, gossip emission, opportunistic grafting and the
// heartbeat of the honest nodes.
type Overlay struct {
	Name                      string
	D, Dlo, Dhi, Dscore, Dout int
	Dlazy                     int
	GossipFactor              float64
	GossipPeers               int           // most peers one heartbeat's IHAVE goes to per topic; 0: no cap
	HistoryGossip             int           // newest message cache windows announced in IHAVE
	Heartbeat                 time.Duration // heartbeat interval
	OpportunisticGraft        time.Duration // period, in whole heartbeats
	OpportunisticGraftPeers   int
}

// SpecOverlay is the start of the overlay search: the values of the GossipSub v1.0 and v1.1 parameter tables.
func SpecOverlay() Overlay {
	return Overlay{Name: "spec", D: 6, Dlo: 4, Dhi: 12, Dscore: 4, Dout: 2, Dlazy: 6, GossipFactor: 0.25,
		HistoryGossip: 3, Heartbeat: time.Second, OpportunisticGraft: time.Minute, OpportunisticGraftPeers: 2}
}

// DefaultOverlay is the overlay of the default router config.
func DefaultOverlay() Overlay { return overlayOf(core.DefaultConfig()) }

// apply sets the overlay in a router config.
func (o Overlay) apply(cfg *core.Config) {
	cfg.Params = core.Params{D: o.D, Dlo: o.Dlo, Dhi: o.Dhi, Dscore: o.Dscore, Dout: o.Dout, Dlazy: o.Dlazy,
		GossipFactor: o.GossipFactor, GossipPeers: o.GossipPeers}
	if o.GossipPeers == 0 {
		cfg.Params.GossipPeers = math.MaxInt32
	}
	cfg.HistoryGossip = o.HistoryGossip
	cfg.HeartbeatInterval = o.Heartbeat
	cfg.OpportunisticGraftTicks = max(1, int(o.OpportunisticGraft/o.Heartbeat))
	cfg.OpportunisticGraftPeers = o.OpportunisticGraftPeers
}

// overlayOf reads the overlay of a router config.
func overlayOf(cfg *core.Config) Overlay {
	p := cfg.Params
	if p.GossipPeers == math.MaxInt32 {
		p.GossipPeers = 0
	}
	return Overlay{D: p.D, Dlo: p.Dlo, Dhi: p.Dhi, Dscore: p.Dscore, Dout: p.Dout, Dlazy: p.Dlazy,
		GossipFactor: p.GossipFactor, GossipPeers: p.GossipPeers, HistoryGossip: cfg.HistoryGossip, Heartbeat: cfg.HeartbeatInterval,
		OpportunisticGraft:      time.Duration(cfg.OpportunisticGraftTicks) * cfg.HeartbeatInterval,
		OpportunisticGraftPeers: cfg.OpportunisticGraftPeers}
}

// With returns o with the overrides in spec applied: comma-separated Field=value pairs, durations in Go syntax.
func (o Overlay) With(spec string) (Overlay, error) {
	if err := with(reflect.ValueOf(&o).Elem(), spec); err != nil {
		return o, err
	}
	if spec != "" {
		o.Name += "+" + spec
	}
	return o, nil
}

// with applies Field=value overrides to the struct v; Name cannot be set.
func with(v reflect.Value, spec string) error {
	if spec == "" {
		return nil
	}
	for _, kv := range strings.Split(spec, ",") {
		name, val, ok := strings.Cut(kv, "=")
		f := v.FieldByName(name)
		if !ok || !f.IsValid() || name == "Name" {
			return fmt.Errorf("sim: bad knob %q", kv)
		}
		switch f.Interface().(type) {
		case time.Duration:
			d, err := time.ParseDuration(val)
			if err != nil {
				return fmt.Errorf("sim: knob %s: %w", name, err)
			}
			f.SetInt(int64(d))
		case int:
			n, err := strconv.Atoi(val)
			if err != nil {
				return fmt.Errorf("sim: knob %s: %w", name, err)
			}
			f.SetInt(int64(n))
		case float64:
			x, err := strconv.ParseFloat(val, 64)
			if err != nil || math.IsNaN(x) || math.IsInf(x, 0) {
				return fmt.Errorf("sim: knob %s: %q is not a finite number", name, val)
			}
			f.SetFloat(x)
		}
	}
	return nil
}

func overlayGrid(from Overlay, specs ...string) []Overlay {
	var out []Overlay
	for i := 0; i < len(specs); i += 2 {
		o, err := from.With(specs[i+1])
		if err != nil {
			panic(err)
		}
		o.Name = specs[i]
		out = append(out, o)
	}
	return out
}
