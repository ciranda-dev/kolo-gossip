//go:build simscale

package sim

import (
	"encoding/json"
	"flag"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

var (
	scaleNodes     = flag.String("sim.nodes", "1000,10000", "comma-separated network sizes")
	scaleScenarios = flag.String("sim.scenarios", "", "comma-separated scenario ids; empty runs all")
	scaleSeed      = flag.Uint64("sim.seed", 1, "seed")
	scaleMaxHeap   = flag.Uint64("sim.maxheap", 0, "abort a run whose heap passes this many bytes")
	scaleTopics    = flag.Int("sim.topics", 1, "topics in the network")
	scalePlaces    = flag.Int("sim.places", 64, "connection places of an honest node, half of them inbound")
)

// TestScale runs the exit-criteria scenarios with the default score parameters and prints
// one JSON result per line, prefixed with SIMRESULT. S13 is report only.
func TestScale(t *testing.T) {
	SetHeapLimit(*scaleMaxHeap)
	defer SetHeapLimit(0)
	var ids []string
	if *scaleScenarios != "" {
		ids = strings.Split(*scaleScenarios, ",")
	}
	set, err := ScoreByName("default")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range strings.Split(*scaleNodes, ",") {
		n, err := strconv.Atoi(f)
		if err != nil {
			t.Fatal(err)
		}
		o := DefaultOptions(*scaleSeed)
		o.Topics, o.MaxPeers, o.MaxInbound = *scaleTopics, *scalePlaces, *scalePlaces/2
		results, err := Run(ids, Case{Nodes: n, Seed: *scaleSeed, Score: set, Opts: &o})
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range results {
			b, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			fmt.Printf("SIMRESULT %s\n", b)
			if !r.Pass && r.Scenario != "S13" {
				t.Errorf("%s %s at %d nodes: %v", r.Scenario, r.Variant, n, r.Failures)
			}
		}
	}
}
