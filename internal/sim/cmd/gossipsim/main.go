// Command gossipsim runs the kolo-gossip simulator scenarios and prints one JSON result per line.
//
//	go run ./internal/sim/cmd/gossipsim -scenario S1,S2 -n 1000 -seed 1 -score default
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/ciranda-dev/kolo-gossip/internal/sim"
)

func main() {
	scenarios := flag.String("scenario", "", "comma-separated scenario ids (S1 to S13, M1); empty runs all")
	n := flag.Int("n", 100, "honest nodes")
	seed := flag.Uint64("seed", 1, "seed")
	score := flag.String("score", "default", "score parameters: off, default, or a candidate name of -derive")
	knobs := flag.String("knobs", "", "overrides of a candidate's knobs, such as MeshThreshold=0,MeshActivation=5s")
	derive := flag.String("derive", "", "run a stage of the parameter search (mesh, graft, penalty, overlay) instead of scenarios")
	seeds := flag.Int("seeds", 2, "seeds per candidate in -derive")
	workers := flag.Int("workers", 3, "runs at once in -derive")
	maxHeap := flag.Uint64("maxheap", 0, "abort when the heap passes this many bytes (0: no limit)")
	overlay := flag.String("overlay", "", "honest overlay as overrides of the defaults, such as Dscore=6,GossipPeers=0 (0: no cap); empty: the defaults")
	topics := flag.Int("topics", 1, "topics in the network")
	rooms := flag.Int("rooms", 0, "topics each honest node joins, chosen at random; 0: all")
	busy := flag.Float64("busy", 0, "share of each workload published in topic 0, the rest spread over the topics")
	places := flag.Int("places", 64, "connection places of an honest node, half of them inbound")
	work := flag.Bool("work", true, "frames wait for the receiver's work buckets; false reproduces the traces recorded without them")
	loss := flag.Float64("loss", 0, "probability that a frame needs a retransmission")
	samples := flag.Bool("samples", false, "include every score sample in the results")
	flag.Parse()
	sim.KeepSamples = *samples
	if *maxHeap > 0 {
		sim.SetHeapLimit(*maxHeap)
	}
	enc := json.NewEncoder(os.Stdout)
	sim.Workers = *workers
	if *derive != "" {
		err := sim.Derive(*derive, *n, *seed, *seeds, func(v any) {
			if err := enc.Encode(v); err != nil {
				fatal(err)
			}
		})
		if err != nil {
			fatal(err)
		}
		return
	}
	set, err := sim.ScoreByName(*score)
	if err != nil {
		fatal(err)
	}
	if *knobs != "" {
		k, ok := sim.KnobsByName(*score)
		if !ok {
			fatal(fmt.Errorf("-knobs needs a candidate in -score, not %q", *score))
		}
		if k, err = k.With(*knobs); err != nil {
			fatal(err)
		}
		set = k.Set()
	}
	var ids []string
	if *scenarios != "" {
		ids = strings.Split(*scenarios, ",")
	}
	for _, id := range ids {
		if _, ok := sim.Find(id); !ok {
			fatal(fmt.Errorf("unknown scenario %q", id))
		}
	}
	fail := false
	for _, s := range sim.Scenarios {
		if len(ids) > 0 && !contains(ids, s.ID) {
			continue
		}
		o := sim.DefaultOptions(*seed)
		o.Loss = *loss
		o.Topics, o.Rooms, o.Busy, o.Work = *topics, *rooms, *busy, *work
		o.MaxPeers, o.MaxInbound = *places, *places/2
		c := sim.Case{Nodes: *n, Seed: *seed, Score: set, Opts: &o}
		if *overlay != "" {
			ov, err := sim.DefaultOverlay().With(*overlay)
			if err != nil {
				fatal(err)
			}
			c.Overlay = &ov
		}
		for _, r := range s.Run(c) {
			if err := enc.Encode(r); err != nil {
				fatal(err)
			}
			fail = fail || !r.Pass
		}
	}
	if fail {
		os.Exit(1)
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "gossipsim:", err)
	os.Exit(2)
}
