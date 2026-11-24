package sim

import (
	"fmt"
	"math"
	"slices"
	"sync"
	"time"
)

// start is the starting point of the search: the structure of gossipsub-v1.1.md (thresholds, squared penalties,
// counters that decay to zero over a window) with the unit GossipThreshold = -10 and the mesh setup of
// DefaultConfig.
func start() Knobs {
	return Knobs{Name: "start", Gossip: -10, PublishX: 2, GraylistX: 8,
		MeshTimeMax: 1, MeshTimeCap: time.Hour,
		FirstWeight: 1, FirstCap: 10, FirstDecay: 10 * time.Minute,
		MeshThreshold: 1, MeshToNegative: 0.5, MeshActivation: 10 * time.Second, MeshDecay: time.Minute,
		MeshWindow: 10 * time.Millisecond, FailureX: 1, FailureDecay: 10 * time.Minute,
		InvalidToGraylist: 3, InvalidDecay: 10 * time.Minute,
		BehaviourThreshold: 10, BehaviourToGray: 10, BehaviourDecay: 10 * time.Minute,
		ColocationThreshold: 3, ColocationX: 1, OpportunisticGraft: 1}
}

func grid(from Knobs, specs ...string) []Knobs {
	var out []Knobs
	for i := 0; i < len(specs); i += 2 {
		k, err := from.With(specs[i+1])
		if err != nil {
			panic(err)
		}
		k.Name = specs[i]
		out = append(out, k)
	}
	return out
}

// meshGrid is stage 1: the mesh terms (P1, P2, P3, P3b) and the opportunistic graft threshold.
func meshGrid() []Knobs {
	return grid(start(),
		"p3-off", "MeshThreshold=0",
		"p3-off-p2-1h", "MeshThreshold=0,FirstDecay=1h",
		"p3-off-og-5", "MeshThreshold=0,OpportunisticGraft=5",
		"p3-10s", "FailureX=0",
		"p3-10s-p3b-1m", "FailureDecay=1m",
		"p3-10s-p3b-10m", "FailureX=1",
		"p3-10s-p3b-10m-w200", "MeshWindow=200ms",
		"p3-30s-p3b-10m", "MeshActivation=30s",
		"p3-10s-p3b-10m-t05", "MeshThreshold=0.5",
		"p3-10s-p3b-10m-p2-1h-og-5", "FirstDecay=1h,OpportunisticGraft=5")
}

// stage1 is the winner of stage 1.
const stage1 = "MeshThreshold=0,OpportunisticGraft=5"

// graftGrid is stage 2: the opportunistic graft threshold and the P2 cap around the stage 1 winner.
func graftGrid() []Knobs {
	from, _ := start().With(stage1)
	return grid(from,
		"og-3", "OpportunisticGraft=3",
		"og-5", "OpportunisticGraft=5",
		"og-10", "OpportunisticGraft=10",
		"og-5-cap-30", "FirstCap=30",
		"og-10-cap-30", "OpportunisticGraft=10,FirstCap=30")
}

// stage2 is the winner of stage 2.
const stage2 = "MeshThreshold=0,OpportunisticGraft=3"

// penaltyGrid is stage 3: thresholds and the penalty terms P4, P6 and P7 around the stage 2 winner.
func penaltyGrid() []Knobs {
	from, _ := start().With(stage2)
	return grid(from,
		"pen-start", "GraylistX=8",
		"pen-gray-4", "GraylistX=4",
		"pen-gray-16", "GraylistX=16",
		"pen-p4-6", "InvalidToGraylist=6",
		"pen-p7-t2", "BehaviourThreshold=2",
		"pen-p7-k20", "BehaviourToGray=20",
		"pen-decay-1m", "InvalidDecay=1m,BehaviourDecay=1m",
		"pen-col-2", "ColocationThreshold=2")
}

// stage3 is the winner of stage 3.
const stage3 = stage2

// chosen returns the default knobs: start with the winners of every stage.
func chosen() Knobs {
	k, err := start().With(stage3)
	if err != nil {
		panic(err)
	}
	k.Name = "chosen"
	return k
}

// overlayScenarios are the scenarios of the overlay stages: every exit criterion the overlay can change.
var overlayScenarios = []string{"S1", "S2", "S3", "S7", "S8", "S10", "S11", "S12"}

// overlayStage1 is the first overlay stage: each spec value and its neighbours, one at a time, then the paper's
// overlay and the combinations the single changes suggest.
func overlayStage1() []Overlay {
	return overlayGrid(SpecOverlay(),
		"spec", "D=6",
		"dlo-5", "Dlo=5",
		"dscore-5", "Dscore=5",
		"dscore-6", "Dscore=6",
		"dout-3", "Dout=3",
		"dlazy-12", "Dlazy=12",
		"gf-0.5", "GossipFactor=0.5",
		"gf-1", "GossipFactor=1",
		"hg-5", "HistoryGossip=5",
		"og-30s", "OpportunisticGraft=30s",
		"og-peers-4", "OpportunisticGraftPeers=4",
		"hb-500ms", "Heartbeat=500ms",
		"paper", "D=8,Dlo=6,Dscore=6,Dlazy=8",
		"dscore-6-gf-0.5", "Dscore=6,GossipFactor=0.5",
		"dscore-5-gf-0.5", "Dscore=5,GossipFactor=0.5",
		"dscore-6-gf-1", "Dscore=6,GossipFactor=1")
}

// overlayStage2 is the second overlay stage, run at 10,000 nodes on the scenarios the first stage could not
// separate: the gossip factors that delivered, alone and with Dscore 6.
func overlayStage2() []Overlay {
	return overlayGrid(SpecOverlay(),
		"gf-1", "GossipFactor=1",
		"gf-0.75", "GossipFactor=0.75",
		"dscore-6", "Dscore=6",
		"dscore-6-gf-0.75", "Dscore=6,GossipFactor=0.75",
		"dscore-6-gf-1", "Dscore=6,GossipFactor=1")
}

// overlayStage3 checks the two winners of stage 2 at 1,000 nodes on every overlay scenario, as stage 1 did.
func overlayStage3() []Overlay {
	return overlayGrid(SpecOverlay(),
		"dscore-6-gf-0.75", "Dscore=6,GossipFactor=0.75",
		"dscore-6-gf-1", "Dscore=6,GossipFactor=1")
}

// chosenOverlay returns the default overlay: the spec values with the winners of every overlay stage.
func chosenOverlay() Overlay {
	o, err := SpecOverlay().With(overlayChosen)
	if err != nil {
		panic(err)
	}
	o.Name = "chosen"
	return o
}

// overlayChosen is the winner of the overlay stages.
const overlayChosen = "Dscore=6,GossipFactor=0.75,GossipPeers=43"

// Stage is one step of the search: score candidates on the default overlay, or overlay candidates with the
// default score parameters.
type Stage struct {
	Name       string
	Candidates func() []Knobs
	Scenarios  []string
	Overlays   func() []Overlay
}

// Stages are the steps of the search, in order.
var Stages = []Stage{
	{Name: "mesh", Candidates: meshGrid, Scenarios: []string{"S1", "S2", "S4", "S7", "S8", "S10"}},
	{Name: "graft", Candidates: graftGrid, Scenarios: []string{"S1", "S2", "S10"}},
	{Name: "penalty", Candidates: penaltyGrid, Scenarios: []string{"S4", "S5", "S7", "S8", "S11"}},
	{Name: "overlay", Overlays: overlayStage1, Scenarios: overlayScenarios},
	{Name: "overlay2", Overlays: overlayStage2, Scenarios: []string{"S2", "S10"}},
	{Name: "overlay3", Overlays: overlayStage3, Scenarios: overlayScenarios},
}

// Candidates returns every knob set the search defines; the first is the chosen default.
func Candidates() []Knobs {
	out := []Knobs{chosen(), start()}
	for _, st := range Stages {
		if st.Candidates != nil {
			out = append(out, st.Candidates()...)
		}
	}
	return out
}

// Overlays returns every overlay the search defines; the first is the chosen default.
func Overlays() []Overlay {
	out := []Overlay{chosenOverlay(), SpecOverlay()}
	for _, st := range Stages {
		if st.Overlays != nil {
			out = append(out, st.Overlays()...)
		}
	}
	return out
}

// Row is one run of one candidate in the search.
type Row struct {
	Candidate string  `json:"candidate"`
	Seed      uint64  `json:"seed"`
	Result    Result  `json:"result"`
	FullShare float64 `json:"full_share"`
}

// Rank is a candidate's summary over all its rows, compared in field order.
type Rank struct {
	Candidate       string  `json:"candidate"`
	HonestGraylist  int     `json:"honest_graylisted_pairs"`
	CleanFailures   int     `json:"clean_failures"`
	Failures        int     `json:"failed_pass_criteria"`
	MissedShare     float64 `json:"missed_message_share"`
	GraylistSeconds float64 `json:"attacker_graylist_seconds"`
	CleanP99        float64 `json:"clean_p99_ms"`
	CleanB          float64 `json:"clean_b"`
	CleanRMR        float64 `json:"clean_rmr"`
	HonestNegative  int     `json:"honest_negative_pairs"`
	AttackInMeshEnd int     `json:"attacker_mesh_slots_at_end"`
	Runs            int     `json:"runs"`
}

func better(a, b Rank) bool {
	switch {
	case a.HonestGraylist != b.HonestGraylist:
		return a.HonestGraylist < b.HonestGraylist
	case a.CleanFailures != b.CleanFailures:
		return a.CleanFailures < b.CleanFailures
	case a.Failures != b.Failures:
		return a.Failures < b.Failures
	case a.MissedShare != b.MissedShare:
		return a.MissedShare < b.MissedShare
	case a.GraylistSeconds != b.GraylistSeconds:
		return a.GraylistSeconds < b.GraylistSeconds
	case math.Round(a.CleanP99) != math.Round(b.CleanP99):
		// Whole milliseconds, the resolution results are reported in: a smaller difference is no measurable gain.
		return a.CleanP99 < b.CleanP99
	}
	return a.CleanB < b.CleanB
}

// graylistRoles are the attackers that must end below the graylist threshold; noGraylist is the time counted
// for one that never does.
var graylistRoles = map[string]bool{IHaveSpam.String(): true, InvalidSpam.String(): true, RejectSpam.String(): true,
	ForgeSig.String(): true, ForgePerson.String(): true, Revoked.String(): true}

const noGraylist = 1000.0

// graylistBound is the time within which an attacker must be graylisted; faster counts the same, so a start
// value only changes for a measurable gain.
const graylistBound = 10 * time.Second

// Workers is how many runs Derive keeps going at once; each run is single-threaded and deterministic.
var Workers = 3

// Derive runs one stage of the score search: every candidate of the stage on its scenarios, seeds seed to
// seed+seeds-1, at n nodes. It emits every Row, then the Ranks best first.
func Derive(stage string, n int, seed uint64, seeds int, out func(any)) error {
	var st *Stage
	for i := range Stages {
		if Stages[i].Name == stage {
			st = &Stages[i]
		}
	}
	if st == nil {
		return fmt.Errorf("sim: no stage %q", stage)
	}
	type cand struct {
		name    string
		score   *ScoreSet
		overlay *Overlay
	}
	var cands []cand
	if st.Overlays != nil {
		for _, o := range st.Overlays() {
			cands = append(cands, cand{o.Name, chosen().Set(), &o})
		}
	} else {
		for _, k := range st.Candidates() {
			cands = append(cands, cand{k.Name, k.Set(), nil})
		}
	}
	type job struct {
		c    cand
		seed uint64
		sc   Scenario
	}
	var jobs []job
	for _, c := range cands {
		for s := seed; s < seed+uint64(seeds); s++ {
			for _, id := range st.Scenarios {
				sc, ok := Find(id)
				if !ok {
					return fmt.Errorf("sim: no scenario %s", id)
				}
				jobs = append(jobs, job{c, s, sc})
			}
		}
	}
	rows := make([][]Row, len(jobs))
	var wg sync.WaitGroup
	next := make(chan int)
	var mu sync.Mutex
	for range Workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				j := jobs[i]
				for _, r := range j.sc.Run(Case{Nodes: n, Seed: j.seed, Score: j.c.score, Overlay: j.c.overlay}) {
					row := Row{Candidate: j.c.name, Seed: j.seed, Result: r}
					if r.Delivery.Messages > 0 {
						row.FullShare = float64(r.Delivery.Full) / float64(r.Delivery.Messages)
					}
					rows[i] = append(rows[i], row)
					mu.Lock()
					out(row)
					mu.Unlock()
				}
			}
		}()
	}
	for i := range jobs {
		next <- i
	}
	close(next)
	wg.Wait()
	ranks := map[string]*Rank{}
	for _, rs := range rows {
		for _, row := range rs {
			rk := ranks[row.Candidate]
			if rk == nil {
				rk = &Rank{Candidate: row.Candidate}
				ranks[row.Candidate] = rk
			}
			r := row.Result
			rk.Runs++
			rk.HonestGraylist += r.Honest.MaxBelowGraylist
			rk.Failures += len(r.Failures)
			rk.MissedShare += 1 - row.FullShare
			rk.HonestNegative = max(rk.HonestNegative, r.Honest.MaxNegative)
			for _, a := range r.Attack {
				rk.AttackInMeshEnd += a.MeshSlotsLast
				if graylistRoles[a.Role] {
					t := a.AllGraylisted
					if t < 0 {
						t = noGraylist
					}
					rk.GraylistSeconds += max(t, graylistBound.Seconds())
				}
			}
			if r.Scenario == "S1" {
				rk.CleanFailures += len(r.Failures)
				rk.CleanP99 = max(rk.CleanP99, r.Delivery.P99)
				rk.CleanB = max(rk.CleanB, r.Overhead.B)
				rk.CleanRMR = max(rk.CleanRMR, r.Delivery.RMR)
			}
		}
	}
	var list []Rank
	for _, c := range cands {
		list = append(list, *ranks[c.name])
	}
	slices.SortStableFunc(list, func(a, b Rank) int {
		switch {
		case better(a, b):
			return -1
		case better(b, a):
			return 1
		}
		return 0
	})
	for _, r := range list {
		out(r)
	}
	return nil
}
