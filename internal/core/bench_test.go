package core

import (
	"sort"
	"testing"

	"github.com/ciranda-dev/kolo-gossip/internal/wire"
)

// BenchmarkPaths runs each audited handler path with its most expensive frame on a fresh router and reports the
// time it takes and the units it charges, under the lock and on the reader, and in all but the signature check
// (the test verifier checks none): a path is calibrated when ns/op is at most 10 x units/op.
func BenchmarkPaths(b *testing.B) {
	names := make([]string, 0, len(auditPaths))
	for name := range auditPaths {
		names = append(names, name)
	}
	sort.Strings(names)
	// The baseline is the cost of the timer stops and starts of one iteration, which every path includes.
	auditPaths["~baseline"] = func(t *testing.T) (*fixture, func()) { return meshFixture(t, nil, 1, 0), func() {} }
	defer delete(auditPaths, "~baseline")
	names = append(names, "~baseline")
	for _, name := range names {
		b.Run(name, func(b *testing.B) {
			var units, lock, reader int64
			for b.Loop() {
				b.StopTimer()
				f, send := auditPaths[name](&testing.T{})
				f.sink.bench = true
				f.r.AuditOps()
				b.StartTimer()
				send()
				b.StopTimer()
				_, charged := f.r.Audit()
				for op, n := range charged {
					c := Cost(op, int(n))
					if op.outside() {
						reader += c
					} else {
						lock += c
					}
					if op != OpSignature && op != OpSigBytes {
						units += c
					}
				}
				b.StartTimer()
			}
			b.ReportMetric(float64(units)/float64(b.N), "units/op")
			b.ReportMetric(float64(lock)/float64(b.N), "lock-units/op")
			b.ReportMetric(float64(reader)/float64(b.N), "reader-units/op")
			// The calibration: measured time per charged unit; at most 10 means the units cover the work.
			if units > 0 {
				b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(units), "ns/unit")
			}
		})
	}
}

// BenchmarkDuplicate measures a copy of a message we hold, the cheapest message frame, without a fresh router.
func BenchmarkDuplicate(b *testing.B) {
	f := meshFixture(&testing.T{}, nil, 2, 0)
	f.sink.bench = true
	raw := envelope(T, key(9), 1, f.now, 1000)
	f.receive(2, raw, Accept)
	id := wire.NewID(raw)
	p := f.r.byID[key(1)]
	before := p.lock.level + p.out.level
	for b.Loop() {
		f.r.MessageWithID(f.now, key(1), raw, id)
	}
	b.ReportMetric(float64(before-p.lock.level-p.out.level)/float64(b.N), "units/op")
}

// BenchmarkEmptyControl measures an empty control frame without a fresh router.
func BenchmarkEmptyControl(b *testing.B) {
	f := meshFixture(&testing.T{}, nil, 1, 0)
	c := &wire.Control{}
	p := f.r.byID[key(1)]
	before := p.lock.level + p.out.level
	for b.Loop() {
		if err := f.r.ControlFrame(f.now, key(1), c, 0); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(before-p.lock.level-p.out.level)/float64(b.N), "units/op")
}

// BenchmarkScoreLookup measures the score check a frame makes, with an application score cached for the heartbeat.
func BenchmarkScoreLookup(b *testing.B) {
	cfg := scoringConfig()
	cfg.Score.AppScore = func(PeerID) float64 { return 0 }
	f := newFixture(&testing.T{}, cfg)
	f.join(T, &TopicConfig{Score: topicScore()})
	f.addPeers(1, T)
	for b.Loop() {
		f.r.scoreOf(key(1))
	}
}

// BenchmarkIDontWant measures an IDONTWANT of one id within MaxIDontWantMessages, without a fresh router.
func BenchmarkIDontWant(b *testing.B) {
	f := meshFixture(&testing.T{}, nil, 1, 0)
	c := &wire.Control{IDontWant: ids(4, 1)}
	p := f.r.byID[key(1)]
	before := p.lock.level + p.out.level
	for b.Loop() {
		p.dontwant = 0
		if err := f.r.ControlFrame(f.now, key(1), c, 41); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(before-p.lock.level-p.out.level)/float64(b.N), "units/op")
}

// BenchmarkIgnoredCopy measures a copy of a message ignored for its author, without a fresh router.
func BenchmarkIgnoredCopy(b *testing.B) {
	f := meshFixture(&testing.T{}, nil, 2, 0)
	raw := markedEnvelope(1, f.now, unknownSig)
	f.r.Message(f.now, key(2), raw)
	id := wire.NewID(raw)
	p := f.r.byID[key(1)]
	before := p.lock.level + p.out.level
	for b.Loop() {
		f.r.MessageWithID(f.now, key(1), raw, id)
	}
	b.ReportMetric(float64(before-p.lock.level-p.out.level)/float64(b.N), "units/op")
}

// BenchmarkWarm measures message paths on a router that has seen many such frames, 1,000 new envelopes at a time
// built outside the timer, and reports the lock units each charges.
func BenchmarkWarm(b *testing.B) {
	for name, c := range map[string]struct {
		setup func() *fixture
		raw   func(f *fixture, seq uint64) []byte
	}{
		"message waiting for its author's chain": {
			func() *fixture {
				f := resolverFixture(&testing.T{}, nil, &stubResolver{want: &wire.CertWant{}})
				f.join(T, nil)
				f.addPeers(1, T)
				return f
			},
			func(f *fixture, seq uint64) []byte { return markedEnvelope(seq, f.now, unresolvedSig) },
		},
		"bad signature": {
			func() *fixture { cfg := DefaultConfig(); cfg.Score = nil; return meshFixture(&testing.T{}, cfg, 1, 0) },
			func(f *fixture, seq uint64) []byte { return badEnvelope(T, key(9), seq, f.now) },
		},
		"throttled message": {
			func() *fixture {
				cfg := DefaultConfig()
				cfg.MaxPeerValidating = 1
				f := meshFixture(&testing.T{}, cfg, 1, 0)
				f.r.Message(f.now, key(1), envelope(T, key(9), 1<<40, f.now, 1))
				return f
			},
			func(f *fixture, seq uint64) []byte { return envelope(T, key(9), seq, f.now, 1000) },
		},
		"new message accepted, evicting from a full cache": {
			func() *fixture {
				cfg := DefaultConfig()
				cfg.MaxCacheMessages = 100
				cfg.MaxSeen = 1 << 30
				return meshFixture(&testing.T{}, cfg, 13, 12)
			},
			func(f *fixture, seq uint64) []byte { return envelope(T, key(9), seq, f.now, 1000) },
		},
	} {
		b.Run(name, func(b *testing.B) {
			f := c.setup()
			f.sink.bench = true
			const batch = 1000
			calls := make([]func(), batch)
			var seq uint64
			var lock int64
			for b.Loop() {
				b.StopTimer()
				for i := range calls {
					seq++
					calls[i] = f.driverMessage(1, c.raw(f, seq), Accept)
				}
				f.r.AuditOps()
				b.StartTimer()
				for _, call := range calls {
					call()
				}
				b.StopTimer()
				_, charged := f.r.Audit()
				for op, n := range charged {
					if !op.outside() {
						lock += Cost(op, int(n))
					}
				}
				f.sink.validate = f.sink.validate[:0]
				b.StartTimer()
			}
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/batch, "ns/frame")
			b.ReportMetric(float64(lock)/float64(b.N)/batch, "lock-units/frame")
		})
	}
}
