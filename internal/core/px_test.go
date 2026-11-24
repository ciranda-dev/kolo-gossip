package core

import (
	"errors"
	"math"
	"net/netip"
	"testing"
	"time"

	"github.com/ciranda-dev/kolo-gossip/internal/wire"
)

// pxRecs returns n peer exchange records for keys from first on.
func pxRecs(first, n int) []wire.PeerRecord {
	recs := make([]wire.PeerRecord, n)
	for i := range recs {
		recs[i] = wire.PeerRecord{Key: wire.Key(key(first + i)), Addr: addr(first + i)}
	}
	return recs
}

// pxFixture is meshFixture with scoring on and an application score of 20 for peer 1, over AcceptPX 12.
func pxFixture(t *testing.T, tweak func(*Config)) *fixture {
	cfg := DefaultConfig()
	cfg.Score.AppScore = func(p PeerID) float64 {
		if p == key(1) {
			return 20
		}
		return 0
	}
	if tweak != nil {
		tweak(cfg)
	}
	return meshFixture(t, cfg, 3, 3)
}

// TestPXAccepted: the peer exchange of a PRUNE from a peer at or above AcceptPX is passed on to dial, without our
// own key, connected peers and repeats, and its sender pays for each dial on its reader bucket.
func TestPXAccepted(t *testing.T) {
	f := pxFixture(t, nil)
	recs := append(pxRecs(100, 3), wire.PeerRecord{Key: wire.Key(key(0)), Addr: addr(0)},
		wire.PeerRecord{Key: wire.Key(key(2)), Addr: addr(2)}, pxRecs(100, 1)[0])
	f.r.AuditPeer(key(1))
	f.control(1, &wire.Control{Prune: []wire.Prune{{Topic: T, PX: recs}}})
	if len(f.sink.dials) != 1 || f.sink.dials[0].from != key(1) || f.sink.dials[0].topic != T || len(f.sink.dials[0].recs) != 3 {
		t.Fatalf("dials %+v", f.sink.dials)
	}
	for _, rec := range f.sink.dials[0].recs {
		if k := PeerID(rec.Key); k == key(0) || k == key(2) {
			t.Fatalf("record for %x passed on", k[:4])
		}
	}
	if _, charged := f.r.Audit(); charged[OpDial] != 3 {
		t.Fatalf("%d dials charged for 3", charged[OpDial])
	}
	if f.r.Stats().PXAccepted != 3 {
		t.Fatal("PXAccepted not counted")
	}
}

// TestPXRefused: peer exchange is not dialed from a peer below AcceptPX, for a topic we are not in, or with
// scoring off.
func TestPXRefused(t *testing.T) {
	f := pxFixture(t, nil)
	f.control(2, &wire.Control{Prune: []wire.Prune{{Topic: T, PX: pxRecs(100, 2)}}})
	f.control(1, &wire.Control{Prune: []wire.Prune{{Topic: topicID(9), PX: pxRecs(100, 2)}}})
	if len(f.sink.dials) != 0 {
		t.Fatalf("dials %+v", f.sink.dials)
	}
}

// TestPXScoringOff: with scoring off no peer exchange is dialed: nothing vouches for the sender.
func TestPXScoringOff(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Score = nil
	f := meshFixture(t, cfg, 2, 2)
	f.control(1, &wire.Control{Prune: []wire.Prune{{Topic: T, PX: pxRecs(100, 2)}}})
	if len(f.sink.dials) != 0 {
		t.Fatalf("dials %+v", f.sink.dials)
	}
}

// TestPXCapped: at most PrunePeers records of one PRUNE entry are dialed.
func TestPXCapped(t *testing.T) {
	f := pxFixture(t, nil)
	f.control(1, &wire.Control{Prune: []wire.Prune{{Topic: T, PX: pxRecs(100, 40)}}})
	if len(f.sink.dials) != 1 || len(f.sink.dials[0].recs) != 16 {
		t.Fatalf("dials %+v", f.sink.dials)
	}
}

// TestPXEmission: with PeerExchange on, a PRUNE for an oversubscribed mesh, for Leave and for a GRAFT refused
// because the mesh is full lists up to PrunePeers peers of the topic with an address and a score of at least 0,
// never the pruned peer; a GRAFT in backoff, a negative score or a GRAFT for a topic we are not in gets none.
func TestPXEmission(t *testing.T) {
	cfg := DefaultConfig()
	cfg.PeerExchange = true
	cfg.Params.Dhi = 4
	cfg.Params.D, cfg.Params.Dlo, cfg.Params.Dscore, cfg.Params.Dout = 3, 2, 2, 1
	cfg.IDontWantThreshold = 1024
	f := newFixture(t, cfg)
	f.join(T, nil)
	f.addPeers(8, T)
	if err := f.r.AddPeer(f.now, key(9), true, netip.AddrPort{}); err != nil { // relayed: no address to offer
		t.Fatal(err)
	}
	f.control(9, &wire.Control{Subs: []wire.Sub{{Topic: T, Subscribe: true}}})
	if err := f.r.AddPeer(f.now, key(10), true, netip.AddrPortFrom(ip(10), 0)); err != nil { // its port unknown
		t.Fatal(err)
	}
	f.control(10, &wire.Control{Subs: []wire.Sub{{Topic: T, Subscribe: true}}})
	for i := 1; i <= 9; i++ {
		f.control(i, &wire.Control{Graft: []wire.Topic{T}})
	}
	check := func(what string, pr []wire.Prune, to PeerID) {
		t.Helper()
		if len(pr) == 0 || len(pr[0].PX) == 0 {
			t.Fatalf("%s: no peer exchange in %+v", what, pr)
		}
		for _, rec := range pr[0].PX {
			if k := PeerID(rec.Key); k == to || k == key(9) || k == key(10) || rec.Addr.Port() == 0 {
				t.Fatalf("%s: record %x %v offered to %x", what, k[:4], rec.Addr, to[:4])
			}
		}
	}
	// Inbound GRAFTs past Dhi were refused for a full mesh.
	refused := 0
	for i := 2; i <= 8; i += 2 {
		if pr := f.sink.prunesTo(key(i), T); len(pr) > 0 {
			check("full mesh", pr, key(i))
			refused++
		}
	}
	if refused == 0 {
		t.Fatal("no GRAFT refused for a full mesh")
	}
	f.sink.reset()
	f.control(6, &wire.Control{Graft: []wire.Topic{T}}) // in backoff now
	if pr := f.sink.prunesTo(key(6), T); len(pr) != 1 || len(pr[0].PX) != 0 {
		t.Fatalf("GRAFT in backoff: %+v", pr)
	}
	f.sink.reset()
	f.r.backoff.m[T].m = map[PeerID]backoffEntry{}
	f.control(8, &wire.Control{Graft: []wire.Topic{T, topicID(7)}})
	if len(f.sink.prunesTo(key(8), T)) == 0 {
		t.Fatal("no PRUNE for a full mesh")
	}
	for _, pr := range f.sink.prunesTo(key(8), T) {
		if len(pr.PX) != 0 {
			t.Fatal("peer exchange with a GRAFT for a topic we are not in")
		}
	}
	f.sink.reset()
	f.r.Leave(f.now, T)
	for _, p := range []int{1, 3, 5, 7} {
		if pr := f.sink.prunesTo(key(p), T); len(pr) > 0 {
			check("leave", pr, key(p))
			return
		}
	}
	t.Fatal("no PRUNE on Leave")
}

// TestPXHeartbeat: the heartbeat's PRUNE of an oversubscribed mesh carries peer exchange, the PRUNE of a peer with a
// negative score none.
func TestPXHeartbeat(t *testing.T) {
	cfg := scoringConfig()
	cfg.PeerExchange = true
	f := newFixture(t, cfg)
	f.join(T, &TopicConfig{Score: topicScore()})
	f.addPeers(20, T)
	for i := 1; i <= 20; i++ { // past Dhi only the outbound (odd) peers are taken
		f.control(i, &wire.Control{Graft: []wire.Topic{T}})
	}
	if len(f.r.Mesh(T)) <= f.r.cfg.Params.Dhi {
		t.Fatalf("mesh of %d not oversubscribed", len(f.r.Mesh(T)))
	}
	f.r.score.penalty(key(1), 10)
	f.sink.reset()
	f.heartbeat()
	if pr := f.sink.prunesTo(key(1), T); len(pr) != 1 || len(pr[0].PX) != 0 {
		t.Fatalf("negative score PRUNE: %+v", pr)
	}
	with := 0
	for i := 2; i <= 20; i++ {
		if pr := f.sink.prunesTo(key(i), T); len(pr) == 1 && len(pr[0].PX) > 0 {
			with++
		}
	}
	if with == 0 {
		t.Fatal("no oversubscription PRUNE with peer exchange")
	}
}

// TestPXOffByDefault: by default the PRUNE we send has no peer exchange.
func TestPXOffByDefault(t *testing.T) {
	f := meshFixture(t, nil, 3, 3)
	f.r.Leave(f.now, T)
	for i := 1; i <= 3; i++ {
		for _, pr := range f.sink.prunesTo(key(i), T) {
			if len(pr.PX) != 0 {
				t.Fatal("peer exchange sent by default")
			}
		}
	}
}

// TestGoneExpiry: what is kept for a key that left is dropped RetainScore after it left, and the oldest key first
// past MaxRetained.
func TestGoneExpiry(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxRetained = 2
	f := meshFixture(t, cfg, 4, 0)
	for i := 1; i <= 3; i++ {
		f.r.byID[key(i)].lock.level = -1
		f.r.RemovePeer(f.now, key(i))
	}
	if f.r.gone.m[key(1)] != nil || f.r.gone.m[key(2)] == nil || f.r.gone.m[key(3)] == nil {
		t.Fatal("the oldest key was not the one dropped")
	}
	f.tick(cfg.Score.RetainScore - time.Second)
	if len(f.r.gone.m) != 2 {
		t.Fatal("dropped before RetainScore")
	}
	f.tick(2 * time.Second)
	if len(f.r.gone.m) != 0 || len(f.r.gone.q) != 0 {
		t.Fatalf("%d kept after RetainScore", len(f.r.gone.m))
	}
}

// TestAskPrepaysHedge: an ask pays when it is made for the heartbeats that look at it.
func TestAskPrepaysHedge(t *testing.T) {
	f := meshFixture(t, nil, 1, 0)
	f.r.AuditPeer(key(1))
	f.control(1, &wire.Control{IHave: []wire.IHave{{Topic: T, IDs: fakeIDs(1, 100)}}})
	if _, charged := f.r.Audit(); charged[OpLookup] < int64(100*f.r.hedgeLookups()) {
		t.Fatalf("%d lookups charged for 100 asks", charged[OpLookup])
	}
}

// TestCanceledVerdictFrees: the verdict of a validation the router dropped frees its place in the global bounds.
func TestCanceledVerdictFrees(t *testing.T) {
	f := meshFixture(t, nil, 1, 0)
	f.r.Message(f.now, key(1), envelope(T, key(900), 1, f.now, 10))
	f.r.Leave(f.now, T)
	if len(f.sink.canceled) != 1 || f.sink.canceled[0] != f.sink.validate[0].n || f.r.Stats().Validating != 1 {
		t.Fatalf("canceled %v, %d validating", f.sink.canceled, f.r.Stats().Validating)
	}
	f.done(0, Accept)
	if s := f.r.Stats(); s.Validating != 0 || s.Delivered != 0 {
		t.Fatalf("%+v", s)
	}
}

// TestPXAuditPaths: the audited peer exchange paths do what they are named for.
func TestPXAuditPaths(t *testing.T) {
	f, send := auditPaths["PRUNE of 32 topics with 40 peer exchange records each, from a vouched peer"](t)
	send()
	if n := f.r.Stats().PXAccepted; n != 16*16 {
		t.Fatalf("%d records passed on, want 16 for each of 16 joined topics", n)
	}
	f, send = auditPaths["GRAFT of 16 topics refused for full meshes, with peer exchange"](t)
	f.sink.reset()
	send()
	n := 0
	for _, c := range f.sink.ctrlTo(key(1)) {
		for _, pr := range c.Prune {
			if len(pr.PX) == f.r.cfg.PrunePeers {
				n++
			}
		}
	}
	if n != 16 {
		t.Fatalf("%d of 16 refusals carry %d records", n, f.r.cfg.PrunePeers)
	}
}

// TestPXZeroThreshold: an AcceptPX of 0, as a hand-built Thresholds has, dials no peer exchange at all.
func TestPXZeroThreshold(t *testing.T) {
	f := pxFixture(t, func(c *Config) { c.Score.Thresholds.AcceptPX = 0 })
	f.control(1, &wire.Control{Prune: []wire.Prune{{Topic: T, PX: pxRecs(100, 2)}}})
	if len(f.sink.dials) != 0 {
		t.Fatalf("dials %+v", f.sink.dials)
	}
}

// TestPXChargedTaken: the PRUNE's sender pays for the records the driver takes to dial, not for those it drops.
func TestPXChargedTaken(t *testing.T) {
	f := pxFixture(t, nil)
	f.sink.dialCap = 2
	f.r.AuditPeer(key(1))
	f.control(1, &wire.Control{Prune: []wire.Prune{{Topic: T, PX: pxRecs(100, 5)}}})
	if _, charged := f.r.Audit(); charged[OpDial] != 2 {
		t.Fatalf("%d dials charged, 2 taken", charged[OpDial])
	}
}

// TestSplitTopicsCapped: no control frame we send carries more GRAFT or PRUNE entries than the receiver reads, also
// when PRUNEs kept after a full queue pile up.
func TestSplitTopicsCapped(t *testing.T) {
	f := meshFixture(t, nil, 1, 0)
	p := f.r.byID[key(1)]
	for i := range 40 {
		p.pendings().prune = append(p.pendings().prune, wire.Prune{Topic: topicID(100 + i)})
		p.pendings().graft = append(p.pendings().graft, topicID(200+i))
	}
	f.sink.reset()
	f.r.sendControl(p, &wire.Control{}, true)
	prunes := 0
	for _, c := range f.sink.ctrlTo(key(1)) {
		if len(c.Prune) > maxFrameTopics || len(c.Graft) > maxFrameTopics {
			t.Fatalf("a frame with %d PRUNE and %d GRAFT entries", len(c.Prune), len(c.Graft))
		}
		prunes += len(c.Prune)
	}
	if prunes != 40 {
		t.Fatalf("%d of 40 PRUNE entries sent", prunes)
	}
	var grafts []wire.Topic
	for i := range 40 {
		grafts = append(grafts, topicID(i))
	}
	for _, c := range splitControl(&wire.Control{Graft: grafts}, f.r.cfg.MaxControlSize, 10, 32) {
		if len(c.Graft) > 32 {
			t.Fatalf("a frame with %d GRAFT entries", len(c.Graft))
		}
	}
}

// TestPruneFrameFits: with PeerExchange on, MaxControlSize must hold one PRUNE entry with PrunePeers records, and
// such an entry is sent in one frame within it, never after an empty frame.
func TestPruneFrameFits(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxControlSize = minControlSize
	if err := cfg.validate(); err != nil {
		t.Fatalf("the smallest MaxControlSize refused without peer exchange: %v", err)
	}
	cfg.PeerExchange = true
	if err := cfg.validate(); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("a MaxControlSize that cannot hold a PRUNE with peer exchange accepted: %v", err)
	}
	pr0 := wire.Prune{Backoff: seconds(cfg.PruneBackoff), PX: make([]wire.PeerRecord, cfg.PrunePeers)}
	for i := range pr0.PX {
		pr0.PX[i].Addr = netip.AddrPortFrom(ip(i), 65535)
	}
	cfg.MaxControlSize = 8 + wire.PruneSize(&pr0)
	if err := cfg.validate(); err != nil {
		t.Fatal(err)
	}
	cfg.MaxControlSize--
	if err := cfg.validate(); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("one byte short accepted: %v", err)
	}
	cfg.MaxControlSize++
	huge := *cfg
	huge.PrunePeers = math.MaxInt
	if err := huge.validate(); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("a PrunePeers no frame holds accepted: %v", err)
	}
	pr := wire.Prune{Topic: T, Backoff: seconds(cfg.PruneBackoff), PX: make([]wire.PeerRecord, cfg.PrunePeers)}
	for i := range pr.PX {
		pr.PX[i] = wire.PeerRecord{Key: wire.Key(key(i)), Addr: netip.AddrPortFrom(ip(i), 65535)}
	}
	frames := splitControl(&wire.Control{Prune: []wire.Prune{pr, pr}}, cfg.MaxControlSize, 10, 32)
	for _, f := range frames {
		if f.Empty() || f.Size() > cfg.MaxControlSize {
			t.Fatalf("a frame of %d bytes, empty %v, limit %d", f.Size(), f.Empty(), cfg.MaxControlSize)
		}
	}
	if len(frames) != 2 {
		t.Fatalf("%d frames for two entries that fit one each", len(frames))
	}
}

// TestNoAddressNoPort: a peer added without an IPv4 address is never offered, whatever port comes with it.
func TestNoAddressNoPort(t *testing.T) {
	f := newFixture(t, nil)
	if err := f.r.AddPeer(f.now, key(1), true, netip.AddrPortFrom(netip.Addr{}, 4000)); err != nil {
		t.Fatal(err)
	}
	if p := f.r.byID[key(1)]; p.port != 0 || p.ip != [4]byte{} {
		t.Fatalf("stored %v:%d", p.ip, p.port)
	}
}
