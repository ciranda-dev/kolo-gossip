package core

import (
	"math"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/ciranda-dev/kolo-gossip/internal/wire"
)

var T = topicID(1)

// TestJoinGraftsUpToD: JOIN selects D peers and sends them GRAFT; every peer learns the subscription
// (gossipsub-v1.0.md:296-305, 280-290).
func TestJoinGraftsUpToD(t *testing.T) {
	f := newFixture(t, nil)
	f.addPeers(10, T)
	f.sink.reset()
	f.join(T, nil)
	mesh := f.r.Mesh(T)
	if len(mesh) != 6 {
		t.Fatalf("mesh %d, want D 6", len(mesh))
	}
	for i := 1; i <= 10; i++ {
		subs := 0
		for _, c := range f.sink.ctrlTo(key(i)) {
			subs += count(c.Subs, wire.Sub{Topic: T, Subscribe: true})
		}
		if subs != 1 {
			t.Fatalf("peer %d got %d subscriptions", i, subs)
		}
		if g := f.sink.graftsTo(key(i), T); (g == 1) != f.inMesh(T, i) || g > 1 {
			t.Fatalf("peer %d: %d grafts, in mesh %v", i, g, f.inMesh(T, i))
		}
	}
	f.sink.reset()
	f.join(T, nil)
	if len(f.sink.ctrl) != 0 {
		t.Fatal("joining twice sent control")
	}
}

// TestJoinFromFanout: JOIN keeps the fanout peers as mesh peers (gossipsub-v1.0.md:300-302).
func TestJoinFromFanout(t *testing.T) {
	cfg := DefaultConfig()
	cfg.FloodPublish = false
	f := newFixture(t, cfg)
	f.addPeers(10, T)
	if _, err := f.r.Publish(f.now, envelope(T, key(0), 1, f.now, 10)); err != nil {
		t.Fatal(err)
	}
	fanout := f.r.Fanout(T)
	if len(fanout) != 6 || f.sink.msgsTo(fanout[0]) != 1 || len(f.sink.msgs) != 6 {
		t.Fatalf("fanout %d, %d messages", len(fanout), len(f.sink.msgs))
	}
	f.join(T, nil)
	if !slices.Equal(f.r.Mesh(T), fanout) || len(f.r.Fanout(T)) != 0 {
		t.Fatal("mesh is not the fanout")
	}
}

// TestJoinSkipsBackoff: peers backed off after a LEAVE are not grafted on rejoin (gossipsub-v1.1.md:108-109).
func TestJoinSkipsBackoff(t *testing.T) {
	f := newFixture(t, nil)
	f.addPeers(10, T)
	f.join(T, nil)
	old := f.r.Mesh(T)
	f.sink.reset()
	f.r.Leave(f.now, T)
	for _, p := range old {
		prs := f.sink.prunesTo(p, T)
		if len(prs) != 1 || prs[0].Backoff != 10 {
			t.Fatalf("leave prune %+v, want backoff 10 s", prs)
		}
	}
	for i := 1; i <= 10; i++ {
		if count(f.sink.ctrlTo(key(i))[0].Subs, wire.Sub{Topic: T}) != 1 {
			t.Fatalf("peer %d not told of the leave", i)
		}
	}
	f.now = f.now.Add(5 * time.Second)
	f.join(T, nil)
	for _, p := range f.r.Mesh(T) {
		if slices.Contains(old, p) {
			t.Fatal("rejoined a backed-off peer")
		}
	}
	if len(f.r.Mesh(T)) != 4 {
		t.Fatalf("mesh %d, want the 4 peers not backed off", len(f.r.Mesh(T)))
	}
}

// TestGraftAccepted: a GRAFT from a subscribed peer adds it to the mesh without a reply (gossipsub-v1.0.md:369-376).
func TestGraftAccepted(t *testing.T) {
	f := newFixture(t, nil)
	f.join(T, nil)
	f.addPeers(1, T)
	f.sink.reset()
	f.control(1, &wire.Control{Graft: []wire.Topic{T}})
	if !f.inMesh(T, 1) || len(f.sink.ctrl) != 0 {
		t.Fatalf("mesh %v, replies %d", f.r.Mesh(T), len(f.sink.ctrl))
	}
}

// TestGraftUnknownTopicIgnored: GRAFT for a topic we are not in gets no reply (gossipsub-v1.1.md:624-626).
func TestGraftUnknownTopicIgnored(t *testing.T) {
	f := newFixture(t, nil)
	f.addPeers(1, T)
	f.sink.reset()
	f.control(1, &wire.Control{Graft: []wire.Topic{T, topicID(9)}})
	if len(f.sink.ctrl) != 0 || len(f.r.Mesh(T)) != 0 {
		t.Fatal("unknown-topic GRAFT answered")
	}
}

// TestGraftDuringBackoff: a GRAFT inside the backoff is refused with PRUNE, the backoff is refreshed and P7 grows
// by 1, plus 1 more inside GraftFloodThreshold (gossipsub-v1.1.md:102-106).
func TestGraftDuringBackoff(t *testing.T) {
	f := newFixture(t, scoringConfig())
	f.join(T, nil)
	f.addPeers(1, T)
	f.control(1, &wire.Control{Graft: []wire.Topic{T}})
	f.control(1, &wire.Control{Prune: []wire.Prune{{Topic: T}}})
	f.sink.reset()
	f.now = f.now.Add(5 * time.Second)
	f.control(1, &wire.Control{Graft: []wire.Topic{T}})
	if f.inMesh(T, 1) || len(f.sink.prunesTo(key(1), T)) != 1 {
		t.Fatal("GRAFT in backoff not refused")
	}
	if got := f.r.score.stats[key(1)].behaviourPenalty; got != 2 {
		t.Fatalf("penalty %v, want 2 inside the flood threshold", got)
	}
	exp, _ := f.r.backoff.expiry(T, key(1))
	if !exp.Equal(f.now.Add(time.Minute)) {
		t.Fatal("backoff not refreshed")
	}
	f.now = f.now.Add(30 * time.Second)
	f.control(1, &wire.Control{Graft: []wire.Topic{T}})
	if got := f.r.score.stats[key(1)].behaviourPenalty; got != 3 {
		t.Fatalf("penalty %v, want 3 after a late regraft", got)
	}
}

// TestGraftNegativeScore: a GRAFT from a negative-score peer is refused and backed off (gossipsub-v1.1.md:250).
func TestGraftNegativeScore(t *testing.T) {
	cfg := scoringConfig()
	cfg.Score.AppScore = func(p PeerID) float64 { return -1 }
	f := newFixture(t, cfg)
	f.join(T, nil)
	f.addPeers(1, T)
	f.sink.reset()
	f.control(1, &wire.Control{Graft: []wire.Topic{T}})
	if f.inMesh(T, 1) || len(f.sink.prunesTo(key(1), T)) != 1 || !f.r.backoff.has(T, key(1)) {
		t.Fatal("negative-score GRAFT accepted")
	}
}

// TestGraftAtDhi: at Dhi only outbound peers are accepted (gossipsub-v1.1.md:194-197).
func TestGraftAtDhi(t *testing.T) {
	f := newFixture(t, nil)
	f.join(T, nil)
	f.addPeers(14, T)
	for i := 1; i <= 12; i++ {
		f.control(i, &wire.Control{Graft: []wire.Topic{T}})
	}
	if len(f.r.Mesh(T)) != 12 {
		t.Fatalf("mesh %d", len(f.r.Mesh(T)))
	}
	f.sink.reset()
	f.control(14, &wire.Control{Graft: []wire.Topic{T}})
	if f.inMesh(T, 14) || len(f.sink.prunesTo(key(14), T)) != 1 {
		t.Fatal("inbound GRAFT at Dhi accepted")
	}
	f.control(13, &wire.Control{Graft: []wire.Topic{T}})
	if !f.inMesh(T, 13) {
		t.Fatal("outbound GRAFT at Dhi refused")
	}
}

// TestPruneReceived: PRUNE removes the link and the peer's backoff is obeyed, PruneBackoff when it gives none
// (gossipsub-v1.1.md:113-118).
func TestPruneReceived(t *testing.T) {
	f := newFixture(t, nil)
	f.join(T, nil)
	f.addPeers(3, T)
	for i := 1; i <= 3; i++ {
		f.control(i, &wire.Control{Graft: []wire.Topic{T}})
	}
	f.control(1, &wire.Control{Prune: []wire.Prune{{Topic: T, Backoff: 120}}})
	f.control(2, &wire.Control{Prune: []wire.Prune{{Topic: T}}})
	f.control(3, &wire.Control{Prune: []wire.Prune{{Topic: T, Backoff: math.MaxUint64}}})
	if len(f.r.Mesh(T)) != 0 {
		t.Fatal("pruned peers kept")
	}
	for i, want := range map[int]time.Duration{1: 2 * time.Minute, 2: time.Minute} {
		if exp, _ := f.r.backoff.expiry(T, key(i)); !exp.Equal(f.now.Add(want)) {
			t.Fatalf("peer %d backoff until %v", i, exp)
		}
	}
	if exp, _ := f.r.backoff.expiry(T, key(3)); !exp.After(f.now.Add(100 * 365 * 24 * time.Hour)) {
		t.Fatal("huge backoff not kept")
	}
}

// TestHeartbeatGraftsBelowDlo: below Dlo the heartbeat grafts up to D (gossipsub-v1.0.md:421-430).
func TestHeartbeatGraftsBelowDlo(t *testing.T) {
	f := newFixture(t, nil)
	f.join(T, nil)
	f.addPeers(10, T)
	if len(f.r.Mesh(T)) != 0 {
		t.Fatal("mesh before heartbeat")
	}
	f.sink.reset()
	f.heartbeat()
	if len(f.r.Mesh(T)) != 6 {
		t.Fatalf("mesh %d, want D", len(f.r.Mesh(T)))
	}
	for _, p := range f.r.Mesh(T) {
		if f.sink.graftsTo(p, T) != 1 {
			t.Fatal("grafted peer not told")
		}
	}
}

// TestHeartbeatPrunesAboveDhi: the mesh is pruned to D only when it is over Dhi, not at Dhi
// (gossipsub-v1.0.md:432-436).
func TestHeartbeatPrunesAboveDhi(t *testing.T) {
	for _, n := range []int{12, 13} {
		f := newFixture(t, nil)
		f.join(T, nil)
		f.addPeers(14, T)
		for i := 1; i <= n; i++ {
			f.addMeshPeer(i)
		}
		f.sink.reset()
		f.heartbeat()
		want := map[int]int{12: 12, 13: 6}[n]
		if got := len(f.r.Mesh(T)); got != want {
			t.Fatalf("mesh of %d after heartbeat: %d, want %d", n, got, want)
		}
		prunes := 0
		for i := 1; i <= 14; i++ {
			prunes += len(f.sink.prunesTo(key(i), T))
		}
		if prunes != n-want {
			t.Fatalf("%d prunes sent", prunes)
		}
	}
}

// addMeshPeer puts peer i in T's mesh directly, outbound or not as it was added.
func (f *fixture) addMeshPeer(i int) {
	tp := f.r.topics[T]
	if !slices.Contains(tp.mesh, key(i)) {
		tp.mesh = append(tp.mesh, key(i))
		f.r.score.graft(f.now, key(i), T)
	}
}

// TestHeartbeatKeepsDout: pruning an oversubscribed mesh keeps Dout outbound peers even when scores rank inbound
// peers higher (gossipsub-v1.1.md:192-196, 253-256).
func TestHeartbeatKeepsDout(t *testing.T) {
	cfg := scoringConfig()
	cfg.Score.AppScore = func(p PeerID) float64 {
		if p[3]%2 == 1 {
			return 10 // inbound peers (even i, so key byte i+1 odd) score higher
		}
		return 0
	}
	for seed := range 20 {
		f := newFixture(t, cfg)
		f.r.rnd = randFor(uint64(seed))
		f.join(T, nil)
		f.addPeers(16, T)
		for i := 1; i <= 16; i++ {
			f.addMeshPeer(i)
		}
		f.heartbeat()
		if out := f.r.countOutbound(f.r.Mesh(T)); len(f.r.Mesh(T)) != 6 || out < 2 {
			t.Fatalf("seed %d: mesh %d with %d outbound", seed, len(f.r.Mesh(T)), out)
		}
	}
}

// TestHeartbeatKeepsBestDscore: pruning an oversubscribed mesh keeps the best Dscore peers by score and fills the
// rest of D at random (gossipsub-v1.1.md:251-254); with Dscore = D, the default, the D best survive.
func TestHeartbeatKeepsBestDscore(t *testing.T) {
	cfg := scoringConfig()
	cfg.Score.AppScore = func(p PeerID) float64 { return float64(p[3]) } // peer i scores i+1
	for _, dscore := range []int{4, 6} {
		random := map[PeerID]bool{}
		for seed := range 20 {
			cfg.Params.Dscore = dscore
			f := newFixture(t, cfg)
			f.r.rnd = randFor(uint64(seed))
			f.join(T, nil)
			f.addPeers(13, T)
			for i := 1; i <= 13; i++ {
				f.addMeshPeer(i)
			}
			f.heartbeat()
			mesh := f.r.Mesh(T)
			for i := 13; i > 13-dscore; i-- {
				if !slices.Contains(mesh, key(i)) {
					t.Fatalf("Dscore %d, seed %d: peer %d of the best %d pruned", dscore, seed, i, dscore)
				}
			}
			for _, p := range mesh {
				if int(p[3])-1 <= 13-dscore {
					random[p] = true
				}
			}
		}
		if dscore == 4 && len(random) < 3 || dscore == 6 && len(random) != 0 {
			t.Fatalf("Dscore %d: %d distinct peers outside the best kept at random", dscore, len(random))
		}
	}
}

// TestHeartbeatGraftsOutboundQuota: with at least Dlo peers but fewer than Dout outbound, outbound peers are
// grafted (gossipsub-v1.1.md:197-199).
func TestHeartbeatGraftsOutboundQuota(t *testing.T) {
	f := newFixture(t, nil)
	f.join(T, nil)
	f.addPeers(12, T)
	for i := 2; i <= 10; i += 2 {
		f.addMeshPeer(i)
	}
	f.heartbeat()
	if out := f.r.countOutbound(f.r.Mesh(T)); out != 2 || len(f.r.Mesh(T)) != 7 {
		t.Fatalf("mesh %d with %d outbound, want 7 with 2", len(f.r.Mesh(T)), out)
	}
}

// TestHeartbeatPrunesNegative: negative-score mesh peers are pruned (gossipsub-v1.1.md:248-250).
func TestHeartbeatPrunesNegative(t *testing.T) {
	cfg := scoringConfig()
	bad := key(3)
	cfg.Score.AppScore = func(p PeerID) float64 {
		if p == bad {
			return -1
		}
		return 0
	}
	f := newFixture(t, cfg)
	f.join(T, nil)
	f.addPeers(8, T)
	for i := 1; i <= 6; i++ {
		f.addMeshPeer(i)
	}
	f.sink.reset()
	f.heartbeat()
	if f.inMesh(T, 3) || len(f.sink.prunesTo(bad, T)) != 1 || !f.r.backoff.has(T, bad) {
		t.Fatal("negative peer kept")
	}
	if len(f.r.Mesh(T)) != 5 {
		t.Fatalf("mesh %d", len(f.r.Mesh(T)))
	}
}

// TestBackoffExpiry: a backoff blocks grafting until it is cleaned up, every 15 heartbeats and 2 heartbeats
// after it ends (gossipsub-v1.1.md:115-117).
func TestBackoffExpiry(t *testing.T) {
	cfg := DefaultConfig()
	cfg.PruneBackoff = 3 * time.Second
	f := newFixture(t, cfg)
	f.join(T, nil)
	f.addPeers(1, T)
	f.control(1, &wire.Control{Prune: []wire.Prune{{Topic: T}}})
	for range 14 {
		f.heartbeat()
		if f.inMesh(T, 1) {
			t.Fatalf("grafted at tick %d during backoff or slack", f.r.ticks)
		}
	}
	f.heartbeat()
	if f.r.ticks != 15 || !f.inMesh(T, 1) {
		t.Fatalf("not grafted at the cleanup tick %d", f.r.ticks)
	}
}

// TestUnsubscribeLeavesMesh: a peer that unsubscribes leaves the mesh and the fanout.
func TestUnsubscribeLeavesMesh(t *testing.T) {
	f := newFixture(t, nil)
	f.join(T, nil)
	f.addPeers(2, T)
	f.control(1, &wire.Control{Graft: []wire.Topic{T}})
	f.control(1, &wire.Control{Subs: []wire.Sub{{Topic: T}}})
	if f.inMesh(T, 1) || f.r.TopicStats(T).Peers != 1 {
		t.Fatal("unsubscribed peer kept")
	}
}

// TestRemovePeer: a disconnected peer leaves every mesh and fanout.
func TestRemovePeer(t *testing.T) {
	f := newFixture(t, nil)
	f.join(T, nil)
	f.addPeers(3, T)
	f.control(1, &wire.Control{Graft: []wire.Topic{T}})
	f.r.RemovePeer(f.now, key(1))
	f.r.RemovePeer(f.now, key(9))
	if f.inMesh(T, 1) || f.r.Stats().Peers != 2 {
		t.Fatal("removed peer kept")
	}
	f.sink.reset()
	f.r.Message(f.now, key(1), envelope(T, key(50), 1, f.now, 1))
	if f.r.Stats().MessagesReceived != 0 {
		t.Fatal("message from a removed peer handled")
	}
}

// TestAddPeerChecks: IPv4 or no address (Kolo refuses every IPv6 form), no duplicates, no own key, MaxPeers.
func TestAddPeerChecks(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxPeers = 2
	f := newFixture(t, cfg)
	for _, a := range []string{"::1", "::ffff:10.0.0.1"} {
		if err := f.r.AddPeer(f.now, key(1), true, netip.AddrPortFrom(mustAddr(a), 4000)); err == nil {
			t.Fatalf("%s accepted", a)
		}
	}
	if err := f.r.AddPeer(f.now, key(0), true, addr(1)); err == nil {
		t.Fatal("own key accepted")
	}
	f.addPeers(1)
	// A relayed connection has no address: accepted, outside the colocation score.
	if err := f.r.AddPeer(f.now, key(2), true, netip.AddrPort{}); err != nil {
		t.Fatal(err)
	}
	if err := f.r.AddPeer(f.now, key(1), true, addr(1)); err == nil {
		t.Fatal("duplicate accepted")
	}
	if err := f.r.AddPeer(f.now, key(3), true, addr(3)); err == nil {
		t.Fatal("peer over MaxPeers accepted")
	}
}

// TestAddPeerAnnouncesTopics: a new peer is told every joined topic (gossipsub-v1.0.md:280-290).
func TestAddPeerAnnouncesTopics(t *testing.T) {
	f := newFixture(t, nil)
	f.join(T, nil)
	f.join(topicID(2), nil)
	f.addPeers(1)
	if c := f.sink.ctrlTo(key(1)); len(c) != 1 || len(c[0].Subs) != 2 {
		t.Fatal("subscriptions not announced")
	}
}

// TestMaxTopics: joining more than MaxTopics topics fails.
func TestMaxTopics(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxTopics = 2
	f := newFixture(t, cfg)
	f.join(topicID(1), nil)
	f.join(topicID(2), nil)
	if err := f.r.Join(f.now, topicID(3), nil); err == nil {
		t.Fatal("third topic joined")
	}
	f.r.Leave(f.now, topicID(2))
	f.join(topicID(3), nil)
}

// TestBackoffSlack: a backoff that ended less than 2 heartbeats before a cleanup tick is kept until the next one.
func TestBackoffSlack(t *testing.T) {
	cfg := DefaultConfig()
	cfg.PruneBackoff = 13 * time.Second
	f := newFixture(t, cfg)
	f.join(T, nil)
	f.addPeers(1, T)
	f.control(1, &wire.Control{Prune: []wire.Prune{{Topic: T}}})
	for range 15 {
		f.heartbeat()
	}
	if f.inMesh(T, 1) {
		t.Fatal("backoff cleared inside the slack")
	}
	for range 15 {
		f.heartbeat()
	}
	if !f.inMesh(T, 1) {
		t.Fatal("backoff kept past the next cleanup")
	}
}
