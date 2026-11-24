package core

import (
	"slices"
	"testing"
	"time"

	"github.com/ciranda-dev/kolo-gossip/internal/wire"
)

func ids(base byte, n int) []wire.ID {
	out := make([]wire.ID, n)
	for i := range out {
		out[i][0], out[i][1], out[i][2] = base, byte(i>>8), byte(i)
	}
	return out
}

func iwants(s *recSink, p PeerID) int {
	n := 0
	for _, c := range s.ctrlTo(p) {
		n += len(c.IWant)
	}
	return n
}

// TestGossipEmission: each heartbeat sends IHAVE with the ids of the newest HistoryGossip windows to
// max(Dlazy, GossipFactor x candidates) peers outside the mesh (gossipsub-v1.0.md:475-494; gossipsub-v1.1.md:165-184).
func TestGossipEmission(t *testing.T) {
	// Dlazy 6, GossipFactor 0.25 and 0.75 (DefaultConfig): 6 mesh peers, the rest are candidates.
	for _, c := range []struct {
		peers  int
		factor float64
		want   int
	}{{12, 0.75, 6}, {46, 0.25, 10}, {46, 0.75, 30}} {
		cfg := DefaultConfig()
		cfg.Params.GossipFactor = c.factor
		f := meshFixture(t, cfg, c.peers, 6)
		f.receive(1, envelope(T, key(90), 1, f.now, 1), Accept)
		f.heartbeat()
		f.heartbeat()
		f.heartbeat()
		f.receive(1, envelope(T, key(90), 2, f.now, 1), Accept)
		f.sink.reset()
		f.heartbeat()
		got := 0
		for _, sc := range f.sink.ctrl {
			for _, h := range sc.c.IHave {
				got++
				if slices.Contains(f.r.Mesh(T), sc.to) || len(h.IDs) != 1 {
					t.Fatalf("IHAVE to mesh peer or with %d ids (the oldest window is past HistoryGossip)", len(h.IDs))
				}
			}
		}
		if got != c.want {
			t.Errorf("%d peers, factor %v: IHAVE to %d, want %d", c.peers, c.factor, got, c.want)
		}
	}
}

// TestGraftGossip: a peer that enters the mesh hears by IHAVE of the ids of the gossip windows, which reached us
// before it did, whether it grafted us or we grafted it; as a mesh peer it is left out of gossip.
func TestGraftGossip(t *testing.T) {
	announced := func(f *fixture, p PeerID, id wire.ID) bool {
		for _, c := range f.sink.ctrlTo(p) {
			for _, h := range c.IHave {
				if h.Topic == T && slices.Contains(h.IDs, id) {
					return true
				}
			}
		}
		return false
	}
	t.Run("accepted", func(t *testing.T) {
		f := meshFixture(t, nil, 6, 5)
		raw := envelope(T, key(90), 1, f.now, 1)
		f.receive(1, raw, Accept)
		f.control(6, &wire.Control{Graft: []wire.Topic{T}})
		if !f.inMesh(T, 6) {
			t.Fatal("graft refused")
		}
		for range f.r.cfg.HistoryGossip {
			f.heartbeat()
		}
		if f.sink.msgsTo(key(6)) == 0 && !announced(f, key(6), wire.NewID(raw)) {
			t.Fatal("the grafted peer never heard of the message")
		}
	})
	t.Run("grafted", func(t *testing.T) {
		f := meshFixture(t, nil, 6, 1)
		raw := envelope(T, key(90), 1, f.now, 1)
		f.receive(1, raw, Accept)
		f.heartbeat()
		for i := 2; i <= 6; i++ {
			if f.inMesh(T, i) && f.sink.msgsTo(key(i)) == 0 && !announced(f, key(i), wire.NewID(raw)) {
				t.Fatalf("peer %d, grafted at the heartbeat, never heard of the message", i)
			}
		}
	})
}

// TestGossipTruncated: an IHAVE never carries more than MaxIHaveLength ids, to the 2 peers outside the mesh and to
// the 6 that grafted us since the last heartbeat.
func TestGossipTruncated(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxIHaveLength = 3
	f := meshFixture(t, cfg, 8, 6)
	for i := range 5 {
		f.receive(1, envelope(T, key(90), uint64(i), f.now, 1), Accept)
	}
	f.sink.reset()
	f.heartbeat()
	n := 0
	for _, sc := range f.sink.ctrl {
		for _, h := range sc.c.IHave {
			n++
			if len(h.IDs) != 3 {
				t.Fatalf("IHAVE of %d ids", len(h.IDs))
			}
		}
	}
	if n != 8 {
		t.Fatalf("%d IHAVE", n)
	}
}

// TestIHaveLimits: IHAVE is ignored after MaxIHaveMessages frames per heartbeat and past MaxIHaveLength ids per
// frame, for topics we are not in and for seen ids (gossipsub-v1.1.md:631-634); one peer is asked at most askCap ids
// at once.
func TestIHaveLimits(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxIHaveMessages = 2
	cfg.MaxIHaveLength = 5
	f := meshFixture(t, cfg, 1, 0)
	f.receive(1, envelope(T, key(90), 1, f.now, 1), Accept)
	seen := wire.NewID(envelope(T, key(90), 1, f.now, 1))
	f.sink.reset()
	f.control(1, &wire.Control{IHave: []wire.IHave{{Topic: T, IDs: append(ids(1, 3), seen)}, {Topic: topicID(7), IDs: ids(2, 3)}}})
	if got := iwants(f.sink, key(1)); got != 3 {
		t.Fatalf("asked %d, want the 3 unseen ids of the joined topic", got)
	}
	f.control(1, &wire.Control{IHave: []wire.IHave{{Topic: T, IDs: ids(3, 4)}}})
	if got := iwants(f.sink, key(1)); got != 5 {
		t.Fatalf("asked %d in total, want askCap 5 at once", got)
	}
	f.control(1, &wire.Control{IHave: []wire.IHave{{Topic: T, IDs: ids(4, 1)}}})
	if got := iwants(f.sink, key(1)); got != 5 {
		t.Fatal("asked over MaxIHaveMessages")
	}
	// The asks end with IWantFollowupTime, and the frame count with the heartbeat.
	f.tick(4 * time.Second)
	f.sink.reset()
	f.control(1, &wire.Control{IHave: []wire.IHave{{Topic: T, IDs: ids(5, 9)}}})
	if got := iwants(f.sink, key(1)); got != 5 {
		t.Fatalf("after the asks ended asked %d, want 5", got)
	}
	f.control(1, &wire.Control{IHave: []wire.IHave{{Topic: T, IDs: ids(6, 1)}}})
	f.control(1, &wire.Control{IHave: []wire.IHave{{Topic: T, IDs: ids(7, 1)}}})
	if f.r.byID[key(1)].ihaves != 3 {
		t.Fatal("IHAVE frames not counted")
	}
}

// TestIHaveFrameCount: the third IHAVE frame in one heartbeat is ignored even with room for ids left.
func TestIHaveFrameCount(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxIHaveMessages = 2
	f := meshFixture(t, cfg, 1, 0)
	for i := range 3 {
		f.control(1, &wire.Control{IHave: []wire.IHave{{Topic: T, IDs: ids(byte(i), 1)}}})
	}
	if got := iwants(f.sink, key(1)); got != 2 {
		t.Fatalf("asked %d, want 2", got)
	}
}

// TestIWantRetransmission: IWANT is answered from the cache at most GossipRetransmission times per peer, never
// after the peer's IDONTWANT and never below the gossip threshold (gossipsub-v1.1.md:627-630).
func TestIWantRetransmission(t *testing.T) {
	cfg := scoringConfig()
	cfg.Score.AppScore = func(p PeerID) float64 {
		if p == key(3) {
			return -15
		}
		return 0
	}
	f := newFixture(t, cfg)
	f.join(T, nil)
	f.addPeers(3, T)
	raw := envelope(T, key(90), 1, f.now, 1)
	f.receive(1, raw, Accept)
	id := wire.NewID(raw)
	f.sink.reset()
	for range 5 {
		f.control(2, &wire.Control{IWant: []wire.ID{id, ids(9, 1)[0]}})
		f.control(3, &wire.Control{IWant: []wire.ID{id}})
	}
	if f.sink.msgsTo(key(2)) != 3 || f.sink.msgsTo(key(3)) != 0 {
		t.Fatalf("answers %d and %d", f.sink.msgsTo(key(2)), f.sink.msgsTo(key(3)))
	}
	f.control(1, &wire.Control{IDontWant: []wire.ID{id}})
	f.control(1, &wire.Control{IWant: []wire.ID{id}})
	if f.sink.msgsTo(key(1)) != 0 {
		t.Fatal("answered after IDONTWANT")
	}
}

// TestPromises: an IWANT sent for an IHAVE promises one random asked id; if no copy arrives within
// IWantFollowupTime the advertiser gets a P7 penalty (gossipsub-v1.1.md:635-640).
func TestPromises(t *testing.T) {
	f := newFixture(t, scoringConfig())
	f.join(T, nil)
	f.addPeers(2, T)
	asked := ids(1, 1)
	f.control(1, &wire.Control{IHave: []wire.IHave{{Topic: T, IDs: asked}}})
	raw := envelope(T, key(90), 1, f.now, 1)
	f.control(2, &wire.Control{IHave: []wire.IHave{{Topic: T, IDs: []wire.ID{wire.NewID(raw)}}}})
	f.receive(1, raw, Accept)
	f.tick(2900 * time.Millisecond)
	if f.r.score.stats[key(1)].behaviourPenalty != 0 {
		t.Fatal("penalised before the follow-up time")
	}
	f.now = f.now.Add(200 * time.Millisecond)
	f.heartbeat()
	if got := f.r.score.stats[key(1)].behaviourPenalty; got <= 0 {
		t.Fatalf("broken promise penalty %v", got)
	}
	if got := f.r.score.stats[key(2)].behaviourPenalty; got != 0 {
		t.Fatalf("kept promise penalised %v", got)
	}
}

// TestControlRetry: a GRAFT, PRUNE or subscription dropped by a full queue is sent again at the next heartbeat,
// unless it went stale.
func TestControlRetry(t *testing.T) {
	f := newFixture(t, nil)
	f.addPeers(10, T)
	for i := 1; i <= 10; i++ {
		f.sink.full[key(i)] = true
	}
	f.join(T, nil)
	mesh := f.r.Mesh(T)
	stale := mesh[0]
	if err := f.r.Control(f.now, stale, &wire.Control{Prune: []wire.Prune{{Topic: T}}}); err != nil {
		t.Fatal(err)
	}
	f.sink.full = map[PeerID]bool{}
	f.sink.reset()
	f.heartbeat()
	for i := 1; i <= 10; i++ {
		subs := 0
		for _, c := range f.sink.ctrlTo(key(i)) {
			subs += count(c.Subs, wire.Sub{Topic: T, Subscribe: true})
		}
		if subs != 1 {
			t.Fatalf("peer %d: subscription sent %d times", i, subs)
		}
		want := 0
		if key(i) != stale && slices.Contains(mesh, key(i)) {
			want = 1
		}
		if got := f.sink.graftsTo(key(i), T); got != want {
			t.Fatalf("peer %d: %d grafts, want %d", i, got, want)
		}
	}
	if f.r.Stats().SendDropped != 10 {
		t.Fatalf("%d drops counted", f.r.Stats().SendDropped)
	}
}

// TestSplitControl: a control frame over MaxControlSize is cut into frames within it, losing nothing.
func TestSplitControl(t *testing.T) {
	c := &wire.Control{
		Subs:      []wire.Sub{{Topic: topicID(1), Subscribe: true}},
		Graft:     []wire.Topic{topicID(2), topicID(3)},
		Prune:     []wire.Prune{{Topic: topicID(4), Backoff: 60}},
		IHave:     []wire.IHave{{Topic: topicID(5), IDs: ids(1, 300)}, {Topic: topicID(6), IDs: ids(2, 7)}, {Topic: topicID(7)}},
		IWant:     ids(3, 40),
		IDontWant: ids(4, 40),
		CertWant:  []wire.CertWant{{}, {}},
		Cert:      [][]byte{make([]byte, 514), {1}},
	}
	for _, limit := range []int{minControlSize, 1000, 4000, 1 << 20} {
		frames := splitControl(c, limit, 10, 32)
		var all wire.Control
		for _, f := range frames {
			if f.Size() > limit {
				t.Fatalf("limit %d: frame of %d", limit, f.Size())
			}
			if f.Empty() {
				t.Fatalf("limit %d: empty frame", limit)
			}
			all.Subs = append(all.Subs, f.Subs...)
			all.Graft = append(all.Graft, f.Graft...)
			all.Prune = append(all.Prune, f.Prune...)
			for _, h := range f.IHave {
				if n := len(all.IHave); n > 0 && all.IHave[n-1].Topic == h.Topic && len(h.IDs) > 0 {
					all.IHave[n-1].IDs = append(all.IHave[n-1].IDs, h.IDs...)
				} else {
					all.IHave = append(all.IHave, wire.IHave{Topic: h.Topic, IDs: slices.Clone(h.IDs)})
				}
			}
			all.IWant = append(all.IWant, f.IWant...)
			all.IDontWant = append(all.IDontWant, f.IDontWant...)
			all.CertWant = append(all.CertWant, f.CertWant...)
			all.Cert = append(all.Cert, f.Cert...)
		}
		a, _ := all.Encode()
		b, _ := c.Encode()
		if string(a) != string(b) {
			t.Fatalf("limit %d: content changed over %d frames", limit, len(frames))
		}
	}
}

// TestCacheBounds: the message cache keeps at most MaxCacheMessages per topic and MaxCacheBytes overall, dropping
// the oldest, and forgets messages after HistoryLength heartbeats (gossipsub-v1.0.md:201, 343-348).
func TestCacheBounds(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxCacheMessages = 3
	cfg.MaxCacheBytes = cfg.MaxMessageSize
	f := meshFixture(t, cfg, 1, 0)
	var first wire.ID
	for i := range 4 {
		raw := envelope(T, key(90), uint64(i), f.now, 10)
		if i == 0 {
			first = wire.NewID(raw)
		}
		f.receive(1, raw, Accept)
	}
	if s := f.r.Stats(); s.CacheMessages != 3 || s.CacheEvicted != 1 || f.r.cache.m[first] != nil {
		t.Fatalf("count bound: %+v", s)
	}
	f.receive(1, envelope(T, key(90), 9, f.now, cfg.MaxMessageSize-400), Accept)
	if s := f.r.Stats(); s.CacheBytes > cfg.MaxCacheBytes || s.CacheMessages != 2 {
		t.Fatalf("byte bound: %+v", s)
	}
	for range 5 {
		f.heartbeat()
	}
	if s := f.r.Stats(); s.CacheMessages != 0 || s.CacheBytes != 0 {
		t.Fatalf("not shifted out: %+v", s)
	}
}

// TestBackoffBound: a full backoff table drops a disconnected peer's entry first.
func TestBackoffBound(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxBackoff = 3
	f := meshFixture(t, cfg, 4, 0)
	for i := 1; i <= 3; i++ {
		f.control(i, &wire.Control{Prune: []wire.Prune{{Topic: T, Backoff: uint64(100 - i)}}})
	}
	f.r.RemovePeer(f.now, key(1))
	f.control(4, &wire.Control{Prune: []wire.Prune{{Topic: T}}})
	tb := f.r.backoff.m[T]
	if len(tb.m) != 3 || f.r.backoff.has(T, key(1)) || !f.r.backoff.has(T, key(4)) {
		t.Fatalf("table %v", tb.m)
	}
	f.control(2, &wire.Control{Prune: []wire.Prune{{Topic: T}}})
	f.addPeer(5, true, T)
	f.control(5, &wire.Control{Prune: []wire.Prune{{Topic: T}}})
	if len(tb.m) != 3 || f.r.backoff.has(T, key(4)) {
		t.Fatal("earliest expiry not dropped")
	}
}

// TestLeftBackoffTables: at most max(16, topics held) tables of left topics are kept.
func TestLeftBackoffTables(t *testing.T) {
	f := newFixture(t, nil)
	var topics []wire.Topic
	for i := 1; i <= 18; i++ {
		topics = append(topics, topicID(i))
	}
	f.addPeers(1, topics...)
	for _, tp := range topics {
		f.join(tp, nil)
		f.control(1, &wire.Control{Graft: []wire.Topic{tp}})
		f.r.Leave(f.now, tp)
	}
	if len(f.r.backoff.m) != 16 || f.r.backoff.has(topicID(2), key(1)) || !f.r.backoff.has(topicID(18), key(1)) {
		t.Fatalf("left tables not bounded: %d", len(f.r.backoff.m))
	}
	f.join(topicID(3), nil)
	if len(f.r.backoff.left) != 15 || f.inMesh(topicID(3), 1) {
		t.Fatal("rejoin lost its backoff")
	}
}
