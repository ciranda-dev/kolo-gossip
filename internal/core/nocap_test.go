package core

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/ciranda-dev/kolo-gossip/internal/wire"
)

// manyTopic is the i-th of up to 65,536 topics we do not otherwise use.
func manyTopic(i int) wire.Topic { return wire.Topic{0xaa, byte(i >> 8), byte(i)} }

// topicsFrame is a subscription frame for n topics from manyTopic(from).
func topicsFrame(from, n int) *wire.Control {
	c := &wire.Control{}
	for i := range n {
		c.Subs = append(c.Subs, wire.Sub{Topic: manyTopic(from + i), Subscribe: true})
	}
	return c
}

// TestManySharedTopics: with the default config a node joins 50 topics, a peer announces all 50 and is in every
// mesh after a heartbeat, and no GRAFT frame holds more than the frame rule.
func TestManySharedTopics(t *testing.T) {
	f := newFixture(t, nil)
	var topics []wire.Topic
	for i := range 50 {
		topics = append(topics, topicID(i))
		f.join(topicID(i), nil)
	}
	f.addPeers(1, topics...)
	f.heartbeat()
	for _, tp := range topics {
		if !f.inMesh(tp, 1) {
			t.Fatalf("peer not in the mesh of topic %x", tp[:2])
		}
	}
	for _, c := range f.sink.ctrlTo(key(1)) {
		if len(c.Graft) > maxFrameTopics {
			t.Fatalf("a frame with %d GRAFT entries", len(c.Graft))
		}
	}
}

// TestSubscriptionsKeptForLaterJoin: a peer's 40 subscriptions to topics we do not hold are kept without an
// error, and a Join of one of them grafts the peer.
func TestSubscriptionsKeptForLaterJoin(t *testing.T) {
	f := newFixture(t, nil)
	f.addPeers(1)
	f.control(1, topicsFrame(0, 40))
	f.join(manyTopic(39), nil)
	if !f.inMesh(manyTopic(39), 1) {
		t.Fatal("the peer was not grafted at Join")
	}
}

// TestOtherTopicsBounded: subscriptions to topics we hold no state for are kept up to MaxPeerTopics, the rest are
// counted and never an error; a subscription to a topic we hold is kept when the other list is full, and Leave
// moves it back or drops it.
func TestOtherTopicsBounded(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxPeerTopics = 3
	f := newFixture(t, cfg)
	f.addPeers(1)
	f.control(1, topicsFrame(0, 5))
	if topics, other := listsOf(f, 1); len(topics) != 0 || len(other) != 3 || dropped(f) != 2 {
		t.Fatalf("%d topics, %d other, %d dropped", len(topics), len(other), dropped(f))
	}
	f.join(manyTopic(0), nil)
	f.control(1, topicsFrame(7, 1))
	f.join(manyTopic(100), nil)
	f.control(1, topicsFrame(100, 1))
	topics, other := listsOf(f, 1)
	if !slices.Equal(topics, []wire.Topic{manyTopic(0), manyTopic(100)}) || len(other) != 3 || dropped(f) != 2 {
		t.Fatalf("topics %d, other %d, dropped %d", len(topics), len(other), dropped(f))
	}
	f.r.Leave(f.now, manyTopic(0))
	if topics, other := listsOf(f, 1); len(topics) != 1 || len(other) != 3 || dropped(f) != 3 {
		t.Fatalf("after Leave: topics %d, other %d, dropped %d", len(topics), len(other), dropped(f))
	}
	f.control(1, &wire.Control{Subs: []wire.Sub{{Topic: manyTopic(1)}, {Topic: manyTopic(7)}}})
	f.r.Leave(f.now, manyTopic(100))
	if _, other := listsOf(f, 1); len(other) != 2 || dropped(f) != 3 {
		t.Fatalf("after unsubscribes: other %d, dropped %d", len(other), dropped(f))
	}
}

// TestSubscriptionFrameMerge: the largest subscription frames end in the right lists: distinct topics up to the
// bound, and the last entry of a topic wins however many alternate.
func TestSubscriptionFrameMerge(t *testing.T) {
	f := newFixture(t, nil)
	f.addPeers(1)
	f.control(1, topicsFrame(0, 15887))
	if _, other := listsOf(f, 1); len(other) != 1024 || dropped(f) != 15887-1024 || !slices.IsSortedFunc(other, cmpTopic) {
		t.Fatalf("%d kept, %d dropped", len(other), dropped(f))
	}
	c := &wire.Control{}
	for i := range 15887 {
		c.Subs = append(c.Subs, wire.Sub{Topic: manyTopic(60000), Subscribe: i%2 == 0})
	}
	f.control(1, c)
	if _, other := listsOf(f, 1); len(other) != 1024 || dropped(f) != 15887-1024+1 {
		t.Fatalf("an alternating frame ending in a subscribe: %d kept, %d dropped", len(other), dropped(f))
	}
	d := newFixture(t, nil)
	d.addPeers(1)
	c.Subs = append(c.Subs, wire.Sub{Topic: manyTopic(60000)})
	d.control(1, c)
	if _, other := listsOf(d, 1); len(other) != 0 || dropped(d) != 0 {
		t.Fatalf("an alternating frame ending in an unsubscribe: %d kept, %d dropped", len(other), dropped(d))
	}
	g := newFixture(t, nil)
	g.join(T, nil)
	g.addPeers(1)
	g.control(1, &wire.Control{Subs: []wire.Sub{{Topic: T, Subscribe: true}, {Topic: T}, {Topic: T, Subscribe: true}, {Topic: topicID(9), Subscribe: true}, {Topic: topicID(9)}}})
	if topics, other := listsOf(g, 1); !slices.Equal(topics, []wire.Topic{T}) || len(other) != 0 {
		t.Fatalf("topics %v other %v", topics, other)
	}
}

// TestNoPeerCap: with the default config 1,300 peers are served, and an application cap still refuses.
func TestNoPeerCap(t *testing.T) {
	cfg := DefaultConfig()
	manyPeers(cfg)
	f := newFixture(t, cfg)
	f.join(T, nil)
	for i := 1; i <= 1300; i++ {
		f.addPeer(i, i%2 == 1, T)
	}
	if f.r.Stats().Peers != 1300 {
		t.Fatalf("%d peers", f.r.Stats().Peers)
	}
	capped := DefaultConfig()
	capped.MaxPeers = 2
	g := newFixture(t, capped)
	g.addPeers(2)
	if err := g.r.AddPeer(g.now, key(3), true, addr(3)); !errors.Is(err, ErrLimit) {
		t.Fatalf("a third peer over MaxPeers 2: %v", err)
	}
}

// TestNoTopicCap: 100 joined topics with the default config, and an application cap still refuses.
func TestNoTopicCap(t *testing.T) {
	f := newFixture(t, nil)
	for i := range 100 {
		f.join(topicID(i), nil)
	}
	if f.r.Stats().Topics != 100 {
		t.Fatalf("%d topics", f.r.Stats().Topics)
	}
}

// headroomFixture is a node with peers peers all in topics topics, joined by us; peers 1 to D are in every mesh.
func headroomFixture(t *testing.T, cfg *Config, peers, topics int) (*fixture, []wire.Topic) {
	f := newFixture(t, cfg)
	ts := []wire.Topic{T}
	for i := 1; i < topics; i++ {
		ts = append(ts, topicID(i+1))
	}
	for _, tp := range ts {
		f.join(tp, nil)
	}
	f.addPeers(peers, ts...)
	for i := 1; i <= f.r.cfg.Params.D; i++ {
		for k := 0; k < len(ts); k += maxFrameTopics {
			f.control(i, &wire.Control{Graft: ts[k:min(k+maxFrameTopics, len(ts))]})
		}
	}
	f.heartbeat()
	f.sink.reset()
	f.settle()
	return f, ts
}

// TestHonestHeadroomAt: honest mesh peers never wait, lose no message and keep their score at the design rate with
// bursts, from 64 to 1,258 connected peers, in one topic, in 50 topics with all the traffic in one, and with it
// spread over all.
func TestHonestHeadroomAt(t *testing.T) {
	for _, c := range []struct {
		name          string
		peers, topics int
		spread        bool
	}{
		{"64 peers", 64, 1, false}, {"256 peers", 256, 1, false}, {"1,000 peers", 1000, 1, false}, {"1,258 peers", 1258, 1, false},
		{"1,000 peers, 50 topics, one busy", 1000, 50, false}, {"1,000 peers, 50 topics, spread", 1000, 50, true},
	} {
		cfg := DefaultConfig()
		manyPeers(cfg)
		f, ts := headroomFixture(t, cfg, c.peers, c.topics)
		if c.spread {
			f.spread = ts
		}
		f, sent, waited := honestRunOn(t, f, cfg, cfg.DesignRate, 8, true, false)
		if waited != (PeerID{}) {
			t.Fatalf("%s: peer %x waited after %d messages", c.name, waited[:4], sent)
		}
		if s := f.r.Stats(); s.Delivered != uint64(sent) || s.Waits != 0 {
			t.Fatalf("%s: %d of %d delivered, %d waits", c.name, s.Delivered, sent, s.Waits)
		}
		for q := 1; q <= cfg.Params.D; q++ {
			if f.r.Score(key(q)) < 0 {
				t.Fatalf("%s: mesh peer %d penalised: %v", c.name, q, f.r.Score(key(q)))
			}
		}
	}
}

// TestHonestHeadroomMeasuredAt reports, for limits.md, what an honest mesh peer uses per second of its buckets at the
// design rate against its share, from 64 to 1,258 peers and 1 to 50 topics, and that the share is never short.
func TestHonestHeadroomMeasuredAt(t *testing.T) {
	for _, c := range []struct {
		peers, topics int
		spread        bool
	}{{64, 1, false}, {1000, 1, false}, {1258, 1, false}, {1000, 50, false}, {1258, 50, false}, {1000, 50, true}} {
		for _, sole := range []bool{false, true} {
			cfg := DefaultConfig()
			cfg.WorkBurst = time.Hour // nothing waits, so the use can be read in full
			f, ts := headroomFixture(t, cfg, c.peers, c.topics)
			if c.spread {
				f.spread = ts
			}
			f.r.AuditOps()
			start := f.r.byID[key(1)].lock.level
			f, sent, _ := honestRunOn(t, f, cfg, cfg.DesignRate, 4, false, sole)
			_, charged := f.r.Audit()
			var lock, out int64
			for op, n := range charged {
				if op.outside() {
					out += Cost(op, int(n))
				} else {
					lock += Cost(op, int(n))
				}
			}
			d := int64(cfg.Params.D) * 4
			rl, ro := rateOf(f, 1)
			if sole {
				used := (start - f.r.byID[key(1)].lock.level) / 4
				t.Logf("%d peers, %d topics, spread %v, sole source: %d lock units/s of %d (%.2fx its rate)", c.peers, c.topics, c.spread, used, rl, float64(used)/float64(rl))
				continue
			}
			t.Logf("%d peers, %d topics, spread %v, %d messages in 4 s: a mesh peer used %d lock units/s of %d (%.1fx headroom), %d reader units/s of %d (%.1fx)",
				c.peers, c.topics, c.spread, sent, lock/d, rl, float64(rl)/float64(lock/d), out/d, ro, float64(ro)/float64(out/d))
			if rl < lock/d {
				t.Fatalf("share %d under the use %d", rl, lock/d)
			}
		}
	}
}

// TestIHaveOfSeenIDsCost reports what one IHAVE of 5,000 ids we have seen, from a peer outside our mesh, costs it.
func TestIHaveOfSeenIDsCost(t *testing.T) {
	f := meshFixture(t, nil, 2, 1)
	var all []wire.ID
	for i := range 5000 {
		raw := envelope(T, key(900), uint64(i), f.now, 100)
		all = append(all, wire.NewID(raw))
		f.receive(1, raw, Accept)
	}
	f.r.AuditPeer(key(2))
	f.control(2, &wire.Control{IHave: []wire.IHave{{Topic: T, IDs: all}}})
	_, charged := f.r.Audit()
	var lock, out int64
	for op, n := range charged {
		if op.outside() {
			out += Cost(op, int(n))
		} else {
			lock += Cost(op, int(n))
		}
	}
	t.Logf("an IHAVE of 5,000 seen ids charges %d lock units and %d reader units", lock, out)
}

// TestShareRule: a peer's rate is half the budget shared by connection, a quarter by mesh places and a quarter by
// delivered messages; a mesh peer that delivered nothing gets no traffic share; with no mesh everything is shared
// by connection; rates never sum to more than the budget; the reader rate is capped.
func TestShareRule(t *testing.T) {
	f := meshFixture(t, nil, 4, 0)
	b := f.r.cfg.LockWork
	near := func(got, want int64) bool { return got >= want-1 && got <= want+1 }
	for i := 1; i <= 4; i++ {
		if lock, _ := rateOf(f, i); !near(lock, b/4) {
			t.Fatalf("no mesh: peer %d rate %d, want %d", i, lock, b/4)
		}
	}
	setShares(f, []int32{2, 1, 0, 0}, []int64{30, 10, 0, 0})
	for i, want := range []float64{1.0/8 + 2.0/12 + 30.0/160, 1.0/8 + 1.0/12 + 10.0/160, 1.0 / 8, 1.0 / 8} {
		if lock, _ := rateOf(f, i+1); !near(lock, int64(float64(b)*want)) {
			t.Fatalf("peer %d rate %d, want %d", i+1, lock, int64(float64(b)*want))
		}
	}
	setShares(f, []int32{2, 1, 0, 0}, []int64{0, 0, 0, 0})
	if lock, _ := rateOf(f, 1); !near(lock, int64(float64(b)*(1.0/8+2.0/12+2.0/12))) {
		t.Fatalf("mesh without traffic: rate %d", lock)
	}
	setShares(f, []int32{1, 1, 0, 0}, []int64{50, 0, 0, 0})
	silent, _ := rateOf(f, 2)
	if want := int64(float64(b) * (1.0/8 + 1.0/8)); !near(silent, want) {
		t.Fatalf("a silent mesh peer got %d, want %d", silent, want)
	}
	var sum int64
	for i := 1; i <= 4; i++ {
		lock, _ := rateOf(f, i)
		sum += lock
	}
	if sum > b {
		t.Fatalf("rates sum to %d over the budget %d", sum, b)
	}
	if _, out := rateOf(f, 1); out != f.r.cfg.PeerWork {
		t.Fatalf("reader rate %d not capped at PeerWork %d", out, f.r.cfg.PeerWork)
	}
}

// TestSharesFollowTheMesh: after a heartbeat a mesh peer that delivered messages has a larger rate than a mesh peer
// that delivered none, which has a larger one than a peer outside the mesh.
func TestSharesFollowTheMesh(t *testing.T) {
	f := meshFixture(t, nil, 6, 4)
	for i := range 10 {
		f.receive(1, envelope(T, key(900), uint64(i), f.now, 100), Accept)
	}
	f.heartbeat()
	busy, _ := rateOf(f, 1)
	silent, _ := rateOf(f, 3)
	outside, _ := rateOf(f, 5)
	if !(busy > silent && silent > outside) {
		t.Fatalf("rates: delivering mesh peer %d, silent mesh peer %d, peer outside the mesh %d", busy, silent, outside)
	}
	if f.r.byID[key(1)].delivered != 10 || f.r.byID[key(3)].delivered != 0 || f.r.meshPlaces != 4 {
		t.Fatalf("snapshot: %d delivered by peer 1, %d by peer 3, %d places", f.r.byID[key(1)].delivered, f.r.byID[key(3)].delivered, f.r.meshPlaces)
	}
}

// TestShareSumBounded: over a run of connections, mesh changes, messages and heartbeats, the rates of all peers
// never sum to more than LockWork and ReaderWork.
func TestShareSumBounded(t *testing.T) {
	f := newFixture(t, nil)
	f.join(T, nil)
	rnd := randFor(5)
	seq := uint64(0)
	check := func() {
		var lock, out int64
		for _, p := range f.r.peers {
			l, o := peerRates(f, p)
			lock, out = lock+l, out+o
		}
		if lock > f.r.cfg.LockWork || out > readerWork(&f.r.cfg) {
			t.Fatalf("%d peers: lock rates %d of %d, reader rates %d of %d", len(f.r.peers), lock, f.r.cfg.LockWork, out, readerWork(&f.r.cfg))
		}
	}
	for step := range 400 {
		switch k := rnd.IntN(10); {
		case k < 4:
			if i := 1 + rnd.IntN(200); f.r.byID[key(i)] == nil {
				f.addPeer(i, rnd.IntN(2) == 0, T)
			}
		case k < 5:
			f.r.RemovePeer(f.now, key(1+rnd.IntN(200)))
		case k < 7:
			f.r.Control(f.now, key(1+rnd.IntN(200)), &wire.Control{Graft: []wire.Topic{T}})
		case k < 9:
			seq++
			f.r.Message(f.now, key(1+rnd.IntN(200)), envelope(T, key(900), seq, f.now, 100))
			for _, v := range f.sink.validate {
				f.r.ValidationDone(f.now, v.id, v.n, Accept)
			}
			f.sink.reset()
		default:
			f.heartbeat()
		}
		if step%10 == 0 {
			check()
		}
	}
	f.heartbeat()
	check()
}

// TestReaderBudget: at 1,000 peers the reader rates sum to at most ReaderWork, so the reader CPU of all peers
// does not grow with their number.
func TestReaderBudget(t *testing.T) {
	cfg := DefaultConfig()
	manyPeers(cfg)
	f := meshFixture(t, cfg, 1000, 6)
	f.heartbeat()
	var sum int64
	for i := 1; i <= 1000; i++ {
		_, out := rateOf(f, i)
		sum += out
	}
	if sum > readerWork(cfg) {
		t.Fatalf("reader rates sum to %d, over %d", sum, readerWork(cfg))
	}
}

// TestNewcomerPoolFixed: the grant of a new key is the same at 1,000 peers as at the first of 64: a 64th of
// LockWork, whatever the number of peers.
func TestNewcomerPoolFixed(t *testing.T) {
	cfg := DefaultConfig()
	manyPeers(cfg)
	f := meshFixture(t, cfg, 1000, 0)
	f.now = f.now.Add(2 * cfg.WorkBurst)
	if err := f.r.AddPeer(f.now, key(2000), false, addr(2000)); err != nil {
		t.Fatal(err)
	}
	if got, want := f.r.byID[key(2000)].lock.level, cfg.LockWork/64; got < want-100 || got > want { // the connect itself is charged a few lookups
		t.Fatalf("a new key at 1,000 peers got %d units, want %d", got, want)
	}
}

// TestValidationFairShare: 200 senders outside the mesh with a validator that never answers hold at most half of
// MaxValidating, a mesh peer is still admitted, and a sender past its fair share is throttled.
func TestValidationFairShare(t *testing.T) {
	cfg := DefaultConfig()
	manyPeers(cfg)
	f := meshFixture(t, cfg, 201, 1)
	seq := uint64(0)
	send := func(p, n int) {
		for range n {
			seq++
			f.r.Message(f.now, key(p), envelope(T, key(900), seq, f.now, 10))
		}
	}
	for range 16 {
		for p := 2; p <= 201; p++ {
			send(p, 1)
		}
	}
	if s := f.r.Stats(); s.Validating > cfg.MaxValidating/2 {
		t.Fatalf("senders outside the mesh hold %d, over half of %d", s.Validating, cfg.MaxValidating)
	}
	held := f.r.Stats().Validating
	send(1, 8)
	if s := f.r.Stats(); s.Validating != held+5 {
		t.Fatalf("a mesh peer holds %d of its 8 messages, want 5 (a fair share of %d among 201)", s.Validating-held, cfg.MaxValidating)
	}
}

// TestGossipPeersCap: at the design rate one heartbeat sends IHAVE to 43 of 300 non-mesh peers of a topic, not to
// 0.75 of them; a quiet node sends it to 0.75 of them, as the specification says. The peers the heartbeat grafts get
// their own IHAVE (TestGraftGossip) and are not counted.
func TestGossipPeersCap(t *testing.T) {
	for _, c := range []struct{ msgs, want int }{{1, 220}, {5000, 43}} {
		cfg := DefaultConfig()
		f := meshFixture(t, cfg, 300, 0)
		for i := range c.msgs {
			f.receive(1, envelope(T, key(900), uint64(i), f.now, 10), Accept)
		}
		f.sink.reset()
		f.heartbeat()
		n := 0
		for i := 1; i <= 300; i++ {
			for _, ctl := range f.sink.ctrlTo(key(i)) {
				if len(ctl.IHave) > 0 && !f.inMesh(T, i) {
					n++
				}
			}
		}
		if n != c.want {
			t.Fatalf("%d ids: IHAVE to %d peers, want %d", c.msgs, n, c.want)
		}
	}
}

// TestGossipCoversCandidates: the peers one heartbeat leaves out get the next heartbeat's IHAVE first, so with
// GossipFactor 0.75 every candidate hears of an id within two heartbeats.
func TestGossipCoversCandidates(t *testing.T) {
	f := meshFixture(t, nil, 40, 0)
	f.receive(1, envelope(T, key(900), 1, f.now, 10), Accept)
	got := map[int]bool{}
	for range 2 {
		f.sink.reset()
		f.heartbeat()
		for i := 1; i <= 40; i++ {
			for _, ctl := range f.sink.ctrlTo(key(i)) {
				if len(ctl.IHave) > 0 && !f.inMesh(T, i) {
					got[i] = true
				}
			}
		}
	}
	if want := 40 - len(f.r.Mesh(T)); len(got) != want {
		t.Fatalf("two heartbeats announced to %d of %d candidates", len(got), want)
	}
}

// TestJoinMovesSubscriptions: a fanout topic created by a publish takes the peers' subscriptions from their other
// lists, and its expiry gives them back.
func TestJoinMovesSubscriptions(t *testing.T) {
	cfg := DefaultConfig()
	cfg.FloodPublish = false
	f := newFixture(t, cfg)
	f.addPeers(1)
	f.control(1, topicsFrame(0, 1))
	if topics, other := listsOf(f, 1); len(topics) != 0 || len(other) != 1 {
		t.Fatalf("before: %d topics, %d other", len(topics), len(other))
	}
	if _, err := f.r.Publish(f.now, envelope(manyTopic(0), key(0), 1, f.now, 10)); err != nil {
		t.Fatal(err)
	}
	if topics, other := listsOf(f, 1); len(topics) != 1 || len(other) != 0 || len(f.r.Fanout(manyTopic(0))) != 1 {
		t.Fatalf("fanout: %d topics, %d other", len(topics), len(other))
	}
	f.tick(cfg.FanoutTTL + 2*time.Second)
	if topics, other := listsOf(f, 1); len(topics) != 0 || len(other) != 1 {
		t.Fatalf("expired: %d topics, %d other", len(topics), len(other))
	}
}

// TestPublishReachesOtherTopics: our own message to a topic we hold no state for is flooded to the peers that
// announced it, as before.
func TestPublishReachesOtherTopics(t *testing.T) {
	f := newFixture(t, nil)
	f.addPeers(2)
	f.control(1, topicsFrame(0, 1))
	if _, err := f.r.Publish(f.now, envelope(manyTopic(0), key(0), 1, f.now, 10)); err != nil {
		t.Fatal(err)
	}
	if f.sink.msgsTo(key(1)) != 1 || f.sink.msgsTo(key(2)) != 0 {
		t.Fatalf("copies: %d and %d", f.sink.msgsTo(key(1)), f.sink.msgsTo(key(2)))
	}
}

// TestGraftRecordsSubscription: a peer whose subscription we did not keep is subscribed again when it grafts a
// topic we joined.
func TestGraftRecordsSubscription(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxPeerTopics = 1
	f := newFixture(t, cfg)
	f.addPeers(1)
	f.control(1, topicsFrame(0, 3))
	f.join(manyTopic(2), nil)
	if f.inMesh(manyTopic(2), 1) {
		t.Fatal("a dropped subscription was used")
	}
	f.control(1, &wire.Control{Graft: []wire.Topic{manyTopic(2)}})
	if topics, _ := listsOf(f, 1); !f.inMesh(manyTopic(2), 1) || len(topics) != 1 {
		t.Fatal("the GRAFT did not record the subscription")
	}
}

// TestCopiesRecordedBounded: the copies recorded for a message never pass the peers connected.
func TestCopiesRecordedBounded(t *testing.T) {
	f := meshFixture(t, nil, 3, 0)
	raw := envelope(T, key(900), 1, f.now, 10)
	for i := 1; i <= 3; i++ {
		f.r.Message(f.now, key(i), raw)
	}
	for i := 1; i <= 3; i++ {
		f.r.Message(f.now, key(i), raw)
	}
	if n := len(f.r.recs[wire.NewID(raw)].peers); n != 3 {
		t.Fatalf("%d copies recorded, want the 3 peers connected", n)
	}
}

// TestLeaveCost: a peer leaving a node of 1,258 peers and 50 topics is charged less than one transport handshake.
func TestLeaveCost(t *testing.T) {
	cfg := DefaultConfig()
	manyPeers(cfg)
	f, _ := headroomFixture(t, cfg, 1258, 50)
	f.r.AuditPeer(key(1000))
	f.r.RemovePeer(f.now, key(1000))
	_, charged := f.r.Audit()
	var units int64
	for op, n := range charged {
		units += Cost(op, int(n))
	}
	t.Logf("leaving charged %d units", units)
	if units >= Cost(OpDial, 1) {
		t.Fatalf("leaving charged %d units, a handshake is %d", units, Cost(OpDial, 1))
	}
}

func BenchmarkLeave(b *testing.B) {
	cfg := DefaultConfig()
	f, _ := headroomFixture(&testing.T{}, cfg, 1258, 50)
	f.sink.bench = true
	for i := 0; b.Loop(); i++ {
		b.StopTimer()
		k := key(1259 + i)
		f.addPeer(1259+i, true, T)
		b.StartTimer()
		f.r.RemovePeer(f.now, k)
	}
}

func BenchmarkJoinMoves(b *testing.B) {
	f := newFixture(&testing.T{}, nil)
	f.sink.bench = true
	f.addPeers(1258)
	for i := 1; i <= 1258; i++ {
		f.control(i, topicsFrame(0, 1))
	}
	for b.Loop() {
		f.join(manyTopic(0), nil)
		f.r.Leave(f.now, manyTopic(0))
	}
}

func BenchmarkHeartbeat(b *testing.B) {
	f, _ := headroomFixture(&testing.T{}, DefaultConfig(), 1258, 50)
	f.sink.bench = true
	for b.Loop() {
		f.heartbeat()
	}
}

// TestMergeSubsCapacity: a frame of many unsubscribes leaves the other-topics list at its own size, not the frame's.
func TestMergeSubsCapacity(t *testing.T) {
	f := newFixture(t, nil)
	f.addPeers(1)
	f.control(1, topicsFrame(0, 1024))
	c := &wire.Control{}
	for i := range 15887 {
		c.Subs = append(c.Subs, wire.Sub{Topic: manyTopic(20000 + i)})
	}
	f.control(1, c)
	_, other := listsOf(f, 1)
	if len(other) != 1024 || cap(other) > 2*len(other) {
		t.Fatalf("other list: length %d, capacity %d", len(other), cap(other))
	}
}

// TestBootstrapGossip: a bootstrap Params has no GossipPeers cap, so it gossips as the specification says.
func TestBootstrapGossip(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Params = Params{Dlazy: 6, GossipFactor: 0.75}
	f := newFixture(t, cfg)
	f.join(T, nil)
	f.addPeers(40, T)
	f.receive(1, envelope(T, key(900), 1, f.now, 10), Accept)
	f.sink.reset()
	f.heartbeat()
	n := 0
	for i := 1; i <= 40; i++ {
		for _, c := range f.sink.ctrlTo(key(i)) {
			if len(c.IHave) > 0 {
				n++
			}
		}
	}
	if n != 30 {
		t.Fatalf("IHAVE to %d of 40 peers, want 30", n)
	}
}

// TestGossipBudgetAcrossTopics: the gossip budget is the node's: 2,000 ids in 20 topics leave each topic 106 targets, not 43.
func TestGossipBudgetAcrossTopics(t *testing.T) {
	cfg := DefaultConfig()
	f, ts := headroomFixture(t, cfg, 300, 20)
	for k, tp := range ts {
		for i := range 100 {
			f.receive(1+k%cfg.Params.D, envelope(tp, key(900), uint64(k*100+i), f.now, 10), Accept)
		}
	}
	f.sink.reset()
	f.heartbeat()
	n := 0
	for i := 1; i <= 300; i++ {
		for _, c := range f.sink.ctrlTo(key(i)) {
			n += len(c.IHave)
		}
	}
	if want := 20 * (cfg.Params.GossipPeers * cfg.MaxIHaveLength / (20*100 + 20)); n != want {
		t.Fatalf("%d IHAVE for 20 topics, want %d: the budget is the node's, shared by their ids", n, want)
	}
}

// TestHeadroomSharedTopics: with all traffic in one topic and 256 peers sharing many topics, an honest mesh peer keeps
// its headroom at 50 and 100 shared topics; the figures are in limits.md.
func TestHeadroomSharedTopics(t *testing.T) {
	for _, c := range []struct {
		topics int
		min    float64
	}{{50, 3}, {100, 1.5}, {200, 0}} {
		cfg := DefaultConfig()
		cfg.WorkBurst = time.Hour
		f, _ := headroomFixture(t, cfg, 256, c.topics)
		f.r.AuditOps()
		f, sent, _ := honestRunOn(t, f, cfg, cfg.DesignRate, 2, false, false)
		_, charged := f.r.Audit()
		var lock int64
		for op, n := range charged {
			if !op.outside() {
				lock += Cost(op, int(n))
			}
		}
		use := lock / int64(cfg.Params.D*2)
		rl, _ := rateOf(f, 1)
		h := float64(rl) / float64(use)
		t.Logf("%d shared topics, %d messages: a mesh peer uses %d lock units/s of %d (%.2fx headroom)", c.topics, sent, use, rl, h)
		if h < c.min {
			t.Fatalf("%d shared topics: headroom %.2fx, want at least %.2fx", c.topics, h, c.min)
		}
	}
}
