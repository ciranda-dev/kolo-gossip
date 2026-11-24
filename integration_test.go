package kologossip

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	kolodht "github.com/ciranda-dev/kolo-dht"
	"github.com/ciranda-dev/kolo-gossip/internal/wire"
	koloid "github.com/ciranda-dev/kolo-id"
	koloswarm "github.com/ciranda-dev/kolo-swarm"
)

// TestDeliveryBothWays: messages flow both ways with their author, sequence and neighbour, Gossip.Publish on a
// joined topic continues the room's sequence, and our own messages are not delivered to ourselves.
func TestDeliveryBothWays(t *testing.T) {
	checkGoroutines(t)
	a, b := newMember(t), newMember(t)
	ros := newRoster(a, b)
	topic := testTopic("two")
	na, nb := newNode(t, nodeOpts{m: a}), newNode(t, nodeOpts{m: b})
	ra := na.join(t, topic, &TopicOptions{Authors: ros}).collect(na)
	rb := nb.join(t, topic, &TopicOptions{Authors: ros}).collect(nb)
	na.connect(t, topic, nb)
	subscribed(t, ra.Room, 1)
	subscribed(t, rb.Room, 1)

	id1 := publish(t, ra.Room, "from a")
	id2 := publish(t, rb.Room, "from b")
	waitFor(t, 10*time.Second, "delivery", func() bool { return rb.has(id1) && ra.has(id2) })
	m := rb.msg(id1)
	if string(m.Body) != "from a" || !bytes.Equal(m.Person, a.person.PublicKey()) || !bytes.Equal(m.Device, a.device.PublicKey()) ||
		!bytes.Equal(m.From, a.device.PublicKey()) || m.Topic != topic || time.Since(m.Time) > time.Minute {
		t.Fatalf("message %+v", m)
	}
	id3 := publish(t, ra.Room, "second")
	m4, err := na.g.Publish(context.Background(), topic, []byte("third"))
	if err != nil {
		t.Fatal(err)
	}
	id4 := m4.ID
	waitFor(t, 10*time.Second, "later deliveries", func() bool { return rb.has(id3, id4) })
	if rb.msg(id3).Seq != m.Seq+1 || rb.msg(id4).Seq != m.Seq+2 {
		t.Fatalf("seq %d and %d after %d", rb.msg(id3).Seq, rb.msg(id4).Seq, m.Seq)
	}
	if ra.has(id1) || ra.has(id3) || ra.count() != 1 {
		t.Fatal("own message delivered")
	}
	waitFor(t, 10*time.Second, "mesh", func() bool { return rb.Stats().Mesh == 1 && ra.Stats().Mesh == 1 })
	if s := rb.Stats(); s.Delivered != 3 || s.Peers != 1 || s.Dropped != 0 {
		t.Fatalf("room stats %+v", s)
	}
}

// TestDiscoveryThroughDHT: five nodes that find each other through a kolo-dht server, as Join does by default,
// deliver every message to every other member.
func TestDiscoveryThroughDHT(t *testing.T) {
	checkGoroutines(t)
	srv := newServer(t)
	_, rooms := dhtRoom(t, srv, 5)
	var ids []MessageID
	for i, r := range rooms {
		ids = append(ids, publish(t, r.Room, fmt.Sprintf("m%d", i)))
	}
	for i, r := range rooms {
		want := append(append([]MessageID{}, ids[:i]...), ids[i+1:]...)
		waitFor(t, 10*time.Second, fmt.Sprintf("node %d delivery", i), func() bool { return r.has(want...) })
	}
}

// TestLateJoiner: a member that joins later gets what is published after it joined and nothing that left the
// message caches before.
func TestLateJoiner(t *testing.T) {
	checkGoroutines(t)
	srv := newServer(t)
	nodes, rooms := dhtRoom(t, srv, 3)
	early := publish(t, rooms[0].Room, "early")
	waitFor(t, 10*time.Second, "early delivery", func() bool { return rooms[1].has(early) && rooms[2].has(early) })
	// Messages still in a message cache would reach a late joiner through IHAVE, as GossipSub intends.
	for i, n := range nodes {
		waitFor(t, 10*time.Second, fmt.Sprintf("node %d cache to age out", i), func() bool { return n.g.Stats().Router.CacheMessages == 0 })
	}
	m := newMember(t)
	rooms[0].ros.add(m)
	late := newNode(t, nodeOpts{m: m, server: srv})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	lr, err := late.g.Join(ctx, rooms[0].Topic(), &TopicOptions{Authors: rooms[0].ros})
	if err != nil {
		t.Fatal(err)
	}
	lroom := (&room{Room: lr, got: map[MessageID]*Message{}}).collect(late)
	subscribed(t, lr, 1)
	waitFor(t, 20*time.Second, "late joiner known", func() bool { return rooms[0].Stats().Peers == 3 })
	after := publish(t, rooms[0].Room, "after")
	waitFor(t, 10*time.Second, "late delivery", func() bool { return lroom.has(after) })
	if lroom.count() != 1 {
		t.Fatalf("late joiner got %d messages, want only the one after it joined", lroom.count())
	}
}

// dhtRoom starts n nodes that join one closed room through srv and waits until each sees all the others.
func dhtRoom(t *testing.T, srv *kolodht.Node, n int) ([]*node, []*room) {
	t.Helper()
	var ms []*member
	for range n {
		ms = append(ms, newMember(t))
	}
	ros := newRoster(ms...)
	topic := testTopic(t.Name())
	var nodes []*node
	var rooms []*room
	for _, m := range ms {
		nd := newNode(t, nodeOpts{m: m, server: srv})
		nodes = append(nodes, nd)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		rm, err := nd.g.Join(ctx, topic, &TopicOptions{Authors: ros})
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		rooms = append(rooms, (&room{Room: rm, got: map[MessageID]*Message{}, ros: ros}).collect(nd))
	}
	(&cluster{rooms: rooms}).ready(t, n-1)
	return nodes, rooms
}

// cluster is n nodes in one closed room, connected along edges.
type cluster struct {
	members []*member
	ros     *roster
	nodes   []*node
	rooms   []*room
	topic   Topic
}

func newCluster(t *testing.T, n int, edges [][2]int, tweak func(*Config)) *cluster {
	t.Helper()
	c := &cluster{topic: testTopic(t.Name())}
	for range n {
		c.members = append(c.members, newMember(t))
	}
	c.ros = newRoster(c.members...)
	for _, m := range c.members {
		nd := newNode(t, nodeOpts{m: m, tweak: tweak})
		c.nodes = append(c.nodes, nd)
		c.rooms = append(c.rooms, nd.join(t, c.topic, &TopicOptions{Authors: c.ros}).collect(nd))
	}
	for _, e := range edges {
		c.nodes[e[0]].connect(t, c.topic, c.nodes[e[1]])
	}
	return c
}

// ready waits until every room sees peers subscribed peers and holds them all in its mesh (fewer than Dlo 4), so a
// message is pushed along the mesh rather than repaired by gossip.
func (c *cluster) ready(t *testing.T, peers int, skip ...int) {
	t.Helper()
	for i, r := range c.rooms {
		if slices.Contains(skip, i) {
			continue
		}
		waitFor(t, 20*time.Second, fmt.Sprintf("node %d mesh", i), func() bool {
			s := r.Stats()
			return s.Peers >= peers && s.Mesh >= min(peers, 4)
		})
	}
}

// ring returns the edges of a ring of n nodes plus a chord from each node to the one k ahead.
func ring(n, k int) [][2]int {
	var e [][2]int
	for i := range n {
		e = append(e, [2]int{i, (i + 1) % n})
		if k > 1 && n > 2*k {
			e = append(e, [2]int{i, (i + k) % n})
		}
	}
	return e
}

// delivered waits until every room except the publisher's (and those in skip) has every id.
func (c *cluster) delivered(t *testing.T, d time.Duration, from int, ids []MessageID, skip ...int) {
	t.Helper()
	for i, r := range c.rooms {
		if i == from || slices.Contains(skip, i) {
			continue
		}
		waitFor(t, d, fmt.Sprintf("node %d to get %d messages from node %d", i, len(ids), from), func() bool { return r.has(ids...) })
	}
}

// TestMultiHopDelivery: 20 nodes on a ring with chords, four connections each, so most messages cross several
// hops; every message reaches every member exactly once and the meshes form within their bounds.
func TestMultiHopDelivery(t *testing.T) {
	checkGoroutines(t)
	c := newCluster(t, 20, ring(20, 5), nil)
	c.ready(t, 4)
	start := time.Now()
	for from := range 20 {
		var ids []MessageID
		for k := range 3 {
			ids = append(ids, publish(t, c.rooms[from].Room, fmt.Sprintf("%d/%d", from, k)))
		}
		c.delivered(t, 20*time.Second, from, ids)
	}
	t.Logf("60 messages to 19 members each in %v", time.Since(start))
	for i, r := range c.rooms {
		if r.count() != 57 {
			t.Fatalf("node %d got %d messages, want 57", i, r.count())
		}
	}
}

// TestPeerDies: a node that disappears without a word does not stop the others.
func TestPeerDies(t *testing.T) {
	checkGoroutines(t)
	c := newCluster(t, 5, [][2]int{{0, 1}, {1, 2}, {2, 3}, {3, 4}, {4, 0}, {0, 2}, {1, 3}, {2, 4}}, nil)
	c.ready(t, 3)
	id := publish(t, c.rooms[0].Room, "before")
	c.delivered(t, 10*time.Second, 0, []MessageID{id})
	c.nodes[2].sw.Close()
	waitFor(t, 20*time.Second, "the dead peer to be removed", func() bool {
		for i, r := range c.rooms {
			if i != 2 && r.Stats().Peers != 2 {
				return false
			}
		}
		return true
	})
	c.ready(t, 2, 2)
	for _, from := range []int{0, 1, 3, 4} {
		id := publish(t, c.rooms[from].Room, fmt.Sprintf("after %d", from))
		c.delivered(t, 10*time.Second, from, []MessageID{id}, 2)
	}
}

// TestRestart: a node that restarts with the same device key reconnects; its new messages and the others' reach
// it and the others, and the seen caches never mistake them for old ones.
func TestRestart(t *testing.T) {
	checkGoroutines(t)
	c := newCluster(t, 3, [][2]int{{0, 1}, {1, 2}, {2, 0}}, nil)
	c.ready(t, 2)
	id := publish(t, c.rooms[2].Room, "first life")
	c.delivered(t, 10*time.Second, 2, []MessageID{id})
	c.nodes[2].close()

	n := newNode(t, nodeOpts{m: c.members[2]})
	r := n.join(t, c.topic, &TopicOptions{Authors: c.ros}).collect(n)
	n.connect(t, c.topic, c.nodes[0])
	n.connect(t, c.topic, c.nodes[1])
	c.nodes[2], c.rooms[2] = n, r
	c.ready(t, 2)
	again := publish(t, r.Room, "second life")
	c.delivered(t, 10*time.Second, 2, []MessageID{again})
	back := publish(t, c.rooms[0].Room, "to the restarted node")
	c.delivered(t, 10*time.Second, 0, []MessageID{back})
	if r.count() != 1 {
		t.Fatalf("restarted node got %d messages", r.count())
	}
}

// TestClosedModeRevoked: a device whose own roster holds its revocation refuses to publish; one that does not know
// yet publishes, and nodes that know ignore its message without penalising the forwarder that did not know. A
// device the roster does not know is ignored without penalty too, while the other members' messages flow.
func TestClosedModeRevoked(t *testing.T) {
	checkGoroutines(t)
	c := newCluster(t, 4, [][2]int{{1, 2}, {0, 1}, {3, 0}, {3, 1}}, nil)
	c.ready(t, 1)
	revoked, stranger := c.members[2], c.members[3]
	rev, err := revoked.person.RevokeDevice(&koloid.RevokeOptions{Person: revoked.person.PublicKey(), Device: revoked.device.PublicKey(), UpToSerial: 1})
	if err != nil {
		t.Fatal(err)
	}
	unaware := newRoster(c.members[:3]...)
	c.ros.revoke(revoked, rev)
	c.ros.mu.Lock()
	delete(c.ros.m, pairKey(stranger.person.PublicKey(), stranger.device.PublicKey()))
	c.ros.mu.Unlock()
	if _, err := c.rooms[2].Publish(context.Background(), []byte("refused")); !errors.Is(err, koloid.ErrCertRevoked) {
		t.Fatalf("a device that knows its revocation published: %v", err)
	}
	for _, i := range []int{1, 2} {
		g := c.nodes[i].g
		g.mu.Lock()
		g.rooms[c.topic].authors = unaware
		g.mu.Unlock()
	}

	id := publish(t, c.rooms[2].Room, "revoked")
	waitFor(t, 10*time.Second, "the unaware forwarder to deliver it", func() bool { return c.rooms[1].has(id) })
	publish(t, c.rooms[3].Room, "unknown")
	waitFor(t, 10*time.Second, "both ignored", func() bool { return c.nodes[0].g.Stats().Router.UnknownAuthor >= 2 })
	first := c.nodes[0].g
	if first.Score(c.members[1].device.PublicKey()) < 0 || first.Score(stranger.device.PublicKey()) < 0 || first.Stats().Router.BadSignature != 0 {
		t.Fatalf("an honest forwarder or an unknown author lost score: %v %v", first.Score(c.members[1].device.PublicKey()), first.Score(stranger.device.PublicKey()))
	}
	if c.rooms[0].has(id) {
		t.Fatal("a revoked device's message was delivered")
	}
	member := publish(t, c.rooms[0].Room, "member")
	waitFor(t, 10*time.Second, "member delivery", func() bool { return c.rooms[1].has(member) && c.rooms[3].has(member) })
}

// TestOpenMode: with no roster, a device's chain is fetched with CERTWANT from the peer that forwarded its first
// message: from the author itself, then from a forwarder's cache.
func TestOpenMode(t *testing.T) {
	checkGoroutines(t)
	topic := testTopic(t.Name())
	open := func(Topic, ed25519.PublicKey) ([]*koloid.Revocation, bool) { return nil, true }
	var nodes []*node
	var rooms []*room
	for range 3 {
		n := newNode(t, nodeOpts{})
		nodes = append(nodes, n)
		rooms = append(rooms, n.join(t, topic, &TopicOptions{Open: open}).collect(n))
	}
	nodes[0].connect(t, topic, nodes[1])
	nodes[1].connect(t, topic, nodes[2])
	c := &cluster{nodes: nodes, rooms: rooms, topic: topic}
	c.ready(t, 1)
	id := publish(t, rooms[0].Room, "open")
	c.delivered(t, 10*time.Second, 0, []MessageID{id})
	if nodes[1].g.Stats().Router.CertWantSent != 1 || nodes[2].g.Stats().Router.CertWantSent != 1 {
		t.Fatal("chains not fetched")
	}
	if nodes[0].g.Stats().Authors.Served != 1 || nodes[1].g.Stats().Authors.Served != 1 {
		t.Fatal("chains not served by the author and the forwarder")
	}
	again := publish(t, rooms[0].Room, "cached")
	c.delivered(t, 10*time.Second, 0, []MessageID{again})
	if nodes[2].g.Stats().Router.CertWantSent != 1 {
		t.Fatal("a cached chain was fetched again")
	}
}

// TestPublishWithoutJoin: a node that only looks the topic up on the swarm publishes to it, by flooding to every
// subscribed peer or, without flood publishing, through fanout peers as GossipSub defines.
func TestPublishWithoutJoin(t *testing.T) {
	checkGoroutines(t)
	for _, flood := range []bool{true, false} {
		t.Run(fmt.Sprint("flood=", flood), func(t *testing.T) {
			c := newCluster(t, 3, [][2]int{{0, 1}, {1, 2}}, nil)
			c.ready(t, 1)
			pm := newMember(t)
			c.ros.add(pm)
			p := newNode(t, nodeOpts{m: pm, tweak: func(cfg *Config) { cfg.NoFloodPublish = !flood }})
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := p.sw.Join(ctx, c.topic, &koloswarm.JoinOptions{Lookup: true}); err != nil {
				t.Fatal(err)
			}
			p.connect(t, c.topic, c.nodes[0])
			p.connect(t, c.topic, c.nodes[1])
			waitFor(t, 10*time.Second, "subscriptions", func() bool {
				p.g.mu.Lock()
				defer p.g.mu.Unlock()
				return p.g.r.TopicStats(wire.Topic(c.topic)).Peers == 2
			})
			sent, err := p.g.Publish(ctx, c.topic, []byte("from outside"))
			if err != nil {
				t.Fatal(err)
			}
			c.delivered(t, 10*time.Second, -1, []MessageID{sent.ID})
			p.g.mu.Lock()
			fanout := len(p.g.r.Fanout(wire.Topic(c.topic)))
			p.g.mu.Unlock()
			if flood && fanout != 0 {
				t.Fatalf("flood publishing kept %d fanout peers", fanout)
			}
			if !flood && fanout != 2 {
				t.Fatalf("fanout publishing chose %d peers, want both subscribed peers", fanout)
			}
		})
	}
}

// TestValidator: the application's verdicts apply; Reject costs the sender score, a panic is Ignore, and Leave
// cancels a validator that waits.
func TestValidator(t *testing.T) {
	checkGoroutines(t)
	a, b := newMember(t), newMember(t)
	ros := newRoster(a, b)
	topic := testTopic(t.Name())
	na, nb := newNode(t, nodeOpts{m: a}), newNode(t, nodeOpts{m: b})
	blocked := make(chan struct{})
	v := func(ctx context.Context, m *Message) Verdict {
		switch string(m.Body) {
		case "bad":
			return Reject
		case "skip":
			return Ignore
		case "boom":
			panic("boom")
		case "wait":
			close(blocked)
			<-ctx.Done()
			return Accept
		case "unknown":
			return 7
		}
		return Accept
	}
	ra := na.join(t, topic, &TopicOptions{Authors: ros}).collect(na)
	rb := nb.join(t, topic, &TopicOptions{Authors: ros, Validate: v}).collect(nb)
	na.connect(t, topic, nb)
	(&cluster{rooms: []*room{ra, rb}}).ready(t, 1)
	for _, body := range []string{"bad", "skip", "boom", "unknown"} {
		publish(t, ra.Room, body)
	}
	good := publish(t, ra.Room, "good")
	waitFor(t, 10*time.Second, "good", func() bool { return rb.has(good) })
	waitFor(t, 10*time.Second, "every verdict", func() bool {
		s := nb.g.Stats().Router
		return s.Rejected == 1 && s.Ignored == 3
	})
	s := nb.g.Stats().Router
	if rb.count() != 1 || s.Rejected != 1 || s.Ignored != 3 || nb.g.Score(a.device.PublicKey()) >= 0 {
		t.Fatalf("delivered %d, stats %+v, score %v", rb.count(), s, nb.g.Score(a.device.PublicKey()))
	}
	publish(t, ra.Room, "wait")
	<-blocked
	rb.Leave()
	waitFor(t, 10*time.Second, "the waiting validator released", func() bool { return nb.g.Stats().Router.Validating == 0 })
}

// TestLifecycle: Join, Leave, Close and their errors.
func TestLifecycle(t *testing.T) {
	checkGoroutines(t)
	a, b := newMember(t), newMember(t)
	ros := newRoster(a, b)
	topic := testTopic(t.Name())
	na, nb := newNode(t, nodeOpts{m: a}), newNode(t, nodeOpts{m: b})
	ctx := context.Background()
	if _, err := na.g.Join(ctx, topic, &TopicOptions{}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("join without authors: %v", err)
	}
	ra := na.join(t, topic, &TopicOptions{Authors: ros})
	if _, err := na.g.Join(ctx, topic, &TopicOptions{Authors: ros}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("second join: %v", err)
	}
	rb := nb.join(t, topic, &TopicOptions{Authors: ros})
	na.connect(t, topic, nb)
	subscribed(t, rb.Room, 1)
	ra.Leave()
	ra.Leave()
	// Leaving the swarm topic also closes the connection, which shared no other topic.
	waitFor(t, 10*time.Second, "the leave seen", func() bool { return rb.Stats().Peers == 0 })
	if _, err := ra.Next(ctx); !errors.Is(err, ErrNotJoined) {
		t.Fatalf("next after leave: %v", err)
	}
	if _, err := ra.Publish(ctx, nil); !errors.Is(err, ErrNotJoined) {
		t.Fatalf("publish after leave: %v", err)
	}
	ra = na.join(t, topic, &TopicOptions{Authors: ros}).collect(na)
	na.connect(t, topic, nb)
	(&cluster{rooms: []*room{ra, rb}}).ready(t, 1)
	id := publish(t, rb.Room, "after rejoin")
	waitFor(t, 10*time.Second, "delivery after rejoin", func() bool { return ra.has(id) })

	short, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := rb.Publish(short, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("publish with a done context: %v", err)
	}
	if _, err := rb.Next(short); !errors.Is(err, context.Canceled) {
		t.Fatalf("next with a done context: %v", err)
	}
	nb.forgetServed(a.device.PublicKey())
	if err := nb.g.Close(); err != nil {
		t.Fatal(err)
	}
	if err := nb.g.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := rb.Next(ctx); !errors.Is(err, ErrClosed) {
		t.Fatalf("next after close: %v", err)
	}
	if _, err := nb.g.Publish(ctx, topic, nil); !errors.Is(err, ErrClosed) {
		t.Fatalf("publish after close: %v", err)
	}
	if _, err := nb.g.Join(ctx, testTopic("other"), &TopicOptions{Authors: ros}); !errors.Is(err, ErrClosed) {
		t.Fatalf("join after close: %v", err)
	}
	waitFor(t, 10*time.Second, "ServeConn to end", func() bool { _, ok := nb.servedErr(a.device.PublicKey()); return ok })
	if err, _ := nb.servedErr(a.device.PublicKey()); !errors.Is(err, ErrClosed) {
		t.Fatalf("ServeConn after close: %v", err)
	}
	waitFor(t, 10*time.Second, "the closed peer removed", func() bool { return ra.Stats().Peers == 0 })
	if err := nb.g.ServeConn(ctx, nil, true); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("nil conn: %v", err)
	}
}

// TestLeaveKeepsConnection: without Config.Swarm the application owns the swarm topic; Leave only unsubscribes,
// and the connection stays served.
func TestLeaveKeepsConnection(t *testing.T) {
	checkGoroutines(t)
	a, b := newMember(t), newMember(t)
	ros := newRoster(a, b)
	topic := testTopic(t.Name())
	na := newNode(t, nodeOpts{m: a, tweak: func(c *Config) { c.Swarm = nil }})
	nb := newNode(t, nodeOpts{m: b})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := na.sw.Join(ctx, topic, &koloswarm.JoinOptions{Lookup: true}); err != nil {
		t.Fatal(err)
	}
	ra := na.join(t, topic, &TopicOptions{Authors: ros})
	rb := nb.join(t, topic, &TopicOptions{Authors: ros})
	na.connect(t, topic, nb)
	subscribed(t, rb.Room, 1)
	ra.Leave()
	waitFor(t, 10*time.Second, "the unsubscription", func() bool { return rb.Stats().Peers == 0 })
	if na.g.Stats().Router.Peers != 1 || nb.g.Stats().Router.Peers != 1 {
		t.Fatal("the connection stopped being served")
	}
	ra = na.join(t, topic, &TopicOptions{Authors: ros}).collect(na)
	subscribed(t, rb.Room, 1)
	(&cluster{rooms: []*room{ra, rb}}).ready(t, 1)
	id := publish(t, rb.Room, "again")
	waitFor(t, 10*time.Second, "delivery", func() bool { return ra.has(id) })

	// Close resets our streams, so it returns and the peer stops serving us, while the connection stays.
	closed := make(chan error, 1)
	go func() { closed <- na.g.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Close did not return")
	}
	waitFor(t, 10*time.Second, "the peer's gossip to end", func() bool { return nb.g.Stats().Router.Peers == 0 })
	if na.sw.Addr() == nil {
		t.Fatal("swarm closed")
	}
}

// TestGossipRepair: with a mesh of one peer, the hub announces each message with IHAVE to its other peers, which
// fetch it with IWANT: every leaf gets every message.
func TestGossipRepair(t *testing.T) {
	checkGoroutines(t)
	p := &Params{D: 1, Dlo: 1, Dhi: 1, Dlazy: 6, Dscore: 1, Dout: 0, GossipFactor: 0.75, GossipPeers: 43}
	c := newCluster(t, 4, [][2]int{{1, 0}, {2, 0}, {3, 0}}, func(cfg *Config) { cfg.Params = p })
	waitFor(t, 20*time.Second, "the hub's mesh", func() bool { s := c.rooms[0].Stats(); return s.Peers == 3 && s.Mesh == 1 })
	var ids []MessageID
	for i := range 5 {
		ids = append(ids, publish(t, c.rooms[1].Room, fmt.Sprint(i)))
	}
	c.delivered(t, 20*time.Second, 1, ids)
	if s := c.nodes[0].g.Stats().Router; s.IHaveSent == 0 || s.IWantReceived == 0 {
		t.Fatalf("no repair through gossip: %+v", s)
	}
}

// TestManyRooms: two nodes join 40 rooms and stay connected, a peer announcing more than 32 topics being no
// violation, and a message in the last room is delivered.
func TestManyRooms(t *testing.T) {
	checkGoroutines(t)
	a, b := newNode(t, nodeOpts{}), newNode(t, nodeOpts{})
	ros := newRoster(a.m, b.m)
	var ra, rb []*room
	for i := range 40 {
		topic := testTopic(fmt.Sprintf("many-rooms-%d", i))
		ra = append(ra, a.join(t, topic, &TopicOptions{Authors: ros}).collect(a))
		rb = append(rb, b.join(t, topic, &TopicOptions{Authors: ros}).collect(b))
	}
	a.connect(t, testTopic("many-rooms-0"), b)
	subscribed(t, ra[39].Room, 1)
	subscribed(t, rb[39].Room, 1)
	id := publish(t, ra[39].Room, "in the last room")
	waitFor(t, 10*time.Second, "delivery in room 40", func() bool { return rb[39].has(id) })
	if err, ended := a.servedErr(b.key()); ended {
		t.Fatalf("ServeConn ended: %v", err)
	}
}

// TestMaxPeers: a peer over MaxPeers is not served; ServeConn says so and the others keep going.
func TestMaxPeers(t *testing.T) {
	checkGoroutines(t)
	c := newCluster(t, 3, nil, func(cfg *Config) { cfg.MaxPeers = 1 })
	c.nodes[1].connect(t, c.topic, c.nodes[0])
	subscribed(t, c.rooms[0].Room, 1)
	c.nodes[2].tryConnect(c.topic, c.nodes[0]) // the refused connection may close during the hello
	waitFor(t, 10*time.Second, "the refused ServeConn", func() bool { _, ok := c.nodes[0].servedErr(c.nodes[2].key()); return ok })
	if err, _ := c.nodes[0].servedErr(c.nodes[2].key()); !errors.Is(err, ErrLimit) {
		t.Fatalf("ServeConn over MaxPeers: %v", err)
	}
	c.ready(t, 1, 2)
	id := publish(t, c.rooms[1].Room, "still served")
	waitFor(t, 10*time.Second, "delivery", func() bool { return c.rooms[0].has(id) })
}

// TestJoinSwarmFailure: when the swarm refuses the topic, Join fails and leaves the topic, so it can be joined
// again.
func TestJoinSwarmFailure(t *testing.T) {
	checkGoroutines(t)
	n := newNode(t, nodeOpts{})
	topic := testTopic(t.Name())
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := n.sw.Join(ctx, topic, &koloswarm.JoinOptions{Lookup: true}); err != nil {
		t.Fatal(err)
	}
	ros := newRoster(n.m)
	if _, err := n.g.Join(ctx, topic, &TopicOptions{Authors: ros}); !errors.Is(err, koloswarm.ErrInvalidArgument) {
		t.Fatalf("join over a swarm topic already joined: %v", err)
	}
	n.sw.Leave(topic)
	n.join(t, topic, &TopicOptions{Authors: ros})
}
