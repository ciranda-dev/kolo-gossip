package kologossip

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/ciranda-dev/kolo-gossip/internal/auth"
	"github.com/ciranda-dev/kolo-gossip/internal/wire"
	koloswarm "github.com/ciranda-dev/kolo-swarm"
)

// raw is a peer that speaks the gossip wire format by hand: it serves nothing itself.
type raw struct {
	*node
	conn koloswarm.Conn
}

// newRaw starts a node that joins topic on the swarm only and connects to target; the test drives its streams.
func newRaw(t *testing.T, m *member, ros Authors, topic Topic, target *node) *raw {
	t.Helper()
	n := newNode(t, nodeOpts{m: m, noLoop: true})
	n.join(t, topic, &TopicOptions{Authors: ros})
	n.connect(t, topic, target)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for {
		ev, err := n.sw.Next(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if ev.Kind == koloswarm.Connected {
			return &raw{node: n, conn: ev.Peer.Conn()}
		}
	}
}

// stream opens a stream and writes its header (any bytes for a broken one).
func (x *raw) stream(t testing.TB, header []byte) interface{ Write([]byte) (int, error) } {
	t.Helper()
	st, err := x.conn.OpenUniStream(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Write(header); err != nil {
		t.Fatal(err)
	}
	return st
}

func header(k wire.Kind) []byte { return wire.AppendStreamHeader(nil, k) }

func frame(t testing.TB, w interface{ Write([]byte) (int, error) }, body []byte) {
	t.Helper()
	if _, err := w.Write(wire.AppendFrame(nil, body)); err != nil {
		t.Fatal(err)
	}
}

func control(t testing.TB, c *wire.Control) []byte {
	t.Helper()
	b, err := c.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func sign(t testing.TB, m *member, topic Topic, seq uint64, body []byte) []byte {
	t.Helper()
	b, err := auth.Sign(m.device, m.person.PublicKey(), wire.Topic(topic), seq, time.Now(), body)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// subscribe makes x announce topic to its target and graft it.
func (x *raw) subscribe(t testing.TB, topic Topic) interface{ Write([]byte) (int, error) } {
	t.Helper()
	ctl := x.stream(t, header(wire.KindControl))
	frame(t, ctl, control(t, &wire.Control{Subs: []wire.Sub{{Topic: wire.Topic(topic), Subscribe: true}}, Graft: []wire.Topic{wire.Topic(topic)}}))
	return ctl
}

// TestSlowPeer: a mesh peer that never reads does not stall the others: the publisher's queue for it fills and
// drops, Publish never blocks, and every other member gets every message.
func TestSlowPeer(t *testing.T) {
	checkGoroutines(t)
	c := newCluster(t, 3, [][2]int{{0, 1}, {1, 2}, {2, 0}}, nil)
	c.ready(t, 2)
	x := newRaw(t, newMember(t), c.ros, c.topic, c.nodes[0])
	x.subscribe(t, c.topic)
	waitFor(t, 10*time.Second, "the slow peer in the mesh", func() bool { return c.rooms[0].Stats().Mesh == 3 })
	body := bytes.Repeat([]byte{7}, 64<<10)
	// A Publish that waited for the slow peer would hang here until the test's timeout.
	for i := range 100 {
		id := publish(t, c.rooms[0].Room, string(body[:len(body)-i]))
		c.delivered(t, 10*time.Second, 0, []MessageID{id})
	}
	if s := c.nodes[0].g.Stats().Router; s.SendDropped == 0 {
		t.Fatal("nothing dropped for the slow peer")
	}
	if s := c.nodes[1].g.Stats().Router; s.IDontWantSent == 0 {
		t.Fatal("no IDONTWANT for large messages")
	}
}

// TestSlowReader: a member whose application never calls Next still forwards everything; only its own room
// queue drops, and it counts the drops.
func TestSlowReader(t *testing.T) {
	checkGoroutines(t)
	c := &cluster{topic: testTopic(t.Name())}
	for range 3 {
		c.members = append(c.members, newMember(t))
	}
	c.ros = newRoster(c.members...)
	for i, m := range c.members {
		// Only the slow reader has a small room queue: a fast reader's collector could fall behind a burst too.
		tweak := func(cfg *Config) { cfg.RoomQueue = 4 }
		if i != 1 {
			tweak = nil
		}
		n := newNode(t, nodeOpts{m: m, tweak: tweak})
		c.nodes = append(c.nodes, n)
		r := n.join(t, c.topic, &TopicOptions{Authors: c.ros})
		if i != 1 {
			r.collect(n)
		}
		c.rooms = append(c.rooms, r)
	}
	c.nodes[0].connect(t, c.topic, c.nodes[1])
	c.nodes[1].connect(t, c.topic, c.nodes[2])
	c.ready(t, 1)
	var ids []MessageID
	for i := range 20 {
		ids = append(ids, publish(t, c.rooms[0].Room, fmt.Sprint(i)))
	}
	waitFor(t, 10*time.Second, "delivery past the slow reader", func() bool { return c.rooms[2].has(ids...) })
	if s := c.rooms[1].Stats(); s.Delivered != 4 || s.Dropped != 16 {
		t.Fatalf("slow reader stats %+v", s)
	}
}

// TestInvalidSignatureFlood: a peer that sends messages with bad signatures is graylisted: ServeConn stops serving
// it, Allow refuses its key so the swarm will not readmit it, and the honest members are unaffected.
func TestInvalidSignatureFlood(t *testing.T) {
	checkGoroutines(t)
	c := newCluster(t, 2, [][2]int{{0, 1}}, nil)
	c.ready(t, 1)
	xm := newMember(t)
	c.ros.add(xm)
	x := newRaw(t, xm, c.ros, c.topic, c.nodes[0])
	a := c.nodes[0]
	msg := x.stream(t, header(wire.KindMessage))
	for i := range 20 {
		b := sign(t, c.members[1], c.topic, uint64(i), []byte("forged"))
		b[len(b)-1] ^= 1
		// Once graylisted the peer's streams are reset, so later writes may fail.
		if _, err := msg.Write(wire.AppendFrame(nil, b)); err != nil {
			break
		}
	}
	waitFor(t, 10*time.Second, "graylisting", func() bool { return !a.g.Allow(x.key(), x.addr()) })
	if s := a.g.Stats().Router; s.BadSignature < 4 || a.g.Score(x.key()) >= DefaultScore().Thresholds.Graylist {
		t.Fatalf("score %v, stats %+v", a.g.Score(x.key()), s)
	}
	waitFor(t, 10*time.Second, "ServeConn to end", func() bool { _, ok := a.servedErr(x.key()); return ok })
	if err, _ := a.servedErr(x.key()); !errors.Is(err, ErrGraylisted) {
		t.Fatalf("ServeConn of a graylisted peer returned %v", err)
	}
	waitFor(t, 10*time.Second, "the graylisted connection closed", func() bool { return x.conn.Context().Err() != nil })
	if c.rooms[0].count() != 0 {
		t.Fatal("a forged message was delivered")
	}
	id := publish(t, c.rooms[1].Room, "honest")
	c.delivered(t, 10*time.Second, 1, []MessageID{id})

	x.conn.CloseWithError(0, "")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := x.sw.Connect(ctx, c.topic, a.key(), a.addr(), loopback)
	for errors.Is(err, koloswarm.ErrWait) {
		<-time.After(20 * time.Millisecond)
		err = x.sw.Connect(ctx, c.topic, a.key(), a.addr(), loopback)
	}
	if err == nil {
		t.Fatal("a graylisted key was readmitted")
	}
}

// TestDuplicateFlood: the same valid message sent hundreds of times is delivered once and costs its sender
// nothing.
func TestDuplicateFlood(t *testing.T) {
	checkGoroutines(t)
	c := newCluster(t, 2, [][2]int{{0, 1}}, nil)
	c.ready(t, 1)
	xm := newMember(t)
	c.ros.add(xm)
	x := newRaw(t, xm, c.ros, c.topic, c.nodes[0])
	msg := x.stream(t, header(wire.KindMessage))
	b := sign(t, xm, c.topic, 1, []byte("once"))
	for range 300 {
		frame(t, msg, b)
	}
	a := c.nodes[0]
	waitFor(t, 10*time.Second, "the duplicates", func() bool { return a.g.Stats().Router.Duplicates >= 299 })
	id := MessageID(wire.NewID(b))
	waitFor(t, 10*time.Second, "forwarding", func() bool { return c.rooms[1].has(id) })
	if c.rooms[0].count() != 1 || c.rooms[1].count() != 1 || a.g.Score(x.key()) < 0 {
		t.Fatalf("delivered %d and %d, score %v", c.rooms[0].count(), c.rooms[1].count(), a.g.Score(x.key()))
	}
}

// TestMessageSize: a message at the topic's limit is delivered, one byte more is ErrTooLarge, and a frame over
// MaxMessageSize ends the sender's connection.
func TestMessageSize(t *testing.T) {
	checkGoroutines(t)
	const limit = 4096
	c := newCluster(t, 2, [][2]int{{0, 1}}, func(cfg *Config) { cfg.MaxMessageSize = limit })
	c.ready(t, 1)
	overhead := len(sign(t, c.members[0], c.topic, 1<<62, make([]byte, 1000))) - 1000
	body := make([]byte, limit-overhead)
	sent, err := c.rooms[0].Publish(context.Background(), body)
	if err != nil {
		t.Fatal(err)
	}
	c.delivered(t, 10*time.Second, 0, []MessageID{sent.ID})
	if _, err := c.rooms[0].Publish(context.Background(), append(body, 0)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("one byte over: %v", err)
	}

	x := newRaw(t, newMember(t), c.ros, c.topic, c.nodes[0])
	x.stream(t, header(wire.KindMessage)).Write(wire.AppendFrame(nil, make([]byte, limit+1)))
	waitFor(t, 10*time.Second, "the connection closed", func() bool { return x.conn.Context().Err() != nil })
	waitFor(t, 10*time.Second, "ServeConn to end", func() bool { _, ok := c.nodes[0].servedErr(x.key()); return ok })
	if err, _ := c.nodes[0].servedErr(x.key()); !errors.Is(err, ErrProtocol) || c.nodes[0].g.Stats().ProtocolClosed != 1 {
		t.Fatalf("ServeConn returned %v, closed %d", err, c.nodes[0].g.Stats().ProtocolClosed)
	}
}

// TestProtocolViolations: each broken stream or frame ends ServeConn with ErrProtocol and closes the connection.
func TestProtocolViolations(t *testing.T) {
	checkGoroutines(t)
	topics := &wire.Control{}
	for i := range 33 {
		topics.Graft = append(topics.Graft, wire.Topic{byte(i), 1})
	}
	cases := []struct {
		name string
		send func(t *testing.T, x *raw)
	}{
		{"unknown kind", func(t *testing.T, x *raw) { x.stream(t, []byte{0, 'x'}) }},
		{"unknown version", func(t *testing.T, x *raw) { x.stream(t, []byte{1, 'c'}) }},
		{"second control stream", func(t *testing.T, x *raw) {
			x.stream(t, header(wire.KindControl))
			x.stream(t, header(wire.KindControl))
		}},
		{"third stream", func(t *testing.T, x *raw) {
			x.stream(t, header(wire.KindControl))
			x.stream(t, header(wire.KindMessage))
			x.stream(t, []byte{0})
		}},
		{"malformed control", func(t *testing.T, x *raw) { frame(t, x.stream(t, header(wire.KindControl)), []byte{9, 9, 9}) }},
		{"control over the limit", func(t *testing.T, x *raw) {
			// A well-formed control frame one id over MaxControlSize; the peer resets the stream after reading the
			// length, so the write may fail.
			big := &wire.Control{IWant: make([]wire.ID, (512<<10)/wire.IDSize)}
			x.stream(t, header(wire.KindControl)).Write(wire.AppendFrame(nil, control(t, big)))
		}},
		{"too many GRAFT entries", func(t *testing.T, x *raw) { frame(t, x.stream(t, header(wire.KindControl)), control(t, topics)) }},
		{"non-canonical length", func(t *testing.T, x *raw) {
			x.stream(t, append(header(wire.KindMessage), 0x80, 0x00))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newCluster(t, 1, nil, nil)
			x := newRaw(t, newMember(t), c.ros, c.topic, c.nodes[0])
			tc.send(t, x)
			a := c.nodes[0]
			waitFor(t, 10*time.Second, "ServeConn to end", func() bool { _, ok := a.servedErr(x.key()); return ok })
			if err, _ := a.servedErr(x.key()); !errors.Is(err, ErrProtocol) {
				t.Fatalf("ServeConn returned %v", err)
			}
			waitFor(t, 10*time.Second, "the connection closed", func() bool { return x.conn.Context().Err() != nil })
			if a.g.Stats().ProtocolClosed != 1 {
				t.Fatal("not counted")
			}
		})
	}
}
