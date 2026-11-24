package kologossip

import (
	"context"
	"crypto/ed25519"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ciranda-dev/kolo-gossip/internal/auth"
	"github.com/ciranda-dev/kolo-gossip/internal/wire"
)

// signAt signs body for m at the author time at.
func signAt(t testing.TB, m *member, topic Topic, seq uint64, at time.Time, body []byte) []byte {
	t.Helper()
	b, err := auth.Sign(m.device, m.person.PublicKey(), wire.Topic(topic), seq, at, body)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestBudgetBackpressure: a peer that floods validly signed messages of an unknown author has every signature
// check charged to its reader's bucket; while the bucket is empty its stream is not read, so it gets no more checks
// than the bucket refills, and it loses no score.
func TestBudgetBackpressure(t *testing.T) {
	checkGoroutines(t)
	const budget = 20
	c := newCluster(t, 1, nil, func(cfg *Config) {
		cfg.PeerWork = budget * 30 * time.Microsecond // 20 signature checks a second, and a 1 s burst
		cfg.WorkBurst = time.Second
	})
	stranger := newMember(t)
	x := newRaw(t, stranger, c.ros, c.topic, c.nodes[0])
	msg := x.stream(t, header(wire.KindMessage))
	g := c.nodes[0].g
	go func() {
		for i := range 300 {
			if _, err := msg.Write(wire.AppendFrame(nil, sign(t, stranger, c.topic, uint64(i), nil))); err != nil {
				return
			}
		}
	}()
	// A new key starts with an empty reader bucket: it gets the refill, 20 checks a second, and no more.
	waitFor(t, 10*time.Second, "the reader to stop", func() bool { return g.Stats().Waited >= 1 })
	start := time.Now()
	time.Sleep(1500 * time.Millisecond)
	s := g.Stats().Router
	limit := uint64(time.Since(start).Seconds()*budget) + 3
	if s.SignatureChecks > limit || s.SignatureChecks < budget/2 || g.Score(x.key()) != 0 {
		t.Fatalf("%d signature checks for %d a second, score %v", s.SignatureChecks, budget, g.Score(x.key()))
	}
}

// TestEdgeOfWindowNotForwarded: a message that would leave the window before the next hop takes it is delivered
// but not forwarded, so the next hop never refuses it for its time.
func TestEdgeOfWindowNotForwarded(t *testing.T) {
	checkGoroutines(t)
	c := newCluster(t, 2, [][2]int{{0, 1}}, func(cfg *Config) { cfg.HeartbeatInterval = time.Second }) // the margin
	c.ready(t, 1)
	author := newMember(t)
	c.ros.add(author)
	x := newRaw(t, author, c.ros, c.topic, c.nodes[0])
	msg := x.stream(t, header(wire.KindMessage))
	for i := range 20 {
		frame(t, msg, signAt(t, author, c.topic, uint64(i), time.Now().Add(-time.Minute+300*time.Millisecond), nil))
	}
	a, b := c.nodes[0].g, c.nodes[1].g
	waitFor(t, 10*time.Second, "the edge messages", func() bool { return a.Stats().Router.EdgeOfWindow == 20 })
	if c.rooms[0].count() != 20 || b.Stats().Router.OutOfWindow != 0 || b.Score(c.nodes[0].key()) < 0 {
		t.Fatalf("delivered %d; the next hop saw %d out of window", c.rooms[0].count(), b.Stats().Router.OutOfWindow)
	}
}

// TestGraylistedByHeartbeat: a silent peer graylisted between frames, here by the application score, is ended at
// the heartbeat, and its connection is closed so the swarm can decide again through Allow.
func TestGraylistedByHeartbeat(t *testing.T) {
	checkGoroutines(t)
	var bad atomic.Pointer[[]byte]
	c := newCluster(t, 1, nil, func(cfg *Config) {
		s := DefaultScore()
		s.AppScore = func(k ed25519.PublicKey) float64 {
			if p := bad.Load(); p != nil && string(*p) == string(k) {
				return -1000
			}
			return 0
		}
		cfg.Score = s
	})
	x := newRaw(t, newMember(t), c.ros, c.topic, c.nodes[0])
	waitFor(t, 10*time.Second, "the peer served", func() bool { return c.nodes[0].g.Stats().Router.Peers == 1 })
	k := []byte(x.key())
	bad.Store(&k)
	waitFor(t, 10*time.Second, "ServeConn to end", func() bool { _, ok := c.nodes[0].servedErr(x.key()); return ok })
	if err, _ := c.nodes[0].servedErr(x.key()); !errors.Is(err, ErrGraylisted) {
		t.Fatalf("ServeConn returned %v", err)
	}
	waitFor(t, 10*time.Second, "the connection closed", func() bool { return x.conn.Context().Err() != nil })
}

// TestStuckValidators: validators that ignore their context past ValidateTimeout are counted, and their messages
// stay charged to their sender's share until they return, so no more than MaxPeerValidating of one sender's run and
// its new messages are throttled.
func TestStuckValidators(t *testing.T) {
	checkGoroutines(t)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	c := newCluster(t, 2, [][2]int{{0, 1}}, func(cfg *Config) { cfg.ValidateTimeout = 100 * time.Millisecond; cfg.MaxPeerValidating = 2 })
	c.ready(t, 1)
	var calls atomic.Int32
	g := c.nodes[1].g
	g.mu.Lock()
	g.rooms[c.topic].validate = func(context.Context, *Message) Verdict {
		calls.Add(1)
		<-release
		return Accept
	}
	g.mu.Unlock()
	for i := range 2 {
		publish(t, c.rooms[0].Room, string(rune('a'+i)))
		waitFor(t, 10*time.Second, "a stuck validator", func() bool { return g.Stats().StuckValidators == i+1 })
	}
	// The stuck validators' messages still hold the sender's two places, so its third is throttled.
	publish(t, c.rooms[0].Room, "c")
	waitFor(t, 10*time.Second, "the third message throttled", func() bool { return g.Stats().Router.Throttled >= 1 })
	if calls.Load() != 2 {
		t.Fatalf("%d validators started with two stuck", calls.Load())
	}
}

// TestRelayFirstCannotCensor: a peer whose own validation place is full relays a real message first; only its copy
// is dropped, and the same message from an honest peer is delivered.
func TestRelayFirstCannotCensor(t *testing.T) {
	checkGoroutines(t)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	c := newCluster(t, 1, nil, func(cfg *Config) { cfg.MaxPeerValidating = 1 })
	author := newMember(t)
	c.ros.add(author)
	g := c.nodes[0].g
	g.mu.Lock()
	g.rooms[c.topic].validate = func(_ context.Context, m *Message) Verdict {
		if string(m.Body) == "hold" {
			<-release
		}
		return Accept
	}
	g.mu.Unlock()
	x := newRaw(t, newMember(t), c.ros, c.topic, c.nodes[0])
	y := newRaw(t, newMember(t), c.ros, c.topic, c.nodes[0])
	real := sign(t, author, c.topic, 2, []byte("real"))
	xs := x.stream(t, header(wire.KindMessage))
	frame(t, xs, sign(t, author, c.topic, 1, []byte("hold")))
	waitFor(t, 10*time.Second, "the attacker's place held", func() bool { return g.Stats().Router.Validating == 1 })
	frame(t, xs, real)
	waitFor(t, 10*time.Second, "the attacker's copy dropped", func() bool { return g.Stats().Router.Throttled == 1 })
	frame(t, y.stream(t, header(wire.KindMessage)), real)
	waitFor(t, 10*time.Second, "the honest copy delivered", func() bool { return c.rooms[0].has(MessageID(wire.NewID(real))) })
}

// TestRemoteEndKeepsConnection: a peer that ends its own gossip (its streams end) keeps the connection, which may
// carry other protocols; a peer that opens no stream for FrameTimeout is closed.
func TestRemoteEndKeepsConnection(t *testing.T) {
	checkGoroutines(t)
	c := newCluster(t, 1, nil, func(cfg *Config) { cfg.FrameTimeout = 300 * time.Millisecond })
	x := newRaw(t, newMember(t), c.ros, c.topic, c.nodes[0])
	st, err := x.conn.OpenUniStream(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	st.Write(header(wire.KindControl))
	waitFor(t, 10*time.Second, "the peer served", func() bool { return c.nodes[0].g.Stats().Router.Peers == 1 })
	st.CancelWrite(0)
	waitFor(t, 10*time.Second, "ServeConn to end", func() bool { _, ok := c.nodes[0].servedErr(x.key()); return ok })
	if x.conn.Context().Err() != nil {
		t.Fatal("the connection was closed when the peer ended its gossip")
	}
	quiet := newRaw(t, newMember(t), c.ros, c.topic, c.nodes[0])
	waitFor(t, 10*time.Second, "the silent peer closed", func() bool { return quiet.conn.Context().Err() != nil })
}

// TestCertFrameCap: a control frame of more than MaxCertWants certificates breaks the protocol, before the
// certificates are copied.
func TestCertFrameCap(t *testing.T) {
	checkGoroutines(t)
	c := newCluster(t, 1, nil, nil)
	x := newRaw(t, newMember(t), c.ros, c.topic, c.nodes[0])
	st := x.stream(t, header(wire.KindControl))
	certs := make([][]byte, 11)
	for i := range certs {
		certs[i] = []byte{1}
	}
	frame(t, st, control(t, &wire.Control{Cert: certs}))
	waitFor(t, 10*time.Second, "ServeConn to end", func() bool { _, ok := c.nodes[0].servedErr(x.key()); return ok })
	if err, _ := c.nodes[0].servedErr(x.key()); !errors.Is(err, ErrProtocol) {
		t.Fatalf("ServeConn returned %v", err)
	}
}
