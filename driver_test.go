package kologossip

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ciranda-dev/kolo-gossip/internal/core"
	"github.com/ciranda-dev/kolo-gossip/internal/wire"
	koloid "github.com/ciranda-dev/kolo-id"
	koloswarm "github.com/ciranda-dev/kolo-swarm"
)

// TestFrameTimeout: a frame or a stream header that stops partway ends the peer's gossip after FrameTimeout, so it
// cannot pin memory, and the connection is closed so the swarm may connect again; an idle stream between frames
// is fine.
func TestFrameTimeout(t *testing.T) {
	checkGoroutines(t)
	for name, send := range map[string]func(t *testing.T, x *raw){
		"frame": func(t *testing.T, x *raw) {
			x.stream(t, append(header(wire.KindMessage), wire.AppendFrame(nil, make([]byte, 1000))[:12]...))
		},
		"header": func(t *testing.T, x *raw) { x.stream(t, []byte{0}) },
	} {
		t.Run(name, func(t *testing.T) {
			c := newCluster(t, 1, nil, func(cfg *Config) { cfg.FrameTimeout = 200 * time.Millisecond })
			x := newRaw(t, newMember(t), c.ros, c.topic, c.nodes[0])
			idle := x.stream(t, header(wire.KindControl))
			frame(t, idle, control(t, &wire.Control{}))
			waitFor(t, 10*time.Second, "the peer served", func() bool { return c.nodes[0].g.Stats().Router.Peers == 1 })
			send(t, x)
			waitFor(t, 10*time.Second, "ServeConn to end", func() bool { _, ok := c.nodes[0].servedErr(x.key()); return ok })
			if err, _ := c.nodes[0].servedErr(x.key()); err != nil {
				t.Fatalf("ServeConn returned %v", err)
			}
			waitFor(t, 10*time.Second, "the connection closed", func() bool { return x.conn.Context().Err() != nil })
		})
	}
}

// TestSlowFrame: FrameTimeout bounds a stall, not a slow frame: one that keeps arriving, a byte at a time below
// the timeout, is read whole.
func TestSlowFrame(t *testing.T) {
	checkGoroutines(t)
	c := newCluster(t, 1, nil, func(cfg *Config) { cfg.FrameTimeout = 300 * time.Millisecond })
	x := newRaw(t, newMember(t), c.ros, c.topic, c.nodes[0])
	st := x.stream(t, header(wire.KindMessage))
	frame := wire.AppendFrame(nil, make([]byte, 8))
	for _, b := range frame {
		if _, err := st.Write([]byte{b}); err != nil {
			t.Fatal(err)
		}
		<-time.After(100 * time.Millisecond) // pacing the frame, slower in total than FrameTimeout
	}
	g := c.nodes[0].g
	waitFor(t, 10*time.Second, "the slow frame read", func() bool { return g.Stats().Router.MessagesReceived == 1 })
	if _, ended := c.nodes[0].servedErr(x.key()); ended {
		t.Fatal("a slow frame ended ServeConn")
	}
}

// TestOwnChainExpired: a node whose own chain has expired refuses to publish instead of sending messages every
// receiver would ignore.
func TestOwnChainExpired(t *testing.T) {
	m := &member{person: ident(t), device: ident(t)}
	expiry := time.Now().Truncate(time.Second).Add(2 * time.Second)
	offer, err := m.person.OfferDeviceCert(m.device.PublicKey(), &koloid.IssueOptions{Serial: 1, ExpiresAt: expiry})
	if err != nil {
		t.Fatal(err)
	}
	if m.cert, err = m.device.AcceptDeviceCert(offer, m.person.PublicKey()); err != nil {
		t.Fatal(err)
	}
	g, err := New(m.device, &Config{Cert: m.cert})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	rm, err := g.Join(context.Background(), testTopic("own"), &TopicOptions{Authors: newRoster(m)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rm.Publish(context.Background(), []byte("valid")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 10*time.Second, "the chain to expire", func() bool { return !time.Now().Before(expiry) })
	_, err = rm.Publish(context.Background(), []byte("expired"))
	if !errors.Is(err, ErrOwnChain) || !errors.Is(err, koloid.ErrCertExpired) || strings.Count(err.Error(), "kologossip:") != 1 {
		t.Fatalf("publish with an expired chain: %v", err)
	}
}

// TestValidatorTimeout: a validator that runs past ValidateTimeout is counted as stuck and its message keeps its
// place, charged to its sender, until it returns; it never holds Close.
func TestValidatorTimeout(t *testing.T) {
	checkGoroutines(t)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	c := newCluster(t, 2, [][2]int{{0, 1}}, func(cfg *Config) { cfg.ValidateTimeout = 200 * time.Millisecond })
	c.ready(t, 1)
	g := c.nodes[1].g
	g.mu.Lock()
	g.rooms[c.topic].validate = func(ctx context.Context, m *Message) Verdict {
		<-release
		return Accept
	}
	g.mu.Unlock()
	publish(t, c.rooms[0].Room, "slow")
	// Past its timeout the validator is stuck and its message keeps its place, charged to its sender.
	waitFor(t, 10*time.Second, "the timeout", func() bool { return g.Stats().StuckValidators == 1 })
	if s := g.Stats().Router; s.Validating != 1 || s.Ignored != 0 {
		t.Fatalf("a stuck validator's message lost its place: %+v", s)
	}
	closed := make(chan error, 1)
	go func() { closed <- g.Close() }()
	select {
	case <-closed:
	case <-time.After(10 * time.Second):
		t.Fatal("Close waited for a validator that ignores its context")
	}
	if c.rooms[1].count() != 0 {
		t.Fatal("a timed out message was delivered")
	}
}

// TestJoinCloseRace: a Close that runs while Join is joining the swarm topic still leaves that topic, and Join
// reports ErrClosed; run with -race it also checks the room's swarm flag.
func TestJoinCloseRace(t *testing.T) {
	checkGoroutines(t)
	n := newNode(t, nodeOpts{})
	topic := testTopic(t.Name())
	n.g.hooks.swarmJoined = func() { n.g.Close() }
	_, err := n.g.Join(context.Background(), topic, &TopicOptions{Authors: newRoster(n.m), Swarm: &koloswarm.JoinOptions{Lookup: true}})
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("Join during Close: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := n.sw.Join(ctx, topic, &koloswarm.JoinOptions{Lookup: true}); err != nil {
		t.Fatalf("the swarm topic was left joined: %v", err)
	}
}

// TestTopicOptions: each option reaches the router or the room, and inconsistent options are refused.
func TestTopicOptions(t *testing.T) {
	m := newMember(t)
	g, err := New(m.device, &Config{Cert: m.cert, MaxMessageSize: 4096})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	ros := newRoster(m)
	ctx := context.Background()
	p := DefaultParams()
	p.D, p.Dhi = 5, 10
	score := DefaultTopicScore()
	score.TopicWeight = 0.5
	var seq uint64 = 41
	rooms := map[string]*TopicOptions{
		"params":   {Authors: ros, Params: p},
		"score":    {Authors: ros, Score: score},
		"no score": {Authors: ros, NoScore: true},
		"size":     {Authors: ros, MaxMessageSize: 512},
		"seq":      {Authors: ros, Seq: func() uint64 { return seq }},
	}
	joined := map[string]*Room{}
	for name, o := range rooms {
		rm, err := g.Join(ctx, testTopic(name), o)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		joined[name] = rm
	}
	rm := joined["size"]
	if _, err := rm.Publish(ctx, make([]byte, 400)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("over the topic's size: %v", err)
	}
	if _, err := rm.Publish(ctx, make([]byte, 300)); err != nil {
		t.Fatal(err)
	}
	if m, err := g.Publish(ctx, testTopic("size"), make([]byte, 600)); !errors.Is(err, ErrTooLarge) || m != nil {
		t.Fatalf("an early size check: %v %v", err, m)
	}
	// A Seq that repeats gives the same bytes within one millisecond: the second is a duplicate.
	dup := false
	for range 10_000 {
		m, err := joined["seq"].Publish(ctx, []byte("same"))
		if err != nil {
			if !errors.Is(err, ErrDuplicate) || m != nil {
				t.Fatalf("a repeated Seq: %v %v", err, m)
			}
			dup = true
			break
		}
	}
	if !dup {
		t.Fatal("no two publishes in one millisecond")
	}
	bad := map[string]struct {
		o    *TopicOptions
		want error
	}{
		"no authors":    {&TopicOptions{}, ErrInvalidArgument},
		"zero score":    {&TopicOptions{Authors: ros, Score: &TopicScoreParams{}}, ErrInvalidConfig},
		"zero params":   {&TopicOptions{Authors: ros, Params: &Params{}}, ErrInvalidConfig},
		"bad params":    {&TopicOptions{Authors: ros, Params: &Params{D: 6, Dlo: 7, Dhi: 12}}, ErrInvalidConfig},
		"size over max": {&TopicOptions{Authors: ros, MaxMessageSize: 8192}, ErrInvalidConfig},
	}
	for name, c := range bad {
		if _, err := g.Join(ctx, testTopic("bad "+name), c.o); !errors.Is(err, c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	done, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := g.Join(done, testTopic("done"), &TopicOptions{Authors: ros}); !errors.Is(err, context.Canceled) {
		t.Errorf("a done context: %v", err)
	}
	bootstrap := &Params{Bootstrap: true}
	if _, err := g.Join(ctx, testTopic("bootstrap"), &TopicOptions{Authors: ros, Params: bootstrap}); err != nil {
		t.Errorf("a bootstrap topic: %v", err)
	}
}

// TestTopicOptionsReachRouter: the overlay and score options of a topic are the router's.
func TestTopicOptionsReachRouter(t *testing.T) {
	p := DefaultParams()
	p.D, p.Dhi = 5, 10
	score := DefaultTopicScore()
	score.TopicWeight = 0.5
	for name, c := range map[string]struct {
		o     *TopicOptions
		check func(*core.TopicConfig) bool
	}{
		"params":   {&TopicOptions{Authors: newRoster(), Params: p}, func(tc *core.TopicConfig) bool { return tc.Params.D == 5 && tc.Params.Dhi == 10 }},
		"score":    {&TopicOptions{Authors: newRoster(), Score: score}, func(tc *core.TopicConfig) bool { return tc.Score.TopicWeight == 0.5 }},
		"no score": {&TopicOptions{Authors: newRoster(), NoScore: true}, func(tc *core.TopicConfig) bool { return *tc.Score == core.TopicScoreParams{} }},
		"default":  {&TopicOptions{Authors: newRoster()}, func(tc *core.TopicConfig) bool { return tc.Score == nil && tc.Params == nil }},
		"size":     {&TopicOptions{Authors: newRoster(), MaxMessageSize: 512}, func(tc *core.TopicConfig) bool { return tc.MaxMessageSize == 512 }},
	} {
		tc, err := c.o.core()
		if err != nil || !c.check(tc) {
			t.Errorf("%s: %v %+v", name, err, tc)
		}
	}
}

// TestScoreParamsFields: the public score parameters carry every field of the router's, with the same types except
// the application score's key.
func TestScoreParamsFields(t *testing.T) {
	for _, c := range []struct{ pub, in reflect.Type }{
		{reflect.TypeFor[ScoreParams](), reflect.TypeFor[core.ScoreParams]()},
		{reflect.TypeFor[TopicScoreParams](), reflect.TypeFor[core.TopicScoreParams]()},
		{reflect.TypeFor[Thresholds](), reflect.TypeFor[core.Thresholds]()},
		{reflect.TypeFor[RouterStats](), reflect.TypeFor[core.Stats]()},
	} {
		if c.pub.NumField() != c.in.NumField() {
			t.Fatalf("%v has %d fields, %v %d", c.pub, c.pub.NumField(), c.in, c.in.NumField())
		}
		for i := range c.in.NumField() {
			pf, f := c.pub.Field(i), c.in.Field(i)
			if pf.Name != f.Name || (pf.Type != f.Type && f.Name != "AppScore" && f.Name != "Thresholds") {
				t.Errorf("%v.%s differs from %v.%s", c.pub, pf.Name, c.in, f.Name)
			}
		}
	}
	s := DefaultScore()
	s.AppScore = func(ed25519.PublicKey) float64 { return 0 }
	c, err := s.core()
	if err != nil {
		t.Fatal(err)
	}
	pv, cv := reflect.ValueOf(*s), reflect.ValueOf(*c)
	for i := range cv.NumField() {
		if name := cv.Type().Field(i).Name; name != "AppScore" && name != "Thresholds" && !pv.Field(i).Equal(cv.Field(i)) {
			t.Errorf("%s not copied", name)
		}
	}
	if Thresholds(c.Thresholds) != s.Thresholds {
		t.Error("thresholds not copied")
	}
}

// TestLeftValidatorCounted: a validator that ignores its context when its room is left keeps its message's place in
// the validation bounds until it returns, and is not counted as stuck.
func TestLeftValidatorCounted(t *testing.T) {
	checkGoroutines(t)
	release := make(chan struct{})
	c := newCluster(t, 2, [][2]int{{0, 1}}, nil)
	c.ready(t, 1)
	g := c.nodes[1].g
	g.mu.Lock()
	g.rooms[c.topic].validate = func(context.Context, *Message) Verdict {
		<-release
		return Accept
	}
	g.mu.Unlock()
	publish(t, c.rooms[0].Room, "held")
	waitFor(t, 10*time.Second, "the validation", func() bool { return g.Stats().Router.Validating == 1 })
	c.rooms[1].Leave()
	time.Sleep(50 * time.Millisecond)
	if s := g.Stats(); s.Router.Validating != 1 || s.StuckValidators != 0 {
		t.Fatalf("after Leave: %d validating, %d stuck", s.Router.Validating, s.StuckValidators)
	}
	close(release)
	waitFor(t, 10*time.Second, "the place released", func() bool { return g.Stats().Router.Validating == 0 })
}

// TestSlowValidatorNotCharged: the time a validator takes is not charged to the peer that sent the message, so a
// slow validator never makes an honest sender wait.
func TestSlowValidatorNotCharged(t *testing.T) {
	checkGoroutines(t)
	c := newCluster(t, 2, [][2]int{{0, 1}}, nil)
	c.ready(t, 1)
	g := c.nodes[1].g
	g.mu.Lock()
	g.rooms[c.topic].validate = func(context.Context, *Message) Verdict {
		time.Sleep(30 * time.Millisecond)
		return Accept
	}
	g.mu.Unlock()
	for i := range 30 {
		id := publish(t, c.rooms[0].Room, fmt.Sprint("slow ", i))
		c.delivered(t, 10*time.Second, 0, []MessageID{id})
	}
	if n := g.Stats().Waited; n != 0 {
		t.Fatalf("the sender waited %d times for 30 validations of 30 ms", n)
	}
}

// TestServeConnClosesOnLimit: a connection refused because MaxPeers peers are served is closed, so it holds no
// place in the swarm: dialing the key again is not a duplicate.
func TestServeConnClosesOnLimit(t *testing.T) {
	checkGoroutines(t)
	c := newCluster(t, 3, nil, func(cfg *Config) { cfg.MaxPeers = 1 })
	c.nodes[1].connect(t, c.topic, c.nodes[0])
	subscribed(t, c.rooms[0].Room, 1)
	c.nodes[2].tryConnect(c.topic, c.nodes[0]) // the refused connection may close during the hello
	waitFor(t, 10*time.Second, "the refusal", func() bool {
		err, ok := c.nodes[0].servedErr(c.nodes[2].key())
		return ok && errors.Is(err, ErrLimit)
	})
	waitFor(t, 5*time.Second, "the refused connection to close", func() bool {
		return !errors.Is(c.nodes[2].tryConnect(c.topic, c.nodes[0]), koloswarm.ErrDuplicate)
	})
}

// TestMaxCertsFollowsCertWants: our CERT frames carry at most the MaxCertWants certificates the receiver reads.
func TestMaxCertsFollowsCertWants(t *testing.T) {
	s, err := (&Config{Cert: newMember(t).cert, MaxCertWants: 3}).settings()
	if err != nil {
		t.Fatal(err)
	}
	if s.router.MaxCerts != 3 {
		t.Fatalf("MaxCerts %d", s.router.MaxCerts)
	}
}
