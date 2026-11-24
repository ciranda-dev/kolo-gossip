package kologossip

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"net/netip"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ciranda-dev/kolo-gossip/internal/core"
	"github.com/ciranda-dev/kolo-gossip/internal/wire"
	koloid "github.com/ciranda-dev/kolo-id"
)

// peerWith adds a peer of the given key and address to g without a connection; done removes it.
func peerWith(t *testing.T, g *Gossip, key ed25519.PublicKey, addr string) (p *peer, done func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	var id core.PeerID
	copy(id[:], key)
	p, err := g.addPeer(ctx, cancel, id, nil, true, netip.MustParseAddrPort(addr))
	if err != nil {
		t.Fatal(err)
	}
	return p, func() {
		g.removePeer(p)
		cancel()
	}
}

// feed runs the frames of a stream of kind k from p through g.
func feed(t *testing.T, g *Gossip, p *peer, k wire.Kind, frames ...[]byte) {
	t.Helper()
	in := header(k)
	for _, f := range frames {
		in = wire.AppendFrame(in, f)
	}
	if err := g.readStream(p, bufio.NewReader(bytes.NewReader(in)), nil); err != nil {
		t.Fatal(err)
	}
}

// queued returns the control frames and messages waiting for p's writers.
func queued(t *testing.T, p *peer) (ctl []*wire.Control, msgs [][]byte) {
	t.Helper()
	p.q.mu.Lock()
	defer p.q.mu.Unlock()
	for _, b := range slices.Concat(p.q.lanes[laneUrgent], p.q.lanes[laneControl]) {
		c, err := wire.DecodeControl(b, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		ctl = append(ctl, c)
	}
	return ctl, slices.Clone(p.q.lanes[laneMessage])
}

// told reports whether anything in what was queued concerns topic t, and whether a subscription to it was sent.
func told(ctl []*wire.Control, msgs [][]byte, t Topic) (any, subscribed bool) {
	for _, c := range ctl {
		for _, s := range c.Subs {
			if s.Topic == wire.Topic(t) {
				any, subscribed = true, s.Subscribe
			}
		}
		for _, pr := range c.Prune {
			any = any || pr.Topic == wire.Topic(t)
		}
		for _, h := range c.IHave {
			any = any || h.Topic == wire.Topic(t)
		}
		any = any || slices.Contains(c.Graft, wire.Topic(t))
	}
	for _, m := range msgs {
		if mt, _ := wire.EnvelopeTopic(m); mt == wire.Topic(t) {
			any = true
		}
	}
	return any, subscribed
}

// TestAllowPeerHidesTheClosedTopic: on one node with an open and a closed topic, a peer that the closed topic's AllowPeer
// refuses learns nothing of the closed topic however it behaves: no subscription, GRAFT, PRUNE, IHAVE or message of
// it, while the open topic serves it; a peer admitted to both gets both; RefreshPeers can change the answer.
func TestAllowPeerHidesTheClosedTopic(t *testing.T) {
	checkGoroutines(t)
	m, author := newMember(t), newMember(t)
	ros := newRoster(m, author)
	open, closed := testTopic("open"), testTopic("closed")
	g, err := New(m.device, &Config{Cert: m.cert, NoScore: true, LockWork: time.Hour, PeerWork: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	stranger, friend, other := ident(t).PublicKey(), ident(t).PublicKey(), ident(t).PublicKey()
	var admit atomic.Bool
	ctx := context.Background()
	ro, err := g.Join(ctx, open, &TopicOptions{Authors: ros})
	if err != nil {
		t.Fatal(err)
	}
	rc, err := g.Join(ctx, closed, &TopicOptions{Authors: ros, AllowPeer: func(k ed25519.PublicKey) bool {
		return admit.Load() || !bytes.Equal(k, stranger)
	}})
	if err != nil {
		t.Fatal(err)
	}
	x, doneX := peerWith(t, g, stranger, "10.0.0.1:4000")
	defer doneX()
	y, doneY := peerWith(t, g, friend, "10.0.0.2:4000")
	defer doneY()
	z, doneZ := peerWith(t, g, other, "10.0.0.3:4000")
	defer doneZ()
	both := []wire.Sub{{Topic: wire.Topic(open), Subscribe: true}, {Topic: wire.Topic(closed), Subscribe: true}}
	feed(t, g, x, wire.KindControl, control(t, &wire.Control{Subs: both, Graft: []wire.Topic{wire.Topic(open), wire.Topic(closed)},
		Prune: []wire.Prune{{Topic: wire.Topic(closed)}}, IHave: []wire.IHave{{Topic: wire.Topic(closed), IDs: []wire.ID{{1}}}}, IWant: []wire.ID{{9}}}))
	feed(t, g, x, wire.KindMessage, sign(t, author, closed, 1, []byte("from the stranger")))
	feed(t, g, y, wire.KindControl, control(t, &wire.Control{Subs: both, Graft: []wire.Topic{wire.Topic(closed)}}))
	feed(t, g, z, wire.KindControl, control(t, &wire.Control{Subs: both[1:]}))
	feed(t, g, y, wire.KindMessage, sign(t, author, closed, 2, []byte("from a friend")))
	if _, err := rc.Publish(ctx, []byte("ours, closed")); err != nil {
		t.Fatal(err)
	}
	if _, err := ro.Publish(ctx, []byte("ours, open")); err != nil {
		t.Fatal(err)
	}
	// Six heartbeats of gossip, run on the router's clock.
	g.call(func(now time.Time) {
		for i := 1; i <= 6; i++ {
			g.r.Tick(now.Add(time.Duration(i) * time.Second))
		}
	})
	ctl, msgs := queued(t, x)
	if any, _ := told(ctl, msgs, closed); any {
		t.Fatalf("the refused peer was sent something of the closed topic: %+v, %d messages", ctl, len(msgs))
	}
	if any, sub := told(ctl, msgs, open); !any || !sub || len(msgs) != 1 {
		t.Fatalf("the refused peer lost the open topic: %+v, %d messages", ctl, len(msgs))
	}
	if n := g.Stats().Router.NotJoined; n != 1 {
		t.Fatalf("the refused peer's closed message was counted %d times as for a topic not joined", n)
	}
	if rc.Stats().Mesh != 2 {
		t.Fatalf("closed mesh %+v, want the two admitted peers and not the refused one", rc.Stats())
	}
	ctlY, msgsY := queued(t, y)
	ctlZ, msgsZ := queued(t, z)
	if any, sub := told(ctlY, msgsY, closed); !any || !sub || len(msgsY) != 2 {
		t.Fatalf("the admitted peer: %+v, %d messages", ctlY, len(msgsY))
	}
	if any, sub := told(ctlZ, msgsZ, closed); !any || !sub || len(msgsZ) != 1 {
		t.Fatalf("the second admitted peer: %+v, %d messages", ctlZ, len(msgsZ))
	}
	admit.Store(true)
	rc.RefreshPeers()
	ctl, msgs = queued(t, x)
	if _, sub := told(ctl, msgs, closed); !sub {
		t.Fatalf("an admitted peer was not told after RefreshPeers: %+v", ctl)
	}
}

// TestAllowPeerBetweenNodes: two nodes in both topics, the closed one refusing the other: the refused node's closed room
// has no peer and gets none of its messages, the open topic works, and RefreshPeers admits it and refuses it again.
func TestAllowPeerBetweenNodes(t *testing.T) {
	checkGoroutines(t)
	a, b := newMember(t), newMember(t)
	ros := newRoster(a, b)
	open, closed := testTopic(t.Name()+"/open"), testTopic(t.Name()+"/closed")
	na, nb := newNode(t, nodeOpts{m: a}), newNode(t, nodeOpts{m: b})
	var admit atomic.Bool
	allow := func(k ed25519.PublicKey) bool { return admit.Load() || !bytes.Equal(k, b.device.PublicKey()) }
	rao := na.join(t, open, &TopicOptions{Authors: ros}).collect(na)
	rac := na.join(t, closed, &TopicOptions{Authors: ros, AllowPeer: allow}).collect(na)
	rbo := nb.join(t, open, &TopicOptions{Authors: ros}).collect(nb)
	rbc := nb.join(t, closed, &TopicOptions{Authors: ros}).collect(nb)
	na.connect(t, open, nb)
	(&cluster{rooms: []*room{rao, rbo}}).ready(t, 1)
	waitFor(t, 10*time.Second, "the closed topic announced to the refused node", func() bool { return rac.Stats().Peers == 1 })
	publish(t, rac.Room, "closed, refused")
	publish(t, rbc.Room, "closed, from the refused node")
	opened := publish(t, rao.Room, "open")
	waitFor(t, 10*time.Second, "the open message", func() bool { return rbo.has(opened) })
	time.Sleep(500 * time.Millisecond)
	if s := rbc.Stats(); s.Peers != 0 || rbc.count() != 0 || rac.count() != 0 {
		t.Fatalf("the refused node learned of the closed topic: %+v, %d and %d messages", s, rbc.count(), rac.count())
	}
	admit.Store(true)
	rac.RefreshPeers()
	waitFor(t, 10*time.Second, "the closed topic announced after the refresh", func() bool { return rbc.Stats().Peers == 1 })
	allowed := publish(t, rac.Room, "closed, admitted")
	waitFor(t, 10*time.Second, "the admitted message", func() bool { return rbc.has(allowed) })
	admit.Store(false)
	rac.RefreshPeers()
	waitFor(t, 10*time.Second, "the refusal to reach the node", func() bool { return rbc.Stats().Peers == 0 })
	publish(t, rac.Room, "closed, refused again")
	time.Sleep(500 * time.Millisecond)
	if rbc.count() != 1 {
		t.Fatalf("%d closed messages after the second refusal, want the one sent between", rbc.count())
	}
}

// TestRetryVerdict: a message the validator answers Retry for is kept, not delivered, and validated again on
// Room.Revalidate or after RetryInterval; the later Accept delivers it once.
func TestRetryVerdict(t *testing.T) {
	for name, byHand := range map[string]bool{"Revalidate": true, "RetryInterval": false} {
		t.Run(name, func(t *testing.T) {
			checkGoroutines(t)
			a, b := newMember(t), newMember(t)
			ros := newRoster(a, b)
			topic := testTopic(t.Name())
			na := newNode(t, nodeOpts{m: a})
			nb := newNode(t, nodeOpts{m: b, tweak: func(c *Config) {
				if !byHand {
					c.RetryInterval = 100 * time.Millisecond
				} else {
					c.RetryInterval = time.Hour
				}
			}})
			var calls atomic.Int32
			var ready atomic.Bool
			ra := na.join(t, topic, &TopicOptions{Authors: ros}).collect(na)
			rb := nb.join(t, topic, &TopicOptions{Authors: ros, Validate: func(context.Context, *Message) Verdict {
				calls.Add(1)
				if ready.Load() {
					return Accept
				}
				return Retry
			}}).collect(nb)
			na.connect(t, topic, nb)
			(&cluster{rooms: []*room{ra, rb}}).ready(t, 1)
			sent := publish(t, ra.Room, "too early")
			waitFor(t, 10*time.Second, "the first validation", func() bool { return calls.Load() >= 1 })
			time.Sleep(300 * time.Millisecond)
			if s := nb.g.Stats().Router; rb.count() != 0 || s.Validating != 1 || s.Retried == 0 || s.Ignored != 0 {
				t.Fatalf("a retried message: %d delivered, %+v", rb.count(), s)
			}
			ready.Store(true)
			if byHand {
				rb.Revalidate()
			}
			waitFor(t, 10*time.Second, "the message after the retry", func() bool { return rb.has(sent) })
			if s := nb.g.Stats().Router; s.Validating != 0 || s.Delivered != 1 {
				t.Fatalf("after the retry: %+v", s)
			}
		})
	}
}

// TestConfigNow: Config.Now is the clock of signing, of the time windows and of the heartbeat: a node whose clock is two
// days ahead signs at it, takes messages signed at it and refuses ones signed at the real time, and its seen ids expire
// when its clock passes SeenTTL.
func TestConfigNow(t *testing.T) {
	checkGoroutines(t)
	virtual := time.Now().Add(48 * time.Hour).Truncate(time.Millisecond)
	var clock atomic.Int64
	clock.Store(virtual.UnixNano())
	now := func() time.Time { return time.Unix(0, clock.Load()) }
	m, author := newMember(t), newMember(t)
	g, err := New(m.device, &Config{Cert: m.cert, NoScore: true, Now: now, HeartbeatInterval: 20 * time.Millisecond,
		LockWork: time.Hour, PeerWork: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	topic := testTopic("now")
	rm, err := g.Join(context.Background(), topic, &TopicOptions{Authors: newRoster(m, author)})
	if err != nil {
		t.Fatal(err)
	}
	p, done := peerWith(t, g, ident(t).PublicKey(), "10.0.0.1:4000")
	defer done()
	feed(t, g, p, wire.KindMessage, signAt(t, author, topic, 1, now(), []byte("virtual")), signAt(t, author, topic, 2, time.Now(), []byte("real")))
	got, err := rm.Next(context.Background())
	if err != nil || string(got.Body) != "virtual" {
		t.Fatalf("the message at the node's own time: %v %v", got, err)
	}
	if s := g.Stats().Router; s.OutOfWindow != 1 || s.Delivered != 1 {
		t.Fatalf("the message at the real time: %+v", s)
	}
	sent, err := rm.Publish(context.Background(), []byte("signed by the virtual clock"))
	if err != nil || !sent.Time.Equal(virtual) {
		t.Fatalf("published at %v, want %v: %v", sent, virtual, err)
	}
	if g.Stats().Router.Seen != 2 {
		t.Fatalf("seen %+v", g.Stats().Router)
	}
	clock.Store(virtual.Add(10 * time.Minute).UnixNano())
	waitFor(t, 10*time.Second, "the seen ids to expire on the virtual clock", func() bool { return g.Stats().Router.Seen == 0 })
	later, err := rm.Publish(context.Background(), []byte("ten minutes later"))
	if err != nil || !later.Time.Equal(virtual.Add(10*time.Minute)) {
		t.Fatalf("published at %v: %v", later, err)
	}
}

// TestPublishReturnsTheMessage: Publish returns the message as signed, and a receiver gets the same id, sequence number,
// time, author and envelope bytes, which VerifyEnvelope accepts for the author.
func TestPublishReturnsTheMessage(t *testing.T) {
	checkGoroutines(t)
	c := newCluster(t, 2, [][2]int{{0, 1}}, nil)
	c.ready(t, 1)
	sent, err := c.rooms[0].Publish(context.Background(), []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, 10*time.Second, "delivery", func() bool { return c.rooms[1].has(sent.ID) })
	got := c.rooms[1].msg(sent.ID)
	a := c.members[0]
	if !bytes.Equal(sent.Raw, got.Raw) || sent.Seq != got.Seq || !sent.Time.Equal(got.Time) || !bytes.Equal(sent.Device, got.Device) ||
		!bytes.Equal(sent.Person, got.Person) || !bytes.Equal(sent.Body, got.Body) || sent.Topic != c.topic ||
		!bytes.Equal(sent.Device, a.device.PublicKey()) || !bytes.Equal(sent.Person, a.person.PublicKey()) || sent.From != nil {
		t.Fatalf("sent %+v, received %+v", sent, got)
	}
	again, err := VerifyEnvelope(c.topic, got.Raw, a.author())
	if err != nil || again.ID != sent.ID || again.Seq != sent.Seq || string(again.Body) != "hello" || again.From != nil {
		t.Fatalf("VerifyEnvelope: %+v %v", again, err)
	}
	if _, err := c.rooms[0].Publish(context.Background(), make([]byte, 2<<20)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("a body too large: %v", err)
	}
}

// TestVerifyEnvelope: an envelope is accepted only for its topic, its author's keys, a good signature, and a chain that
// certifies the device at the envelope's own time.
func TestVerifyEnvelope(t *testing.T) {
	a, b := newMember(t), newMember(t)
	topic := testTopic("verify")
	at := time.Now().Add(time.Minute)
	raw := signAt(t, a, topic, 7, at, []byte("body"))
	m, err := VerifyEnvelope(topic, raw, a.author())
	if err != nil || m.Seq != 7 || string(m.Body) != "body" || !bytes.Equal(m.Raw, raw) || !m.Time.Equal(at.Truncate(time.Millisecond)) {
		t.Fatalf("a good envelope: %+v %v", m, err)
	}
	flip := func(i int) []byte {
		c := bytes.Clone(raw)
		c[i] ^= 1
		return c
	}
	rev, err := a.person.RevokeDevice(&koloid.RevokeOptions{Person: a.person.PublicKey(), Device: a.device.PublicKey(), UpToSerial: 1})
	if err != nil {
		t.Fatal(err)
	}
	revoked := a.author()
	revoked.Revocations = []*koloid.Revocation{rev}
	for _, c := range []struct {
		name  string
		topic Topic
		raw   []byte
		by    *Author
		is    error
	}{
		{"another topic", testTopic("other"), raw, a.author(), ErrBadEnvelope},
		{"another author", topic, raw, b.author(), ErrBadEnvelope},
		{"a changed body", topic, flip(len(raw) - wire.SigSize - 1), a.author(), ErrBadEnvelope},
		{"a changed signature", topic, flip(len(raw) - 1), a.author(), ErrBadEnvelope},
		{"a cut envelope", topic, raw[:len(raw)-1], a.author(), ErrBadEnvelope},
		{"no bytes", topic, nil, a.author(), ErrBadEnvelope},
		{"a revoked device", topic, raw, revoked, koloid.ErrCertRevoked},
		{"no author", topic, raw, nil, ErrInvalidArgument},
		{"an author without a certificate", topic, raw, &Author{Person: a.person.PublicKey()}, ErrInvalidArgument},
	} {
		if m, err := VerifyEnvelope(c.topic, c.raw, c.by); !errors.Is(err, c.is) || m != nil {
			t.Errorf("%s: %v %v", c.name, m, err)
		}
	}
	expiring := newMemberWith(t, &koloid.IssueOptions{Serial: 1, ExpiresAt: time.Now().Add(time.Hour)})
	for at, ok := range map[time.Duration]bool{30 * time.Minute: true, 2 * time.Hour: false} {
		_, err := VerifyEnvelope(topic, signAt(t, expiring, topic, 1, time.Now().Add(at), nil), expiring.author())
		if ok != (err == nil) || !ok && !errors.Is(err, koloid.ErrCertExpired) {
			t.Errorf("signed %v from now with a chain that expires in an hour: %v", at, err)
		}
	}
}

func newMemberWith(t testing.TB, o *koloid.IssueOptions) *member {
	t.Helper()
	m := &member{person: ident(t), device: ident(t)}
	offer, err := m.person.OfferDeviceCert(m.device.PublicKey(), o)
	if err != nil {
		t.Fatal(err)
	}
	if m.cert, err = m.device.AcceptDeviceCert(offer, m.person.PublicKey()); err != nil {
		t.Fatal(err)
	}
	return m
}
