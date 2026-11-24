package kologossip

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ciranda-dev/kolo-gossip/internal/core"
	"github.com/ciranda-dev/kolo-gossip/internal/wire"
	kolosecure "github.com/ciranda-dev/kolo-secure"
)

// TestPeerExchange: B, whose mesh is full, refuses A's GRAFT with a PRUNE listing C; A, which scores B above
// AcceptPX, dials C through its swarm and serves it. Without PeerExchange on B, or when C dialed B so that B does not
// know where C accepts connections, A never learns C.
func TestPeerExchange(t *testing.T) {
	for _, tc := range []struct{ px, bDials bool }{{true, true}, {false, true}, {true, false}} {
		px := tc.px && tc.bDials
		checkGoroutines(t)
		topic := testTopic(t.Name())
		ms := []*member{newMember(t), newMember(t), newMember(t)}
		ros := newRoster(ms...)
		b := ms[1].device.PublicKey()
		tweaks := []func(*Config){
			func(c *Config) {
				c.Score = DefaultScore()
				c.Score.AppScore = func(k ed25519.PublicKey) float64 {
					if bytes.Equal(k, b) {
						return 20
					}
					return 0
				}
			},
			func(c *Config) {
				c.PeerExchange = tc.px
				c.Params = &Params{D: 1, Dlo: 1, Dhi: 1, Dscore: 1, Dlazy: 6, GossipFactor: 0.25, GossipPeers: 43}
			},
			nil,
		}
		var nodes []*node
		var rooms []*room
		for i, m := range ms {
			n := newNode(t, nodeOpts{m: m, tweak: tweaks[i]})
			rooms = append(rooms, n.join(t, topic, &TopicOptions{Authors: ros}))
			nodes = append(nodes, n)
		}
		if tc.bDials {
			nodes[1].connect(t, topic, nodes[2]) // B knows where C accepts connections
		} else {
			nodes[2].connect(t, topic, nodes[1])
		}
		waitFor(t, 10*time.Second, "C in B's mesh", func() bool { return rooms[1].Stats().Mesh == 1 })
		nodes[0].connect(t, topic, nodes[1])
		if !px {
			waitFor(t, 10*time.Second, "B's PRUNE", func() bool { return nodes[0].g.Stats().Router.Peers == 1 && rooms[0].Stats().Mesh == 0 })
			time.Sleep(500 * time.Millisecond)
			if s := nodes[0].g.Stats(); s.PXDials != 0 || rooms[0].Stats().Peers != 1 {
				t.Fatalf("without peer exchange A dialed %d records and sees %d peers", s.PXDials, rooms[0].Stats().Peers)
			}
			for _, n := range nodes {
				n.close()
			}
			continue
		}
		waitFor(t, 20*time.Second, "A to serve C", func() bool { return rooms[0].Stats().Peers == 2 })
		if s := nodes[0].g.Stats(); s.PXConnected == 0 || s.Router.PXAccepted == 0 {
			t.Fatalf("peer exchange stats %+v", s)
		}
		for _, n := range nodes {
			n.close()
		}
	}
}

// TestDroppedValidationCanceled: a validation the router drops, past the departed share, has its context
// canceled, so a validator that honours it returns at once.
func TestDroppedValidationCanceled(t *testing.T) {
	checkGoroutines(t)
	c := newCluster(t, 3, [][2]int{{1, 0}, {2, 0}}, func(c *Config) { c.MaxPeerValidating = 1 })
	c.ready(t, 1, 0)
	subscribed(t, c.rooms[0].Room, 2)
	g := c.nodes[0].g
	var canceled atomic.Int32
	g.mu.Lock()
	g.rooms[c.topic].validate = func(ctx context.Context, _ *Message) Verdict {
		<-ctx.Done()
		if errors.Is(ctx.Err(), context.Canceled) {
			canceled.Add(1)
		}
		return Ignore
	}
	g.mu.Unlock()
	for _, from := range []int{1, 2} {
		publish(t, c.rooms[from].Room, "held")
		waitFor(t, 10*time.Second, "the validation", func() bool { return g.Stats().Router.Validating == from })
		c.nodes[from].close()
		waitFor(t, 10*time.Second, "the sender to leave", func() bool { return g.Stats().Router.Peers == 2-from })
	}
	waitFor(t, 10*time.Second, "the dropped validation canceled", func() bool { return canceled.Load() == 1 })
	// Its place is freed once its verdict comes back; the departed share keeps the other.
	waitFor(t, 10*time.Second, "the canceled validation's place freed", func() bool { return g.Stats().Router.Validating == 1 })
}

// localConn is a fake connection with a local address.
type localConn struct {
	*fakeConn
	local net.Addr
}

func (c localConn) LocalAddr() net.Addr { return c.local }

// TestListenPortRule: a peer's port is kept for peer exchange only when it holds an outbound place and we opened the
// connection from a socket other than our swarm's.
func TestListenPortRule(t *testing.T) {
	checkGoroutines(t)
	n := newNode(t, nodeOpts{})
	own := n.sw.Addr().(*net.UDPAddr)
	remote := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 7), Port: 4100}
	other := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: own.Port + 1}
	for _, tc := range []struct {
		local    net.Addr
		outbound bool
		port     uint16
	}{{other, true, 4100}, {other, false, 0}, {own, true, 0}} {
		c := localConn{&fakeConn{remote: remote}, tc.local}
		got, err := n.g.remoteAddr(c, tc.outbound)
		if err != nil || got.Addr() != netip.MustParseAddr("10.0.0.7") || got.Port() != tc.port {
			t.Fatalf("local %v outbound %v: %v %v, want port %d", tc.local, tc.outbound, got, err, tc.port)
		}
	}
}

// TestPXQueueBounded: past PXPending records waiting for a dialer, the rest of a PRUNE's records are dropped and
// counted.
func TestPXQueueBounded(t *testing.T) {
	g := &Gossip{dials: make(chan dialReq, 2), peers: map[core.PeerID]*peer{}}
	sink{g}.Dial(wire.Topic{}, core.PeerID{1}, make([]wire.PeerRecord, 5))
	if len(g.dials) != 2 || g.pxDropped.Load() != 3 {
		t.Fatalf("%d queued, %d dropped of 5 with room for 2", len(g.dials), g.pxDropped.Load())
	}
}

// TestPXConfig: the peer exchange dial bounds take their defaults when zero and refuse negative values.
func TestPXConfig(t *testing.T) {
	cert := newMember(t).cert
	s, err := (&Config{Cert: cert}).settings()
	if err != nil || s.pxPending != 128 || s.pxDialers != 8 || s.pxTimeout != 30*time.Second {
		t.Fatalf("%+v, %v", s, err)
	}
	for _, c := range []*Config{{Cert: cert, PXPending: -1}, {Cert: cert, PXDialers: -1}, {Cert: cert, PXTimeout: -time.Second}} {
		if _, err := c.settings(); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("%+v accepted: %v", c, err)
		}
	}
}

// BenchmarkPXDial measures one authenticated dial on loopback, both sides of the handshake: what a peer exchange
// record makes the node run, the source of core.OpDial.
func BenchmarkPXDial(b *testing.B) {
	ctx := context.Background()
	sid := ident(b)
	server, err := kolosecure.Listen(ctx, "127.0.0.1:0", sid, nil)
	if err != nil {
		b.Fatal(err)
	}
	defer server.Close()
	client, err := kolosecure.Listen(ctx, "127.0.0.1:0", ident(b), nil)
	if err != nil {
		b.Fatal(err)
	}
	defer client.Close()
	accepted := make(chan *kolosecure.Conn)
	go func() {
		for {
			c, err := server.Accept(ctx)
			if err != nil {
				close(accepted)
				return
			}
			accepted <- c
		}
	}()
	key := sid.PublicKey()
	b.ResetTimer()
	for b.Loop() {
		c, err := client.Dial(ctx, addrOf(server.Addr()), key)
		if err != nil {
			b.Fatal(err)
		}
		(<-accepted).Close()
		c.Close()
	}
}
