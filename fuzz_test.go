package kologossip

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/ciranda-dev/kolo-gossip/internal/core"
	"github.com/ciranda-dev/kolo-gossip/internal/wire"
)

var fuzzTopic = testTopic("fuzz")

// fuzzGossip returns a Gossip in one closed room with scoring off, so no input graylists the test peer, and the
// room's author.
func fuzzGossip(t testing.TB) (*Gossip, *member) {
	t.Helper()
	m, author := newMember(t), newMember(t)
	// A peer per input is a churn far faster than any swarm admits: the node's budgets are made big enough for it.
	g, err := New(m.device, &Config{Cert: m.cert, NoScore: true, MaxMessageSize: 4096, MaxControlSize: 4096,
		LockWork: time.Hour, PeerWork: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { g.Close() })
	if _, err := g.Join(context.Background(), fuzzTopic, &TopicOptions{Authors: newRoster(author)}); err != nil {
		t.Fatal(err)
	}
	return g, author
}

// fuzzPeer adds a peer without a connection, for the stream reader; done removes it.
func fuzzPeer(t testing.TB, g *Gossip) (p *peer, done func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	var id core.PeerID
	copy(id[:], ident(t).PublicKey())
	p, err := g.addPeer(ctx, cancel, id, nil, true, netip.MustParseAddrPort("10.0.0.1:4000"))
	if err != nil {
		t.Fatal(err)
	}
	return p, func() {
		g.removePeer(p)
		cancel()
	}
}

// FuzzReadStream: any bytes on a peer's stream end it cleanly, as cut, or as a protocol violation, never with a
// panic, and the router keeps its bounds. Each input runs on a fresh peer.
func FuzzReadStream(f *testing.F) {
	g, author := fuzzGossip(f)
	env := sign(f, author, fuzzTopic, 1, []byte("seed"))
	ctl := &wire.Control{Subs: []wire.Sub{{Topic: wire.Topic(fuzzTopic), Subscribe: true}}, Graft: []wire.Topic{wire.Topic(fuzzTopic)},
		IHave: []wire.IHave{{Topic: wire.Topic(fuzzTopic), IDs: []wire.ID{{1}}}}, IWant: []wire.ID{wire.NewID(env)},
		CertWant: []wire.CertWant{{}}, IDontWant: []wire.ID{{2}}}
	cb, err := ctl.Encode()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(append(header(wire.KindControl), wire.AppendFrame(nil, cb)...))
	f.Add(append(header(wire.KindMessage), wire.AppendFrame(nil, env)...))
	bad := bytes.Clone(env)
	bad[len(bad)-1] ^= 1
	f.Add(append(header(wire.KindMessage), wire.AppendFrame(wire.AppendFrame(nil, env), bad)...))
	f.Add([]byte{0, 'm', 0xff, 0xff, 0xff, 0xff, 0x0f})
	cfg := g.set.router
	f.Add([]byte("221212212121221212122122121221212122121212212121221212212122121212212122121212121221212122121212212121212122121217212212122121221212122122121"))
	f.Add([]byte("0222272222227222222222222272222222222227222222222222272222222222"))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, done := fuzzPeer(t, g)
		defer done()
		err := g.readStream(p, bufio.NewReader(bytes.NewReader(data)), nil)
		if err != nil && !errors.Is(err, ErrProtocol) && !errors.Is(err, errEnded) {
			t.Fatalf("unexpected error %v", err)
		}
		g.mu.Lock()
		s := g.r.Stats()
		g.mu.Unlock()
		if s.Validating > cfg.MaxValidating || s.Seen > cfg.MaxSeen || s.CacheBytes > cfg.MaxCacheBytes || s.Peers > 1 {
			t.Fatalf("bounds broken: %+v", s)
		}
	})
}
