package kologossip

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	kolodht "github.com/ciranda-dev/kolo-dht"
	koloid "github.com/ciranda-dev/kolo-id"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	koloswarm "github.com/ciranda-dev/kolo-swarm"
	kolotransport "github.com/ciranda-dev/kolo-transport"
)

var loopback = netip.MustParseAddr("127.0.0.1")

// checkGoroutines fails the test if goroutines started during it outlive its cleanups. It compares all goroutines
// of the process, so it is not safe in a test that runs in parallel with others.
func checkGoroutines(t *testing.T) {
	t.Helper()
	before := goroutines()
	t.Cleanup(func() {
		deadline := time.Now().Add(10 * time.Second)
		for {
			var leaked []string
			for id, stack := range goroutines() {
				if _, ok := before[id]; !ok {
					leaked = append(leaked, stack)
				}
			}
			if len(leaked) == 0 {
				return
			}
			if time.Now().After(deadline) {
				t.Errorf("%d goroutines leaked:\n%s", len(leaked), strings.Join(leaked, "\n\n"))
				return
			}
			<-time.After(10 * time.Millisecond)
		}
	})
}

func goroutines() map[string]string {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	out := map[string]string{}
	for _, stack := range strings.Split(string(buf), "\n\n") {
		if id, _, ok := strings.Cut(strings.TrimPrefix(stack, "goroutine "), " "); ok {
			out[id] = stack
		}
	}
	return out
}

// waitFor polls cond until it holds, failing the test after d.
func waitFor(t testing.TB, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %v waiting for %s", d, what)
		}
		<-tick.C
	}
}

func testTopic(name string) Topic { return Topic(sha256.Sum256([]byte(name))) }

func ident(t testing.TB) *koloid.Identity {
	t.Helper()
	id, err := koloid.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// member is a person with one device certified by the person key.
type member struct {
	person, device *koloid.Identity
	cert           *koloid.DeviceCert
}

func newMember(t testing.TB) *member {
	t.Helper()
	m := &member{person: ident(t), device: ident(t)}
	offer, err := m.person.OfferDeviceCert(m.device.PublicKey(), &koloid.IssueOptions{Serial: 1})
	if err != nil {
		t.Fatal(err)
	}
	if m.cert, err = m.device.AcceptDeviceCert(offer, m.person.PublicKey()); err != nil {
		t.Fatal(err)
	}
	return m
}

func (m *member) author() *Author {
	return &Author{Person: m.person.PublicKey(), Cert: m.cert}
}

// roster is a closed-mode roster shared by the nodes of a test; it is safe for concurrent use.
type roster struct {
	mu sync.Mutex
	m  map[[64]byte]*Author
}

func newRoster(ms ...*member) *roster {
	r := &roster{m: map[[64]byte]*Author{}}
	for _, m := range ms {
		r.add(m)
	}
	return r
}

func pairKey(person, device ed25519.PublicKey) [64]byte {
	var k [64]byte
	copy(k[:32], person)
	copy(k[32:], device)
	return k
}

func (r *roster) add(m *member) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[pairKey(m.person.PublicKey(), m.device.PublicKey())] = m.author()
}

func (r *roster) revoke(m *member, rev *koloid.Revocation) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a := *m.author()
	a.Revocations = []*koloid.Revocation{rev}
	r.m[pairKey(m.person.PublicKey(), m.device.PublicKey())] = &a
}

func (r *roster) Lookup(_ Topic, person, device ed25519.PublicKey) (*Author, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if a := r.m[pairKey(person, device)]; a != nil {
		return a, nil
	}
	return nil, ErrUnknownAuthor
}

// newServer starts a kolo-dht server on loopback with per-IP limits raised: every test peer is 127.0.0.1.
func newServer(t *testing.T) *kolodht.Node {
	t.Helper()
	n, err := kolodht.New(context.Background(), "127.0.0.1:0", ident(t), &kolodht.Config{
		Server:               true,
		RequestTimeout:       300 * time.Millisecond,
		MaxRequestsPerIP:     5000,
		MaxRequestsPerPrefix: 10000,
		MaxRequests:          20000,
		MaxRecordsPerIP:      512,
		MaxRecordsPerTopic:   128,
		MaxRelays:            256,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.Close() })
	return n
}

func addrOf(a net.Addr) netip.AddrPort {
	ap := a.(*net.UDPAddr).AddrPort()
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

// swarmConfig has test timings and per-IP limits raised for loopback; allow, if set, is chained into Allow.
func swarmConfig(allow func(ed25519.PublicKey, netip.AddrPort) bool) *koloswarm.Config {
	return &koloswarm.Config{
		DHT: &kolodht.Config{
			RequestTimeout: 300 * time.Millisecond,
			PunchTimeout:   time.Second,
			Secure:         &kolosecure.Config{Transport: &kolotransport.Config{MaxConnsPerIP: 64}},
		},
		MaxConnecting:      4,
		MaxHandshakes:      64,
		MaxHandshakesPerIP: 64,
		HelloTimeout:       2 * time.Second,
		LookupInterval:     time.Second,
		RetryMin:           100 * time.Millisecond,
		RetryMax:           time.Second,
		Allow:              allow,
	}
}

// node is a swarm on loopback with a Gossip on the same device key that serves every connected peer.
type node struct {
	t      testing.TB
	m      *member
	sw     *koloswarm.Swarm
	g      *Gossip
	gp     atomic.Pointer[Gossip]
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu     sync.Mutex
	served map[string]error // last ServeConn result per remote key
}

type nodeOpts struct {
	m      *member
	server *kolodht.Node
	tweak  func(*Config)
	swarm  func(*koloswarm.Config)
	noLoop bool // the test serves connections itself
}

func newNode(t *testing.T, o nodeOpts) *node {
	t.Helper()
	if o.m == nil {
		o.m = newMember(t)
	}
	n := &node{t: t, m: o.m, served: map[string]error{}}
	scfg := swarmConfig(func(k ed25519.PublicKey, a netip.AddrPort) bool {
		g := n.gp.Load()
		return g == nil || g.Allow(k, a)
	})
	if o.swarm != nil {
		o.swarm(scfg)
	}
	sw, err := koloswarm.New(context.Background(), "127.0.0.1:0", o.m.device, scfg)
	if err != nil {
		t.Fatal(err)
	}
	n.sw = sw
	if o.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := sw.Bootstrap(ctx, []netip.AddrPort{addrOf(o.server.Addr())}); err != nil {
			t.Fatal(err)
		}
	}
	cfg := &Config{Cert: o.m.cert, Swarm: sw, HeartbeatInterval: 100 * time.Millisecond}
	if o.tweak != nil {
		o.tweak(cfg)
	}
	if n.g, err = New(o.m.device, cfg); err != nil {
		t.Fatal(err)
	}
	n.gp.Store(n.g)
	ctx, cancel := context.WithCancel(context.Background())
	n.cancel = cancel
	if !o.noLoop {
		n.wg.Add(1)
		go n.loop(ctx)
	}
	t.Cleanup(n.close)
	return n
}

// loop serves every connected peer, as an application does.
func (n *node) loop(ctx context.Context) {
	defer n.wg.Done()
	for {
		ev, err := n.sw.Next(ctx)
		if err != nil {
			return
		}
		if ev.Kind != koloswarm.Connected {
			continue
		}
		n.wg.Add(1)
		go func(p *koloswarm.Peer) {
			defer n.wg.Done()
			err := n.g.ServeConn(ctx, p.Conn(), p.Outbound())
			n.mu.Lock()
			n.served[string(p.PublicKey())] = err
			n.mu.Unlock()
		}(ev.Peer)
	}
}

// forgetServed drops the last ServeConn result for key, so a later one can be waited for.
func (n *node) forgetServed(key ed25519.PublicKey) {
	n.mu.Lock()
	defer n.mu.Unlock()
	delete(n.served, string(key))
}

func (n *node) servedErr(key ed25519.PublicKey) (error, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	err, ok := n.served[string(key)]
	return err, ok
}

// close stops the gossip, then the swarm, and waits for the node's goroutines.
func (n *node) close() {
	n.g.Close()
	n.cancel()
	n.sw.Close()
	n.wg.Wait()
}

func (n *node) key() ed25519.PublicKey { return n.m.device.PublicKey() }

func (n *node) addr() netip.AddrPort { return addrOf(n.sw.Addr()) }

// connect dials other directly for topic t, retrying while the swarm asks to wait.
func (n *node) connect(t testing.TB, topic Topic, other *node) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for {
		err := n.sw.Connect(ctx, topic, other.key(), other.addr(), loopback)
		switch {
		case err == nil, errors.Is(err, koloswarm.ErrDuplicate):
			return
		case errors.Is(err, koloswarm.ErrWait):
			select {
			case <-time.After(20 * time.Millisecond):
				continue
			case <-ctx.Done():
			}
		}
		t.Fatalf("connect %x to %x: %v", n.key()[:4], other.key()[:4], err)
	}
}

// tryConnect dials other directly for topic t, retrying while the swarm asks to wait, and returns how the dial ended:
// a peer that refuses us at the gossip layer may close the connection during the swarm's hello.
func (n *node) tryConnect(topic Topic, other *node) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for {
		err := n.sw.Connect(ctx, topic, other.key(), other.addr(), loopback)
		if !errors.Is(err, koloswarm.ErrWait) {
			return err
		}
		select {
		case <-time.After(20 * time.Millisecond):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (n *node) join(t testing.TB, topic Topic, opts *TopicOptions) *room {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if opts.Swarm == nil {
		opts.Swarm = &koloswarm.JoinOptions{Lookup: true}
	}
	rm, err := n.g.Join(ctx, topic, opts)
	if err != nil {
		t.Fatal(err)
	}
	return &room{Room: rm, got: map[MessageID]*Message{}}
}

// room collects what a Room delivers.
type room struct {
	*Room
	mu    sync.Mutex
	got   map[MessageID]*Message
	order []MessageID
	ros   *roster // the room's roster, when the test needs it
}

// collect reads the room until it ends.
func (r *room) collect(n *node) *room {
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		for {
			m, err := r.Next(context.Background())
			if err != nil {
				return
			}
			r.mu.Lock()
			if r.got[m.ID] != nil {
				r.mu.Unlock()
				n.t.Errorf("message %x delivered twice", m.ID[:4])
				return
			}
			r.got[m.ID] = m
			r.order = append(r.order, m.ID)
			r.mu.Unlock()
		}
	}()
	return r
}

func (r *room) has(ids ...MessageID) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, id := range ids {
		if r.got[id] == nil {
			return false
		}
	}
	return true
}

func (r *room) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.got)
}

func (r *room) msg(id MessageID) *Message {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.got[id]
}

func publish(t testing.TB, r *Room, body string) MessageID {
	t.Helper()
	m, err := r.Publish(context.Background(), []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	return m.ID
}

// subscribed waits until r sees at least n subscribed peers.
func subscribed(t testing.TB, r *Room, n int) {
	t.Helper()
	waitFor(t, 20*time.Second, fmt.Sprintf("%d subscribed peers", n), func() bool { return r.Stats().Peers >= n })
}
