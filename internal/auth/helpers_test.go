package auth

import (
	"crypto/ed25519"
	"math/rand/v2"
	"net/netip"
	"testing"
	"time"

	"github.com/ciranda-dev/kolo-gossip/internal/core"
	"github.com/ciranda-dev/kolo-gossip/internal/wire"
	koloid "github.com/ciranda-dev/kolo-id"
)

var (
	t0     = time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	issued = t0.Add(-24 * time.Hour)
	topic  = wire.Topic{0x70, 1}
)

// ident returns a deterministic identity, so every run uses the same keys.
func ident(t testing.TB, n byte) *koloid.Identity {
	t.Helper()
	seed := make([]byte, 32)
	seed[0], seed[31] = n, 0x5e
	id, err := koloid.FromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// person is one person key with an approver device and an ordinary device certified by that approver.
type person struct {
	key              *koloid.Identity
	approver, device *koloid.Identity
	approverCert     *koloid.DeviceCert
	deviceCert       *koloid.DeviceCert
}

func newPerson(t testing.TB, n byte) *person {
	t.Helper()
	p := &person{key: ident(t, n), approver: ident(t, n+1), device: ident(t, n+2)}
	p.approverCert = certify(t, p.key, p.approver, &koloid.IssueOptions{Serial: 1, Approver: true, IssuedAt: issued})
	p.deviceCert = certify(t, p.approver, p.device, &koloid.IssueOptions{Parent: p.approverCert, Serial: 1, IssuedAt: issued})
	return p
}

func certify(t testing.TB, issuer, dev *koloid.Identity, o *koloid.IssueOptions) *koloid.DeviceCert {
	t.Helper()
	offer, err := issuer.OfferDeviceCert(dev.PublicKey(), o)
	if err != nil {
		t.Fatal(err)
	}
	personKey := issuer.PublicKey()
	if o.Parent != nil {
		personKey = o.Parent.Person()
	}
	c, err := dev.AcceptDeviceCert(offer, personKey)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (p *person) pub() ed25519.PublicKey { return p.key.PublicKey() }

// sign returns an envelope by p's ordinary device at time at.
func (p *person) sign(t testing.TB, seq uint64, at time.Time, body string) []byte {
	t.Helper()
	raw, err := Sign(p.device, p.pub(), topic, seq, at, []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (p *person) author() *Author {
	return &Author{Person: p.pub(), Cert: p.deviceCert}
}

func decode(t testing.TB, raw []byte) (*wire.Envelope, []byte) {
	t.Helper()
	env, err := wire.DecodeEnvelope(raw, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	return env, raw[:len(raw)-wire.SigSize]
}

// roster is a map of authors by person and device that counts lookups.
type roster struct {
	m       map[pair]*Author
	err     error
	lookups int
}

func newRoster(ps ...*person) *roster {
	r := &roster{m: map[pair]*Author{}}
	for _, p := range ps {
		r.add(p.pub(), p.device.PublicKey(), p.author())
		r.add(p.pub(), p.approver.PublicKey(), &Author{Person: p.pub(), Cert: p.approverCert})
	}
	return r
}

func (r *roster) add(person, device ed25519.PublicKey, a *Author) {
	r.m[keyOf(person, device)] = a
}

func (r *roster) Lookup(t wire.Topic, person, device ed25519.PublicKey) (*Author, error) {
	r.lookups++
	if r.err != nil {
		return nil, r.err
	}
	a := r.m[keyOf(person, device)]
	if a == nil {
		return nil, ErrUnknownAuthor
	}
	return a, nil
}

// opener is an open mode that accepts the persons in ok, with their revocations.
type opener struct {
	ok    map[[32]byte][]*koloid.Revocation
	calls int
}

func newOpener(ps ...*person) *opener {
	o := &opener{ok: map[[32]byte][]*koloid.Revocation{}}
	for _, p := range ps {
		o.ok[[32]byte(p.pub())] = nil
	}
	return o
}

func (o *opener) open(t wire.Topic, person ed25519.PublicKey) ([]*koloid.Revocation, bool) {
	o.calls++
	revs, ok := o.ok[[32]byte(person)]
	return revs, ok
}

type clock struct{ now time.Time }

func (c *clock) Now() time.Time { return c.now }

func newResolver(t testing.TB, c *clock, authors Authors, open Open, tweak func(*Config)) *Resolver {
	t.Helper()
	cfg := DefaultConfig()
	cfg.Authors, cfg.Open, cfg.Now = authors, open, c.Now
	if tweak != nil {
		tweak(cfg)
	}
	r, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// sink records the router's effects.
type sink struct {
	ctrl     map[core.PeerID][]*wire.Control
	validate []wire.ID
	inst     map[wire.ID]uint64 // the last validation number of each id
	deliver  []wire.ID
}

func newSink() *sink {
	return &sink{ctrl: map[core.PeerID][]*wire.Control{}, inst: map[wire.ID]uint64{}}
}

func (s *sink) SendControl(to core.PeerID, c *wire.Control, urgent bool) bool {
	s.ctrl[to] = append(s.ctrl[to], c)
	return true
}
func (s *sink) SendMessage(to core.PeerID, raw []byte) bool { return true }
func (s *sink) Validate(id wire.ID, n uint64, env *wire.Envelope, from core.PeerID) {
	s.validate = append(s.validate, id)
	s.inst[id] = n
}
func (s *sink) Cancel(uint64)                                       {}
func (s *sink) Dial(wire.Topic, core.PeerID, []wire.PeerRecord) int { return 0 }
func (s *sink) Deliver(id wire.ID, env *wire.Envelope, from core.PeerID) {
	s.deliver = append(s.deliver, id)
}

func (s *sink) certWants(p core.PeerID) []wire.CertWant {
	var out []wire.CertWant
	for _, c := range s.ctrl[p] {
		out = append(out, c.CertWant...)
	}
	return out
}

func (s *sink) certs(p core.PeerID) [][]byte {
	var out [][]byte
	for _, c := range s.ctrl[p] {
		out = append(out, c.Cert...)
	}
	return out
}

// node is a router that checks authors with a Resolver, joined to topic with peers 1..n.
type node struct {
	t    *testing.T
	clk  *clock
	res  *Resolver
	r    *core.Router
	sink *sink
}

func peerKey(i int) core.PeerID {
	var k core.PeerID
	k[0], k[1] = 0xEE, byte(i)
	return k
}

func newNode(t *testing.T, authors Authors, open Open, peers int, tweak func(*Config), ctweak func(*core.Config)) *node {
	t.Helper()
	n := &node{t: t, clk: &clock{now: t0}, sink: newSink()}
	n.res = newResolver(t, n.clk, authors, open, tweak)
	cfg := core.DefaultConfig()
	cfg.LockWork = 1 << 46 // new peers start with a burst big enough that these tests never reach a budget
	if ctweak != nil {
		ctweak(cfg)
	}
	r, err := core.New(t0, peerKey(0), cfg, rand.New(rand.NewPCG(1, 2)), n.res, n.sink)
	if err != nil {
		t.Fatal(err)
	}
	n.r = r
	if err := r.Join(t0, topic, nil); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= peers; i++ {
		if err := r.AddPeer(t0, peerKey(i), true, netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 0, byte(i)}), 4000)); err != nil {
			t.Fatal(err)
		}
		n.control(i, &wire.Control{Subs: []wire.Sub{{Topic: topic, Subscribe: true}}})
	}
	return n
}

func (n *node) control(i int, c *wire.Control) {
	n.t.Helper()
	if err := n.r.Control(n.clk.now, peerKey(i), c); err != nil {
		n.t.Fatal(err)
	}
}

func (n *node) message(i int, raw []byte) {
	n.r.Message(n.clk.now, peerKey(i), raw)
}

func (n *node) advance(d time.Duration) {
	n.clk.now = n.clk.now.Add(d)
}

// heartbeat runs the router's due work at the clock's time.
func (n *node) heartbeat() {
	n.r.Tick(n.clk.now)
}

func (n *node) validated(raw []byte) bool {
	id := wire.NewID(raw)
	for _, v := range n.sink.validate {
		if v == id {
			return true
		}
	}
	return false
}
