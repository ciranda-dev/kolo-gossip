package auth

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/ciranda-dev/kolo-gossip/internal/core"
	"github.com/ciranda-dev/kolo-gossip/internal/wire"
	koloid "github.com/ciranda-dev/kolo-id"
)

// TestRevokedAnswerVoidsOnlyItsRequest: a peer that answers with an old, revoked chain of a real device ends only
// its own request; a message of the same author waiting on an honest peer is released by that peer's chain.
func TestRevokedAnswerVoidsOnlyItsRequest(t *testing.T) {
	q := newPerson(t, 20)
	rev, err := q.key.RevokeDevice(&koloid.RevokeOptions{Person: q.pub(), Device: q.device.PublicKey(), UpToSerial: 1, At: t0})
	if err != nil {
		t.Fatal(err)
	}
	renewed := certify(t, q.approver, q.device, &koloid.IssueOptions{Parent: q.approverCert, Serial: 2, IssuedAt: issued})
	op := newOpener(q)
	op.ok[[32]byte(q.pub())] = []*koloid.Revocation{rev}
	n := newNode(t, nil, op.open, 2, nil, nil)
	viaAttacker, viaHonest := q.sign(t, 1, t0, "a"), q.sign(t, 2, t0, "b")
	n.message(2, viaAttacker)
	n.message(1, viaHonest)
	n.control(2, &wire.Control{Cert: [][]byte{q.deviceCert.Encode()}})
	if s := n.res.Stats(); s.Revoked != 1 || s.Waiting != 1 || s.CacheChains != 0 || n.r.Stats().CertBroken != 0 {
		t.Fatalf("revoked answer: %+v", s)
	}
	n.control(1, &wire.Control{Cert: [][]byte{renewed.Encode()}})
	if !n.validated(viaHonest) || n.validated(viaAttacker) {
		t.Fatal("the honest peer's chain did not release its message")
	}
}

// TestNotHeldAnswer: a forwarder that no longer holds a chain says so; its request ends without a penalty and,
// with no other copy waiting, the message is forgotten, so another peer's copy asks that peer at once.
func TestNotHeldAnswer(t *testing.T) {
	q := newPerson(t, 20)
	n := openNode(t, 2, q)
	raw := q.sign(t, 1, t0, "")
	n.message(1, raw)
	k := keyOf(q.pub(), q.device.PublicKey())
	n.control(1, &wire.Control{Cert: [][]byte{k[:]}})
	if s := n.r.Stats(); s.CertBroken != 0 || s.Seen != 0 || n.res.Stats().NotHeld != 1 || n.res.Stats().Waiting != 0 {
		t.Fatalf("not held: %+v", s)
	}
	n.message(2, raw)
	if got := n.sink.certWants(peerKey(2)); len(got) != 1 {
		t.Fatal("another peer's copy did not ask its forwarder at once")
	}
	n.control(2, &wire.Control{Cert: [][]byte{q.deviceCert.Encode()}})
	if !n.validated(raw) {
		t.Fatal("not released by the second forwarder")
	}
	// A "not held" for a request never sent is unsolicited.
	n.control(1, &wire.Control{Cert: [][]byte{k[:]}})
	if n.res.Stats().NotHeld != 1 {
		t.Fatal("unsolicited not-held answer counted")
	}
}

// TestChainResultReuse: the chain check is reused for the same certificate and revocations until the chain
// expires, and redone for other revocations.
func TestChainResultReuse(t *testing.T) {
	p := newPerson(t, 10)
	expiring := certify(t, p.approver, p.device, &koloid.IssueOptions{Parent: p.approverCert, Serial: 2, IssuedAt: issued, ExpiresAt: t0.Add(time.Second)})
	rev, err := p.key.RevokeDevice(&koloid.RevokeOptions{Person: p.pub(), Device: p.device.PublicKey(), UpToSerial: 2, At: t0})
	if err != nil {
		t.Fatal(err)
	}
	ros := newRoster()
	ros.add(p.pub(), p.device.PublicKey(), &Author{Person: p.pub(), Cert: expiring})
	c := &clock{t0}
	r := newResolver(t, c, ros, nil, nil)
	env, signed := decode(t, p.sign(t, 1, t0, ""))
	for range 3 {
		if err := r.Verify(env, signed); err != nil {
			t.Fatal(err)
		}
	}
	if byContent(r) != 1 {
		t.Fatalf("%d chain results", byContent(r))
	}
	ros.add(p.pub(), p.device.PublicKey(), &Author{Person: p.pub(), Cert: expiring, Revocations: []*koloid.Revocation{rev}})
	if err := r.Verify(env, signed); err == nil {
		t.Fatal("a result was reused for other revocations")
	}
	ros.add(p.pub(), p.device.PublicKey(), &Author{Person: p.pub(), Cert: expiring})
	if err := r.Verify(env, signed); err != nil {
		t.Fatal(err)
	}
	c.now = t0.Add(time.Second)
	if err := r.Verify(env, signed); err == nil {
		t.Fatal("a result was reused after the chain expired")
	}
}

// TestRosterChainsKept: chains fetched from the network never push out the chains the roster gave, which the
// node needs to answer CERTWANT.
func TestRosterChainsKept(t *testing.T) {
	p, q := newPerson(t, 10), newPerson(t, 20)
	n := newNode(t, newRoster(p), newOpener(q).open, 2, func(c *Config) { c.CertCacheBytes = wire.MaxCertSize + entryOverhead }, nil)
	n.message(1, p.sign(t, 1, t0, ""))
	n.message(1, q.sign(t, 1, t0, ""))
	n.control(1, &wire.Control{Cert: [][]byte{q.deviceCert.Encode()}})
	n.control(2, &wire.Control{CertWant: []wire.CertWant{wantFor(p), wantFor(q)}})
	got := n.sink.certs(peerKey(2))
	if len(got) != 2 || !bytes.Equal(got[0], p.deviceCert.Encode()) || !bytes.Equal(got[1], q.deviceCert.Encode()) {
		t.Fatalf("answers %d", len(got))
	}
}

// TestUnsignedExpiredAnswer: a forged, unsigned chain that is also expired is a bad chain (P7), not a merely stale
// one: the signatures are checked before expiry and revocation decide.
func TestUnsignedExpiredAnswer(t *testing.T) {
	q := newPerson(t, 20)
	expired := certify(t, q.approver, q.device, &koloid.IssueOptions{Parent: q.approverCert, Serial: 3, IssuedAt: issued, ExpiresAt: t0.Add(-time.Second)}).Encode()
	parent := len(q.approverCert.Encode())
	expired[len(expired)-parent-1-wire.UvarintLen(uint64(parent))-10] ^= 1 // inside the device signature
	if _, err := koloid.DecodeDeviceCert(expired); err != nil {
		t.Fatal(err)
	}
	n := openNode(t, 1, q)
	n.message(1, q.sign(t, 1, t0, ""))
	n.control(1, &wire.Control{Cert: [][]byte{expired}})
	if s := n.res.Stats(); s.BadChains != 1 || s.Revoked != 0 || n.r.Stats().CertBroken != 1 {
		t.Fatalf("unsigned expired answer: %+v", s)
	}
}

// byContent counts the chain results kept by the hash of their encodings.
func byContent(r *Resolver) int {
	n := 0
	for k := range r.chains.m {
		if k.sum != ([32]byte{}) {
			n++
		}
	}
	return n
}

// TestChainReuseByContent: a roster that returns new objects each time still gets the chain result reused, and
// no kolo-id check runs again.
func TestChainReuseByContent(t *testing.T) {
	p := newPerson(t, 10)
	raw := p.deviceCert.Encode()
	r := newResolver(t, &clock{t0}, decodingRoster{p: p, cert: raw}, nil, nil)
	env, signed := decode(t, p.sign(t, 1, t0, ""))
	if err := r.Verify(env, signed); err != nil {
		t.Fatal(err)
	}
	r.Work()
	for range 4 {
		if err := r.Verify(env, signed); err != nil {
			t.Fatal(err)
		}
	}
	if byContent(r) != 1 || r.Work()[core.OpChain] != 0 {
		t.Fatalf("%d chain results by content for one chain, or checked again", byContent(r))
	}
}

// TestChainReuseByObjects: a roster that keeps its objects has its chain result found by them, without hashing.
func TestChainReuseByObjects(t *testing.T) {
	p := newPerson(t, 10)
	ros := newRoster()
	ros.add(p.pub(), p.device.PublicKey(), &Author{Person: p.pub(), Cert: p.deviceCert})
	r := newResolver(t, &clock{t0}, ros, nil, nil)
	env, signed := decode(t, p.sign(t, 1, t0, ""))
	if err := r.Verify(env, signed); err != nil {
		t.Fatal(err)
	}
	for k := range r.chains.m {
		if k.sum != ([32]byte{}) {
			delete(r.chains.m, k)
		}
	}
	if err := r.Verify(env, signed); err != nil || byContent(r) != 0 {
		t.Fatalf("the second check was not found by its objects: %v, %d", err, byContent(r))
	}
}

// TestChainCachedUntilExpiry: a valid chain's result is kept as long as it holds at the second checked an hour
// ahead (or before the device's expiry), and checked again only after that; when a link expires within that hour,
// the result is kept for its second only and checked with two kolo-id checks at most each time.
func TestChainCachedUntilExpiry(t *testing.T) {
	q := newPerson(t, 20)
	k := keyOf(q.pub(), q.device.PublicKey())
	long := certify(t, q.approver, q.device, &koloid.IssueOptions{Parent: q.approverCert, Serial: 6, IssuedAt: issued, ExpiresAt: t0.Add(48 * time.Hour)})
	r := newResolver(t, &clock{t0}, newRoster(), nil, nil)
	if err := r.chain(t0, k, long, nil); err != nil {
		t.Fatal(err)
	}
	if w := r.Work(); w[core.OpChain] != 2 {
		t.Fatalf("%d checks for a new chain, want 2", w[core.OpChain])
	}
	if err := r.chain(t0.Add(time.Hour), k, long, nil); err != nil || r.Work()[core.OpChain] != 0 {
		t.Fatalf("the result was not kept for the hour: %v", err)
	}
	// An approver that expires in two hours: the hour ahead still holds, so the result is kept that long.
	app2 := certify(t, q.key, q.approver, &koloid.IssueOptions{Serial: 3, Approver: true, IssuedAt: issued, ExpiresAt: t0.Add(2 * time.Hour)})
	mid := certify(t, q.approver, q.device, &koloid.IssueOptions{Parent: app2, Serial: 7, IssuedAt: issued, ExpiresAt: t0.Add(48 * time.Hour)})
	if err := r.chain(t0, k, mid, nil); err != nil {
		t.Fatal(err)
	}
	r.Work()
	if err := r.chain(t0.Add(time.Hour), k, mid, nil); err != nil || r.Work()[core.OpChain] != 0 {
		t.Fatalf("a chain valid for two more hours was checked again within the hour: %v", err)
	}
	approver := certify(t, q.key, q.approver, &koloid.IssueOptions{Serial: 2, Approver: true, IssuedAt: issued, ExpiresAt: t0.Add(10 * time.Minute)})
	short := certify(t, q.approver, q.device, &koloid.IssueOptions{Parent: approver, Serial: 5, IssuedAt: issued, ExpiresAt: t0.Add(time.Hour)})
	if err := r.chain(t0, k, short, nil); err != nil {
		t.Fatal(err)
	}
	r.Work()
	if err := r.chain(t0.Add(10*time.Minute-time.Second), k, short, nil); err != nil || r.Work()[core.OpChain] > 2 {
		t.Fatalf("before the approver's expiry: %v", err)
	}
	if err := r.chain(t0.Add(10*time.Minute), k, short, nil); !errors.Is(err, koloid.ErrCertExpired) {
		t.Fatalf("at the approver's expiry: %v", err)
	}
}

// decodingRoster decodes its chain and revocations on every lookup, as a roster backed by stored bytes does.
type decodingRoster struct {
	p    *person
	cert []byte
	revs [][]byte
}

func (d decodingRoster) Lookup(wire.Topic, ed25519.PublicKey, ed25519.PublicKey) (*Author, error) {
	c, err := koloid.DecodeDeviceCert(d.cert)
	if err != nil {
		return nil, err
	}
	a := &Author{Person: d.p.pub(), Cert: c}
	for _, b := range d.revs {
		rv, err := koloid.DecodeRevocation(b)
		if err != nil {
			return nil, err
		}
		a.Revocations = append(a.Revocations, rv)
	}
	return a, nil
}

// TestRequestBounds: a request our queue dropped ends at once without a penalty, at most MaxCertAnswers requests go
// to one peer per heartbeat, and Leave ends the requests of its topic without a penalty.
func TestRequestBounds(t *testing.T) {
	var ps []*person
	for i := range 3 {
		ps = append(ps, newPerson(t, byte(20+10*i)))
	}
	c := &clock{t0}
	r := newResolver(t, c, nil, newOpener(ps...).open, func(cfg *Config) { cfg.MaxCertAnswers = 2 })
	for i, p := range ps {
		env, signed := decode(t, p.sign(t, 1, t0, ""))
		w, err := r.Resolve(t0, wire.ID{byte(i)}, env, signed, peerKey(1))
		if (err == nil) != (i < 2) || i == 2 && !errors.Is(err, core.ErrPeerBusy) {
			t.Fatalf("request %d: %v", i, err)
		}
		if i == 0 {
			r.Dropped(peerKey(1), wire.ID{byte(i)}, *w)
		}
	}
	res := r.Expire(t0.Add(4 * time.Second))
	if len(res.Broken) != 1 || len(res.Done) != 1 {
		t.Fatalf("a dropped request was charged: %+v", res)
	}
	env, signed := decode(t, ps[2].sign(t, 2, t0, ""))
	if _, err := r.Resolve(t0, wire.ID{9}, env, signed, peerKey(1)); err != nil {
		t.Fatal(err)
	}
	r.Leave(topic)
	if s := r.Stats(); s.Waiting != 0 || s.Outstanding != 0 {
		t.Fatalf("Leave kept requests: %+v", s)
	}
	if res := r.Expire(t0.Add(time.Hour)); len(res.Broken) != 0 {
		t.Fatal("a request ended by Leave was charged")
	}
}

// TestChainResultByCertificate: two different chains for one device in the same second get their own results.
func TestChainResultByCertificate(t *testing.T) {
	p := newPerson(t, 10)
	stale := certify(t, p.approver, p.device, &koloid.IssueOptions{Parent: p.approverCert, Serial: 2, IssuedAt: issued, ExpiresAt: t0})
	ros := newRoster()
	ros.add(p.pub(), p.device.PublicKey(), p.author())
	r := newResolver(t, &clock{t0}, ros, nil, nil)
	env, signed := decode(t, p.sign(t, 1, t0, ""))
	if err := r.Verify(env, signed); err != nil {
		t.Fatal(err)
	}
	ros.add(p.pub(), p.device.PublicKey(), &Author{Person: p.pub(), Cert: stale})
	if err := r.Verify(env, signed); !errors.Is(err, koloid.ErrCertExpired) {
		t.Fatalf("the result of another chain was reused: %v", err)
	}
}

// TestFutureDatedDeviceChain: a genuine chain whose device certificate is dated after its approver's expiry, valid
// now, is not taken for a bad chain: the signature check runs at a time nothing has expired.
func TestFutureDatedDeviceChain(t *testing.T) {
	q := newPerson(t, 20)
	approver := certify(t, q.key, q.approver, &koloid.IssueOptions{Serial: 2, Approver: true, IssuedAt: issued, ExpiresAt: t0.Add(time.Hour)})
	device := certify(t, q.approver, q.device, &koloid.IssueOptions{Parent: approver, Serial: 5, IssuedAt: t0.Add(2 * time.Hour)})
	n := openNode(t, 1, q)
	raw := q.sign(t, 1, t0, "")
	n.message(1, raw)
	n.control(1, &wire.Control{Cert: [][]byte{device.Encode()}})
	if s := n.res.Stats(); s.BadChains != 0 || n.r.Stats().CertBroken != 0 || !n.validated(raw) {
		t.Fatalf("a genuine future-dated chain: %+v", s)
	}
}

// TestEndRequests: the requests to a peer we stopped reading or that left end at once without a penalty, their
// messages to be asked of other peers; a request unanswered in time is a broken one.
func TestEndRequests(t *testing.T) {
	p, q := newPerson(t, 20), newPerson(t, 30)
	r := newResolver(t, &clock{t0}, nil, newOpener(p, q).open, nil)
	for i, x := range []*person{p, q} {
		env, signed := decode(t, x.sign(t, 1, t0, ""))
		if _, err := r.Resolve(t0, wire.ID{byte(i)}, env, signed, peerKey(1+i)); err != nil {
			t.Fatal(err)
		}
	}
	if res := r.End(peerKey(1)); len(res.Broken) != 0 || len(res.Done) != 1 || res.Done[0].ID != (wire.ID{0}) || res.Done[0].Err == nil {
		t.Fatalf("end: %+v", res)
	}
	res := r.Expire(t0.Add(time.Minute))
	if len(res.Broken) != 1 || res.Broken[0] != peerKey(2) {
		t.Fatalf("broken %+v", res.Broken)
	}
}

// TestDepartedForgetsResolver: messages that waited for their author's chain and are dropped from the departed share
// leave the Resolver too, so rotating keys cannot keep its waiting bound full and refuse new authors.
func TestDepartedForgetsResolver(t *testing.T) {
	pp := newPerson(t, 1)
	q := newPerson(t, 2)
	n := newNode(t, nil, newOpener(pp, q).open, 1, func(c *Config) { c.MaxWaiting = 10 }, func(c *core.Config) {
		c.MaxPeers, c.MaxPeerValidating, c.MaxValidating = 4, 2, 10
	})
	sub := &wire.Control{Subs: []wire.Sub{{Topic: topic, Subscribe: true}}}
	seq := uint64(1)
	for k := range 8 {
		id := 10 + k
		if err := n.r.AddPeer(n.clk.now, peerKey(id), false, netip.AddrPort{}); err != nil {
			t.Fatal(err)
		}
		n.control(id, sub)
		for range 2 {
			raw := pp.sign(t, seq, n.clk.now, "x")
			seq++
			n.message(id, raw)
			n.message(1, raw)
		}
		// The leaving key pays for all its leave does, the author check's part included.
		n.r.AuditPeer(peerKey(id))
		n.r.RemovePeer(n.clk.now, peerKey(id))
		done, charged := n.r.Audit()
		for op, c := range done {
			if charged[op] < c {
				t.Fatalf("key %d left: op %d done %d times, charged %d", k, op, c, charged[op])
			}
		}
	}
	if w, v := n.res.Stats().Waiting, n.r.Stats().Validating; w > v {
		t.Fatalf("the Resolver holds %d waiting messages, the router %d", w, v)
	}
	if err := n.r.AddPeer(n.clk.now, peerKey(99), false, netip.AddrPort{}); err != nil {
		t.Fatal(err)
	}
	n.control(99, sub)
	before := n.res.Stats().Throttled
	n.message(99, q.sign(t, 1, n.clk.now, "honest"))
	if n.res.Stats().Throttled != before {
		t.Fatal("a new author's message was refused")
	}
}
