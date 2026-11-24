package auth

import (
	"bytes"
	"testing"
	"time"

	"github.com/ciranda-dev/kolo-gossip/internal/wire"
	koloid "github.com/ciranda-dev/kolo-id"
)

// openNode is a node in open mode that accepts the given persons and knows no roster.
func openNode(t *testing.T, peers int, ps ...*person) *node {
	return newNode(t, nil, newOpener(ps...).open, peers, nil, nil)
}

func wantFor(p *person) wire.CertWant {
	return wire.CertWant{Person: wire.Key(p.pub()), Device: wire.Key(p.device.PublicKey())}
}

// TestCertAfterMessage: in open mode a message of an unknown chain waits, one CERTWANT goes to the forwarder,
// and its verified answer releases the message to the validator and caches the chain.
func TestCertAfterMessage(t *testing.T) {
	q := newPerson(t, 20)
	n := openNode(t, 1, q)
	raw := q.sign(t, 1, t0, "x")
	n.message(1, raw)
	if got := n.sink.certWants(peerKey(1)); len(got) != 1 || got[0] != wantFor(q) {
		t.Fatalf("CERTWANT %v", got)
	}
	if n.validated(raw) || n.res.Stats().Waiting != 1 || n.r.Stats().Validating != 1 {
		t.Fatal("the message must wait within the validation bound")
	}
	n.advance(time.Second)
	n.control(1, &wire.Control{Cert: [][]byte{q.deviceCert.Encode()}})
	if !n.validated(raw) {
		t.Fatal("the message was not released after the chain arrived")
	}
	s := n.res.Stats()
	if s.Answered != 1 || s.CacheChains != 1 || s.Waiting != 0 || s.Outstanding != 0 {
		t.Fatalf("stats %+v", s)
	}
	// The next message of that device verifies from the cache, with no request.
	raw2 := q.sign(t, 2, n.clk.now, "y")
	n.message(1, raw2)
	if !n.validated(raw2) || len(n.sink.certWants(peerKey(1))) != 1 {
		t.Fatal("a cached chain must verify without a request")
	}
}

// TestCertSharedRequest: several messages of one author wait on one request per forwarder; a valid answer from
// one forwarder releases all of them and cancels the other request without a penalty.
func TestCertSharedRequest(t *testing.T) {
	q := newPerson(t, 20)
	n := openNode(t, 2, q)
	a, b, c := q.sign(t, 1, t0, "a"), q.sign(t, 2, t0, "b"), q.sign(t, 3, t0, "c")
	n.message(1, a)
	n.message(1, b)
	n.message(2, c)
	if len(n.sink.certWants(peerKey(1))) != 1 || len(n.sink.certWants(peerKey(2))) != 1 {
		t.Fatal("one request per forwarder and author")
	}
	n.control(2, &wire.Control{Cert: [][]byte{q.deviceCert.Encode()}})
	if !n.validated(a) || !n.validated(b) || !n.validated(c) {
		t.Fatal("one answer must release every waiting message of the author")
	}
	n.advance(10 * time.Second)
	n.heartbeat()
	if n.r.Stats().CertBroken != 0 || n.res.Stats().Timeouts != 0 {
		t.Fatal("the cancelled request was treated as broken")
	}
	// A late answer from the first forwarder is unsolicited.
	n.control(1, &wire.Control{Cert: [][]byte{q.deviceCert.Encode()}})
	if n.res.Stats().Unsolicited != 1 {
		t.Fatalf("late answer: %+v", n.res.Stats())
	}
}

// TestCertTimeout: an unanswered request waits exactly CertTimeout, then the message is ignored and the
// forwarder gets one behaviour penalty for the request, not one per message.
func TestCertTimeout(t *testing.T) {
	q := newPerson(t, 20)
	n := openNode(t, 1, q)
	a, b := q.sign(t, 1, t0, "a"), q.sign(t, 2, t0, "b")
	n.message(1, a)
	n.message(1, b)
	n.res.Expire(t0.Add(3 * time.Second))
	if n.res.Stats().Waiting != 2 {
		t.Fatal("a request expired at its deadline")
	}
	n.advance(3*time.Second + time.Nanosecond)
	n.heartbeat()
	s := n.r.Stats()
	if s.CertBroken != 1 || s.UnknownAuthor != 2 || n.validated(a) || n.validated(b) || s.Validating != 0 {
		t.Fatalf("after the timeout: %+v", s)
	}
	if rs := n.res.Stats(); rs.Timeouts != 1 || rs.Waiting != 0 || rs.Outstanding != 0 {
		t.Fatalf("resolver %+v", rs)
	}
}

// TestCertUnsolicited: a CERT without an outstanding request from that peer is dropped undecoded and cached
// never, also when another peer was asked.
func TestCertUnsolicited(t *testing.T) {
	q := newPerson(t, 20)
	n := openNode(t, 2, q)
	n.control(1, &wire.Control{Cert: [][]byte{q.deviceCert.Encode(), {1, 2}}})
	if s := n.res.Stats(); s.Unsolicited != 2 || s.CacheChains != 0 || s.Answered != 0 {
		t.Fatalf("unsolicited: %+v", s)
	}
	raw := q.sign(t, 1, t0, "")
	n.message(1, raw)
	n.control(2, &wire.Control{Cert: [][]byte{q.deviceCert.Encode()}})
	if s := n.res.Stats(); s.Unsolicited != 3 || s.CacheChains != 0 || n.validated(raw) {
		t.Fatalf("answer from a peer not asked: %+v", s)
	}
	// An answer for another author than asked is unsolicited too.
	other := newPerson(t, 30)
	n.control(1, &wire.Control{Cert: [][]byte{other.deviceCert.Encode()}})
	if s := n.res.Stats(); s.Unsolicited != 4 || s.Waiting != 1 {
		t.Fatalf("answer for another author: %+v", s)
	}
}

// TestCertBadChain: an answer that matches the request but does not chain to the claimed person or has a bad
// signature breaks the request at once: the messages are ignored, the peer penalised, nothing cached. An expired
// chain ends the request without penalty.
func TestCertBadChain(t *testing.T) {
	q, b := newPerson(t, 20), newPerson(t, 30)
	// b's root-issued certificate of q's device with b's key replaced by q's: it decodes as q's, b signed it.
	forged := bytes.ReplaceAll(certify(t, b.key, q.device, &koloid.IssueOptions{Serial: 1, IssuedAt: issued}).Encode(), b.pub(), q.pub())
	expired := certify(t, q.key, q.device, &koloid.IssueOptions{Serial: 3, IssuedAt: issued, ExpiresAt: t0.Add(-time.Second)}).Encode()
	badSig := q.deviceCert.Encode()
	parent := len(q.approverCert.Encode())
	badSig[len(badSig)-parent-1-wire.UvarintLen(uint64(parent))-10] ^= 1 // inside the device signature
	if _, err := koloid.DecodeDeviceCert(forged); err != nil {
		t.Fatal(err)
	}
	if _, err := koloid.DecodeDeviceCert(badSig); err != nil {
		t.Fatal(err)
	}
	for name, cert := range map[string][]byte{"other person": forged, "expired": expired, "bad signature": badSig} {
		n := openNode(t, 1, q)
		raw := q.sign(t, 1, t0, "")
		n.message(1, raw)
		n.control(1, &wire.Control{Cert: [][]byte{cert}})
		s, rs := n.r.Stats(), n.res.Stats()
		broken := name != "expired" // an expired chain may be all a forwarder knows: no penalty
		if (s.CertBroken == 1) != broken || s.UnknownAuthor != 1 || n.validated(raw) || (rs.BadChains == 1) != broken ||
			(rs.Revoked == 1) == broken || rs.CacheChains != 0 || rs.Waiting != 0 {
			t.Errorf("%s: router %+v, resolver %+v", name, s, rs)
		}
	}
}

// TestCertOtherPersonFromForwarder: a forwarder that answers with a genuine chain of another person gets no
// match: the message is never verified against it and the request breaks at its deadline.
func TestCertOtherPersonFromForwarder(t *testing.T) {
	q, b := newPerson(t, 20), newPerson(t, 30)
	other := certify(t, b.key, q.device, &koloid.IssueOptions{Serial: 1, IssuedAt: issued}).Encode()
	n := openNode(t, 1, q, b)
	raw := q.sign(t, 1, t0, "")
	n.message(1, raw)
	n.control(1, &wire.Control{Cert: [][]byte{other}})
	if n.validated(raw) || n.res.Stats().CacheChains != 0 || n.res.Stats().Unsolicited != 1 {
		t.Fatal("a chain of another person was used")
	}
	n.advance(4 * time.Second)
	n.heartbeat()
	if n.r.Stats().CertBroken != 1 || n.validated(raw) {
		t.Fatal("the request must break at its deadline")
	}
}

// TestCertRevokedAnswer: a genuine chain the application's revocations void ends that request: the message is
// ignored, nobody is penalised and the chain is not cached.
func TestCertRevokedAnswer(t *testing.T) {
	q := newPerson(t, 20)
	rev, err := q.device.RevokeDevice(&koloid.RevokeOptions{Person: q.pub(), Device: q.device.PublicKey(), UpToSerial: 1, At: t0})
	if err != nil {
		t.Fatal(err)
	}
	op := newOpener(q)
	op.ok[[32]byte(q.pub())] = []*koloid.Revocation{rev}
	n := newNode(t, nil, op.open, 1, nil, nil)
	raw := q.sign(t, 1, t0, "")
	n.message(1, raw)
	n.control(1, &wire.Control{Cert: [][]byte{q.deviceCert.Encode()}})
	if s := n.r.Stats(); s.BadSignature != 0 || s.UnknownAuthor != 1 || s.CertBroken != 0 || n.validated(raw) ||
		n.res.Stats().Revoked != 1 || n.res.Stats().CacheChains != 0 || n.r.Score(peerKey(1)) != 0 {
		t.Fatalf("revoked author: %+v", s)
	}
	// The person refused by the time the chain arrives: ignored.
	n = openNode(t, 1, q)
	raw = q.sign(t, 2, t0, "")
	n.message(1, raw)
	n.res.cfg.Open = newOpener().open
	n.control(1, &wire.Control{Cert: [][]byte{q.deviceCert.Encode()}})
	if s := n.r.Stats(); s.UnknownAuthor != 1 || n.validated(raw) {
		t.Fatalf("person refused later: %+v", s)
	}
}

// TestCertFlood: each request we sent a peer lets one CERT entry be read; the rest of a flood is not decoded,
// and a junk entry uses up the request's place.
func TestCertFlood(t *testing.T) {
	q := newPerson(t, 20)
	n := openNode(t, 2, q)
	raw := q.sign(t, 1, t0, "")
	n.message(1, raw)
	flood := make([][]byte, 1000)
	for i := range flood {
		flood[i] = q.deviceCert.Encode()
	}
	flood[0] = []byte{9}
	n.control(1, &wire.Control{Cert: flood})
	if s := n.res.Stats(); s.Unsolicited != 1000 || s.Answered != 0 {
		t.Fatalf("flood: %+v", s)
	}
	n.control(1, &wire.Control{Cert: flood[1:3]})
	if s := n.res.Stats(); s.Answered != 0 || s.Unsolicited != 1002 {
		t.Fatalf("an entry read past the requests sent: %+v", s)
	}
	// The peer that sent a copy meanwhile is asked a heartbeat later, as the first request stays unanswered.
	n.message(2, raw)
	n.advance(time.Second)
	n.heartbeat()
	if len(n.sink.certWants(peerKey(2))) != 1 {
		t.Fatal("no hedged request to the next peer")
	}
	n.control(2, &wire.Control{Cert: flood[1:2]})
	if !n.validated(raw) {
		t.Fatal("the next peer's chain did not release the message")
	}
}

// TestCertWantBounds: at most MaxCertAnswers requests go to one peer per heartbeat and MaxWaiting messages wait;
// beyond either this copy is dropped without a request.
func TestCertWantBounds(t *testing.T) {
	var ps []*person
	for i := range 4 {
		ps = append(ps, newPerson(t, byte(20+10*i)))
	}
	n := newNode(t, nil, newOpener(ps...).open, 2, func(c *Config) { c.MaxCertWants, c.MaxCertAnswers, c.MaxWaiting = 4, 2, 3 }, nil)
	for i, p := range ps[:3] {
		n.message(1, p.sign(t, uint64(i), t0, ""))
	}
	if got := len(n.sink.certWants(peerKey(1))); got != 2 || n.r.Stats().UnknownAuthor != 1 || n.res.Stats().Throttled != 1 {
		t.Fatalf("per-peer bound: %d requests, %+v", got, n.r.Stats())
	}
	n.message(2, ps[2].sign(t, 9, t0, ""))
	n.message(2, ps[3].sign(t, 9, t0, ""))
	if s := n.res.Stats(); s.Waiting != 3 || s.Throttled != 2 || len(n.sink.certWants(peerKey(2))) != 1 {
		t.Fatalf("waiting bound: %+v", s)
	}
}

// TestCertWantAnswers: up to MaxCertWants CERTWANT entries per peer per heartbeat get an answer, a verified
// chain or the person and device that say none is held; entries past it get none, and the bound starts again
// each heartbeat.
func TestCertWantAnswers(t *testing.T) {
	p, q := newPerson(t, 10), newPerson(t, 20)
	n := newNode(t, newRoster(p), nil, 2, func(c *Config) { c.MaxCertAnswers, c.MaxCertWants = 1, 3 }, nil)
	marker := func(x *person) []byte { k := keyOf(x.pub(), x.device.PublicKey()); return k[:] }
	n.control(1, &wire.Control{CertWant: []wire.CertWant{wantFor(p)}})
	if got := n.sink.certs(peerKey(1)); len(got) != 1 || !bytes.Equal(got[0], marker(p)) {
		t.Fatal("a chain not verified yet must be answered as not held")
	}
	n.message(2, p.sign(t, 1, t0, ""))
	ws := []wire.CertWant{wantFor(q), wantFor(p), wantFor(p), wantFor(p)}
	n.control(1, &wire.Control{CertWant: ws})
	got := n.sink.certs(peerKey(1))[1:]
	if len(got) != 2 || !bytes.Equal(got[0], marker(q)) || !bytes.Equal(got[1], p.deviceCert.Encode()) {
		t.Fatalf("answers %d: MaxCertWants entries in the heartbeat, none past it", len(got))
	}
	n.advance(time.Second)
	n.heartbeat()
	n.control(1, &wire.Control{CertWant: ws[1:2]})
	if got := n.sink.certs(peerKey(1)); !bytes.Equal(got[len(got)-1], p.deviceCert.Encode()) || n.res.Stats().Served != 2 {
		t.Fatal("the bound did not start again")
	}
}

// TestCertCheckedAtRouterTime: a fetched chain is checked at the router's time, not the wall clock's.
func TestCertCheckedAtRouterTime(t *testing.T) {
	q := newPerson(t, 20)
	cert := certify(t, q.approver, q.device, &koloid.IssueOptions{Parent: q.approverCert, Serial: 2, IssuedAt: issued, ExpiresAt: t0.Add(time.Hour)})
	n := openNode(t, 1, q)
	raw := q.sign(t, 1, t0, "")
	n.message(1, raw)
	n.control(1, &wire.Control{Cert: [][]byte{cert.Encode()}})
	if !n.validated(raw) || n.r.Stats().CertBroken != 0 {
		t.Fatalf("chain valid at the router's time refused: %+v", n.res.Stats())
	}
}

// TestCertWantSlotReturned: an answered or broken request frees its place in the per-peer bound; at most
// MaxCertAnswers requests go to one peer per heartbeat.
func TestCertWantSlotReturned(t *testing.T) {
	q, b := newPerson(t, 20), newPerson(t, 30)
	n := newNode(t, nil, newOpener(q, b).open, 1, func(c *Config) { c.MaxCertWants, c.MaxCertAnswers = 2, 1 }, nil)
	n.message(1, q.sign(t, 1, t0, ""))
	n.control(1, &wire.Control{Cert: [][]byte{q.deviceCert.Encode()}})
	n.advance(time.Second)
	n.heartbeat()
	raw := b.sign(t, 1, t0, "")
	n.message(1, raw)
	if got := n.sink.certWants(peerKey(1)); len(got) != 2 || got[1] != wantFor(b) {
		t.Fatalf("requests %v", got)
	}
	n.advance(4 * time.Second)
	n.heartbeat()
	n.message(1, b.sign(t, 2, n.clk.now, ""))
	if n.res.Stats().Throttled != 0 || len(n.sink.certWants(peerKey(1))) != 3 {
		t.Fatalf("a broken request kept its place: %+v", n.res.Stats())
	}
}

// TestCertAnswerFromOtherRequester: a peer with its own outstanding request cannot answer one sent to another peer.
func TestCertAnswerFromOtherRequester(t *testing.T) {
	q, b := newPerson(t, 20), newPerson(t, 30)
	n := openNode(t, 2, q, b)
	raw := q.sign(t, 1, t0, "")
	n.message(1, raw)
	n.message(2, b.sign(t, 1, t0, ""))
	n.control(2, &wire.Control{Cert: [][]byte{q.deviceCert.Encode()}})
	if s := n.res.Stats(); n.validated(raw) || s.Unsolicited != 1 || s.Answered != 0 || s.Outstanding != 2 {
		t.Fatalf("answer for a request to another peer: %+v", s)
	}
}

// TestOwnChainServed: the node's own chain answers CERTWANT before any message verified it, and survives a cache
// too small to keep it next to another chain.
func TestOwnChainServed(t *testing.T) {
	p, q := newPerson(t, 10), newPerson(t, 20)
	n := newNode(t, newRoster(q), nil, 2, func(c *Config) { c.CertCacheBytes = wire.MaxCertSize + entryOverhead }, nil)
	n.res.Own(p.deviceCert)
	n.message(2, q.sign(t, 1, t0, ""))
	n.control(1, &wire.Control{CertWant: []wire.CertWant{wantFor(p), wantFor(q)}})
	got := n.sink.certs(peerKey(1))
	if len(got) != 2 || !bytes.Equal(got[0], p.deviceCert.Encode()) || !bytes.Equal(got[1], q.deviceCert.Encode()) {
		t.Fatalf("answers %d", len(got))
	}
}
