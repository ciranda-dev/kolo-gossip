package auth

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/ciranda-dev/kolo-gossip/internal/core"
	"github.com/ciranda-dev/kolo-gossip/internal/wire"
	koloid "github.com/ciranda-dev/kolo-id"
)

// TestSign: the envelope carries every envelope field and its signature is Ed25519ctx by the device under
// kolo-gossip/message/v0 over the Signed bytes, valid under no other context.
func TestSign(t *testing.T) {
	p := newPerson(t, 10)
	raw := p.sign(t, 7, t0, "hello")
	env, signed := decode(t, raw)
	if env.Topic != topic || !bytes.Equal(env.Person[:], p.pub()) || !bytes.Equal(env.Device[:], p.device.PublicKey()) ||
		env.Seq != 7 || env.Time != uint64(t0.UnixMilli()) || string(env.Body) != "hello" {
		t.Fatalf("envelope %+v", env)
	}
	if !bytes.Equal(signed, env.Signed()) {
		t.Fatal("signed bytes are not the envelope without its signature")
	}
	if !koloid.Verify(p.device.PublicKey(), "kolo-gossip/message/v0", signed, env.Sig[:]) {
		t.Fatal("signature does not verify under the message context")
	}
	for _, ctx := range []string{"kolo-gossip/message/v1", "kolo-swarm/hello/v0", "x"} {
		if koloid.Verify(p.device.PublicKey(), ctx, signed, env.Sig[:]) {
			t.Fatalf("signature verifies under %q", ctx)
		}
	}
	if err := koloid.VerifyDevice(p.deviceCert, &koloid.VerifyOptions{Person: p.pub(), Now: t0}, Context, signed, env.Sig[:]); err != nil {
		t.Fatal(err)
	}
}

func TestSignArguments(t *testing.T) {
	p := newPerson(t, 10)
	cases := []struct {
		name   string
		dev    *koloid.Identity
		person []byte
		at     time.Time
	}{
		{"nil identity", nil, p.pub(), t0},
		{"short person", p.device, p.pub()[:31], t0},
		{"long person", p.device, append(p.pub(), 0), t0},
		{"before 1970", p.device, p.pub(), time.Unix(-1, 0)},
		{"one millisecond before 1970", p.device, p.pub(), time.UnixMilli(-1)},
		{"cleared identity", func() *koloid.Identity { d := ident(t, 99); d.Clear(); return d }(), p.pub(), t0},
	}
	for _, c := range cases {
		if _, err := Sign(c.dev, c.person, topic, 1, c.at, nil); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("%s: error %v", c.name, err)
		}
	}
	if _, err := Sign(p.device, p.pub(), topic, 1, time.Unix(0, 0), nil); err != nil {
		t.Fatalf("the epoch itself: %v", err)
	}
}

// TestVerifyClosed: in closed mode the roster's chain decides; approver and approver-issued devices both verify.
func TestVerifyClosed(t *testing.T) {
	p := newPerson(t, 10)
	ros := newRoster(p)
	r := newResolver(t, &clock{t0}, ros, nil, nil)
	env, signed := decode(t, p.sign(t, 1, t0, "a"))
	if err := r.Verify(env, signed); err != nil {
		t.Fatal(err)
	}
	raw, err := Sign(p.approver, p.pub(), topic, 2, t0, nil)
	if err != nil {
		t.Fatal(err)
	}
	env, signed = decode(t, raw)
	if err := r.Verify(env, signed); err != nil {
		t.Fatalf("approver device: %v", err)
	}
	if s := r.Stats(); s.CacheChains != 2 {
		t.Fatalf("roster chains cached for CERTWANT: %d, want 2", s.CacheChains)
	}
}

// TestVerifyForged: a changed signature, body, seq, time or topic never passes Signed, nor a signature by another
// device.
func TestVerifyForged(t *testing.T) {
	p := newPerson(t, 10)
	r := newResolver(t, &clock{t0}, newRoster(p), nil, nil)
	raw := p.sign(t, 1, t0, "body")
	env, _ := decode(t, raw)
	mutate := []func(e *wire.Envelope){
		func(e *wire.Envelope) { e.Sig[0] ^= 1 },
		func(e *wire.Envelope) { e.Sig[63] ^= 0x80 },
		func(e *wire.Envelope) { e.Body = []byte("bodY") },
		func(e *wire.Envelope) { e.Seq++ },
		func(e *wire.Envelope) { e.Time++ },
		func(e *wire.Envelope) { e.Topic[5] ^= 1 },
	}
	for i, m := range mutate {
		e := *env
		e.Body = bytes.Clone(env.Body)
		m(&e)
		if r.Signed(&e, e.Signed()) {
			t.Errorf("mutation %d signed", i)
		}
	}
	other := newPerson(t, 20)
	forged := *env
	sig, err := other.device.Sign(Context, forged.Signed())
	if err != nil {
		t.Fatal(err)
	}
	copy(forged.Sig[:], sig)
	if Signed(&forged, forged.Signed()) || !Signed(env, env.Signed()) {
		t.Fatal("signed by another device")
	}
}

// TestVerifyWrongPerson: the person the roster expects is the trust anchor; a roster answer for another person
// than the envelope's, or a chain of another person, never verifies and costs no penalty.
func TestVerifyWrongPerson(t *testing.T) {
	a, b := newPerson(t, 10), newPerson(t, 20)
	ros := newRoster()
	// A careless roster that answers by device only: a's device, claimed by b.
	ros.add(b.pub(), a.device.PublicKey(), a.author())
	r := newResolver(t, &clock{t0}, ros, nil, nil)
	raw, err := Sign(a.device, b.pub(), topic, 1, t0, nil)
	if err != nil {
		t.Fatal(err)
	}
	env, signed := decode(t, raw)
	if err := r.Verify(env, signed); !errors.Is(err, ErrUnknownAuthor) {
		t.Fatalf("roster expects a, envelope claims b: %v", err)
	}
	// The roster names b but hands a's chain.
	ros.add(b.pub(), a.device.PublicKey(), &Author{Person: b.pub(), Cert: a.deviceCert})
	if err := r.Verify(env, signed); !errors.Is(err, koloid.ErrCertPerson) {
		t.Fatalf("chain of a for b: %v", err)
	}
	if r.Stats().CacheChains != 0 {
		t.Fatal("a refused chain was cached")
	}
}

// TestVerifyWrongDevice: the chain must certify the envelope's device (else the author is unknown), and the
// signature must be that device's (else Signed fails).
func TestVerifyWrongDevice(t *testing.T) {
	p := newPerson(t, 10)
	ros := newRoster()
	ros.add(p.pub(), p.device.PublicKey(), &Author{Person: p.pub(), Cert: p.approverCert})
	r := newResolver(t, &clock{t0}, ros, nil, nil)
	env, signed := decode(t, p.sign(t, 1, t0, ""))
	if err := r.Verify(env, signed); !errors.Is(err, ErrUnknownAuthor) {
		t.Fatalf("chain of the approver for the device's message: %v", err)
	}
	// A roster that hands the approver's chain for the device: the approver signs, naming the device.
	e := &wire.Envelope{Topic: topic, Person: wire.Key(p.pub()), Device: wire.Key(p.device.PublicKey()), Seq: 1, Time: uint64(t0.UnixMilli())}
	sig, err := p.approver.Sign(Context, e.Signed())
	if err != nil {
		t.Fatal(err)
	}
	copy(e.Sig[:], sig)
	if r.Signed(e, e.Signed()) {
		t.Fatal("approver signing as the device")
	}
	// The envelope names the approver device but the ordinary device signed it.
	ros = newRoster(p)
	r = newResolver(t, &clock{t0}, ros, nil, nil)
	e2 := *env
	copy(e2.Device[:], p.approver.PublicKey())
	if r.Signed(&e2, e2.Signed()) {
		t.Fatal("signature by another device")
	}
}

// TestVerifyRevoked: a revocation the application accepts voids the device and evicts its cached chain.
func TestVerifyRevoked(t *testing.T) {
	p := newPerson(t, 10)
	rev, err := p.key.RevokeDevice(&koloid.RevokeOptions{Person: p.pub(), Device: p.device.PublicKey(), UpToSerial: 1, At: t0})
	if err != nil {
		t.Fatal(err)
	}
	if err := rev.Verify(&koloid.VerifyOptions{Person: p.pub(), Now: t0}, p.deviceCert); err != nil {
		t.Fatal(err)
	}
	ros := newRoster(p)
	r := newResolver(t, &clock{t0}, ros, nil, nil)
	env, signed := decode(t, p.sign(t, 1, t0, ""))
	if err := r.Verify(env, signed); err != nil {
		t.Fatal(err)
	}
	ros.add(p.pub(), p.device.PublicKey(), &Author{Person: p.pub(), Cert: p.deviceCert, Revocations: []*koloid.Revocation{rev}})
	if err := r.Verify(env, signed); !errors.Is(err, koloid.ErrCertRevoked) || !errors.Is(err, ErrVerify) {
		t.Fatalf("revoked: %v", err)
	}
	if r.cache.get(keyOf(p.pub(), p.device.PublicKey())) != nil {
		t.Fatal("revoked chain still cached")
	}
	// Revoking the approver voids the device it certified too.
	revA, err := p.key.RevokeDevice(&koloid.RevokeOptions{Person: p.pub(), Device: p.approver.PublicKey(), UpToSerial: 1, At: t0})
	if err != nil {
		t.Fatal(err)
	}
	ros.add(p.pub(), p.device.PublicKey(), &Author{Person: p.pub(), Cert: p.deviceCert, Revocations: []*koloid.Revocation{revA}})
	if err := r.Verify(env, signed); !errors.Is(err, koloid.ErrCertRevoked) {
		t.Fatalf("approver revoked: %v", err)
	}
}

// TestVerifyExpired: a chain is valid until the second before its expiry.
func TestVerifyExpired(t *testing.T) {
	p := newPerson(t, 10)
	exp := t0.Add(time.Hour)
	cert := certify(t, p.approver, p.device, &koloid.IssueOptions{Parent: p.approverCert, Serial: 2, IssuedAt: issued, ExpiresAt: exp})
	ros := newRoster()
	ros.add(p.pub(), p.device.PublicKey(), &Author{Person: p.pub(), Cert: cert})
	c := &clock{exp.Add(-time.Second)}
	r := newResolver(t, c, ros, nil, nil)
	env, signed := decode(t, p.sign(t, 1, t0, ""))
	if err := r.Verify(env, signed); err != nil {
		t.Fatalf("before expiry: %v", err)
	}
	c.now = exp
	if err := r.Verify(env, signed); !errors.Is(err, koloid.ErrCertExpired) {
		t.Fatalf("at expiry: %v", err)
	}
}

// TestVerifyUnknownClosed: in closed mode an author the roster does not know is ignored, never fetched.
func TestVerifyUnknownClosed(t *testing.T) {
	p, q := newPerson(t, 10), newPerson(t, 20)
	ros := newRoster(p)
	r := newResolver(t, &clock{t0}, ros, nil, nil)
	env, signed := decode(t, q.sign(t, 1, t0, ""))
	err := r.Verify(env, signed)
	if !errors.Is(err, ErrUnknownAuthor) || errors.Is(err, ErrUnresolved) {
		t.Fatalf("unknown author: %v", err)
	}
	appErr := errors.New("roster offline")
	ros.err = appErr
	if err := r.Verify(env, signed); !errors.Is(err, ErrUnknownAuthor) || !errors.Is(err, appErr) {
		t.Fatalf("roster error: %v", err)
	}
	ros.err = nil
	ros.add(q.pub(), q.device.PublicKey(), &Author{Person: q.pub()})
	if err := r.Verify(env, signed); !errors.Is(err, ErrUnknownAuthor) {
		t.Fatalf("roster answer without a chain: %v", err)
	}
	n := newNode(t, ros, nil, 1, nil, nil)
	n.message(1, q.sign(t, 2, t0, ""))
	if len(n.sink.certWants(peerKey(1))) != 0 || n.r.Stats().UnknownAuthor != 1 || len(n.sink.validate) != 0 {
		t.Fatalf("closed mode fetched or validated: %+v", n.r.Stats())
	}
}

// TestVerifyOpen: open mode asks the callback about the person, uses a cached chain and verifies it with the
// callback's revocations; the roster still answers first.
func TestVerifyOpen(t *testing.T) {
	p, q := newPerson(t, 10), newPerson(t, 20)
	op := newOpener(q)
	ros := newRoster(p)
	r := newResolver(t, &clock{t0}, ros, op.open, nil)
	env, signed := decode(t, p.sign(t, 1, t0, ""))
	if err := r.Verify(env, signed); err != nil || op.calls != 0 {
		t.Fatalf("roster author in open mode: %v, %d callback calls", err, op.calls)
	}
	env, signed = decode(t, q.sign(t, 1, t0, ""))
	if err := r.Verify(env, signed); !errors.Is(err, ErrUnresolved) {
		t.Fatalf("open mode, nothing cached: %v", err)
	}
	r.cache.put(keyOf(q.pub(), q.device.PublicKey()), q.deviceCert, q.deviceCert.Encode())
	if err := r.Verify(env, signed); err != nil {
		t.Fatalf("cached chain: %v", err)
	}
	rev, err := q.approver.RevokeDevice(&koloid.RevokeOptions{Person: q.pub(), Device: q.device.PublicKey(), SignerCert: q.approverCert, Target: q.deviceCert, At: t0})
	if err != nil {
		t.Fatal(err)
	}
	op.ok[[32]byte(q.pub())] = []*koloid.Revocation{rev}
	if err := r.Verify(env, signed); !errors.Is(err, koloid.ErrCertRevoked) {
		t.Fatalf("revocation from the callback: %v", err)
	}
	if r.Stats().CacheChains != 1 {
		t.Fatal("revoked chain still cached")
	}
	delete(op.ok, [32]byte(q.pub()))
	r.cache.put(keyOf(q.pub(), q.device.PublicKey()), q.deviceCert, q.deviceCert.Encode())
	if err := r.Verify(env, signed); !errors.Is(err, ErrUnknownAuthor) {
		t.Fatalf("person refused by the callback: %v", err)
	}
	// Open mode without a roster.
	r = newResolver(t, &clock{t0}, nil, newOpener(q).open, nil)
	if err := r.Verify(env, signed); !errors.Is(err, ErrUnresolved) {
		t.Fatalf("open mode without roster: %v", err)
	}
}

// TestEquivocation: two bodies under one sequence number both verify and get two ids.
func TestEquivocation(t *testing.T) {
	p := newPerson(t, 10)
	n := newNode(t, newRoster(p), nil, 1, nil, nil)
	a, b := p.sign(t, 5, t0, "a"), p.sign(t, 5, t0, "b")
	n.message(1, a)
	n.message(1, b)
	if !n.validated(a) || !n.validated(b) || wire.NewID(a) == wire.NewID(b) {
		t.Fatal("both bodies must reach the validator with their own ids")
	}
}

// TestReplayWindow: a message older than MaxAge or further ahead than MaxSkew is ignored before the roster or
// any signature is consulted; the exact edges are inside; a copy inside the window is the core's duplicate.
func TestReplayWindow(t *testing.T) {
	p := newPerson(t, 10)
	ros := newRoster(p)
	n := newNode(t, ros, nil, 1, nil, nil)
	cfg := core.DefaultConfig()
	for i, at := range []time.Time{t0.Add(-cfg.MaxAge - time.Millisecond), t0.Add(cfg.MaxSkew + time.Millisecond)} {
		n.message(1, p.sign(t, uint64(i), at, ""))
	}
	if ros.lookups != 0 || n.r.Stats().OutOfWindow != 2 {
		t.Fatalf("out-of-window messages reached the roster: %d lookups, %+v", ros.lookups, n.r.Stats())
	}
	old, ahead := p.sign(t, 10, t0.Add(-cfg.MaxAge), ""), p.sign(t, 11, t0.Add(cfg.MaxSkew), "")
	n.message(1, old)
	n.message(1, ahead)
	if !n.validated(old) || !n.validated(ahead) {
		t.Fatal("messages at the window edges must verify")
	}
	n.r.ValidationDone(n.clk.now, wire.NewID(old), n.sink.inst[wire.NewID(old)], core.Accept)
	n.r.ValidationDone(n.clk.now, wire.NewID(ahead), n.sink.inst[wire.NewID(ahead)], core.Accept)
	lookups := ros.lookups
	n.message(1, old)
	if ros.lookups != lookups || n.r.Stats().Duplicates != 1 {
		t.Fatal("a copy inside the window must be dropped as a duplicate before any check")
	}
	// After the seen entry expires, at most two heartbeat intervals after SeenTTL, the replay is out of the window.
	n.advance(cfg.SeenTTL + 2*cfg.HeartbeatInterval + time.Millisecond)
	n.message(1, old)
	if ros.lookups != lookups || n.r.Stats().OutOfWindow != 3 {
		t.Fatalf("replay after expiry: %+v", n.r.Stats())
	}
}

// TestRosterAnswerWithoutPerson: a roster answer naming no person, or without a chain, is an unknown author; it
// does not fall through to open mode.
func TestRosterAnswerWithoutPerson(t *testing.T) {
	p := newPerson(t, 10)
	ros := newRoster()
	ros.add(p.pub(), p.device.PublicKey(), &Author{Cert: p.deviceCert})
	op := newOpener(p)
	r := newResolver(t, &clock{t0}, ros, op.open, nil)
	env, signed := decode(t, p.sign(t, 1, t0, ""))
	if err := r.Verify(env, signed); !errors.Is(err, ErrUnknownAuthor) {
		t.Fatalf("no expected person: %v", err)
	}
	ros.add(p.pub(), p.device.PublicKey(), &Author{Person: p.pub()})
	if err := r.Verify(env, signed); !errors.Is(err, ErrUnknownAuthor) || op.calls != 0 {
		t.Fatalf("no chain: %v, open asked %d times", err, op.calls)
	}
}

func TestConfig(t *testing.T) {
	ros := newRoster()
	bad := []func(*Config){
		func(c *Config) { c.Authors = nil },
		func(c *Config) { c.CertCacheBytes = wire.MaxCertSize + entryOverhead - 1 },
		func(c *Config) { c.CertTimeout = 0 },
		func(c *Config) { c.MaxCertWants = 0 },
		func(c *Config) { c.MaxCertAnswers = 0 },
		func(c *Config) { c.MaxWaiting = 0 },
	}
	for i, f := range bad {
		cfg := DefaultConfig()
		cfg.Authors = ros
		f(cfg)
		if _, err := New(cfg); !errors.Is(err, core.ErrInvalidConfig) {
			t.Errorf("case %d: error %v", i, err)
		}
	}
	if _, err := New(nil); !errors.Is(err, core.ErrInvalidConfig) {
		t.Fatalf("nil config: %v", err)
	}
	cfg := DefaultConfig()
	cfg.Authors, cfg.CertCacheBytes = ros, wire.MaxCertSize+entryOverhead
	r, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if r.cfg.Now == nil {
		t.Fatal("Now not defaulted")
	}
	d := DefaultConfig()
	if d.CertCacheBytes != 1<<20 || d.CertTimeout != 3*time.Second || d.MaxCertWants != 10 || d.MaxCertAnswers != 5 || d.MaxWaiting != 1024 || d.MaxChains != 4096 {
		t.Fatalf("defaults %+v", d)
	}
}
