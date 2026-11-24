package core

import (
	"errors"
	"math/rand/v2"
	"testing"
	"time"

	"github.com/ciranda-dev/kolo-gossip/internal/wire"
)

// Signature markers the stub resolver reads.
const (
	unresolvedSig = 0x55
	unknownSig    = 0x66
)

type resolveCall struct {
	id   wire.ID
	from PeerID
	now  time.Time
}

// stubResolver is a Verifier and Resolver whose answers the test sets.
type stubResolver struct {
	resolves   []resolveCall
	want       *wire.CertWant
	err        error
	certWants  [][]wire.CertWant
	answers    [][]byte
	certs      [][]byte
	next       Resolutions
	expires    []time.Time
	dropped    []wire.CertWant
	left       []wire.Topic
	forgot     []wire.ID
	gone       []PeerID
	ended      Resolutions
	work       Ops
	budget     int64 // what the last Cert call could spend
	expireWork Ops   // work Expire reports
}

func (s *stubResolver) Signed(env *wire.Envelope, signed []byte) bool { return env.Sig[0] != badSig }

func (s *stubResolver) Verify(env *wire.Envelope, signed []byte) error {
	switch env.Sig[0] {
	case unresolvedSig:
		return ErrUnresolved
	case unknownSig:
		return ErrUnknownAuthor
	}
	return nil
}

func (s *stubResolver) Resolve(now time.Time, id wire.ID, env *wire.Envelope, signed []byte, from PeerID) (*wire.CertWant, error) {
	s.resolves = append(s.resolves, resolveCall{id, from, now})
	return s.want, s.err
}

func (s *stubResolver) Dropped(to PeerID, id wire.ID, w wire.CertWant) {
	s.dropped = append(s.dropped, w)
}

func (s *stubResolver) Leave(t wire.Topic) { s.left = append(s.left, t) }

func (s *stubResolver) Forget(id wire.ID, env *wire.Envelope) { s.forgot = append(s.forgot, id) }

func (s *stubResolver) End(p PeerID) Resolutions {
	s.gone = append(s.gone, p)
	rs := s.ended
	s.ended = Resolutions{}
	return rs
}

func (s *stubResolver) Work() Ops { w := s.work; s.work = Ops{}; return w }

func (s *stubResolver) CertWant(from PeerID, w []wire.CertWant) [][]byte {
	s.certWants = append(s.certWants, w)
	return s.answers
}

func (s *stubResolver) Cert(now time.Time, from PeerID, certs [][]byte, budget int64) Resolutions {
	s.certs = append(s.certs, certs...)
	s.budget = budget
	rs := s.next
	s.next = Resolutions{}
	return rs
}

func (s *stubResolver) Expire(now time.Time) Resolutions {
	s.expires = append(s.expires, now)
	s.work = s.expireWork
	rs := s.next
	s.next = Resolutions{}
	return rs
}

func resolverFixture(t *testing.T, cfg *Config, res Verifier) *fixture {
	t.Helper()
	if cfg == nil {
		cfg = DefaultConfig()
	}
	f := &fixture{t: t, sink: newSink(), v: &fakeVerifier{}, now: t0}
	r, err := New(t0, key(0), cfg, rand.New(rand.NewPCG(1, 2)), res, f.sink)
	if err != nil {
		t.Fatal(err)
	}
	f.r = r
	return f
}

func markedEnvelope(seq uint64, at time.Time, mark byte) []byte {
	e := &wire.Envelope{Topic: T, Device: wire.Key(key(9)), Seq: seq, Time: uint64(at.UnixMilli())}
	e.Sig[0] = mark
	return e.Encode()
}

var errBadChain = errors.New("bad chain")

// TestResolveWaits: an unresolved author keeps the message within the validation bound, sends the Resolver's
// CERTWANT to the forwarder, and only a resolution, not ValidationDone, releases it to the validator.
func TestResolveWaits(t *testing.T) {
	res := &stubResolver{want: &wire.CertWant{Person: wire.Key{1}, Device: wire.Key{2}}}
	f := resolverFixture(t, nil, res)
	f.join(T, nil)
	f.addPeers(2, T)
	f.sink.reset()
	raw := markedEnvelope(1, f.now, unresolvedSig)
	id := wire.NewID(raw)
	f.r.Message(f.now, key(1), raw)
	if len(res.resolves) != 1 || res.resolves[0].from != key(1) || res.resolves[0].id != id || !res.resolves[0].now.Equal(f.now) {
		t.Fatalf("resolve calls %+v", res.resolves)
	}
	c := f.sink.ctrlTo(key(1))
	if len(c) != 1 || len(c[0].CertWant) != 1 || c[0].CertWant[0] != *res.want || !f.sink.ctrl[0].urgent {
		t.Fatalf("CERTWANT %+v", c)
	}
	if s := f.r.Stats(); s.Validating != 1 || s.Resolving != 1 || s.CertWantSent != 1 || len(f.sink.validate) != 0 || s.Seen != 0 {
		t.Fatalf("stats %+v", s)
	}
	f.verdict(id, Accept)
	if len(f.sink.deliver) != 0 {
		t.Fatal("ValidationDone released a message waiting for its author")
	}
	res.next = Resolutions{Done: []Resolution{{ID: id}}}
	f.control(2, &wire.Control{Cert: [][]byte{{1}}})
	if len(res.certs) != 1 || len(f.sink.validate) != 1 || f.sink.validate[0].id != id || f.sink.validate[0].from != key(1) {
		t.Fatal("a resolution must hand the message to the validator")
	}
	f.verdict(id, Accept)
	if len(f.sink.deliver) != 1 || f.r.Stats().Validating != 0 || f.r.Stats().Seen != 1 {
		t.Fatal("not delivered and seen after validation")
	}
	// A second resolution for the same id changes nothing.
	f.r.Control(f.now, key(2), &wire.Control{Cert: [][]byte{{1}}})
	res.next = Resolutions{Done: []Resolution{{ID: id}}}
	f.r.Control(f.now, key(2), &wire.Control{Cert: [][]byte{{1}}})
	if len(f.sink.validate) != 1 {
		t.Fatal("a stale resolution was applied")
	}
}

// TestResolveShared: a nil request means the message waits on one already sent; nothing goes out.
func TestResolveShared(t *testing.T) {
	res := &stubResolver{}
	f := resolverFixture(t, nil, res)
	f.join(T, nil)
	f.addPeers(1, T)
	f.sink.reset()
	f.r.Message(f.now, key(1), markedEnvelope(1, f.now, unresolvedSig))
	if len(f.sink.ctrl) != 0 || f.r.Stats().Validating != 1 {
		t.Fatal("waiting message sent a request or was dropped")
	}
}

// TestResolveError: an error from Resolve drops this copy without penalty and leaves it unseen and unremembered,
// so another peer's copy is resolved at once.
func TestResolveError(t *testing.T) {
	for _, err := range []error{ErrUnknownAuthor, ErrPeerBusy} {
		res := &stubResolver{err: err, want: &wire.CertWant{}}
		f := resolverFixture(t, scoringConfig(), res)
		f.join(T, &TopicConfig{Score: topicScore()})
		f.addPeers(2, T)
		f.sink.reset()
		raw := markedEnvelope(1, f.now, unresolvedSig)
		f.r.Message(f.now, key(1), raw)
		s := f.r.Stats()
		if f.r.Score(key(1)) != 0 || s.UnknownAuthor != 1 || s.Validating != 0 || len(f.sink.ctrl) != 0 || len(f.r.recs) != 0 ||
			s.Seen != 0 || f.r.skipped(wire.NewID(raw)) {
			t.Fatalf("%v: score %v, %+v", err, f.r.Score(key(1)), s)
		}
		res.err = nil
		f.r.Message(f.now, key(2), raw)
		if f.r.Score(key(2)) != 0 || len(res.resolves) != 2 || f.r.Stats().Validating != 1 {
			t.Fatalf("%v: another copy was not resolved at once: %d resolves", err, len(res.resolves))
		}
	}
}

// TestResolvedOutcomes: a resolution's error costs nobody score; the chain is asked from the next peer whose copy
// came while the message waited, and with none left the message is forgotten, so a later copy is taken.
func TestResolvedOutcomes(t *testing.T) {
	for _, err := range []error{ErrUnknownAuthor, ErrUnresolved, errBadChain} {
		res := &stubResolver{}
		f := resolverFixture(t, scoringConfig(), res)
		f.join(T, &TopicConfig{Score: topicScore()})
		f.addPeers(4, T)
		raw := markedEnvelope(1, f.now, unresolvedSig)
		id := wire.NewID(raw)
		f.r.Message(f.now, key(1), raw)
		f.r.Message(f.now, key(2), raw)
		f.r.Message(f.now, key(2), raw)
		if f.r.Stats().Duplicates != 2 {
			t.Fatal("copies of a waiting message are not duplicates")
		}
		res.next = Resolutions{Done: []Resolution{{ID: id, Err: err}}}
		f.control(3, &wire.Control{Cert: [][]byte{{1}}})
		if len(res.resolves) != 2 || res.resolves[1].from != key(2) || f.r.Stats().Validating != 1 {
			t.Fatalf("%v: the chain was not asked from the peer whose copy waited: %+v", err, res.resolves)
		}
		res.next = Resolutions{Done: []Resolution{{ID: id, Err: err}}}
		f.control(3, &wire.Control{Cert: [][]byte{{1}}})
		if f.r.Score(key(1)) != 0 || f.r.Score(key(2)) != 0 || f.r.Score(key(3)) != 0 {
			t.Fatalf("%v: scores %v %v %v", err, f.r.Score(key(1)), f.r.Score(key(2)), f.r.Score(key(3)))
		}
		if s := f.r.Stats(); s.Validating != 0 || len(f.sink.validate) != 0 || s.UnknownAuthor != 1 || s.Seen != 0 {
			t.Fatalf("%v: %+v", err, s)
		}
		f.r.Message(f.now, key(4), raw)
		if f.r.Score(key(4)) < 0 || len(res.resolves) != 3 {
			t.Fatalf("%v: a later copy was not checked again: %+v", err, f.r.Stats())
		}
	}
}

// TestResolvedAfterLeave: Leave drops the messages of the topic still waiting, so a late resolution does nothing.
func TestResolvedAfterLeave(t *testing.T) {
	res := &stubResolver{}
	f := resolverFixture(t, nil, res)
	f.join(T, nil)
	f.addPeers(1, T)
	raw := markedEnvelope(1, f.now, unresolvedSig)
	f.r.Message(f.now, key(1), raw)
	f.r.Leave(f.now, T)
	if s := f.r.Stats(); s.Validating != 0 || len(f.r.recs) != 0 || len(res.left) != 1 || res.left[0] != T {
		t.Fatalf("Leave kept a waiting message or did not tell the Resolver: %+v", s)
	}
	res.next = Resolutions{Done: []Resolution{{ID: wire.NewID(raw)}}}
	f.control(1, &wire.Control{Cert: [][]byte{{1}}})
	if s := f.r.Stats(); len(f.sink.validate) != 0 || s.Validating != 0 || len(f.r.recs) != 0 {
		t.Fatalf("%+v, %d records", s, len(f.r.recs))
	}
}

// TestResolvedAfterLeaveFanout: a message resolved after its topic was left and became a fanout topic of ours
// is ignored too.
func TestResolvedAfterLeaveFanout(t *testing.T) {
	cfg := DefaultConfig()
	cfg.FloodPublish = false
	res := &stubResolver{}
	f := resolverFixture(t, cfg, res)
	f.join(T, nil)
	f.addPeers(1, T)
	raw := markedEnvelope(1, f.now, unresolvedSig)
	f.r.Message(f.now, key(1), raw)
	f.r.Leave(f.now, T)
	if _, err := f.r.Publish(f.now, envelope(T, key(0), 1, f.now, 1)); err != nil {
		t.Fatal(err)
	}
	res.next = Resolutions{Done: []Resolution{{ID: wire.NewID(raw)}}}
	f.control(1, &wire.Control{Cert: [][]byte{{1}}})
	if s := f.r.Stats(); len(f.sink.validate) != 0 || s.Validating != 0 {
		t.Fatalf("%+v", s)
	}
}

// TestResolvedAfterSeenExpiry: a waiting message whose seen entry expired is released; its late resolution
// is dropped.
func TestResolvedAfterSeenExpiry(t *testing.T) {
	res := &stubResolver{}
	f := resolverFixture(t, nil, res)
	f.join(T, nil)
	f.addPeers(1, T)
	raw := markedEnvelope(1, f.now, unresolvedSig)
	f.r.Message(f.now, key(1), raw)
	f.now = f.now.Add(DefaultConfig().SeenTTL + time.Nanosecond)
	f.r.Tick(f.now)
	if f.r.Stats().Validating != 0 {
		t.Fatal("expired waiting message still counted")
	}
	res.next = Resolutions{Done: []Resolution{{ID: wire.NewID(raw)}}}
	f.control(1, &wire.Control{Cert: [][]byte{{1}}})
	if len(f.sink.validate) != 0 {
		t.Fatal("a resolution for an expired message was applied")
	}
}

// TestResolvedIgnoresValidating: a resolution for a message that waits for its validator, not its author,
// changes nothing.
func TestResolvedIgnoresValidating(t *testing.T) {
	res := &stubResolver{}
	f := resolverFixture(t, nil, res)
	f.join(T, nil)
	f.addPeers(1, T)
	raw := markedEnvelope(1, f.now, 0)
	f.r.Message(f.now, key(1), raw)
	res.next = Resolutions{Done: []Resolution{{ID: wire.NewID(raw), Err: errBadChain}}}
	f.control(1, &wire.Control{Cert: [][]byte{{1}}})
	if s := f.r.Stats(); len(f.sink.validate) != 1 || s.BadSignature != 0 || s.Validating != 1 {
		t.Fatalf("%+v", s)
	}
}
