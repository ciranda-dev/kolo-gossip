package core

import (
	"errors"
	"testing"
	"time"

	"github.com/ciranda-dev/kolo-gossip/internal/wire"
)

// TestJunkNotSeen: messages ignored before their author is known (out of window, unknown author) or with a bad
// signature never enter the seen cache, so a flood of them cannot fill it, and a real message still passes.
func TestJunkNotSeen(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Score = nil // nothing graylists the sender
	cfg.MaxSeen = 10
	f := meshFixture(t, cfg, 1, 0)
	for i := range 50 {
		f.r.Message(f.now, key(1), markedEnvelope(uint64(i), f.now, unknownSig))
		f.r.Message(f.now, key(1), envelope(T, key(9), uint64(i), f.now.Add(-2*time.Minute), 1))
		f.r.Message(f.now, key(1), badEnvelope(T, key(9), uint64(100+i), f.now))
	}
	s := f.r.Stats()
	if s.Seen != 0 || s.UnknownAuthor != 50 || s.OutOfWindow != 50 || s.BadSignature != 50 || len(f.r.recs) != 0 {
		t.Fatalf("junk kept: %+v", s)
	}
	f.receive(1, envelope(T, key(9), 1, f.now, 1), Accept)
	if f.r.Stats().Delivered != 1 || f.r.Stats().SeenFull != 0 {
		t.Fatalf("a real message after the junk: %+v", f.r.Stats())
	}
}

// TestBuckets: every frame is charged to its peer's buckets; once one is empty, Wait tells the driver how long to
// stop reading the peer, the wait costs no score, and the bucket refills with time.
func TestBuckets(t *testing.T) {
	for name, send := range map[string]func(f *fixture, i int){
		"lock":    func(f *fixture, i int) { f.control(1, &wire.Control{}) },
		"outside": func(f *fixture, i int) { f.r.Message(f.now, key(1), markedEnvelope(uint64(i), f.now, unknownSig)) },
	} {
		cfg := scoringConfig()
		cfg.LockWork, cfg.PeerWork = 1000, 10_000
		f := newFixture(t, cfg)
		f.join(T, &TopicConfig{Score: topicScore()})
		f.addPeers(1, T)
		f.settle()
		n := 0
		for ; f.r.Wait(f.now, key(1)) == 0; n++ {
			send(f, n)
		}
		w := f.r.Wait(f.now, key(1))
		if n < 2 || w <= 0 || f.r.Score(key(1)) != 0 || f.r.Stats().Waits != 1 {
			t.Fatalf("%s: %d frames, wait %v, score %v", name, n, w, f.r.Score(key(1)))
		}
		f.now = f.now.Add(w)
		if f.r.Wait(f.now, key(1)) != 0 {
			t.Fatalf("%s: the bucket did not refill in the wait it asked for", name)
		}
	}
}

// TestSkippedCopies: copies of an id ignored for its author cost no signature check and are not asked with IWANT;
// an id dropped for our load or for its sender's share is not remembered, so another peer's copy is taken at once.
func TestSkippedCopies(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxPeerValidating = 1
	f := meshFixture(t, cfg, 3, 0)
	unknown := markedEnvelope(1, f.now, unknownSig)
	f.r.Message(f.now, key(1), unknown)
	checks := f.r.Stats().SignatureChecks
	f.r.Message(f.now, key(2), unknown)
	if f.r.Stats().SignatureChecks != checks || f.r.Stats().IgnoredCopies != 1 || f.r.MessageWithID(f.now, key(2), unknown, wire.NewID(unknown)) {
		t.Fatal("a copy of an ignored id was checked again")
	}
	f.r.Message(f.now, key(1), envelope(T, key(9), 2, f.now, 1))
	throttled := envelope(T, key(9), 3, f.now, 1)
	f.r.Message(f.now, key(1), throttled)
	f.control(2, &wire.Control{IHave: []wire.IHave{{Topic: T, IDs: []wire.ID{wire.NewID(unknown), wire.NewID(throttled)}}}})
	got := f.sink.ctrlTo(key(2))
	if len(got) != 1 || len(got[0].IWant) != 1 || got[0].IWant[0] != wire.NewID(throttled) {
		t.Fatalf("only the throttled id is asked, at once: %+v", got)
	}
}

// TestSeenAfterVerdict: an id is seen once its validator accepts or rejects it; an ignored one stays unseen and
// its next copy is validated again.
func TestSeenAfterVerdict(t *testing.T) {
	f := meshFixture(t, nil, 2, 0)
	for v, wantSeen := range map[Verdict]int{Accept: 1, Reject: 1, Ignore: 0} {
		raw := envelope(T, key(9), uint64(v)+10, f.now, 1)
		before := f.r.Stats().Seen
		f.receive(1, raw, v)
		if got := f.r.Stats().Seen - before; got != wantSeen {
			t.Errorf("verdict %d: %d seen", v, got)
		}
		if v == Ignore && f.r.skipped(wire.NewID(raw)) {
			t.Error("an ignored id is remembered: the validator may have judged the copy, not the message")
		}
	}
}

// TestForwardMargin: an accepted message that leaves the window within a heartbeat is delivered but not
// forwarded, so the next hop never refuses it for its time.
func TestForwardMargin(t *testing.T) {
	f := meshFixture(t, nil, 3, 3)
	f.receive(1, envelope(T, key(9), 1, f.now.Add(-time.Minute+500*time.Millisecond), 1), Accept)
	if s := f.r.Stats(); s.Delivered != 1 || s.EdgeOfWindow != 1 || len(f.sink.msgs) != 0 {
		t.Fatalf("edge of window forwarded: %+v", s)
	}
	f.receive(1, envelope(T, key(9), 2, f.now.Add(-time.Minute+2*time.Second), 1), Accept)
	if len(f.sink.msgs) != 2 {
		t.Fatalf("a message a heartbeat inside the window was not forwarded: %d", len(f.sink.msgs))
	}
}

// TestThrottledNotSeen: a message over its sender's share is checked no further, sends no IDONTWANT, is not marked
// seen and is not remembered, so another peer's copy is taken at once; one peer holds at most MaxPeerValidating
// messages.
func TestThrottledNotSeen(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxPeerValidating = 2
	f := meshFixture(t, cfg, 3, 3)
	big := 2000
	for i := range 3 {
		f.r.Message(f.now, key(1), envelope(T, key(9), uint64(i), f.now, big))
	}
	s := f.r.Stats()
	if s.Validating != 2 || s.Throttled != 1 || s.Seen != 0 || s.IDontWantSent != 4 {
		t.Fatalf("per-peer bound: %+v", s)
	}
	f.r.Message(f.now, key(2), envelope(T, key(9), 2, f.now, big))
	if s := f.r.Stats(); s.Validating != 3 || s.IgnoredCopies != 0 {
		t.Fatalf("an honest copy of a message its first sender could not hold was dropped: %+v", s)
	}
	f.r.ValidationDone(f.now, f.sink.validate[0].id, f.sink.validate[0].n, Accept)
	f.r.Message(f.now, key(1), envelope(T, key(9), 9, f.now, 1))
	if f.r.Stats().Validating != 3 {
		t.Fatal("a released place was not given back to the peer")
	}
}

// TestStaleVerdictAfterRejoin: a verdict for a message received before Leave does nothing after a rejoin, so the
// new room's validator is never skipped.
func TestStaleVerdictAfterRejoin(t *testing.T) {
	f := meshFixture(t, nil, 1, 0)
	f.r.Message(f.now, key(1), envelope(T, key(9), 1, f.now, 1))
	id := f.sink.validate[0].id
	f.r.Leave(f.now, T)
	f.join(T, nil)
	f.verdict(id, Accept)
	if s := f.r.Stats(); s.Delivered != 0 || s.Validating != 0 {
		t.Fatalf("stale verdict applied: %+v", s)
	}
}

// TestCertAnswerRetried: a CERT answer our full queue dropped is sent with the next control frame, so the asker
// does not count it as a broken request; a CERTWANT our queue dropped is the Resolver's to forget.
func TestCertAnswerRetried(t *testing.T) {
	res := &stubResolver{answers: [][]byte{{7}}, want: &wire.CertWant{Person: wire.Key{1}}}
	f := resolverFixture(t, nil, res)
	f.join(T, nil)
	f.addPeers(1, T)
	f.sink.full[key(1)] = true
	f.control(1, &wire.Control{CertWant: []wire.CertWant{{}}})
	f.r.Message(f.now, key(1), markedEnvelope(1, f.now, unresolvedSig))
	if len(res.dropped) != 1 {
		t.Fatal("a dropped CERTWANT was not reported to the Resolver")
	}
	f.sink.full[key(1)] = false
	f.sink.reset()
	f.heartbeat()
	sent := false
	for _, c := range f.sink.ctrlTo(key(1)) {
		sent = sent || len(c.Cert) == 1
	}
	if !sent {
		t.Fatal("a dropped CERT answer was not sent again")
	}
}

// TestPeerByteQuota: one peer holds at most MaxPeerValidatingBytes of messages waiting; a share always fits one
// largest message, since the bound is at least MaxMessageSize.
func TestPeerByteQuota(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxMessageSize, cfg.MaxPeerValidatingBytes = 3000, 3000
	f := meshFixture(t, cfg, 2, 0)
	f.r.Message(f.now, key(1), envelope(T, key(9), 1, f.now, 2700))
	f.r.Message(f.now, key(1), envelope(T, key(9), 2, f.now, 100))
	if s := f.r.Stats(); s.Validating != 1 || s.Throttled != 1 {
		t.Fatalf("byte quota: %+v", s)
	}
	f.r.Message(f.now, key(2), envelope(T, key(9), 3, f.now, 2000))
	f.r.Message(f.now, key(2), envelope(T, key(9), 4, f.now, 500))
	f.r.Message(f.now, key(2), envelope(T, key(9), 5, f.now, 1000))
	if s := f.r.Stats(); s.Validating != 3 || s.Throttled != 2 {
		t.Fatalf("byte quota of a second peer: %+v", s)
	}
}

// TestSharesFitTheBounds: one sender's share, and the departed share, fit in the global validation bounds, so a
// sender never holds more than half of them.
func TestSharesFitTheBounds(t *testing.T) {
	for name, tweak := range map[string]func(*Config){
		"count": func(c *Config) { c.MaxPeerValidating = c.MaxValidating/2 + 1 },
		"bytes": func(c *Config) { c.MaxPeerValidatingBytes = c.MaxValidatingBytes/2 + 1 },
	} {
		cfg := DefaultConfig()
		tweak(cfg)
		if _, err := New(t0, key(0), cfg, randFor(1), &fakeVerifier{}, newSink()); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestSkipBound: each ignored-id set keeps at most MaxIgnoredIDs ids.
func TestSkipBound(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxIgnoredIDs = 3
	cfg.Score = nil
	f := meshFixture(t, cfg, 1, 0)
	for i := range 10 {
		f.r.Message(f.now, key(1), markedEnvelope(uint64(i), f.now, unknownSig))
	}
	if f.r.skipLong.len() != 3 {
		t.Fatalf("%d ids kept over MaxIgnoredIDs 3", f.r.skipLong.len())
	}
	old := envelope(T, key(9), 50, f.now.Add(-2*time.Minute), 1)
	g := meshFixture(t, nil, 1, 0)
	g.r.Message(g.now, key(1), old)
	g.r.Message(g.now, key(1), old)
	// Out-of-window ids are not remembered: the time check costs no more than the lookup, and remembering them
	// would let one peer fill the set cheaply.
	if s := g.r.Stats(); s.OutOfWindow != 2 || s.IgnoredCopies != 0 || s.SignatureChecks != 0 {
		t.Fatalf("out-of-window copies: %+v", s)
	}
}

// TestSeenFullCountsHeld: messages waiting for their validator count against MaxSeen, for received and published
// messages alike, so seen plus held never pass it.
func TestSeenFullCountsHeld(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxSeen = 2
	f := meshFixture(t, cfg, 1, 0)
	for i := range 3 {
		f.r.Message(f.now, key(1), envelope(T, key(9), uint64(i), f.now, 1))
	}
	if s := f.r.Stats(); s.Validating != 2 || s.SeenFull != 1 || f.r.skipped(wire.NewID(envelope(T, key(9), 2, f.now, 1))) {
		t.Fatalf("held messages not counted, or the refused id remembered: %+v", s)
	}
	if _, err := f.r.Publish(f.now, envelope(T, key(0), 1, f.now, 1)); !errors.Is(err, ErrLimit) {
		t.Fatalf("a publish with seen plus held at MaxSeen: %v", err)
	}
}

// TestIgnoredIDontWant: a large message ignored for its author, with a valid signature, gets an IDONTWANT to the
// mesh, so peers do not send us copies we would drop.
func TestIgnoredIDontWant(t *testing.T) {
	f := meshFixture(t, nil, 3, 3)
	e := &wire.Envelope{Topic: T, Device: wire.Key(key(9)), Seq: 1, Time: uint64(f.now.UnixMilli()), Body: make([]byte, 2000)}
	e.Sig[0] = unknownSig
	f.r.Message(f.now, key(1), e.Encode())
	if f.r.Stats().IDontWantSent != 2 {
		t.Fatalf("%d IDONTWANT for an ignored large message", f.r.Stats().IDontWantSent)
	}
}
