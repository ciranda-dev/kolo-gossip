package core

import (
	"errors"
	"testing"
	"time"

	"github.com/ciranda-dev/kolo-gossip/internal/wire"
)

// TestRetryKeepsTheMessage: a Retry keeps the message held, answers copies as duplicates, and Revalidate runs the
// validator again; the later Accept delivers it once.
func TestRetryKeepsTheMessage(t *testing.T) {
	f := meshFixture(t, nil, 3, 3)
	raw := envelope(T, key(9), 1, f.now, 10)
	id := wire.NewID(raw)
	f.receive(1, raw, Retry)
	if s := f.r.Stats(); len(f.sink.deliver) != 0 || s.Validating != 1 || s.Retried != 1 || s.Ignored != 0 || s.Seen != 0 {
		t.Fatalf("after Retry: %d delivered, %+v", len(f.sink.deliver), s)
	}
	f.r.Message(f.now, key(2), raw)
	if len(f.sink.validate) != 1 || f.r.Stats().Duplicates != 1 {
		t.Fatalf("a copy of a retried message: %d validations", len(f.sink.validate))
	}
	f.r.Revalidate(f.now, T)
	if len(f.sink.validate) != 2 || f.sink.validate[1].id != id || f.sink.validate[1].n == f.sink.validate[0].n {
		t.Fatalf("Revalidate: %+v", f.sink.validate)
	}
	f.verdict(id, Accept)
	if s := f.r.Stats(); len(f.sink.deliver) != 1 || s.Validating != 0 || s.Seen != 1 || f.sink.msgsTo(key(3)) != 1 {
		t.Fatalf("after Accept: %d delivered, %+v", len(f.sink.deliver), s)
	}
	f.r.Revalidate(f.now, T)
	if len(f.sink.validate) != 2 {
		t.Fatal("a decided message was validated again")
	}
}

// TestRetryAfterInterval: with no Revalidate, a retried message is validated again at the first heartbeat RetryInterval
// after its Retry.
func TestRetryAfterInterval(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RetryInterval = 3 * time.Second
	f := meshFixture(t, cfg, 1, 0)
	start := f.now
	raw := envelope(T, key(9), 1, f.now, 10)
	f.receive(1, raw, Retry)
	for len(f.sink.validate) == 1 {
		if f.now.Sub(start) > 10*time.Second {
			t.Fatal("never validated again")
		}
		f.heartbeat()
	}
	if d := f.now.Sub(start); d < 3*time.Second || d >= 4*time.Second {
		t.Fatalf("validated again after %v, want the first heartbeat from 3s", d)
	}
	f.verdict(wire.NewID(raw), Accept)
	if len(f.sink.deliver) != 1 {
		t.Fatal("not delivered after the second validation")
	}
}

// TestRetryEndsAtSeenTTL: a validator that answers Retry every time is run once a RetryInterval until SeenTTL, then its
// message is dropped and holds no place.
func TestRetryEndsAtSeenTTL(t *testing.T) {
	f := meshFixture(t, nil, 1, 0)
	start := f.now
	raw := envelope(T, key(9), 1, f.now.Add(30*time.Second), 10)
	id := wire.NewID(raw)
	f.receive(1, raw, Retry)
	for f.r.Stats().Validating != 0 {
		if f.now.Sub(start) > 5*time.Minute {
			t.Fatal("a retried message outlived SeenTTL")
		}
		n := len(f.sink.validate)
		f.heartbeat()
		if len(f.sink.validate) > n {
			f.verdict(id, Retry)
		}
	}
	if d, s := f.now.Sub(start), f.r.Stats(); d <= 2*time.Minute || d > 2*time.Minute+2*time.Second || s.Validating != 0 || len(f.sink.deliver) != 0 {
		t.Fatalf("dropped after %v: %d delivered, %+v", d, len(f.sink.deliver), s)
	}
	if n := len(f.sink.validate); n < 100 || n > 125 {
		t.Fatalf("%d validations in SeenTTL at one a heartbeat", n)
	}
}

// TestRetryUsesTheSendersShare: retried messages stay in their sender's MaxPeerValidating share, so one peer cannot
// hold more than its share with them, and Leave releases them.
func TestRetryUsesTheSendersShare(t *testing.T) {
	f := meshFixture(t, nil, 2, 0)
	for i := range f.r.cfg.MaxPeerValidating + 1 {
		f.receive(1, envelope(T, key(9), uint64(i), f.now, 10), Retry)
	}
	if s := f.r.Stats(); s.Validating != f.r.cfg.MaxPeerValidating || s.Throttled != 1 {
		t.Fatalf("one peer held %d retried messages, throttled %d", s.Validating, s.Throttled)
	}
	f.receive(2, envelope(T, key(9), 99, f.now, 10), Retry)
	if f.r.Stats().Validating != f.r.cfg.MaxPeerValidating+1 {
		t.Fatal("another peer's share is not its own")
	}
	f.r.Revalidate(f.now, topicID(7))
	if len(f.sink.validate) != f.r.cfg.MaxPeerValidating+1 {
		t.Fatal("Revalidate of another topic validated messages")
	}
	f.r.Leave(f.now, T)
	if s := f.r.Stats(); s.Validating != 0 || len(f.r.retrying) != 0 {
		t.Fatalf("after Leave: %+v", s)
	}
}

// TestRetryIntervalConfig: RetryInterval must be positive.
func TestRetryIntervalConfig(t *testing.T) {
	cfg := DefaultConfig()
	for _, d := range []time.Duration{0, -time.Second} {
		cfg.RetryInterval = d
		if _, err := New(t0, key(0), cfg, randFor(1), &fakeVerifier{}, newSink()); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("RetryInterval %v: %v", d, err)
		}
	}
}
