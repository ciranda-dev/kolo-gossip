package core

import (
	"bytes"
	"slices"
	"testing"
	"time"

	"github.com/ciranda-dev/kolo-gossip/internal/wire"
)

func seenID32(i int) wire.ID {
	return wire.NewID([]byte{byte(i), byte(i >> 8), byte(i >> 16)})
}

// TestSeenCacheLifetime: with calls at random times, every id is seen from its add through add+ttl and gone at any
// call more than ttl plus two intervals after its add; the array stays sorted.
func TestSeenCacheLifetime(t *testing.T) {
	const every, ttl = time.Second, 10 * time.Second
	for seed := range uint64(50) {
		rnd := randFor(seed)
		now := t0
		s := newSeen(now, every)
		added := map[wire.ID]time.Time{}
		for i := range 2000 {
			now = now.Add(time.Duration(rnd.IntN(int(3 * every / 2))))
			if !now.Before(s.until) {
				s.roll(now, every, ttl)
			}
			for id, at := range added {
				age := now.Sub(at)
				switch {
				case age <= ttl && !s.has(id):
					t.Fatalf("seed %d: id gone at age %v", seed, age)
				case age > ttl+2*every && s.has(id):
					t.Fatalf("seed %d: id still seen at age %v", seed, age)
				case age > ttl+2*every:
					delete(added, id)
				}
			}
			if rnd.IntN(3) > 0 {
				id := seenID32(i)
				s.add(id)
				added[id] = now
			}
			if !slices.IsSortedFunc(s.ids, func(a, b seenID) int { return bytes.Compare(a.id[:], b.id[:]) }) {
				t.Fatalf("seed %d: ids not sorted", seed)
			}
		}
		if s.has(seenID32(-1)) {
			t.Fatal("an id never added is seen")
		}
	}
}

// TestSeenCacheBoundary: an id added in the interval ending at u stays seen through u+ttl itself and is gone at the
// next interval end after it.
func TestSeenCacheBoundary(t *testing.T) {
	const every, ttl = time.Second, time.Minute
	s := newSeen(t0, every)
	s.add(seenID32(1))
	for now := t0.Add(every); !now.After(t0.Add(every + ttl)); now = now.Add(every) {
		s.roll(now, every, ttl)
		if !s.has(seenID32(1)) {
			t.Fatalf("gone at %v", now.Sub(t0))
		}
	}
	s.roll(t0.Add(2*every+ttl), every, ttl)
	if s.has(seenID32(1)) || len(s.gens) != 0 {
		t.Fatal("kept after its interval end plus ttl")
	}
}

// TestSeenCacheGap: after a long pause the next call closes the open interval and drops it in the same step.
func TestSeenCacheGap(t *testing.T) {
	s := newSeen(t0, time.Second)
	s.add(seenID32(1))
	now := t0.Add(time.Hour)
	s.roll(now, time.Second, time.Minute)
	if s.has(seenID32(1)) || s.len() != 0 || len(s.gens) != 0 {
		t.Fatalf("stale id kept: %d ids, %d intervals", s.len(), len(s.gens))
	}
	if s.until != now.Add(time.Second) {
		t.Fatalf("next interval ends at %v", s.until.Sub(now))
	}
}

// TestSeenCacheShrinks: the array gives memory back once most of its ids expired.
func TestSeenCacheShrinks(t *testing.T) {
	s := newSeen(t0, time.Second)
	now := t0
	for i := range 1000 {
		s.add(seenID32(i))
	}
	now = now.Add(time.Second)
	s.roll(now, time.Second, time.Minute)
	full := cap(s.ids)
	s.add(seenID32(5000))
	now = now.Add(time.Minute + time.Second)
	s.roll(now, time.Second, time.Minute)
	if s.len() != 1 || cap(s.ids) > full/2 {
		t.Fatalf("%d ids in capacity %d (was %d)", s.len(), cap(s.ids), full)
	}
}

// TestSeenRecords: a delivery record lasts only while scoring needs it: an accepted message's ends after the
// near-first window, an ignored or out-of-window one's at once, an invalid one's after SeenTTL, during which copies
// still cost P4.
func TestSeenRecords(t *testing.T) {
	f := scoreFixture(t, nil, 3)
	valid, ignored, invalid := envelope(T, key(90), 1, f.now, 1), envelope(T, key(90), 2, f.now, 1), envelope(T, key(90), 3, f.now, 1)
	f.receive(1, valid, Accept)
	f.receive(1, ignored, Ignore)
	f.receive(1, invalid, Reject)
	f.r.Message(f.now, key(1), envelope(T, key(90), 4, f.now.Add(-time.Hour), 1))
	if len(f.r.recs) != 2 || f.r.recs[wire.NewID(valid)] == nil || f.r.recs[wire.NewID(invalid)] == nil {
		t.Fatalf("%d records", len(f.r.recs))
	}
	f.tick(time.Second)
	if len(f.r.recs) != 1 || f.r.recs[wire.NewID(invalid)] == nil || !f.r.seen.has(wire.NewID(valid)) {
		t.Fatalf("after the window: %d records", len(f.r.recs))
	}
	f.r.Message(f.now, key(2), invalid)
	f.receive(3, ignored, Ignore) // an ignored message is validated again: the validator may have judged the copy
	if f.stats(2).invalidMessageDeliveries != 1 || f.stats(3).invalidMessageDeliveries != 0 {
		t.Fatal("copies of the invalid message not penalised, or of the ignored one penalised")
	}
	f.tick(DefaultConfig().SeenTTL)
	if len(f.r.recs) != 0 {
		t.Fatalf("%d records after SeenTTL", len(f.r.recs))
	}
}

// TestPublishRecord: our own message earns near-first credit for a mesh peer's copy only within the window after
// the publish, as a validated message does.
func TestPublishRecord(t *testing.T) {
	f := scoreFixture(t, nil, 2)
	for i := 1; i <= 2; i++ {
		f.control(i, &wire.Control{Graft: []wire.Topic{T}})
	}
	raw := envelope(T, key(0), 1, f.now, 1)
	if _, err := f.r.Publish(f.now, raw); err != nil {
		t.Fatal(err)
	}
	f.r.Message(f.now.Add(5*time.Millisecond), key(1), raw)
	f.r.Message(f.now.Add(20*time.Millisecond), key(2), raw)
	if f.stats(1).meshMessageDeliveries != 1 || f.stats(2).meshMessageDeliveries != 0 {
		t.Fatalf("credit %v and %v", f.stats(1).meshMessageDeliveries, f.stats(2).meshMessageDeliveries)
	}
}
