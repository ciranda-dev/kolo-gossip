package core

import (
	"bytes"
	"slices"
	"time"

	"github.com/ciranda-dev/kolo-gossip/internal/wire"
)

const (
	statusUnknown = iota // validating
	statusValid
	statusInvalid
)

// seenRec is the delivery record of a seen id while scoring or validation still needs it: during validation, for
// SeenTTL after an invalid message (its copies cost P4) and within the near-first window after a valid one.
type seenRec struct {
	id        wire.ID
	topic     wire.Topic
	expire    int64 // nanoseconds of the router's monotonic clock
	status    int8
	validated time.Time
	peers     []PeerID // peers that sent a copy after the first, counted once each
	pending   *pendingMsg
}

type pendingMsg struct {
	env       *wire.Envelope
	raw       []byte
	from      PeerID   // the sender whose share holds it
	resolving bool     // waiting for the author's chain, not for the validator
	departed  bool     // its sender left: it is held in the departed share
	open      bool     // counted in the open tier of the validation bounds
	nextHeld  *seenRec // the next older message held for the same sender
	again     int8     // validations run again with another copy's sender after an Ignore
	inst      uint64   // the validation number given to the validator, 0 while waiting for the author's chain
	asks      int32    // chain requests outstanding
	next      int32    // the next of the record's peers to ask for the chain
	sent      int64    // when the last request was sent, in nanoseconds of the router's monotonic clock
	retry     bool     // the validator answered Retry: held with no validation running
	retryAt   int64    // when it answered, in nanoseconds of the router's monotonic clock
}

// seenCache holds the ids seen in the last SeenTTL: the open interval in a map, closed ones in one sorted array, so
// a seen id costs 36 bytes, and an interval leaves in one pass once SeenTTL has passed since its end.
type seenCache struct {
	open  map[wire.ID]struct{}
	ids   []seenID  // sorted by id
	gens  []seenGen // closed intervals, oldest first
	until time.Time // end of the open interval
	gen   uint32    // tag of the open interval
}

type seenID struct {
	id  wire.ID
	gen uint32
}

type seenGen struct {
	gen    uint32
	expire time.Time // its ids stay seen through this instant
}

func newSeen(now time.Time, every time.Duration) seenCache {
	return seenCache{open: map[wire.ID]struct{}{}, until: now.Add(every)}
}

func (s *seenCache) has(id wire.ID) bool {
	if _, ok := s.open[id]; ok {
		return true
	}
	_, ok := slices.BinarySearchFunc(s.ids, id, func(e seenID, id wire.ID) int { return bytes.Compare(e.id[:], id[:]) })
	return ok
}

func (s *seenCache) add(id wire.ID) { s.open[id] = struct{}{} }

func (s *seenCache) len() int { return len(s.open) + len(s.ids) }

// roll runs when the open interval has ended: it closes the open interval, then drops the intervals that ended
// more than ttl ago. An id therefore stays seen for at least ttl and at most ttl plus two intervals.
func (s *seenCache) roll(now time.Time, every, ttl time.Duration) {
	if len(s.open) > 0 {
		add := make([]seenID, 0, len(s.open))
		for id := range s.open {
			add = append(add, seenID{id, s.gen})
		}
		slices.SortFunc(add, func(a, b seenID) int { return bytes.Compare(a.id[:], b.id[:]) })
		s.ids = mergeSeen(s.ids, add)
		s.gens = append(s.gens, seenGen{s.gen, s.until.Add(ttl)})
		s.gen++
		s.open = map[wire.ID]struct{}{}
	}
	s.until = next(s.until, now, every)
	n := 0
	for n < len(s.gens) && s.gens[n].expire.Before(now) {
		n++
	}
	if n > 0 {
		first, last := s.gens[0].gen, s.gens[n-1].gen
		s.ids = slices.DeleteFunc(s.ids, func(e seenID) bool { return e.gen-first <= last-first })
		s.gens = slices.Delete(s.gens, 0, n)
		if cap(s.ids) > 2*len(s.ids) {
			s.ids = slices.Clone(s.ids)
		}
	}
}

// mergeSeen merges the sorted b into the sorted a, in place from the end.
func mergeSeen(a, b []seenID) []seenID {
	i, j := len(a)-1, len(b)-1
	a = slices.Grow(a, len(b))[:len(a)+len(b)]
	for k := len(a) - 1; j >= 0; k-- {
		if i >= 0 && bytes.Compare(a[i].id[:], b[j].id[:]) > 0 {
			a[k], i = a[i], i-1
		} else {
			a[k], j = b[j], j-1
		}
	}
	return a
}

// unwanted holds the ids a peer said it already has (IDONTWANT) until a heartbeat tick, in arrival order, so the
// heartbeat expires them from the front without walking the rest.
type unwanted struct {
	m map[wire.ID]uint64 // id to the tick it expires at
	q []unwantedID
}

type unwantedID struct {
	id    wire.ID
	until uint64
}

func (u *unwanted) has(id wire.ID) bool {
	if u == nil {
		return false
	}
	_, ok := u.m[id]
	return ok
}

// add keeps id until tick, unless it is kept already or limit ids are kept.
func (u *unwanted) add(id wire.ID, until uint64, limit int) {
	if _, ok := u.m[id]; ok || len(u.m) >= limit {
		return
	}
	if u.m == nil {
		u.m = map[wire.ID]uint64{}
	}
	u.m[id] = until
	u.q = append(u.q, unwantedID{id, until})
}

// expire drops the ids whose tick has come and reports whether any are left.
func (u *unwanted) expire(tick uint64) bool {
	if u == nil {
		return false
	}
	n := 0
	for n < len(u.q) && u.q[n].until <= tick {
		delete(u.m, u.q[n].id)
		n++
	}
	u.q = u.q[n:]
	return len(u.q) > 0
}

type cacheEntry struct {
	id    wire.ID
	topic wire.Topic
	raw   []byte
}

// msgCache keeps accepted messages for HistoryLength heartbeat windows to answer IWANT and build IHAVE.
type msgCache struct {
	looked   int // entries looked at or moved by evictions so far, for the unit audit
	m        map[wire.ID]*cacheEntry
	windows  [][]*cacheEntry // newest first
	perTopic map[wire.Topic]int
	bytes    int
}

func newCache(history int) msgCache {
	return msgCache{m: map[wire.ID]*cacheEntry{}, windows: make([][]*cacheEntry, history), perTopic: map[wire.Topic]int{}}
}

// put adds a message, dropping the oldest of its topic over maxPerTopic and the oldest overall over maxBytes.
// It returns the entries it looked at to find what to drop.
func (c *msgCache) put(id wire.ID, t wire.Topic, raw []byte, maxPerTopic, maxBytes int, st *Stats) (steps int) {
	if c.m[id] != nil {
		return 0
	}
	for c.perTopic[t] >= maxPerTopic {
		steps += c.evict(func(e *cacheEntry) bool { return e.topic == t })
		st.CacheEvicted++
	}
	for c.bytes > maxBytes-len(raw) {
		steps += c.evict(func(*cacheEntry) bool { return true })
		st.CacheEvicted++
	}
	e := &cacheEntry{id: id, topic: t, raw: raw}
	c.m[id] = e
	c.windows[0] = append(c.windows[0], e)
	c.perTopic[t]++
	c.bytes += len(raw)
	return steps
}

// evict removes the oldest entry that matches and returns its work: the entries it looked at, and one for each
// eight entries it moved (64 bytes of pointers).
func (c *msgCache) evict(match func(*cacheEntry) bool) int {
	steps := 0
	look := func(e *cacheEntry) bool { c.looked++; return match(e) }
	for w := len(c.windows) - 1; w >= 0; w-- {
		if i := slices.IndexFunc(c.windows[w], look); i >= 0 {
			c.looked += (len(c.windows[w]) - i) / 8
			steps += i + 1 + (len(c.windows[w])-i)/8
			c.drop(c.windows[w][i])
			c.windows[w] = slices.Delete(c.windows[w], i, i+1)
			return steps
		}
		steps += len(c.windows[w])
	}
	return steps
}

func (c *msgCache) drop(e *cacheEntry) {
	delete(c.m, e.id)
	c.bytes -= len(e.raw)
	if c.perTopic[e.topic]--; c.perTopic[e.topic] <= 0 {
		delete(c.perTopic, e.topic)
	}
}

func (c *msgCache) shift() {
	last := len(c.windows) - 1
	for _, e := range c.windows[last] {
		c.drop(e)
	}
	copy(c.windows[1:], c.windows[:last])
	c.windows[0] = nil
}

// gossipIDs returns the ids of t in the newest gossip windows.
func (c *msgCache) gossipIDs(t wire.Topic, gossip int) []wire.ID {
	var ids []wire.ID
	for _, w := range c.windows[:gossip] {
		for _, e := range w {
			if e.topic == t {
				ids = append(ids, e.id)
			}
		}
	}
	return ids
}

// backoffTable holds, for one topic, until when each peer must not be grafted.
type backoffTable struct {
	topic wire.Topic
	m     map[PeerID]backoffEntry
	left  bool
}

// backoffEntry is one peer's backoff; owed means we must respect it (the peer pruned us, or we pruned it from our
// mesh): grafting it early would cost us its penalty.
type backoffEntry struct {
	expire int64 // nanoseconds after the tables' base time
	owed   bool
}

// backoffs keeps the tables of joined topics and of topics left recently, so rejoining respects a backoff.
type backoffs struct {
	base   time.Time // the origin of expiry times, the router's start
	looked int       // entries looked at by evictions so far, for the unit audit
	m      map[wire.Topic]*backoffTable
	left   []wire.Topic // left topics, oldest first
}

func (b *backoffs) has(t wire.Topic, p PeerID) bool {
	_, ok := b.expiry(t, p)
	return ok
}

func (b *backoffs) expiry(t wire.Topic, p PeerID) (time.Time, bool) {
	if tb := b.m[t]; tb != nil {
		e, ok := tb.m[p]
		return b.base.Add(time.Duration(e.expire)), ok
	}
	return time.Time{}, false
}

// add backs off p in t for d, never shortening a longer backoff; a full table first drops one entry.
// It returns the entries it looked at: one, or the whole table when it was full.
func (b *backoffs) add(now time.Time, t wire.Topic, p PeerID, d time.Duration, owed bool, limit int, connected map[PeerID]*peer) int {
	tb := b.m[t]
	if tb == nil {
		tb = &backoffTable{topic: t, m: map[PeerID]backoffEntry{}}
		b.m[t] = tb
	}
	expire := int64(now.Add(d).Sub(b.base))
	old, ok := tb.m[p]
	if ok {
		old.owed = old.owed || owed
		if old.expire < expire {
			old.expire = expire
		}
		tb.m[p] = old
		return 1
	}
	steps := 1
	if len(tb.m) >= limit {
		steps += len(tb.m)
		b.looked += len(tb.m) // victim reads every entry
		delete(tb.m, victim(tb.m, connected))
	}
	tb.m[p] = backoffEntry{expire: expire, owed: owed}
	return steps
}

// victim chooses the entry to drop from a full table: one we are not owed first (a refused GRAFT: keys that
// come and go cannot push out the backoffs we must respect), then a disconnected peer, then the earliest expiry,
// then the lowest key, so the choice never depends on map order.
func victim(m map[PeerID]backoffEntry, connected map[PeerID]*peer) PeerID {
	var best PeerID
	var be backoffEntry
	bestConn, found := false, false
	for p, e := range m {
		conn := connected[p] != nil
		var better bool
		switch {
		case !found:
			better = true
		case e.owed != be.owed:
			better = !e.owed
		case conn != bestConn:
			better = !conn
		default:
			better = e.expire < be.expire || (e.expire == be.expire && bytes.Compare(p[:], best[:]) < 0)
		}
		if better {
			best, be, bestConn, found = p, e, conn, true
		}
	}
	return best
}

func (b *backoffs) join(t wire.Topic) {
	if tb := b.m[t]; tb != nil && tb.left {
		tb.left = false
		b.left = slices.DeleteFunc(b.left, func(x wire.Topic) bool { return x == t })
	}
}

// leave keeps t's table; at most maxLeft tables of left topics are kept, the oldest dropped first.
func (b *backoffs) leave(t wire.Topic, now time.Time, maxLeft int) {
	tb := b.m[t]
	if tb == nil {
		return
	}
	tb.left = true
	b.left = append(b.left, t)
	if len(b.left) > maxLeft {
		delete(b.m, b.left[0])
		b.left = b.left[1:]
	}
}

// cleanup drops backoffs that ended more than slack ago; the slack covers the heartbeat offset of the other side.
func (b *backoffs) cleanup(now time.Time, slack time.Duration) {
	for t, tb := range b.m {
		for p, e := range tb.m {
			if b.base.Add(time.Duration(e.expire) + slack).Before(now) {
				delete(tb.m, p)
			}
		}
		if len(tb.m) == 0 && tb.left {
			delete(b.m, t)
			b.left = slices.DeleteFunc(b.left, func(x wire.Topic) bool { return x == t })
		}
	}
}

type promise struct {
	id     wire.ID
	peer   PeerID
	n      uint64
	expire time.Time
}

// promised is one peer's open promise for an id, by its number.
type promised struct {
	peer PeerID
	n    uint64
}

// promises tracks one asked id per IWANT: if it does not arrive in time, the advertiser broke its promise. A
// peer's promises numbered up to its released mark end without a penalty, so releasing them costs nothing.
type promises struct {
	q    []promise // in creation order, so in expiry order
	open map[wire.ID][]promised
	seq  uint64 // the last number given
}

// add records p's promise to deliver id before expire, unless one of its live promises has id already.
func (ps *promises) add(id wire.ID, p *peer, expire time.Time) {
	refs := ps.open[id]
	if i := slices.IndexFunc(refs, func(q promised) bool { return q.peer == p.id }); i >= 0 {
		if refs[i].n > p.released {
			return
		}
		refs = slices.Delete(refs, i, i+1)
	}
	ps.seq++
	ps.open[id] = append(refs, promised{p.id, ps.seq})
	ps.q = append(ps.q, promise{id, p.id, ps.seq, expire})
}

func (ps *promises) fulfill(id wire.ID) {
	delete(ps.open, id)
}

// broken returns, in creation order, the promises that expired before now unfulfilled, of peers still connected
// that did not release them.
func (ps *promises) broken(now time.Time, connected map[PeerID]*peer) []promise {
	var out []promise
	n := 0
	for ; n < len(ps.q) && ps.q[n].expire.Before(now); n++ {
		pr := ps.q[n]
		refs := ps.open[pr.id]
		i := slices.Index(refs, promised{pr.peer, pr.n})
		if i < 0 {
			continue
		}
		if p := connected[pr.peer]; p != nil && pr.n > p.released {
			out = append(out, pr)
		}
		if refs = slices.Delete(refs, i, i+1); len(refs) == 0 {
			delete(ps.open, pr.id)
		} else {
			ps.open[pr.id] = refs
		}
	}
	ps.q = slices.Delete(ps.q, 0, n)
	return out
}
