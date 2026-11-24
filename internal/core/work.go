package core

import (
	"math"
	"slices"
	"time"
)

// Unit is the measure of work a peer makes us do: 10 ns of one core, the cost of each operation below rounded up
// from the benchmarks of this package and of internal/auth on an Apple M5 (docs/limits.md, Worst case).
const Unit = 10 * time.Nanosecond

// Op is a kind of operation whose cost a peer pays.
type Op int

// The operations a peer's frames cause. Under the router lock: OpCall to OpCert; on the peer's own reader,
// outside the lock: OpHash to OpDecode.
const (
	OpCall      Op = iota // a frame taken by the router: the call, its clock and its peer and score checks
	OpLookup              // one map or sorted-list lookup or insert
	OpAlloc               // one allocation: a record, a list entry
	OpBytes               // 64 bytes decoded, copied or encoded
	OpSend                // one frame queued for a peer
	OpCallback            // one call into the application: a roster lookup, the open mode, the application score
	OpChain               // one kolo-id chain verification
	OpCert                // one kolo-id certificate decoded
	OpHash                // 64 bytes hashed into a message id
	OpSignature           // one Ed25519 signature check, the message hashing aside
	OpSigBytes            // 64 bytes of a message hashed by its signature check (SHA-512)
	OpDecode              // 64 bytes of a control frame decoded
	OpDial                // one peer exchange dial: the handshake it makes us run
	NumOps
)

// Ops counts operations by kind.
type Ops [NumOps]int

// units is the cost of each operation in units.
var units = [NumOps]int64{
	OpCall:      8,
	OpLookup:    2,
	OpAlloc:     6,
	OpBytes:     2,
	OpSend:      10,
	OpCallback:  20,
	OpChain:     25_000,
	OpCert:      80,
	OpHash:      3,
	OpSignature: 3_000,
	OpSigBytes:  5,
	OpDecode:    4,
	OpDial:      162_000,
}

// outside reports whether op runs on the peer's reader, outside the router lock.
func (op Op) outside() bool { return op >= OpHash }

// Cost returns n operations of kind op in units.
func Cost(op Op, n int) int64 { return units[op] * int64(n) }

// chunks returns the 64-byte chunks of n bytes, rounded up.
func chunks(n int) int { return (n + 63) / 64 }

// bucket is a work budget: it refills continuously at a rate up to a capacity, and a peer whose bucket is empty
// is not read until it is positive again.
type bucket struct {
	level int64 // units; may go below zero by the cost of the operation that emptied it
	at    int64 // when level was last brought up to date, in nanoseconds of the router's monotonic clock
}

// refill brings b up to at at rate units per second, within capacity; a debt is paid back first.
func (b *bucket) refill(at, rate, capacity int64) {
	if d := at - b.at; d > 0 {
		add := float64(rate) * float64(d) / 1e9
		b.level = int64(min(float64(capacity), float64(b.level)+add))
		b.at = at
	}
	// A share shrinks as peers connect, so what a bucket holds is capped at its share now.
	b.level = min(capacity, b.level)
}

// maxWait bounds a wait, so a bucket deep in debt is read again within a minute and its debt paid as it goes.
const maxWait = time.Minute

// wait returns how long b needs at rate to become positive, 0 when it is.
func (b *bucket) wait(rate int64) time.Duration {
	if b.level > 0 {
		return 0
	}
	// One unit more than needed covers the rounding of refill.
	return min(maxWait, time.Duration(math.Ceil(float64(2-b.level)/float64(rate)*float64(time.Second))))
}

// mono returns now in nanoseconds since the router started, from the monotonic clock when now carries one, so a
// step of the wall clock never stops a refill.
func (r *Router) mono(now time.Time) int64 { return int64(now.Sub(r.start)) }

// rates returns the refill rates of p's buckets, the lock budget and the reader budget each split three ways: half
// equally among the peers connected now, a quarter by mesh places and a quarter by the valid messages mesh peers
// delivered, both as of the last heartbeat. Without mesh places everything is shared equally. A peer's reader rate
// is at most PeerWork; every rate is at least 1.
func (r *Router) rates(p *peer) (lock, out int64) {
	return r.share(r.cfg.LockWork, p), min(r.cfg.PeerWork, r.share(r.cfg.ReaderWork, p))
}

func (r *Router) share(budget int64, p *peer) int64 {
	s := 1 / float64(max(1, len(r.peers)))
	if r.meshPlaces > 0 {
		mesh := float64(p.meshN) / float64(r.meshPlaces)
		traffic := mesh
		if r.delivered > 0 {
			traffic = float64(p.delivered) / float64(r.delivered)
		}
		s = s/2 + mesh/4 + traffic/4
	}
	return max(1, int64(float64(budget)*s))
}

// credit counts a valid message that id delivered, first or as a copy, when it is in tp's mesh.
func (r *Router) credit(id PeerID, tp *topic) {
	p := r.byID[id]
	if p == nil || tp == nil || !slices.Contains(tp.mesh, id) {
		return
	}
	if p.ring == nil {
		p.ring = make([]int32, r.cfg.HistoryLength)
	}
	p.ring[r.ticks%uint64(len(p.ring))]++
}

// snapshotShares fixes the mesh places and delivered messages that rates splits by until the next heartbeat.
func (r *Router) snapshotShares() {
	r.meshPlaces, r.delivered = 0, 0
	for _, p := range r.peers {
		p.meshN = 0
		r.delivered += p.delivered
	}
	for _, tp := range r.topics {
		for _, id := range tp.mesh {
			r.byID[id].meshN++
			r.meshPlaces++
		}
	}
}

// node is the newcomer pool, which gives new and returning keys their first burst; it refills at one share of a
// full node for all of them together.
type node struct {
	pool, poolOut bucket
}

// nodeRates returns the refill rate and capacity of the node's buckets: newcomerShares-th of the lock budget, and of
// the reader pool one peer's reader rate over newcomerShares, each holding WorkBurst.
func (r *Router) nodeRates() (lock, out, lockCap, outCap int64) {
	lock, out = r.cfg.LockWork/newcomerShares, r.cfg.PeerWork/newcomerShares
	b := r.cfg.WorkBurst.Seconds()
	return lock, out, int64(float64(lock) * b), int64(float64(out) * b)
}

// refillNode brings the node's buckets up to now.
func (r *Router) refillNode() {
	lock, out, lockCap, outCap := r.nodeRates()
	at := r.mono(r.now)
	r.node.pool.refill(at, lock, lockCap)
	r.node.poolOut.refill(at, out, outCap)
}

// charge takes n operations of kind op from p's bucket for it, and counts them for the unit audit; a nil p is
// the node's own work, which nobody pays.
func (r *Router) charge(p *peer, op Op, n int) {
	if n <= 0 || p == nil {
		return
	}
	c := Cost(op, n)
	if op.outside() {
		p.out.level -= c
	} else {
		p.lock.level -= c
	}
	r.audited(p.id, op, int64(n))
}

// audit is the unit audit's count: operations done, and operations charged to the payer it counts (any payer
// unless one is set).
type audit struct {
	done, charged map[Op]int64
	one           bool
	peer          PeerID
}

// audited counts n charged operations of kind op paid by p, when the audit counts that payer.
func (r *Router) audited(p PeerID, op Op, n int64) {
	if a := r.audit; a != nil && (!a.one || p == a.peer) {
		a.charged[op] += n
	}
}

// refund gives back n operations of kind op that p was charged for work we asked of it.
func (r *Router) refund(p *peer, op Op, n int) {
	if p == nil {
		return
	}
	c := Cost(op, n)
	if op.outside() {
		p.out.level += c
	} else {
		p.lock.level += c
	}
	r.audited(p.id, op, -int64(n))
}

// did counts n operations of kind op actually done, for the unit audit; it costs nothing otherwise.
func (r *Router) did(op Op, n int) {
	if r.audit != nil {
		r.audit.done[op] += int64(n)
	}
}

// Wait reports how long the driver must wait before it reads p's next frame: 0 while both of p's buckets are
// positive. A waiting peer drops its promises and certificate requests without a penalty, so others are asked.
func (r *Router) Wait(now time.Time, from PeerID) time.Duration {
	r.advance(now)
	p := r.byID[from]
	if p == nil {
		return 0
	}
	lock, out := r.rates(p)
	burst := r.cfg.WorkBurst.Seconds()
	at := r.mono(r.now)
	p.lock.refill(at, lock, int64(float64(lock)*burst))
	p.out.refill(at, out, int64(float64(out)*burst))
	w := max(p.lock.wait(lock), p.out.wait(out))
	if w > 0 && !p.waiting {
		p.waiting = true
		r.stats.Waits++
		r.release(p)
	}
	if w == 0 {
		p.waiting = false
	}
	return w
}

// release ends p's promises, IWANT asks and certificate requests without a penalty, so they are asked of other
// peers: p is not read now, or has left. p pays, and the work depends on what p holds alone.
func (r *Router) release(p *peer) {
	// Each id of p's index: the ask looked up, both lists searched and changed, the index entry deleted.
	n := 1 + 6*len(p.asking)
	r.charge(p, OpLookup, n)
	r.did(OpLookup, n)
	p.released = r.promises.seq
	for id := range p.asking {
		r.unask(id, p)
	}
	if res := r.resolver(); res != nil {
		out := res.End(p.id)
		r.take(p)
		r.resolved(p, out)
	}
}

// AuditOps turns on the unit audit: from now on the router counts the operations it does and the operations it
// charges to anyone. For tests.
func (r *Router) AuditOps() {
	r.audit = &audit{done: map[Op]int64{}, charged: map[Op]int64{}}
}

// AuditPeer is AuditOps counting only what p pays, so work charged to another peer shows as unpaid.
func (r *Router) AuditPeer(p PeerID) {
	r.AuditOps()
	r.audit.one, r.audit.peer = true, p
}

// Audit returns the operations done and charged since AuditOps or the last Audit, and starts a new count with the
// same payer.
func (r *Router) Audit() (done, charged map[Op]int64) {
	a := r.audit
	done, charged = a.done, a.charged
	a.done, a.charged = map[Op]int64{}, map[Op]int64{}
	return done, charged
}
