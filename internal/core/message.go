package core

import (
	"errors"
	"slices"
	"time"

	"github.com/ciranda-dev/kolo-gossip/internal/wire"
)

// Message runs the receive pipeline on an encoded envelope from a peer, cheapest checks first, computing the id
// and checking the signature itself; the router keeps raw, so the caller must not change it afterwards. The
// driver uses MessageWithID and MessageSigned instead, so no signature is ever checked under its lock.
func (r *Router) Message(now time.Time, from PeerID, raw []byte) {
	id := wire.NewID(raw)
	if r.MessageWithID(now, from, raw, id) {
		ok := false
		if env, err := wire.DecodeEnvelope(raw, len(raw)); err == nil {
			ok = r.v.Signed(env, raw[:len(raw)-wire.SigSize])
		}
		r.MessageSigned(now, from, raw, id, ok)
	}
}

// MessageWithID takes an envelope whose id, wire.NewID(raw), the caller computed; it charges the hashing to the
// peer. It never checks a signature: true means the message is new and needs one, which the caller checks with
// Verifier.Signed outside the router and passes to MessageSigned. Anything else was decided here.
func (r *Router) MessageWithID(now time.Time, from PeerID, raw []byte, id wire.ID) bool {
	r.advance(now)
	p := r.byID[from]
	if p == nil {
		return false
	}
	r.charge(p, OpHash, chunks(len(raw)))
	r.did(OpHash, chunks(len(raw)))
	return r.message(p, raw, id, nil)
}

// MessageSigned takes an envelope whose signature the caller checked after MessageWithID asked for it; the check
// is charged to the peer. If the message became known meanwhile, it is a duplicate.
func (r *Router) MessageSigned(now time.Time, from PeerID, raw []byte, id wire.ID, signed bool) {
	r.advance(now)
	p := r.byID[from]
	if p == nil {
		return
	}
	// The check hashes the whole message, and the reader decoded the envelope for it.
	r.charge(p, OpSignature, 1)
	r.charge(p, OpSigBytes, chunks(len(raw)))
	r.charge(p, OpDecode, chunks(len(raw)))
	r.did(OpSignature, 1)
	r.did(OpSigBytes, chunks(len(raw)))
	r.did(OpDecode, chunks(len(raw)))
	r.message(p, raw, id, &signed)
}

// known reports whether id was seen or is held waiting for its author's chain or its validator.
func (r *Router) known(id wire.ID) bool {
	r.did(OpLookup, 2)
	return r.seen.has(id) || r.recs[id] != nil
}

// skipped reports whether id was ignored for its content or author, so its copies are dropped without a check.
func (r *Router) skipped(id wire.ID) bool {
	r.did(OpLookup, 1)
	return r.skipLong.has(id)
}

// skip remembers an id ignored for what holds for every copy of it, its content or its author, for IgnoredTTL;
// the id covers the whole envelope, signature included, so no other envelope can take it. Past MaxIgnoredIDs an
// id is not kept, which only costs work.
func (r *Router) skip(id wire.ID) {
	r.did(OpLookup, 1)
	if r.skipLong.len() < r.cfg.MaxIgnoredIDs {
		r.skipLong.add(id)
	}
}

// message runs the pipeline for p; signed is nil until the caller checked the signature. It reports whether a
// signature check is needed first.
func (r *Router) message(p *peer, raw []byte, id wire.ID, signed *bool) (check bool) {
	r.stats.MessagesReceived++
	r.charge(p, OpCall, 1)
	r.charge(p, OpLookup, 7) // topic, seen, record, ignored, asked, promise, asking
	r.did(OpCall, 1)
	r.did(OpLookup, 1)
	asked, useful := r.askedOf(id, p), false
	// Whatever becomes of a copy, it keeps the promises made for its id; an answer we asked this very peer for
	// costs it nothing once it brings the message.
	defer func() {
		if !check {
			r.arrive(id, p, asked && useful, len(raw))
		}
	}()
	if r.grayFor(p) {
		r.stats.Graylisted++
		return false
	}
	t, ok := wire.EnvelopeTopic(raw)
	r.did(OpLookup, 1)
	tp := r.topics[t]
	if !ok || tp == nil || !tp.joined || p.refuses(t) {
		r.stats.NotJoined++
		return false
	}
	if len(raw) > tp.maxSize {
		r.stats.TooLarge++
		return false
	}
	if r.known(id) {
		r.stats.Duplicates++
		if rec := r.recs[id]; rec != nil {
			r.charge(p, OpAlloc, 1)
			r.charge(p, OpLookup, len(rec.peers)/4+1)
			r.duplicate(rec, p.id)
		}
		return false
	}
	if r.skipped(id) {
		r.stats.IgnoredCopies++
		return false
	}
	r.charge(p, OpBytes, chunks(len(raw)))
	r.did(OpBytes, chunks(len(raw)))
	env, err := wire.DecodeEnvelope(raw, tp.maxSize)
	if err != nil {
		r.stats.Malformed++
		r.score.invalid(p.id, t)
		return false
	}
	// Nothing below is the forwarder's fault unless the bytes are: the window, the author and our load are not,
	// so they cost no score; its buckets pay the work. Only what holds for every copy (the bytes, the author) is
	// remembered; anything that depends on our load or on this sender drops this copy alone.
	if !r.inWindow(env.Time) {
		r.stats.OutOfWindow++
		return false
	}
	if signed == nil {
		return true
	}
	r.stats.SignatureChecks++
	if !*signed {
		r.stats.BadSignature++
		r.score.invalid(p.id, t)
		r.skip(id)
		return false
	}
	// A copy of our own message is genuine: a restart or a second instance of our key, never the sender's fault.
	if PeerID(env.Device) == r.self {
		r.stats.SelfOrigin++
		r.skip(id)
		return false
	}
	// A full seen cache refuses new ids instead of evicting live ones, which could then be delivered twice; the
	// messages held count, since each becomes seen when its validator answers.
	if r.seen.len()+r.validating >= r.cfg.MaxSeen {
		r.stats.SeenFull++
		return false
	}
	open := !asked && !slices.Contains(tp.mesh, p.id)
	if r.throttled(p, len(raw), open) {
		return false
	}
	body := raw[:len(raw)-wire.SigSize]
	err = r.v.Verify(env, body)
	r.take(p)
	if errors.Is(err, ErrUnresolved) && r.resolver() != nil {
		useful = r.resolve(id, t, env, raw, p)
		return false
	}
	if err != nil {
		r.stats.UnknownAuthor++
		r.skip(id)
		r.idontwant(id, tp, len(raw), p)
		return false
	}
	rec := r.record(id, t, p)
	r.hold(rec, &pendingMsg{env: env, raw: raw, from: p.id, open: open})
	r.validate(rec, tp)
	useful = true
	return false
}

// payer returns the peer that pays for work on a message from id: the connected peer, or what is kept for its
// key after it left.
func (r *Router) payer(id PeerID) *peer {
	if p := r.byID[id]; p != nil {
		return p
	}
	if p := r.gone.m[id]; p != nil {
		return p
	}
	// A key with nothing kept: what it is charged is kept from now on, unless that would push out another key's
	// debt, and then it goes unpaid, at most the verdicts of the departed share.
	p := &peer{id: id}
	if len(r.gone.m) < r.cfg.MaxRetained {
		r.gone.put(p, r.mono(r.now), r.cfg.MaxRetained)
	}
	return p
}

// take charges p for the work the Verifier reported since the last call; nil is the node's own work. It runs
// right after every Verifier and Resolver call, so the work is never left for the next peer to pay.
func (r *Router) take(p *peer) {
	ops := r.v.Work()
	for op, n := range ops {
		r.charge(p, Op(op), n)
		r.did(Op(op), n)
	}
}

// idontwant tells the mesh, except from, that we do not want copies of a large message we ignored for its author
// or are validating.
func (r *Router) idontwant(id wire.ID, tp *topic, n int, from *peer) {
	if n < r.cfg.IDontWantThreshold {
		return
	}
	for _, q := range tp.mesh {
		if q != from.id {
			r.stats.IDontWantSent++
			r.push(from, r.byID[q], &wire.Control{IDontWant: []wire.ID{id}}, false)
		}
	}
}

// record starts the delivery record of a new id; it lasts SeenTTL unless its outcome ends it earlier.
func (r *Router) record(id wire.ID, t wire.Topic, p *peer) *seenRec {
	r.charge(p, OpAlloc, 1)
	r.did(OpAlloc, 1)
	rec := &seenRec{id: id, topic: t, expire: r.mono(r.now.Add(r.cfg.SeenTTL))}
	r.recs[id] = rec
	return rec
}

// accepted marks rec valid now; it stays for the topic's near-first window, so mesh copies still earn P3 credit.
func (r *Router) accepted(rec *seenRec, tp *topic) {
	rec.status, rec.validated, rec.expire = statusValid, r.now, r.mono(r.now)
	if tp.score != nil {
		rec.expire += int64(tp.score.MeshMessageDeliveriesWindow)
	}
}

// forget ends a delivery record: later copies of the id are plain duplicates. A validation it drops is canceled but
// stays in the global bounds until its validator answers; a message waiting for a chain leaves the Resolver too.
func (r *Router) forget(rec *seenRec, payer *peer) {
	if pm := rec.pending; pm != nil && pm.inst != 0 {
		r.running[pm.inst] = len(pm.raw)
		r.runningBytes += len(pm.raw)
		r.out.Cancel(pm.inst)
	} else if pm != nil && pm.resolving && pm.asks > 0 {
		if res := r.resolver(); res != nil {
			res.Forget(rec.id, pm.env)
			r.take(payer)
		}
	}
	r.dropValidation(rec)
	delete(r.recs, rec.id)
}

// validate sends IDONTWANT for a large verified message and hands its held record to the application validator as
// a new validation. The message came from pm.from, which pays.
func (r *Router) validate(rec *seenRec, tp *topic) {
	pm := rec.pending
	payer := r.payer(pm.from)
	r.idontwant(rec.id, tp, len(pm.raw), payer)
	r.charge(payer, OpSend, 1)
	r.did(OpSend, 1)
	r.validations++
	pm.inst = r.validations
	r.out.Validate(rec.id, pm.inst, pm.env, pm.from)
}

// throttled reports, and counts, a message of n bytes that the validation bounds cannot hold for its sender; only
// this copy is dropped. Besides its own and the global bounds, a sender holding messages gets no more than the
// global bounds over the senders holding any, and one outside the topic's mesh that we did not ask (open) shares
// half of them with the others like it. A sender holding nothing is held back only by the global and open bounds.
func (r *Router) throttled(p *peer, n int, open bool) bool {
	r.did(OpLookup, 1)
	h := r.holding[p.id]
	senders := len(r.holding)
	if r.departed.count > 0 {
		senders++
	}
	if h.count == 0 {
		senders++
	}
	if h.count >= r.cfg.MaxPeerValidating || h.bytes > r.cfg.MaxPeerValidatingBytes-n ||
		r.validating+len(r.running) >= r.cfg.MaxValidating || r.validatingBytes+r.runningBytes > r.cfg.MaxValidatingBytes-n ||
		open && (r.open >= r.cfg.MaxValidating/2 || r.openBytes > r.cfg.MaxValidatingBytes/2-n) ||
		h.count > 0 && (h.count+1 > r.cfg.MaxValidating/senders || h.bytes+n > r.cfg.MaxValidatingBytes/senders) {
		r.stats.Throttled++
		return true
	}
	return false
}

// hold keeps a message waiting for the validator or its author's chain, charged to its sender's share.
func (r *Router) hold(rec *seenRec, pm *pendingMsg) {
	rec.pending = pm
	r.validating++
	r.validatingBytes += len(pm.raw)
	if pm.open {
		r.open++
		r.openBytes += len(pm.raw)
	}
	h := r.holding[pm.from]
	h.count++
	h.bytes += len(pm.raw)
	pm.nextHeld, h.head = h.head, rec
	r.holding[pm.from] = h
}

// inWindow accepts author times from now-MaxAge to now+MaxSkew; with MaxAge+MaxSkew <= SeenTTL a message old
// enough to have left the seen cache is always refused, so a replay is never delivered twice.
func (r *Router) inWindow(ms uint64) bool {
	if ms > 1<<63-1 {
		return false
	}
	at := time.UnixMilli(int64(ms))
	return !at.Before(r.now.Add(-r.cfg.MaxAge)) && !at.After(r.now.Add(r.cfg.MaxSkew))
}

// duplicate scores a copy of a message that still has a delivery record: near-first credit for mesh peers, P4 for
// copies of an invalid message.
func (r *Router) duplicate(rec *seenRec, from PeerID) {
	r.did(OpAlloc, 1)
	r.did(OpLookup, len(rec.peers)/4+1) // the list is searched
	if slices.Contains(rec.peers, from) {
		return
	}
	switch rec.status {
	case statusUnknown, statusValid:
		if len(rec.peers) < len(r.peers) {
			rec.peers = append(rec.peers, from)
		}
		if rec.status == statusValid {
			r.score.nearFirst(r.now, from, rec.topic, rec.validated)
			r.credit(from, r.topics[rec.topic])
		}
	case statusInvalid:
		r.score.invalid(from, rec.topic)
	}
}

// ValidationDone applies the application validator's verdict for validation n of message id, passed to
// Sink.Validate; its work is charged to the key that sent the message. A verdict that comes after the message's
// SeenTTL is an Ignore, and one for a validation the router dropped only frees its place.
func (r *Router) ValidationDone(now time.Time, id wire.ID, n uint64, v Verdict) {
	r.advance(now)
	if b, ok := r.running[n]; ok {
		delete(r.running, n)
		r.runningBytes -= b
		return
	}
	rec := r.recs[id]
	if rec == nil || rec.pending == nil || rec.pending.inst != n || n == 0 {
		return
	}
	pm := rec.pending
	tp := r.topics[rec.topic]
	late := tp == nil || !tp.joined || r.mono(r.now) > rec.expire
	if v == Retry && !late {
		r.stats.Retried++
		pm.inst, pm.retry, pm.retryAt = 0, true, r.mono(r.now)
		r.retrying = append(r.retrying, rec)
		return
	}
	p := r.payer(pm.from)
	r.dropValidation(rec)
	if late {
		v = Ignore
	}
	// An id becomes seen once its validator decided, so an Ignore keeps the message out of the seen cache.
	switch v {
	case Accept:
		r.seen.add(id)
		r.accepted(rec, tp)
		r.score.firstDelivery(pm.from, rec.topic)
		r.credit(pm.from, tp)
		for _, q := range rec.peers {
			if q != pm.from {
				r.score.nearFirst(r.now, q, rec.topic, time.Time{})
				r.credit(q, tp)
			}
		}
		r.stats.Delivered++
		r.charge(p, OpBytes, chunks(len(pm.env.Body))) // the delivery copies the body
		r.did(OpBytes, chunks(len(pm.env.Body)))
		r.out.Deliver(id, pm.env, pm.from)
		// A message about to leave the window is neither forwarded nor cached, so no IHAVE announces it either.
		if !r.forwardable(pm.env.Time) {
			r.stats.EdgeOfWindow++
			break
		}
		looked := r.cache.looked
		steps := r.cache.put(id, rec.topic, pm.raw, r.cfg.MaxCacheMessages, r.cfg.MaxCacheBytes, &r.stats)
		r.charge(p, OpLookup, 2+steps)
		r.did(OpLookup, 2+r.cache.looked-looked)
		for _, q := range r.wanted(p, tp.mesh, id) {
			if q != pm.from && q != PeerID(pm.env.Device) {
				r.sendMessage(p, q, pm.raw)
			}
		}
	case Reject:
		r.seen.add(id)
		rec.status = statusInvalid
		r.stats.Rejected++
		r.score.invalid(pm.from, rec.topic)
		for _, q := range rec.peers {
			r.score.invalid(q, rec.topic)
		}
		rec.peers = nil
	default:
		// The validator sees the forwarder (Message.From), so its Ignore may concern this copy only: another sender's
		// copy is validated again.
		if !late && r.revalidate(rec, pm) {
			return
		}
		r.forget(rec, p)
		r.stats.Ignored++
	}
}

// Revalidate validates again every message of t whose validator answered Retry.
func (r *Router) Revalidate(now time.Time, t wire.Topic) {
	r.advance(now)
	r.retryWhere(func(rec *seenRec) bool { return rec.topic == t })
}

// retryWhere hands the retrying messages that due selects to the validator again, in the order they were held, each
// charged to its sender like a first validation.
func (r *Router) retryWhere(due func(*seenRec) bool) {
	var run []*seenRec
	r.retrying = slices.DeleteFunc(r.retrying, func(rec *seenRec) bool {
		if !due(rec) {
			return false
		}
		run = append(run, rec)
		return true
	})
	if len(r.retrying) == 0 {
		r.retrying = nil
	}
	for _, rec := range run {
		pm := rec.pending
		pm.retry = false
		payer := r.payer(pm.from)
		r.charge(payer, OpSend, 1)
		r.did(OpSend, 1)
		r.validations++
		pm.inst = r.validations
		r.out.Validate(rec.id, pm.inst, pm.env, pm.from)
	}
}

// revalidate hands an ignored message to the validator again as the copy of the next peer of the record that sent
// it and has room in its share; false means none is left.
func (r *Router) revalidate(rec *seenRec, pm *pendingMsg) bool {
	for pm.again < 2 && int(pm.again) < len(rec.peers) {
		q := rec.peers[pm.again]
		pm.again++
		qp := r.byID[q]
		open := !slices.Contains(r.topics[rec.topic].mesh, q)
		if q == pm.from || qp == nil || r.throttled(qp, len(pm.raw), open) {
			continue
		}
		r.charge(qp, OpAlloc, 1)
		r.did(OpAlloc, 1)
		r.hold(rec, &pendingMsg{env: pm.env, raw: pm.raw, from: q, again: pm.again, open: open})
		r.charge(qp, OpSend, 1)
		r.did(OpSend, 1)
		r.validations++
		rec.pending.inst = r.validations
		r.out.Validate(rec.id, rec.pending.inst, pm.env, q) // its IDONTWANT went out with the first validation
		return true
	}
	return false
}

// forwardable reports whether an author time is still a heartbeat inside the window on both sides, so a message
// we forward does not leave the window before the next hop takes it.
func (r *Router) forwardable(ms uint64) bool {
	at := time.UnixMilli(int64(ms))
	margin := r.cfg.HeartbeatInterval
	return !at.Before(r.now.Add(-r.cfg.MaxAge+margin)) && !at.After(r.now.Add(r.cfg.MaxSkew-margin))
}

// dropValidation releases a message's place in the validation bounds and in its sender's share, or in the
// departed share.
func (r *Router) dropValidation(rec *seenRec) {
	pm := rec.pending
	if pm == nil {
		return
	}
	r.validating--
	r.validatingBytes -= len(pm.raw)
	if pm.retry {
		r.retrying = slices.DeleteFunc(r.retrying, func(q *seenRec) bool { return q == rec })
	}
	if pm.open {
		r.open--
		r.openBytes -= len(pm.raw)
	}
	if pm.departed {
		d := &r.departed
		d.count--
		d.bytes -= len(pm.raw)
		if i := slices.Index(d.recs, rec); i >= 0 {
			d.recs = slices.Delete(d.recs, i, i+1)
		}
	} else if h, ok := r.holding[pm.from]; ok {
		h.count--
		h.bytes -= len(pm.raw)
		// Unlink rec from the sender's list, at most MaxPeerValidating long.
		for at := &h.head; *at != nil; at = &(*at).pending.nextHeld {
			if *at == rec {
				*at = pm.nextHeld
				break
			}
		}
		if h.count <= 0 {
			delete(r.holding, pm.from)
		} else {
			r.holding[pm.from] = h
		}
	}
	rec.pending = nil
}

// sendMessage queues raw for q, charged to payer, the peer whose frame caused it (nil for our own work).
func (r *Router) sendMessage(payer *peer, q PeerID, raw []byte) bool {
	r.charge(payer, OpSend, 1)
	r.did(OpSend, 1)
	r.stats.MessagesSent++
	if !r.out.SendMessage(q, raw) {
		r.stats.SendDropped++
		return false
	}
	return true
}
