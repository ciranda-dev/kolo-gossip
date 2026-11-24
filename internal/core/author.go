package core

import (
	"bytes"
	"errors"
	"slices"
	"time"

	"github.com/ciranda-dev/kolo-gossip/internal/wire"
)

var (
	// ErrUnresolved from Verifier.Verify means the author's certificate chain must be fetched first; with a
	// Resolver the message waits, within the validation bounds, otherwise it is ignored.
	ErrUnresolved = errors.New("kologossip: author chain not resolved")
	// ErrUnknownAuthor from Verifier.Verify or in a Resolution means the author cannot be checked: the message is
	// ignored without penalty, as is every other author error.
	ErrUnknownAuthor = errors.New("kologossip: unknown author")
	// ErrPeerBusy from Resolver.Resolve means this forwarder already has as many requests as it may: only its copy
	// is dropped, and a copy from another peer is taken.
	ErrPeerBusy = errors.New("kologossip: forwarder has too many requests")
)

// Resolver is an optional part of a Verifier that fetches missing author chains with CERTWANT from the peers that
// forwarded a message and serves its own chains with CERT. Its methods must not call back into the Router.
type Resolver interface {
	// Resolve is called for a message whose Verify returned ErrUnresolved: a request to send to from, nil to wait
	// for a request already sent, or an error that leaves this copy unresolved (ErrPeerBusy: from has as many
	// requests as it may).
	Resolve(now time.Time, id wire.ID, env *wire.Envelope, signed []byte, from PeerID) (*wire.CertWant, error)
	// CertWant returns the encoded chains, or "not held", for a peer's requests, within its per-heartbeat bound.
	CertWant(from PeerID, w []wire.CertWant) [][]byte
	// Cert takes the chains a peer sent and returns what they decide. It stops before a chain check once its work
	// for this call reaches budget units, ending the peer's remaining requests without a penalty.
	Cert(now time.Time, from PeerID, certs [][]byte, budget int64) Resolutions
	// Expire returns what the requests unanswered by now decide; the router calls it every heartbeat.
	Expire(now time.Time) Resolutions
	// Dropped forgets the message id waiting on a request our own full queue did not send.
	Dropped(to PeerID, id wire.ID, w wire.CertWant)
	// End ends every request to a peer we stopped reading or that left, without a penalty.
	End(p PeerID) Resolutions
	// Forget drops message id, which the router no longer holds, from every request; a request left with none
	// ends without a penalty.
	Forget(id wire.ID, env *wire.Envelope)
	// Leave drops the waiting messages of topic t and the requests left with none.
	Leave(t wire.Topic)
}

// Resolution is the author check of a message that waited for its chain, from one of the requests made for it:
// nil verified, any error ends that request.
type Resolution struct {
	ID  wire.ID
	Err error
}

// Resolutions are the messages a Resolver decided and the peers whose requests broke, unanswered in time or
// answered with a bad chain; each broken request costs its peer one behaviour penalty.
type Resolutions struct {
	Done   []Resolution
	Broken []PeerID
}

func (r *Router) resolver() Resolver {
	res, _ := r.v.(Resolver)
	return res
}

// resolve holds a message whose author's chain must be fetched, charged to its sender p's share, and asks p for the
// chain; it reports whether the message is held. Later copies are duplicates meanwhile; their senders are asked next.
func (r *Router) resolve(id wire.ID, t wire.Topic, env *wire.Envelope, raw []byte, p *peer) bool {
	rec := r.record(id, t, p)
	pm := &pendingMsg{env: env, raw: raw, from: p.id, resolving: true}
	if !r.request(p, rec, pm, p.id) {
		delete(r.recs, id)
		return false
	}
	r.hold(rec, pm)
	r.stats.Resolving++
	return true
}

// request asks peer to for the chain of rec's message, charged to payer; false means the Resolver refused or our
// queue to the peer is full, which leaves this request out.
func (r *Router) request(payer *peer, rec *seenRec, pm *pendingMsg, to PeerID) bool {
	res := r.resolver()
	want, err := res.Resolve(r.now, rec.id, pm.env, pm.raw[:len(pm.raw)-wire.SigSize], to)
	r.take(payer)
	if err != nil {
		r.stats.UnknownAuthor++
		return false
	}
	if want != nil {
		r.stats.CertWantSent++
		r.stats.ControlSent++
		r.charge(payer, OpSend, 1)
		r.charge(payer, OpBytes, 2)
		if payer != nil {
			r.did(OpSend, 1)
			r.did(OpBytes, 2)
		}
		if !r.out.SendControl(to, &wire.Control{CertWant: []wire.CertWant{*want}}, true) {
			r.stats.SendDropped++
			res.Dropped(to, rec.id, *want)
			r.take(payer)
			return false
		}
	}
	pm.asks++
	pm.sent = r.mono(r.now)
	return true
}

// retry asks the next peer that sent a copy of rec's message and that we read now; false means none is left. The
// record's peers stay as they are, for their scores: a cursor walks them.
func (r *Router) retry(payer *peer, rec *seenRec, pm *pendingMsg) bool {
	for int(pm.next) < len(rec.peers) {
		q := rec.peers[pm.next]
		pm.next++
		if qp := r.byID[q]; qp == nil || qp.waiting || q == pm.from {
			continue
		}
		if r.request(payer, rec, pm, q) {
			return true
		}
	}
	return false
}

// hedge asks one more peer, every heartbeat, for each chain still unanswered after a heartbeat, so peers that
// relay first and never answer delay a message by one heartbeat each at most.
func (r *Router) hedge() {
	var recs []*seenRec
	for _, rec := range r.recs {
		if pm := rec.pending; pm != nil && pm.resolving && r.mono(r.now)-pm.sent >= int64(r.cfg.HeartbeatInterval) {
			recs = append(recs, rec)
		}
	}
	slices.SortFunc(recs, func(a, b *seenRec) int { return bytes.Compare(a.id[:], b.id[:]) })
	for _, rec := range recs {
		r.retry(nil, rec, rec.pending)
	}
}

// resolved applies a Resolver's decisions, charged to payer (nil for our own heartbeat). A message whose requests
// all ended without a chain asks the next peer that sent a copy, else it is forgotten so a later copy is taken.
func (r *Router) resolved(payer *peer, rs Resolutions) {
	for _, b := range rs.Broken {
		r.stats.CertBroken++
		r.score.penalty(b, 1)
	}
	for _, d := range rs.Done {
		r.charge(payer, OpLookup, 2)
		if payer != nil {
			r.did(OpLookup, 2)
		}
		rec := r.recs[d.ID]
		if rec == nil || rec.pending == nil || !rec.pending.resolving {
			continue
		}
		pm := rec.pending
		tp := r.topics[rec.topic]
		switch {
		case d.Err != nil:
			if pm.asks--; pm.asks > 0 || r.retry(payer, rec, pm) {
				continue
			}
			r.forget(rec, payer)
			r.stats.UnknownAuthor++
			continue
		case tp == nil || !tp.joined:
			r.forget(rec, payer)
			r.stats.Ignored++
			continue
		}
		pm.resolving = false
		r.validate(rec, tp)
	}
}

// handleCertWant answers a peer's certificate requests from the Resolver's chains, charged to the peer.
func (r *Router) handleCertWant(p *peer, ws []wire.CertWant) [][]byte {
	if len(ws) == 0 {
		return nil
	}
	r.stats.CertWantReceived++
	res := r.resolver()
	if res == nil {
		return nil
	}
	certs := res.CertWant(p.id, ws)
	r.take(p)
	r.stats.CertSent += uint64(len(certs))
	return certs
}

// handleCert passes the chains a peer sent to the Resolver and applies what they decide, charged to the peer.
func (r *Router) handleCert(p *peer, certs [][]byte) {
	if len(certs) == 0 {
		return
	}
	r.stats.CertReceived++
	if res := r.resolver(); res != nil {
		// Answers to our own requests are checked even when reading this frame took the bucket below zero: at
		// most one chain check per certificate, still charged.
		budget := max(p.lock.level, 0) + Cost(OpChain, min(len(certs), r.cfg.MaxCerts))
		out := res.Cert(r.now, p.id, certs, budget)
		r.take(p)
		r.resolved(p, out)
	}
}
