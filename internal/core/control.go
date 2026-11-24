package core

import (
	"bytes"
	"fmt"
	"math"
	"math/bits"
	"net/netip"
	"slices"
	"time"

	"github.com/ciranda-dev/kolo-gossip/internal/wire"
)

// pending holds control for one peer: GRAFT, PRUNE and subscriptions are retried after a full queue, and
// heartbeat gossip waits for the heartbeat's flush.
type pending struct {
	subs  []wire.Topic
	graft []wire.Topic
	prune []wire.Prune
	ihave []wire.IHave
	cert  [][]byte // CERT answers a full queue dropped, at most MaxCerts
}

// Control handles a decoded control frame from a peer; ControlFrame with the frame's encoded size is the driver's
// entry. ErrProtocol means the peer broke a rule that ends the connection; nothing from that frame is applied.
func (r *Router) Control(now time.Time, from PeerID, c *wire.Control) error {
	return r.ControlFrame(now, from, c, c.Size())
}

// ControlFrame is Control for a frame of n encoded bytes, which the peer's reader decoded outside the router; the
// decoding and every entry the router looks at, past a cap or not, are charged to the peer.
func (r *Router) ControlFrame(now time.Time, from PeerID, c *wire.Control, n int) error {
	r.advance(now)
	p := r.byID[from]
	if p == nil {
		return nil
	}
	// Decoding costs by the byte and by the list entry: an entry is an allocation and a copy however small.
	dec := chunks(n) + 1 + c.Items()
	r.charge(p, OpDecode, dec)
	r.did(OpDecode, dec)
	r.charge(p, OpCall, 1)
	r.did(OpCall, 1)
	if r.grayFor(p) {
		r.stats.Graylisted++
		return nil
	}
	if len(c.Graft) > maxFrameTopics || len(c.Prune) > maxFrameTopics {
		r.stats.ProtocolErrors++
		return fmt.Errorf("%w: %d GRAFT and %d PRUNE entries, over %d", ErrProtocol, len(c.Graft), len(c.Prune), maxFrameTopics)
	}
	r.handleSubs(p, c.Subs)
	gossip := r.scoreFor(p) >= r.thresholds().Gossip
	reply := &wire.Control{}
	reply.IWant = r.handleIHave(p, c.IHave, gossip)
	r.handleIWant(p, c.IWant, gossip)
	reply.Prune = r.handleGraft(p, c.Graft)
	r.handlePrune(p, c.Prune)
	r.handleIDontWant(p, c.IDontWant)
	if gossip {
		reply.Cert = r.handleCertWant(p, c.CertWant)
	}
	r.handleCert(p, c.Cert)
	if !reply.Empty() {
		r.push(p, p, reply, true)
	}
	return nil
}

// askCap is how many ids we have asked one peer for at once: no more than its share of the design rate.
func (r *Router) askCap() int32 {
	return int32(min(r.cfg.MaxIHaveLength, r.cfg.DesignRate))
}

// handleSubs applies subscription changes, the last of each topic in the frame winning: those for topics we hold
// state for go to the peer's topics list, the others to its other list up to MaxPeerTopics, the rest dropped and
// counted. The frame is sorted and merged once, so its cost is that of the entries and the lists.
func (r *Router) handleSubs(p *peer, subs []wire.Sub) {
	if len(subs) == 0 {
		return
	}
	n, k := len(subs), len(r.topics)
	look := n*(bits.Len(uint(n))+1) + k*(bits.Len(uint(k))+1) + n
	move := chunks(len(wire.Topic{}) * (len(p.topics) + len(p.other) + n + k))
	r.charge(p, OpAlloc, 1)
	r.charge(p, OpLookup, look)
	r.charge(p, OpBytes, move)
	r.did(OpAlloc, 1)
	r.did(OpLookup, look)
	r.did(OpBytes, move)
	es := slices.Clone(subs)
	slices.SortStableFunc(es, func(a, b wire.Sub) int { return cmpTopic(a.Topic, b.Topic) })
	held := make([]wire.Topic, 0, len(r.topics))
	for t := range r.topics {
		held = append(held, t)
	}
	slices.SortFunc(held, cmpTopic)
	var ours, others []wire.Sub
	j := 0
	for i, s := range es {
		if i+1 < len(es) && es[i+1].Topic == s.Topic {
			continue
		}
		for j < len(held) && cmpTopic(held[j], s.Topic) < 0 {
			j++
		}
		if j < len(held) && held[j] == s.Topic {
			ours = append(ours, s)
		} else {
			others = append(others, s)
		}
	}
	p.topics, _ = mergeSubs(p.topics, ours, -1)
	var dropped int
	p.other, dropped = mergeSubs(p.other, others, r.cfg.MaxPeerTopics)
	r.stats.SubscriptionsDropped += uint64(dropped)
	for _, s := range ours {
		if tp := r.topics[s.Topic]; !s.Subscribe {
			if slices.Contains(tp.mesh, p.id) {
				r.score.prune(p.id, s.Topic)
				tp.mesh = remove(tp.mesh, p.id)
			}
			tp.fanout = remove(tp.fanout, p.id)
		}
	}
}

// mergeSubs applies es, sorted with one entry per topic, to the sorted list: unsubscribes remove, subscribes add
// while the list stays within limit (no limit when negative). It returns the new list and the subscribes dropped.
func mergeSubs(list []wire.Topic, es []wire.Sub, limit int) ([]wire.Topic, int) {
	if len(es) == 0 {
		return list, 0
	}
	var adds []wire.Topic
	out := make([]wire.Topic, 0, len(list)) // only list's topics go in: a frame of many entries must not leave its size behind
	i := 0
	for _, s := range es {
		for i < len(list) && cmpTopic(list[i], s.Topic) < 0 {
			out = append(out, list[i])
			i++
		}
		have := i < len(list) && list[i] == s.Topic
		switch {
		case have && s.Subscribe:
			out = append(out, list[i])
			i++
		case have:
			i++
		case s.Subscribe:
			adds = append(adds, s.Topic)
		}
	}
	out = append(out, list[i:]...)
	dropped := 0
	if limit >= 0 && len(out)+len(adds) > limit {
		keep := max(0, limit-len(out))
		dropped, adds = len(adds)-keep, adds[:keep]
	}
	if len(adds) == 0 {
		return out, dropped
	}
	merged := make([]wire.Topic, 0, len(out)+len(adds))
	i = 0
	for _, t := range adds {
		for i < len(out) && cmpTopic(out[i], t) < 0 {
			merged = append(merged, out[i])
			i++
		}
		merged = append(merged, t)
	}
	return append(merged, out[i:]...), dropped
}

// asking is an id we asked with IWANT: asked of at most two peers at once, with up to two more announcers kept and
// one of them asked each heartbeat, so peers that never answer delay it a heartbeat each, not a whole gossip window.
type asking struct {
	peers  [4]*peer // asked
	wait   [2]*peer // announced it after the first two, not asked yet
	n, nw  int8
	expire int64 // when the last ask ends, in nanoseconds of the router's monotonic clock: IWantFollowupTime after it
}

// has reports whether p was asked for the id or waits to be.
func (a *asking) has(p *peer) bool {
	return slices.Contains(a.peers[:a.n], p) || slices.Contains(a.wait[:a.nw], p)
}

// handleIHave asks for unseen advertised ids, within MaxIHaveMessages frames per heartbeat and MaxIHaveLength ids
// read per frame: an id is asked of at most two peers at once, and of one peer at most askCap ids at once. One
// random asked id is tracked as a promise.
func (r *Router) handleIHave(p *peer, ihave []wire.IHave, gossip bool) []wire.ID {
	if len(ihave) == 0 {
		return nil
	}
	r.stats.IHaveReceived++
	p.ihaves++
	if !gossip || p.ihaves > int32(r.cfg.MaxIHaveMessages) {
		return nil
	}
	var want []wire.ID
	scanned := 0
	at := r.mono(r.now)
	for _, h := range ihave {
		r.charge(p, OpLookup, 1)
		r.did(OpLookup, 1)
		if tp := r.topics[h.Topic]; tp == nil || !tp.joined || p.refuses(h.Topic) {
			continue
		}
		for _, id := range h.IDs {
			if scanned >= r.cfg.MaxIHaveLength {
				break
			}
			scanned++
			r.charge(p, OpLookup, 4) // seen, record, ignored, asked
			r.did(OpLookup, 1)
			if r.known(id) || r.skipped(id) {
				continue
			}
			a, ok := r.asks[id]
			switch {
			case a.has(p):
				continue
			case a.n < 2 && p.asked < r.askCap():
				a.peers[a.n], a.expire = p, at+int64(r.cfg.IWantFollowupTime)
				a.n++
				p.asked++
				want = append(want, id)
			case a.n > 0 && a.nw < 2 && p.waits < r.askCap():
				a.wait[a.nw] = p
				a.nw++
				p.waits++
			default:
				continue
			}
			if !ok {
				// A new ask is looked at by every heartbeat it lives through: paid now.
				r.charge(p, OpLookup, r.hedgeLookups())
			}
			r.charge(p, OpAlloc, 3)
			r.did(OpAlloc, 3)
			r.asks[id] = a
			if p.asking == nil {
				p.asking = map[wire.ID]struct{}{}
			}
			p.asking[id] = struct{}{}
		}
	}
	if len(want) == 0 {
		return nil
	}
	r.charge(p, OpAlloc, 1)
	r.did(OpAlloc, 1)
	shuffle(r.rnd, want)
	r.promises.add(want[r.rnd.IntN(len(want))], p, r.now.Add(r.cfg.IWantFollowupTime))
	r.stats.IWantSent++
	return want
}

// hedgeLookups is the heartbeat work one ask causes over its life, rounded up: each heartbeat looks at it, sorts it
// when due and checks its end, for IWantFollowupTime after each of up to four asks, the last two a heartbeat apart.
func (r *Router) hedgeLookups() int {
	beats := int((r.cfg.IWantFollowupTime + r.cfg.HeartbeatInterval - 1) / r.cfg.HeartbeatInterval)
	return 3 * (beats + 3)
}

// unlinkAsk removes id from p's ask index.
func (p *peer) unlinkAsk(id wire.ID) {
	delete(p.asking, id)
	if len(p.asking) == 0 {
		p.asking = nil // a map never gives back what a burst made it grow to
	}
}

// hedgeAsks asks, each heartbeat, one more announcer of every id still missing a heartbeat after it was last
// asked, and ends the asks whose time is up.
func (r *Router) hedgeAsks() {
	at := r.mono(r.now)
	var due []wire.ID
	for id, a := range r.asks {
		if asked := a.expire - int64(r.cfg.IWantFollowupTime); a.nw > 0 && a.n < 4 && (a.n < 2 || at-asked >= int64(r.cfg.HeartbeatInterval)) {
			due = append(due, id)
		}
	}
	slices.SortFunc(due, func(a, b wire.ID) int { return bytes.Compare(a[:], b[:]) })
	byPeer := map[*peer][]wire.ID{}
	for _, id := range due {
		a := r.asks[id]
		// Places freed by peers that waited or left are filled at once; otherwise one more peer is asked.
		k := 1
		if a.n < 2 {
			k = 2 - int(a.n)
		}
		for ; k > 0 && a.nw > 0 && a.n < 4; k-- {
			q := a.wait[0]
			a.wait[0], a.wait[1] = a.wait[1], nil
			a.nw--
			q.waits--
			if !q.waiting && q.asked < r.askCap() {
				a.peers[a.n], a.expire = q, at+int64(r.cfg.IWantFollowupTime)
				a.n++
				q.asked++
				byPeer[q] = append(byPeer[q], id)
			} else {
				q.unlinkAsk(id)
			}
		}
		if a.n == 0 && a.nw == 0 {
			delete(r.asks, id)
			continue
		}
		r.asks[id] = a
	}
	for _, q := range r.peers {
		if ids := byPeer[q]; len(ids) > 0 {
			r.promises.add(ids[r.rnd.IntN(len(ids))], q, r.now.Add(r.cfg.IWantFollowupTime))
			r.stats.IWantSent++
			r.sendControl(q, &wire.Control{IWant: ids}, false)
		}
	}
	for id, a := range r.asks {
		if a.expire < at {
			r.endAsk(id, a)
		}
	}
	if len(r.asks) == 0 {
		r.asks = map[wire.ID]asking{} // a map never gives back what a burst made it grow to
	}
}

// arrive ends the asking for an id that came from any peer, freeing the peers asked for it. If refund is set, from
// brought it because we asked it, and the work the message cost it is given back.
func (r *Router) arrive(id wire.ID, from *peer, refund bool, n int) {
	r.did(OpLookup, 2)
	r.promises.fulfill(id)
	if refund {
		r.refund(from, OpHash, chunks(n))
		r.refund(from, OpSignature, 1)
		r.refund(from, OpSigBytes, chunks(n))
		r.refund(from, OpDecode, chunks(n))
		r.refund(from, OpBytes, chunks(n))
	}
	if a, ok := r.asks[id]; ok {
		r.endAsk(id, a)
	}
}

// endAsk deletes the asking for id and frees the places of its peers.
func (r *Router) endAsk(id wire.ID, a asking) {
	delete(r.asks, id)
	for _, q := range a.peers[:a.n] {
		q.asked--
		q.unlinkAsk(id)
	}
	for _, q := range a.wait[:a.nw] {
		q.waits--
		q.unlinkAsk(id)
	}
}

// askedOf reports whether we asked p for id.
func (r *Router) askedOf(id wire.ID, p *peer) bool {
	a := r.asks[id]
	return slices.Contains(a.peers[:a.n], p)
}

// unask frees p's place in the asking for id, so the id can be asked of another peer.
func (r *Router) unask(id wire.ID, p *peer) {
	a, ok := r.asks[id]
	if !ok {
		return
	}
	if i := slices.Index(a.wait[:a.nw], p); i >= 0 {
		a.wait[i] = a.wait[a.nw-1]
		a.wait[a.nw-1] = nil
		a.nw--
		p.waits--
	}
	if i := slices.Index(a.peers[:a.n], p); i >= 0 {
		a.peers[i] = a.peers[a.n-1]
		a.peers[a.n-1] = nil
		a.n--
		p.asked--
	}
	p.unlinkAsk(id)
	if a.n == 0 && a.nw == 0 {
		delete(r.asks, id)
	} else {
		r.asks[id] = a
	}
}

// handleIWant answers from the message cache, at most GossipRetransmission times per peer per message within
// HistoryLength heartbeats, never with a message the peer sent IDONTWANT for, for at most MaxIHaveLength ids per
// frame, and only while the peer's queue takes them.
func (r *Router) handleIWant(p *peer, ids []wire.ID, gossip bool) {
	if len(ids) == 0 {
		return
	}
	r.stats.IWantReceived++
	if !gossip {
		return
	}
	for _, id := range ids[:min(len(ids), r.cfg.MaxIHaveLength)] {
		r.charge(p, OpLookup, 3) // unwanted, cache, answers sent
		r.did(OpLookup, 2)
		if p.unwanted.has(id) {
			continue
		}
		e := r.cache.m[id]
		if e == nil || p.refuses(e.topic) {
			continue
		}
		r.did(OpLookup, 1)
		sent := p.sent[id]
		if sent >= uint8(min(r.cfg.GossipRetransmission, 255)) || (sent == 0 && len(p.sent) >= r.cfg.MaxCacheMessages) {
			continue
		}
		if !r.sendMessage(p, p.id, e.raw) {
			return
		}
		if p.sent == nil {
			p.sent = map[wire.ID]uint8{}
		}
		r.charge(p, OpAlloc, 1)
		r.did(OpAlloc, 1)
		p.sent[id] = sent + 1
	}
}

// handleGraft applies GRAFT requests and returns the PRUNE replies; a topic listed twice counts once. A refusal
// because the mesh is full carries peer exchange, unless the frame grafts a topic we are not in.
func (r *Router) handleGraft(p *peer, grafts []wire.Topic) []wire.Prune {
	if len(grafts) == 0 {
		return nil
	}
	var full []wire.Topic
	px := true
	// Sorting at most maxFrameTopics topics, then for each a topic, mesh, backoff and score look and a reply.
	r.charge(p, OpLookup, 8*len(grafts))
	r.charge(p, OpAlloc, 2*len(grafts)+1)
	r.did(OpLookup, len(grafts))
	r.did(OpAlloc, 1)
	grafts = slices.Compact(slices.SortedFunc(slices.Values(grafts), cmpTopic))
	var prune []wire.Prune
	score := r.scoreFor(p)
	for _, t := range grafts {
		r.did(OpLookup, 3)
		tp := r.topics[t]
		if tp == nil || !tp.joined || p.refuses(t) {
			px = false // nor learn our peers of other topics
			continue   // GRAFT for a topic we are not in is ignored, so it cannot make us send anything
		}
		if slices.Contains(tp.mesh, p.id) {
			continue
		}
		r.did(OpLookup, 3)
		r.did(OpAlloc, 2)
		if exp, ok := r.backoff.expiry(t, p.id); ok && r.now.Before(exp) {
			r.score.penalty(p.id, 1)
			if r.now.Before(exp.Add(r.cfg.GraftFloodThreshold - r.cfg.PruneBackoff)) {
				r.score.penalty(p.id, 1)
			}
			prune = append(prune, r.refuse(p, t))
			continue
		}
		if score < 0 {
			prune = append(prune, r.refuse(p, t))
			continue
		}
		// At Dhi only outbound peers are accepted, so inbound sybils cannot take over the mesh.
		if len(tp.mesh) >= tp.params.Dhi && !p.outbound {
			prune = append(prune, r.refuse(p, t))
			full = append(full, t)
			continue
		}
		tp.mesh = append(tp.mesh, p.id)
		tp.grafted = append(tp.grafted, p.id)
		r.score.graft(r.now, p.id, t)
		if i, ok := slices.BinarySearchFunc(p.topics, t, cmpTopic); !ok { // a GRAFT implies the subscription
			p.topics = slices.Insert(p.topics, i, t)
		}
	}
	if px {
		for i := range prune {
			if slices.Contains(full, prune[i].Topic) {
				prune[i].PX = r.exchange(p, p.id, prune[i].Topic)
			}
		}
	}
	return prune
}

// exchange returns, when we send peer exchange, up to PrunePeers random peers of t with an address to dial and a
// score of at least 0 other than to, the peer pruned; payer pays for the search.
func (r *Router) exchange(payer *peer, to PeerID, t wire.Topic) []wire.PeerRecord {
	if !r.cfg.PeerExchange {
		return nil
	}
	r.charge(payer, OpLookup, 2*len(r.peers)) // the subscription check and the shuffle
	r.did(OpLookup, len(r.peers))
	var recs []wire.PeerRecord
	for _, q := range r.pick(t, r.cfg.PrunePeers, func(q *peer) bool {
		return q.id != to && q.port != 0 && r.scoreBy(payer, q.id) >= 0
	}) {
		p := r.byID[q]
		recs = append(recs, wire.PeerRecord{Key: wire.Key(q), Addr: netip.AddrPortFrom(netip.AddrFrom4(p.ip), p.port)})
	}
	r.charge(payer, OpAlloc, 1)
	return recs
}

func (r *Router) refuse(p *peer, t wire.Topic) wire.Prune {
	r.backoffFor(p, t, r.cfg.PruneBackoff, false)
	return wire.Prune{Topic: t, Backoff: seconds(r.cfg.PruneBackoff)}
}

// backoffFor records p's backoff for t, the table's work charged to p.
func (r *Router) backoffFor(p *peer, t wire.Topic, d time.Duration, owed bool) {
	looked := r.backoff.looked
	steps := r.backoff.add(r.now, t, p.id, d, owed, r.cfg.MaxBackoff, r.byID)
	r.charge(p, OpLookup, steps)
	r.did(OpLookup, 1+r.backoff.looked-looked)
}

// handlePrune removes the peer from the pruned meshes and records its backoff; a topic listed twice counts once.
// Peer exchange is read for joined topics from a peer whose score is at least AcceptPX, scoring on and AcceptPX
// above 0.
func (r *Router) handlePrune(p *peer, prunes []wire.Prune) {
	if len(prunes) == 0 {
		return
	}
	accept := r.thresholds().AcceptPX > 0 &&
		slices.ContainsFunc(prunes, func(pr wire.Prune) bool { return len(pr.PX) > 0 }) && r.scoreFor(p) >= r.thresholds().AcceptPX
	r.charge(p, OpLookup, 6*len(prunes))
	r.charge(p, OpAlloc, 2*len(prunes)+1)
	r.did(OpAlloc, 1)
	done := map[wire.Topic]bool{}
	for _, pr := range prunes {
		r.did(OpLookup, 1)
		if done[pr.Topic] {
			continue
		}
		done[pr.Topic] = true
		r.did(OpLookup, 1)
		tp := r.topics[pr.Topic]
		if tp == nil || !tp.joined || p.refuses(pr.Topic) {
			continue
		}
		r.did(OpLookup, 3)
		r.did(OpAlloc, 2)
		if slices.Contains(tp.mesh, p.id) {
			r.score.prune(p.id, pr.Topic)
			tp.mesh = remove(tp.mesh, p.id)
		}
		d := r.cfg.PruneBackoff
		if pr.Backoff > 0 {
			d = time.Duration(min(pr.Backoff, uint64(math.MaxInt64/int64(time.Second)))) * time.Second
		}
		r.backoffFor(p, pr.Topic, d, true)
		if accept && len(pr.PX) > 0 {
			r.dial(p, pr.Topic, pr.PX)
		}
	}
}

// dial passes on up to PrunePeers random records of a PRUNE from p, leaving out our own key, connected peers and
// repeats; p pays for each record the Sink takes to dial.
func (r *Router) dial(p *peer, t wire.Topic, px []wire.PeerRecord) {
	r.charge(p, OpLookup, 3*len(px))
	r.did(OpLookup, 3*len(px))
	recs := slices.Clone(px)
	shuffle(r.rnd, recs)
	recs = recs[:min(len(recs), r.cfg.PrunePeers)]
	var seen []PeerID
	recs = slices.DeleteFunc(recs, func(rec wire.PeerRecord) bool {
		k := PeerID(rec.Key)
		if k == r.self || r.byID[k] != nil || slices.Contains(seen, k) {
			return true
		}
		seen = append(seen, k)
		return false
	})
	if len(recs) == 0 {
		return
	}
	r.stats.PXAccepted += uint64(len(recs))
	n := r.out.Dial(t, p.id, recs)
	r.charge(p, OpDial, n)
	r.did(OpDial, n)
}

// handleIDontWant remembers ids the peer already has for IDontWantTTL heartbeats, within MaxIDontWantMessages
// frames per heartbeat, MaxIDontWantLength ids per frame and MaxIDontWantIDs ids in all. A frame past the bound
// still pays for its decoding and its call.
func (r *Router) handleIDontWant(p *peer, ids []wire.ID) {
	if len(ids) == 0 {
		return
	}
	r.stats.IDontWantReceived++
	p.dontwant++
	if p.dontwant > int32(r.cfg.MaxIDontWantMessages) {
		return
	}
	ids = ids[:min(len(ids), r.cfg.MaxIDontWantLength)]
	r.charge(p, OpLookup, len(ids))
	r.charge(p, OpAlloc, len(ids))
	r.did(OpLookup, len(ids))
	r.did(OpAlloc, len(ids))
	for _, id := range ids {
		if p.unwanted == nil {
			p.unwanted = &unwanted{}
		}
		p.unwanted.add(id, r.ticks+uint64(r.cfg.IDontWantTTL), r.cfg.MaxIDontWantIDs)
	}
}

// sendControl sends our own control to p; push is the general form.
func (r *Router) sendControl(p *peer, c *wire.Control, piggyback bool) {
	r.push(nil, p, c, piggyback)
}

// push sends c to p, charged to payer (nil for our own work), first adding p's pending control when piggyback is
// set, and splits it into frames of at most MaxControlSize. GRAFT, PRUNE and subscriptions of a dropped frame are
// retried later.
func (r *Router) push(payer, p *peer, c *wire.Control, piggyback bool) {
	if p == nil {
		return
	}
	if piggyback {
		r.takePending(p, c)
	}
	if c.Empty() {
		return
	}
	for _, f := range splitControl(c, r.cfg.MaxControlSize, r.cfg.MaxCerts, maxFrameTopics) {
		// Every frame but one of IHAVE alone goes first: a subscription, GRAFT or PRUNE must not be overtaken by
		// a later one, and a request that waits behind IHAVE can time out.
		urgent := len(f.IHave) == 0 || len(f.Subs)+len(f.Graft)+len(f.Prune)+len(f.IWant)+len(f.IDontWant)+len(f.CertWant)+len(f.Cert) > 0
		// An IDONTWANT may be joined into the last one queued, which encodes up to MaxIDontWantLength ids again.
		size := f.Size()
		if len(f.IDontWant) > 0 {
			size += r.cfg.MaxIDontWantLength * wire.IDSize
		}
		r.charge(payer, OpSend, 1)
		r.charge(payer, OpBytes, 2*chunks(size))
		if payer != nil {
			r.did(OpSend, 1)
			r.did(OpBytes, 2*chunks(size))
		}
		r.stats.ControlSent++
		if r.out.SendControl(p.id, f, urgent) {
			continue
		}
		r.stats.SendDropped++
		pd := p.pendings()
		for _, s := range f.Subs {
			pd.subs = appendTopic(pd.subs, s.Topic)
		}
		for _, t := range f.Graft {
			pd.graft = appendTopic(pd.graft, t)
		}
		for _, pr := range f.Prune {
			pd.prune = appendPrune(pd.prune, pr)
		}
		// A dropped answer would make the asker charge us for a broken request, so it is sent again.
		for _, b := range f.Cert {
			if len(pd.cert) < r.cfg.MaxCerts {
				pd.cert = append(pd.cert, b)
			}
		}
	}
}

// takePending moves p's pending control into c, dropping what is stale: a GRAFT whose peer left the mesh, a
// PRUNE whose peer is back in it. Subscriptions are sent as they are now.
func (r *Router) takePending(p *peer, c *wire.Control) {
	if p.pend == nil {
		return
	}
	for _, t := range p.pend.subs {
		if !slices.ContainsFunc(c.Subs, func(s wire.Sub) bool { return s.Topic == t }) {
			tp := r.topics[t]
			c.Subs = append(c.Subs, wire.Sub{Topic: t, Subscribe: tp != nil && tp.joined && !p.refuses(t)})
		}
	}
	for _, t := range p.pend.graft {
		if tp := r.topics[t]; tp != nil && slices.Contains(tp.mesh, p.id) && !slices.Contains(c.Graft, t) {
			c.Graft = append(c.Graft, t)
		}
	}
	for _, pr := range p.pend.prune {
		if tp := r.topics[pr.Topic]; tp == nil || !slices.Contains(tp.mesh, p.id) {
			c.Prune = appendPrune(c.Prune, pr)
		}
	}
	c.IHave = append(c.IHave, p.pend.ihave...)
	c.Cert = append(c.Cert, p.pend.cert...)
	p.pend = nil
}

func appendTopic(ts []wire.Topic, t wire.Topic) []wire.Topic {
	if slices.Contains(ts, t) {
		return ts
	}
	return append(ts, t)
}

func appendPrune(ps []wire.Prune, p wire.Prune) []wire.Prune {
	if slices.ContainsFunc(ps, func(q wire.Prune) bool { return q.Topic == p.Topic }) {
		return ps
	}
	return append(ps, p)
}

// splitControl cuts c into frames of at most limit bytes, certs certificates and topics GRAFT and PRUNE entries
// each, the receiver's bounds, splitting long id lists; limit fits any single item.
func splitControl(c *wire.Control, limit, certs, topics int) []*wire.Control {
	if c.Size() <= limit && len(c.Cert) <= certs && len(c.Graft) <= topics && len(c.Prune) <= topics {
		return []*wire.Control{c}
	}
	s := splitter{limit: limit}
	s.next()
	for _, sub := range c.Subs {
		s.fit(32+1, func(f *wire.Control) int { return len(f.Subs) })
		s.cur.Subs = append(s.cur.Subs, sub)
	}
	for _, t := range c.Graft {
		if len(s.cur.Graft) >= topics {
			s.next()
		}
		s.fit(32, func(f *wire.Control) int { return len(f.Graft) })
		s.cur.Graft = append(s.cur.Graft, t)
	}
	for _, p := range c.Prune {
		if len(s.cur.Prune) >= topics {
			s.next()
		}
		s.fit(wire.PruneSize(&p), func(f *wire.Control) int { return len(f.Prune) })
		s.cur.Prune = append(s.cur.Prune, p)
	}
	for _, h := range c.IHave {
		ids := h.IDs
		for {
			k := min(len(ids), 1)
			s.fit(wire.IHaveSize(k), func(f *wire.Control) int { return len(f.IHave) })
			n := k
			for n < len(ids) && s.size+wire.IHaveSize(n+1)-wire.IHaveSize(n) <= s.limit {
				s.size += wire.IHaveSize(n+1) - wire.IHaveSize(n)
				n++
			}
			s.cur.IHave = append(s.cur.IHave, wire.IHave{Topic: h.Topic, IDs: ids[:n]})
			if ids = ids[n:]; len(ids) == 0 {
				break
			}
		}
	}
	for _, id := range c.IWant {
		s.fit(wire.IDSize, func(f *wire.Control) int { return len(f.IWant) })
		s.cur.IWant = append(s.cur.IWant, id)
	}
	for _, id := range c.IDontWant {
		s.fit(wire.IDSize, func(f *wire.Control) int { return len(f.IDontWant) })
		s.cur.IDontWant = append(s.cur.IDontWant, id)
	}
	for _, w := range c.CertWant {
		s.fit(2*wire.KeySize, func(f *wire.Control) int { return len(f.CertWant) })
		s.cur.CertWant = append(s.cur.CertWant, w)
	}
	for _, b := range c.Cert {
		if len(s.cur.Cert) >= certs {
			s.next()
		}
		s.fit(wire.UvarintLen(uint64(len(b)))+len(b), func(f *wire.Control) int { return len(f.Cert) })
		s.cur.Cert = append(s.cur.Cert, b)
	}
	return s.out
}

type splitter struct {
	limit int
	size  int
	cur   *wire.Control
	out   []*wire.Control
}

func (s *splitter) next() {
	s.cur = &wire.Control{}
	s.out = append(s.out, s.cur)
	s.size = s.cur.Size()
}

// fit makes room for an item of n bytes in a list whose current length count returns, starting a new frame
// when needed, and accounts for the item and any growth of the list's count.
func (s *splitter) fit(n int, count func(*wire.Control) int) {
	grow := func() int { k := count(s.cur); return n + wire.UvarintLen(uint64(k+1)) - wire.UvarintLen(uint64(k)) }
	if s.size+grow() > s.limit {
		s.next()
	}
	s.size += grow()
}
