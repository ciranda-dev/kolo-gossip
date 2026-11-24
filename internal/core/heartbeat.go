package core

import (
	"bytes"
	"math"
	"slices"

	"github.com/ciranda-dev/kolo-gossip/internal/wire"
)

// backoffCleanupTicks and backoffSlackTicks: backoffs are cleared every 15 heartbeats, 2 heartbeats after they
// end, so a peer that waits the full backoff is never refused for the heartbeat offset between the two sides.
const (
	backoffCleanupTicks = 15
	backoffSlackTicks   = 2
)

// heartbeat maintains every mesh and fanout, emits gossip, flushes pending control and shifts the message cache.
func (r *Router) heartbeat() {
	r.ticks++
	if r.ticks%backoffCleanupTicks == 0 {
		r.backoff.cleanup(r.now, backoffSlackTicks*r.cfg.HeartbeatInterval)
	}
	for _, p := range r.peers {
		p.delivered = 0
		for _, n := range p.ring {
			p.delivered += int64(n)
		}
		if p.ring != nil {
			p.ring[r.ticks%uint64(len(p.ring))] = 0
		}
		p.ihaves, p.dontwant = 0, 0
		if !p.unwanted.expire(r.ticks) {
			p.unwanted = nil // an empty table releases its memory
		}
	}
	if r.ticks%uint64(r.cfg.HistoryLength) == 0 {
		for _, p := range r.peers {
			p.sent = nil // a message leaves the cache within HistoryLength heartbeats
		}
	}
	r.gone.expire(r.mono(r.now) - int64(r.goneFor()))
	if r.score != nil {
		r.score.app = nil
	}
	for _, pr := range r.promises.broken(r.now, r.byID) {
		r.score.penalty(pr.peer, 1)
	}
	r.hedgeAsks()
	if len(r.retrying) > 0 {
		at := r.mono(r.now)
		r.retryWhere(func(rec *seenRec) bool { return at-rec.pending.retryAt >= int64(r.cfg.RetryInterval) })
	}
	if res := r.resolver(); res != nil {
		out := res.Expire(r.now)
		r.take(nil)
		r.resolved(nil, out)
		r.hedge()
	}
	scores := map[PeerID]float64{}
	score := func(p PeerID) float64 {
		s, ok := scores[p]
		if !ok {
			s = r.scoreOf(p)
			scores[p] = s
		}
		return s
	}
	grafts := map[PeerID][]wire.Topic{}
	prunes := map[PeerID][]wire.Prune{}
	r.gossipLoad = r.gossipEntries()
	for _, tp := range r.joined() {
		r.maintainMesh(tp, score, grafts, prunes)
		r.emitGossip(tp.id, tp.params, tp.mesh, score)
	}
	for _, tp := range r.sortedTopics() {
		if tp.joined {
			continue
		}
		if tp.lastPub.Add(r.cfg.FanoutTTL).Before(r.now) {
			r.dropTopic(tp.id)
			continue
		}
		tp.fanout = slices.DeleteFunc(tp.fanout, func(p PeerID) bool {
			return !r.byID[p].subscribed(tp.id) || score(p) < r.thresholds().Publish
		})
		if need := tp.params.D - len(tp.fanout); need > 0 {
			tp.fanout = append(tp.fanout, r.pick(tp.id, need, func(p *peer) bool {
				return !slices.Contains(tp.fanout, p.id) && score(p.id) >= r.thresholds().Publish
			})...)
		}
		r.emitGossip(tp.id, tp.params, tp.fanout, score)
	}
	r.snapshotShares()
	for _, p := range r.peers {
		for _, t := range grafts[p.id] {
			p.pendings().graft = appendTopic(p.pendings().graft, t)
		}
		for _, pr := range prunes[p.id] {
			p.pendings().prune = appendPrune(p.pendings().prune, pr)
		}
		if p.pend != nil {
			r.sendControl(p, &wire.Control{}, true)
		}
	}
	r.cache.shift()
}

// maintainMesh applies the heartbeat mesh rules of GossipSub v1.1 to one joined topic. A peer pruned for its
// negative score gets no peer exchange.
func (r *Router) maintainMesh(tp *topic, score func(PeerID) float64, grafts map[PeerID][]wire.Topic, prunes map[PeerID][]wire.Prune) {
	t, d := tp.id, tp.params
	prunePeer := func(p PeerID, px bool) {
		r.score.prune(p, t)
		tp.mesh = remove(tp.mesh, p)
		r.backoff.add(r.now, t, p, r.cfg.PruneBackoff, true, r.cfg.MaxBackoff, r.byID)
		pr := wire.Prune{Topic: t, Backoff: seconds(r.cfg.PruneBackoff)}
		if px {
			pr.PX = r.exchange(nil, p, t)
		}
		prunes[p] = append(prunes[p], pr)
	}
	graftPeer := func(p PeerID) {
		r.score.graft(r.now, p, t)
		tp.mesh = append(tp.mesh, p)
		tp.grafted = append(tp.grafted, p)
		grafts[p] = append(grafts[p], t)
	}
	for _, p := range slices.Clone(tp.mesh) {
		if score(p) < 0 {
			prunePeer(p, false)
		}
	}
	if len(tp.mesh) < d.Dlo {
		for _, p := range r.pick(t, d.D-len(tp.mesh), func(p *peer) bool {
			return !slices.Contains(tp.mesh, p.id) && !r.backoff.has(t, p.id) && score(p.id) >= 0
		}) {
			graftPeer(p)
		}
	}
	if len(tp.mesh) > d.Dhi {
		for _, p := range r.selectSurvivors(tp, score)[d.D:] {
			prunePeer(p, true)
		}
	}
	if len(tp.mesh) >= d.Dlo {
		if out := r.countOutbound(tp.mesh); out < d.Dout {
			for _, p := range r.pick(t, d.Dout-out, func(p *peer) bool {
				return p.outbound && !slices.Contains(tp.mesh, p.id) && !r.backoff.has(t, p.id) && score(p.id) >= 0
			}) {
				graftPeer(p)
			}
		}
	}
	if r.score != nil && r.ticks%uint64(r.cfg.OpportunisticGraftTicks) == 0 && len(tp.mesh) > 1 {
		sorted := slices.Clone(tp.mesh)
		slices.SortStableFunc(sorted, func(a, b PeerID) int { return cmpFloat(score(a), score(b)) })
		median := score(sorted[len(sorted)/2])
		if median < r.thresholds().OpportunisticGraft {
			for _, p := range r.pick(t, r.cfg.OpportunisticGraftPeers, func(p *peer) bool {
				return !slices.Contains(tp.mesh, p.id) && !r.backoff.has(t, p.id) && score(p.id) > median
			}) {
				graftPeer(p)
			}
		}
	}
}

// selectSurvivors orders an oversubscribed mesh so its first D peers are kept: the best Dscore by score, the
// rest at random, then outbound peers moved in until Dout of the D are outbound.
func (r *Router) selectSurvivors(tp *topic, score func(PeerID) float64) []PeerID {
	d := tp.params
	plst := slices.Clone(tp.mesh)
	shuffle(r.rnd, plst)
	slices.SortStableFunc(plst, func(a, b PeerID) int { return cmpFloat(score(b), score(a)) })
	shuffle(r.rnd, plst[d.Dscore:])
	outbound := r.countOutbound(plst[:d.D])
	if outbound >= d.Dout {
		return plst
	}
	rotate := func(i int) {
		p := plst[i]
		copy(plst[1:i+1], plst[:i])
		plst[0] = p
	}
	for i, have := 1, outbound; i < d.D && have > 0; i++ {
		if r.byID[plst[i]].outbound {
			rotate(i)
			have--
		}
	}
	for i, need := d.D, d.Dout-outbound; i < len(plst) && need > 0; i++ {
		if r.byID[plst[i]].outbound {
			rotate(i)
			need--
		}
	}
	return plst
}

func (r *Router) countOutbound(ps []PeerID) int {
	n := 0
	for _, p := range ps {
		if r.byID[p].outbound {
			n++
		}
	}
	return n
}

// emitGossip queues IHAVE for t's recent ids to max(Dlazy, min(GossipFactor x candidates, GossipPeers)) random peers outside
// exclude at or above the gossip threshold, each with its own random subset of at most MaxIHaveLength ids. The peers
// that entered the mesh since the last heartbeat get one too: the ids that reached us before them went to the old
// mesh only, and a mesh peer is otherwise left out of gossip.
func (r *Router) emitGossip(t wire.Topic, d Params, exclude []PeerID, score func(PeerID) float64) {
	tp := r.topics[t]
	grafted := tp.grafted
	tp.grafted = nil // grafts are rare once a mesh stands, so no capacity is kept
	ids := r.cache.gossipIDs(t, r.cfg.HistoryGossip)
	if len(ids) == 0 {
		return
	}
	var peers []*peer
	for _, p := range r.peers {
		if p.subscribed(t) && !p.refuses(t) && !slices.Contains(exclude, p.id) && score(p.id) >= r.thresholds().Gossip {
			peers = append(peers, p)
		}
	}
	gp := int64(d.GossipPeers)
	if gp == 0 { // a bootstrap Params: no cap, the specification's rule
		gp = math.MaxInt32
	}
	limit := int(min(int64(math.MaxInt32), max(gp, gp*int64(r.cfg.MaxIHaveLength)/int64(max(1, r.gossipLoad)))))
	target := max(d.Dlazy, min(int(d.GossipFactor*float64(len(peers))), limit))
	if target >= len(peers) {
		target = len(peers)
	} else {
		shuffle(r.rnd, peers)
		// Those the last heartbeat left out go first, so every candidate hears of each id within HistoryGossip heartbeats.
		slices.SortStableFunc(peers, func(a, b *peer) int { return cmpBool(tp.gossiped(a.id), tp.gossiped(b.id)) })
	}
	tp.lastGossip = tp.lastGossip[:0]
	for _, p := range peers[:target] {
		tp.lastGossip = append(tp.lastGossip, p.id)
	}
	slices.SortFunc(tp.lastGossip, cmpPeer)
	for _, id := range grafted {
		if p := r.byID[id]; p != nil && slices.Contains(tp.mesh, id) {
			peers = append(peers[:target], p)
			target++
		}
	}
	shuffle(r.rnd, ids)
	for _, p := range peers[:target] {
		pids := ids
		if len(ids) > r.cfg.MaxIHaveLength {
			shuffle(r.rnd, ids)
			pids = slices.Clone(ids[:r.cfg.MaxIHaveLength])
		}
		p.pendings().ihave = append(p.pendings().ihave, wire.IHave{Topic: t, IDs: pids})
		r.stats.IHaveSent++
	}
}

// gossipEntries counts what this heartbeat's IHAVE announce: the ids of every topic's gossip windows and a header per topic.
func (r *Router) gossipEntries() int {
	n := len(r.topics)
	for _, w := range r.cache.windows[:r.cfg.HistoryGossip] {
		n += len(w)
	}
	return n
}

// gossiped reports whether the last heartbeat sent id this topic's IHAVE.
func (tp *topic) gossiped(id PeerID) bool {
	_, ok := slices.BinarySearchFunc(tp.lastGossip, id, cmpPeer)
	return ok
}

func cmpPeer(a, b PeerID) int { return bytes.Compare(a[:], b[:]) }

func cmpBool(a, b bool) int {
	switch {
	case a == b:
		return 0
	case a:
		return 1
	}
	return -1
}

func cmpFloat(a, b float64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}
