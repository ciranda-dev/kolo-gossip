package sim

import (
	"time"

	"github.com/ciranda-dev/kolo-gossip/internal/wire"
)

// Attack rates per peer per second. IHAVE and IDONTWANT spammers send more frames than one heartbeat accepts
// (MaxIHaveMessages 10, MaxIDontWantMessages 1000), so the caps are what limits them.
const (
	ihaveFrames    = 20
	ihaveIDs       = 50
	iwantFrames    = 10
	dontWantFrames = 1100
	spamMessages   = 10
	forgeMessages  = 5
	maxKnown       = 256
	maxCaught      = 10_000
)

// Replay delays: inside the seen cache, after MaxAge, after SeenTTL.
var replayAt = []time.Duration{5 * time.Second, 65 * time.Second, 125 * time.Second}

// actor is an attacker without a router: it subscribes, grafts and then sends what its role sends.
type actor struct {
	known  []wire.ID
	caught []caught
	seen   map[int32]bool
}

type caught struct {
	raw  []byte
	at   int64
	sent int
}

// inject sends a frame from an attacker; attackers are not limited by the uplink model or the peer queues.
func (s *Sim) inject(n *Node, to int32, raw []byte, c *wire.Control) {
	l := n.byPeer[to]
	if l == nil || l.closedAt != never {
		return
	}
	kind := evMessage
	if c != nil {
		kind = evControl
	}
	s.push(event{at: s.now + s.delay(n.Index, to), kind: kind, a: n.Index, b: to, tx: s.now, l: l, raw: raw, c: c})
}

// actorConnect announces and grafts the topics of the peer it connects to, 32 GRAFT entries to a frame.
func (s *Sim) actorConnect(n *Node, peer int32) {
	c := &wire.Control{}
	var grafts []wire.Topic
	for t, in := range s.nodes[peer].rooms {
		if in {
			c.Subs = append(c.Subs, wire.Sub{Topic: TopicID(t), Subscribe: true})
			grafts = append(grafts, TopicID(t))
		}
	}
	const perFrame = 32
	c.Graft = grafts[:min(perFrame, len(grafts))]
	s.inject(n, peer, nil, c)
	for i := perFrame; i < len(grafts); i += perFrame {
		s.inject(n, peer, nil, &wire.Control{Graft: grafts[i:min(i+perFrame, len(grafts))]})
	}
}

// roomOf returns the first topic the node joins, the one an attacker aims at.
func (s *Sim) roomOf(peer int32) wire.Topic {
	for t, in := range s.nodes[peer].rooms {
		if in {
			return TopicID(t)
		}
	}
	return Topic
}

func (s *Sim) actorControl(n *Node, from int32, c *wire.Control) {
	if n.Role != IWantSpam {
		return
	}
	for _, h := range c.IHave {
		for _, id := range h.IDs {
			if len(n.act.known) >= maxKnown {
				n.act.known = n.act.known[1:]
			}
			n.act.known = append(n.act.known, id)
		}
	}
}

func (s *Sim) actorMessage(n *Node, from int32, raw []byte) {
	if n.Role != Replayer || len(n.act.caught) >= maxCaught {
		return
	}
	i, ok := s.msgIndex(raw)
	if !ok {
		return
	}
	if n.act.seen == nil {
		n.act.seen = map[int32]bool{}
	}
	if !n.act.seen[i] {
		n.act.seen[i] = true
		n.act.caught = append(n.act.caught, caught{raw: raw, at: s.now})
	}
}

func (s *Sim) actorTick(n *Node, gen uint32) {
	if !n.up || n.gen != gen {
		return
	}
	peers := n.Peers()
	all := func(raw []byte) {
		for _, p := range peers {
			s.inject(n, p, raw, nil)
		}
	}
	switch n.Role {
	case IHaveSpam:
		for _, p := range peers {
			for range ihaveFrames {
				ids := make([]wire.ID, ihaveIDs)
				for i := range ids {
					s.randomID(&ids[i])
				}
				s.inject(n, p, nil, &wire.Control{IHave: []wire.IHave{{Topic: s.roomOf(p), IDs: ids}}})
			}
		}
	case IWantSpam:
		if len(n.act.known) > 0 {
			for _, p := range peers {
				for range iwantFrames {
					s.inject(n, p, nil, &wire.Control{IWant: n.act.known})
				}
			}
		}
	case DontWantSpam:
		for _, p := range peers {
			for range dontWantFrames {
				ids := make([]wire.ID, 10)
				for i := range ids {
					s.randomID(&ids[i])
				}
				s.inject(n, p, nil, &wire.Control{IDontWant: ids})
			}
		}
	case InvalidSpam:
		for range spamMessages {
			m, raw := s.envelope(n.Index, personKey(n.Index), 200, false)
			m.kind = kindForged
			all(raw)
		}
	case RejectSpam:
		for range spamMessages {
			m, raw := s.envelope(n.Index, personKey(n.Index), 200, true)
			m.kind = kindRejected
			all(raw)
		}
	case GraftSpam:
		for _, p := range peers {
			s.inject(n, p, nil, &wire.Control{Graft: []wire.Topic{s.roomOf(p)}})
		}
	case ForgeSig, ForgePerson, Revoked:
		for range forgeMessages {
			var m *msgRec
			var raw []byte
			switch h := s.randomHonest(); n.Role {
			case ForgeSig:
				m, raw = s.envelope(h, personKey(h), 200, false)
			case ForgePerson:
				m, raw = s.envelope(n.Index, personKey(h), 200, true)
			default:
				m, raw = s.envelope(n.Index, personKey(n.Index), 200, true)
			}
			m.kind = kindForged
			all(raw)
		}
	case Replayer:
		keep := n.act.caught[:0]
		for _, c := range n.act.caught {
			for c.sent < len(replayAt) && s.now-c.at >= int64(replayAt[c.sent]) {
				all(c.raw)
				s.m.replays++
				c.sent++
			}
			if c.sent < len(replayAt) {
				keep = append(keep, c)
			}
		}
		n.act.caught = keep
	}
	s.after(time.Second, func() { s.actorTick(n, gen) })
}

func (s *Sim) randomID(id *wire.ID) {
	for i := 0; i < len(id); i += 8 {
		v := s.rnd.Uint64()
		for j := range 8 {
			id[i+j] = byte(v >> (8 * j))
		}
	}
}

// randomHonest returns a random honest node index.
func (s *Sim) randomHonest() int32 {
	if s.honest == nil {
		for _, n := range s.nodes {
			if n.Role == Honest {
				s.honest = append(s.honest, n.Index)
			}
		}
	}
	return s.honest[s.rnd.IntN(len(s.honest))]
}
