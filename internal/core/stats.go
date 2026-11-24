package core

import "github.com/ciranda-dev/kolo-gossip/internal/wire"

// Stats counts what a Router did and holds its current sizes.
type Stats struct {
	MessagesReceived, MessagesSent, ControlSent uint64
	Published, Delivered, Duplicates            uint64
	Rejected, Ignored, Throttled                uint64
	NotJoined, TooLarge, Malformed              uint64
	SeenFull, OutOfWindow, SelfOrigin           uint64
	BadSignature, Graylisted, ProtocolErrors    uint64
	SendDropped, CacheEvicted                   uint64
	IHaveSent, IHaveReceived                    uint64 // IHAVE lists sent, IHAVE frames received
	IWantSent, IWantReceived                    uint64 // IWANT frames
	IDontWantSent, IDontWantReceived            uint64 // IDONTWANT frames
	UnknownAuthor, Resolving, CertBroken        uint64 // ignored authors, messages that waited for a chain, broken requests
	CertWantSent, CertWantReceived              uint64 // CERTWANT frames
	CertSent, CertReceived                      uint64 // chains sent, CERT frames received
	SignatureChecks, IgnoredCopies, Waits       uint64 // checks run; copies of ignored ids; times a peer had to wait for its buckets
	EdgeOfWindow, PXAccepted                    uint64 // accepted messages not forwarded because they leave the window; peer exchange records passed on to dial
	SubscriptionsDropped                        uint64 // subscriptions to topics we hold no state for, past MaxPeerTopics
	Retried                                     uint64 // validator answers of Retry

	Peers, Topics, Seen, CacheMessages, CacheBytes, Validating, Retained int
}

// TopicStats are the current sizes of one topic.
type TopicStats struct {
	Joined                        bool
	Peers, Mesh, Outbound, Fanout int
}

// Stats returns the counters and current sizes.
func (r *Router) Stats() Stats {
	s := r.stats
	s.Peers, s.Topics, s.Seen = len(r.peers), len(r.topics), r.seen.len()
	s.CacheMessages, s.CacheBytes, s.Validating = len(r.cache.m), r.cache.bytes, r.validating+len(r.running)
	if r.score != nil {
		s.Retained = len(r.score.retained)
	}
	return s
}

// TopicStats returns the sizes of topic t.
func (r *Router) TopicStats(t wire.Topic) TopicStats {
	var s TopicStats
	for _, p := range r.peers {
		if p.knows(t) {
			s.Peers++
		}
	}
	if tp := r.topics[t]; tp != nil {
		s.Joined, s.Mesh, s.Outbound, s.Fanout = tp.joined, len(tp.mesh), r.countOutbound(tp.mesh), len(tp.fanout)
	}
	return s
}
