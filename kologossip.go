package kologossip

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ciranda-dev/kolo-gossip/internal/auth"
	"github.com/ciranda-dev/kolo-gossip/internal/core"
	"github.com/ciranda-dev/kolo-gossip/internal/wire"
	koloid "github.com/ciranda-dev/kolo-id"
	koloswarm "github.com/ciranda-dev/kolo-swarm"
)

var (
	// ErrInvalidConfig means a Config, TopicOptions or score parameter set breaks a constraint.
	ErrInvalidConfig = errors.New("kologossip: invalid config")
	// ErrInvalidArgument means an argument is unusable, such as a nil identity, a topic joined twice or an IPv6 peer.
	ErrInvalidArgument = errors.New("kologossip: invalid argument")
	// ErrClosed means the Gossip is closed.
	ErrClosed = errors.New("kologossip: closed")
	// ErrNotJoined means the Room was left.
	ErrNotJoined = errors.New("kologossip: topic not joined")
	// ErrTooLarge means a message is over its topic's MaxMessageSize.
	ErrTooLarge = errors.New("kologossip: message too large")
	// ErrLimit means a bound is full: MaxPeers or MaxTopics when the application set one, or the seen cache.
	ErrLimit = errors.New("kologossip: limit reached")
	// ErrDuplicate means a message with the same bytes was already published or seen, as with a repeated Seq.
	ErrDuplicate = errors.New("kologossip: duplicate message")
	// ErrProtocol means a peer broke the gossip protocol; ServeConn closed its connection.
	ErrProtocol = errors.New("kologossip: protocol violation")
	// ErrGraylisted means a peer's score fell below the graylist threshold; ServeConn stopped serving it.
	ErrGraylisted = errors.New("kologossip: peer graylisted")
	// ErrOwnChain means this node's own certificate chain has expired or its room's roster revoked it.
	ErrOwnChain = errors.New("kologossip: own certificate chain not valid")
	// ErrUnknownAuthor from Authors.Lookup means the roster does not know the device; the message is ignored.
	ErrUnknownAuthor = errors.New("kologossip: unknown author")
	// ErrBadEnvelope means VerifyEnvelope refused an envelope: it does not decode, is for another topic or author, is
	// badly signed, or its author's chain does not certify the device.
	ErrBadEnvelope = errors.New("kologossip: bad envelope")
)

// publicErr pairs a public sentinel with the internal error it stands for.
type publicErr struct{ pub, err error }

func (e *publicErr) Error() string   { return e.err.Error() }
func (e *publicErr) Unwrap() []error { return []error{e.pub, e.err} }

// mapErr gives an internal error its public sentinel, keeping its text.
func mapErr(err error) error {
	for _, m := range []struct{ in, pub error }{
		{core.ErrInvalidConfig, ErrInvalidConfig}, {core.ErrInvalidArgument, ErrInvalidArgument},
		{core.ErrTooLarge, ErrTooLarge}, {core.ErrLimit, ErrLimit}, {core.ErrDuplicate, ErrDuplicate},
		{core.ErrProtocol, ErrProtocol},
	} {
		if errors.Is(err, m.in) {
			return &publicErr{m.pub, err}
		}
	}
	return err
}

// Topic is a 32-byte topic id chosen by the application, the same type as a kolo-swarm topic.
type Topic = koloswarm.Topic

// MessageID is a message id: SHA-256 over a domain label and the whole signed envelope.
type MessageID [32]byte

// Conn is a connection to one peer whose key the connection proved; a kolo-swarm Peer's Conn satisfies it.
type Conn = koloswarm.Conn

// Gossip is one node's gossip under one device key: the rooms it joined and the peers it serves.
type Gossip struct {
	dev    *koloid.Identity
	cert   *koloid.DeviceCert
	person ed25519.PublicKey
	swarm  *koloswarm.Swarm
	set    *settings
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	seq    func() uint64 // for topics published without a Room
	hooks  hooks

	waited                          atomic.Uint64 // times a reader waited because its peer's buckets were empty
	pxDials, pxConnected, pxDropped atomic.Uint64
	dials                           chan dialReq // peer exchange records waiting for a dialer; nil without a Swarm

	mu             sync.Mutex
	closed         bool
	r              *core.Router
	res            *auth.Resolver
	rooms          map[Topic]*Room
	peers          map[core.PeerID]*peer
	verdicts       []verdict                     // validations decided during a router call, applied right after it
	validations    map[uint64]context.CancelFunc // validators running, by validation number
	protocolClosed uint64                        // connections closed for breaking the protocol
}

// dialReq is a peer exchange record to dial for topic, which the peer at from sent (zero: relayed).
type dialReq struct {
	topic Topic
	rec   wire.PeerRecord
	from  netip.Addr
}

// hooks let tests act at points they cannot reach otherwise; nil does nothing.
type hooks struct {
	swarmJoined func() // after Join's swarm join returned, before the room records it
}

type verdict struct {
	id wire.ID
	n  uint64
	v  core.Verdict
}

type globalRand struct{}

func (globalRand) IntN(n int) int { return rand.IntN(n) }

// New starts gossip as dev, the device key whose chain is cfg.Cert; with cfg.Swarm, dev is also its key.
func New(dev *koloid.Identity, cfg *Config) (*Gossip, error) {
	key := dev.PublicKey()
	if key == nil {
		return nil, fmt.Errorf("%w: nil or zero identity", ErrInvalidArgument)
	}
	set, err := cfg.settings()
	if err != nil {
		return nil, mapErr(err)
	}
	switch {
	case !bytes.Equal(cfg.Cert.Device(), key):
		return nil, fmt.Errorf("%w: Cert is for another device", ErrInvalidConfig)
	case cfg.Swarm != nil && !bytes.Equal(cfg.Swarm.PublicKey(), key):
		return nil, fmt.Errorf("%w: Swarm runs as another key", ErrInvalidConfig)
	}
	if err := cfg.Cert.Verify(&koloid.VerifyOptions{Person: cfg.Cert.Person()}); err != nil {
		return nil, fmt.Errorf("%w: Cert: %w", ErrInvalidConfig, err)
	}
	g := &Gossip{dev: dev, cert: cfg.Cert, person: cfg.Cert.Person(), swarm: cfg.Swarm, set: set,
		rooms: map[Topic]*Room{}, peers: map[core.PeerID]*peer{}, validations: map[uint64]context.CancelFunc{}}
	g.seq = newSeq(set.now())
	a := set.auth
	a.Authors, a.Open, a.Now = authors{g}, authors{g}.open, set.now
	if g.res, err = auth.New(&a); err != nil {
		return nil, mapErr(err)
	}
	g.res.Own(cfg.Cert)
	if g.r, err = core.New(set.now(), core.PeerID(key), &set.router, globalRand{}, g.res, sink{g}); err != nil {
		return nil, mapErr(err)
	}
	g.ctx, g.cancel = context.WithCancel(context.Background())
	g.wg.Add(1)
	go g.heartbeat()
	if g.swarm != nil {
		g.dials = make(chan dialReq, set.pxPending)
		for range set.pxDialers {
			g.wg.Add(1)
			go g.dialer()
		}
	}
	return g, nil
}

// dialer dials peer exchange records through the swarm until Close; a record the swarm refuses, for now or for
// good, or whose dial fails is skipped.
func (g *Gossip) dialer() {
	defer g.wg.Done()
	for {
		select {
		case <-g.ctx.Done():
			return
		case d := <-g.dials:
			g.pxDials.Add(1)
			ctx, cancel := context.WithTimeout(g.ctx, g.set.pxTimeout)
			err := g.swarm.Connect(ctx, d.topic, d.rec.Key[:], d.rec.Addr, d.from)
			cancel()
			if err == nil {
				g.pxConnected.Add(1)
			}
		}
	}
}

// heartbeat runs the router's heartbeat and score decay when they are due.
func (g *Gossip) heartbeat() {
	defer g.wg.Done()
	t := time.NewTimer(0)
	defer t.Stop()
	for {
		g.mu.Lock()
		next := g.r.NextTick()
		g.mu.Unlock()
		t.Reset(next.Sub(g.set.now()))
		select {
		case <-g.ctx.Done():
			return
		case <-t.C:
		}
		g.call(func(now time.Time) {
			g.r.Tick(now)
			// A heartbeat penalty can graylist a peer that sends nothing: it is ended here, not at its next frame.
			for _, p := range g.peers {
				if g.r.Graylisted(p.id) {
					p.fail(ErrGraylisted)
				}
			}
		})
	}
}

// call runs f on the router with the current time unless the Gossip is closed, then applies the verdicts f
// produced; false means closed.
func (g *Gossip) call(f func(now time.Time)) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.callLocked(f)
}

func (g *Gossip) callLocked(f func(now time.Time)) bool {
	if g.closed {
		return false
	}
	now := g.set.now()
	f(now)
	for len(g.verdicts) > 0 {
		v := g.verdicts[0]
		g.verdicts = g.verdicts[1:]
		g.r.ValidationDone(now, v.id, v.n, v.v)
	}
	g.verdicts = nil
	return true
}

// Close stops every room and every ServeConn and waits for their goroutines. It leaves the swarm topics joined
// through Config.Swarm, which closes the connections that shared no other topic; its peers then close theirs.
func (g *Gossip) Close() error {
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return nil
	}
	g.closed = true
	rooms := make([]*Room, 0, len(g.rooms))
	for _, rm := range g.rooms {
		rooms = append(rooms, rm)
	}
	clear(g.rooms)
	g.mu.Unlock()
	g.cancel()
	for _, rm := range rooms {
		rm.end(ErrClosed)
	}
	g.wg.Wait()
	return nil
}

// Allow reports whether key is at or above the graylist threshold; chain it into koloswarm.Config.Allow so the
// swarm refuses graylisted peers. It always allows when scoring is off.
func (g *Gossip) Allow(key ed25519.PublicKey, _ netip.AddrPort) bool {
	if len(key) != ed25519.PublicKeySize {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	s := g.set.router.Score
	return s == nil || g.r.Score(core.PeerID(key)) >= s.Thresholds.Graylist
}

// Score returns a peer's current score, kept for ScoreParams.RetainScore after it disconnects; 0 when scoring
// is off.
func (g *Gossip) Score(key ed25519.PublicKey) float64 {
	if len(key) != ed25519.PublicKeySize {
		return 0
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.r.Score(core.PeerID(key))
}

// Stats counts what the Gossip did and holds its current sizes.
type Stats struct {
	Router          RouterStats
	Authors         AuthorStats
	ProtocolClosed  uint64 // connections ServeConn closed because the peer broke the protocol
	Waited          uint64 // times a peer's reader waited for its work buckets to refill
	StuckValidators int    // validators still running past ValidateTimeout or their cancel, in the rooms joined now
	PXDials         uint64 // peer exchange records dialed through the swarm
	PXConnected     uint64 // of those, dials the swarm admitted
	PXDropped       uint64 // records dropped because PXPending records waited already
}

// RouterStats are the router's counters and current sizes.
type RouterStats struct {
	MessagesReceived, MessagesSent, ControlSent uint64 // message frames received and sent, control frames sent
	Published, Delivered, Duplicates            uint64 // our own messages, messages accepted, copies of known ones
	Rejected, Ignored, Throttled                uint64 // validator verdicts; messages over a validation bound
	NotJoined, TooLarge, Malformed              uint64 // for a topic not joined; over its size; not decodable
	SeenFull, OutOfWindow, SelfOrigin           uint64 // seen cache full; author time outside the window; our own key
	BadSignature, Graylisted, ProtocolErrors    uint64 // bad device signature; frames of graylisted peers; broken rules
	SendDropped, CacheEvicted                   uint64 // frames dropped by full peer queues; cached messages dropped early
	IHaveSent, IHaveReceived                    uint64 // IHAVE lists sent, IHAVE frames received
	IWantSent, IWantReceived                    uint64 // IWANT frames
	IDontWantSent, IDontWantReceived            uint64 // IDONTWANT frames
	UnknownAuthor, Resolving, CertBroken        uint64 // authors that did not check out, messages that waited for a chain, broken requests
	CertWantSent, CertWantReceived              uint64 // CERTWANT frames
	CertSent, CertReceived                      uint64 // CERT answers sent, CERT frames received
	SignatureChecks, IgnoredCopies, Waits       uint64 // checks run; copies of ignored ids; times a peer had to wait for its buckets
	EdgeOfWindow, PXAccepted                    uint64 // accepted messages not forwarded because they leave the window; peer exchange records passed to the dialers
	SubscriptionsDropped                        uint64 // subscriptions to topics we hold no state for, past MaxPeerTopics
	Retried                                     uint64 // validator answers of Retry

	Peers, Topics, Seen, CacheMessages, CacheBytes, Validating, Retained int
}

// AuthorStats are the counters and sizes of the author chain checks.
type AuthorStats struct {
	Requests, Answered, Unsolicited, BadChains, Timeouts, Throttled uint64 // CERTWANT sent and the answers' fate
	Served, CacheEvicted, NotHeld, Revoked                          uint64 // chains sent, dropped, answers without a chain, revoked or expired answers

	CacheChains, CacheBytes, Waiting, Outstanding int
}

// Stats returns the counters and current sizes.
func (g *Gossip) Stats() Stats {
	g.mu.Lock()
	defer g.mu.Unlock()
	stuck := 0
	for _, rm := range g.rooms {
		stuck += int(rm.stuck.Load())
	}
	return Stats{Router: RouterStats(g.r.Stats()), Authors: AuthorStats(g.res.Stats()), ProtocolClosed: g.protocolClosed,
		Waited: g.waited.Load(), StuckValidators: stuck, PXDials: g.pxDials.Load(), PXConnected: g.pxConnected.Load(),
		PXDropped: g.pxDropped.Load()}
}
