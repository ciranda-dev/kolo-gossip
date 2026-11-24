package kologossip

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
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

// TopicOptions configure a joined topic. Authors, Open or both are required.
type TopicOptions struct {
	// Authors is the roster: closed mode, only the devices it knows are verified.
	Authors Authors
	// Open, if set, also accepts devices the roster does not know: their chain is fetched from the forwarding peer.
	Open Open
	// Validate decides what the library leaves to the application; nil accepts every message whose author checks.
	Validate Validator
	// Params nil takes Config.Params.
	Params *Params
	// Score nil takes DefaultTopicScore when scoring is on.
	Score *TopicScoreParams
	// NoScore leaves the topic unscored: its invalid messages then cost a peer nothing.
	NoScore bool
	// MaxMessageSize is the largest envelope of this topic, at most Config.MaxMessageSize; zero takes that.
	MaxMessageSize int
	// Seq numbers our messages; nil counts up from the Unix nanosecond time of Join. It may be called concurrently.
	Seq func() uint64
	// Swarm is how Join joins the swarm topic when Config.Swarm is set; nil announces and looks up.
	Swarm *koloswarm.JoinOptions
	// AllowPeer admits the peers of this topic; nil admits every peer. A peer it refuses is never told that we joined
	// the topic, is never grafted into its mesh, gets no gossip or message of it, and its frames about it are
	// ignored without penalty. It is asked once when a peer connects, once at Join and again on RefreshPeers; like
	// Authors.Lookup it runs with the Gossip's lock held, answers from memory and must not call the Gossip. A panic
	// refuses the peer. Config's swarm Allow stays node-wide.
	AllowPeer func(peer ed25519.PublicKey) bool
}

// Author is what the application knows about a device: the person it expects and the device's chain, both
// required, and the revocations it accepts. An Author and its slices are read-only once handed out.
type Author struct {
	Person      ed25519.PublicKey    // must equal the message's person
	Cert        *koloid.DeviceCert   // the device's certificate chain
	Revocations []*koloid.Revocation // records that passed Revocation.Verify, kept from first sight, bounded by the application
}

// Authors is the application's roster. Lookup runs with the Gossip's lock held for every new message, so it
// answers from memory and must not call the Gossip; ErrUnknownAuthor or any error means the device is unknown.
type Authors interface {
	Lookup(t Topic, person, device ed25519.PublicKey) (*Author, error)
}

// Open accepts a person the roster does not know and returns the revocations accepted for it. It runs like Lookup.
type Open func(t Topic, person ed25519.PublicKey) (revocations []*koloid.Revocation, ok bool)

// Verdict is a validator's answer.
type Verdict int

// The verdicts of GossipSub v1.1 extended validators; the zero Verdict is not one, and counts as Ignore.
const (
	Accept Verdict = iota + 1 // deliver and forward
	Reject                    // invalid: the sender and every peer that sent a copy lose score
	Ignore                    // drop without penalty
	Retry                     // keep the message and validate it again on Room.Revalidate or after RetryInterval, until SeenTTL
)

func (v Verdict) core() core.Verdict {
	switch v {
	case Accept:
		return core.Accept
	case Reject:
		return core.Reject
	case Retry:
		return core.Retry
	}
	return core.Ignore
}

// Validator decides membership, bans, roles, rate and content. It runs on its own goroutine; its context ends after
// ValidateTimeout, on Leave and on Close. One that returns after its timeout counts as Ignore, and its message
// keeps its places until then; a panic or an unknown verdict is Ignore too. A message answered Retry keeps its place
// in MaxValidating and in its sender's MaxPeerValidating share, and is dropped as an Ignore at SeenTTL.
type Validator func(ctx context.Context, m *Message) Verdict

// Message is a message whose size, time window, author chain and signature the library checked.
type Message struct {
	ID     MessageID
	Topic  Topic
	Person ed25519.PublicKey
	Device ed25519.PublicKey
	Seq    uint64
	Time   time.Time // the author's clock, in milliseconds
	Body   []byte
	Raw    []byte            // the signed envelope as the author sent it, which VerifyEnvelope checks
	From   ed25519.PublicKey // the neighbour that delivered it, not the author; nil for our own message
}

func newMessage(id wire.ID, env *wire.Envelope, from core.PeerID) *Message {
	return &Message{
		ID:     MessageID(id),
		Topic:  Topic(env.Topic),
		Person: bytes.Clone(env.Person[:]),
		Device: bytes.Clone(env.Device[:]),
		Seq:    env.Seq,
		Time:   time.UnixMilli(int64(env.Time)),
		Body:   bytes.Clone(env.Body),
		Raw:    env.Encode(),
		From:   bytes.Clone(from[:]),
	}
}

// validate runs v on m: nil accepts; a panic, an unknown verdict or a context already done is Ignore.
func validate(ctx context.Context, v Validator, m *Message) (verdict Verdict) {
	if ctx.Err() != nil {
		return Ignore
	}
	if v == nil {
		return Accept
	}
	defer func() {
		if recover() != nil {
			verdict = Ignore
		}
	}()
	switch verdict = v(ctx, m); verdict {
	case Accept, Reject, Ignore, Retry:
		return verdict
	}
	return Ignore
}

// Room is a joined topic: publish to it and read what its members publish.
type Room struct {
	g        *Gossip
	topic    Topic
	authors  Authors
	open     Open
	validate Validator
	seq      func() uint64
	maxSize  int
	swarm    atomic.Bool  // joined on the swarm by Join and not left yet
	stuck    atomic.Int64 // validators of this room past their timeout that still run
	ctx      context.Context
	cancel   context.CancelFunc
	ch       chan *Message
	done     chan struct{}
	once     sync.Once
	err      error

	delivered, dropped uint64 // guarded by g.mu
}

// RoomStats are the current sizes of a room and what it delivered.
type RoomStats struct {
	Peers, Mesh, Outbound, Fanout int    // peers subscribed, in our mesh, outbound in it, fanout peers
	Delivered, Dropped            uint64 // messages queued for Next, and dropped because Next fell behind
}

// Join subscribes to t. With Config.Swarm it then joins the swarm topic too, and a failure there leaves t.
func (g *Gossip) Join(ctx context.Context, t Topic, opts *TopicOptions) (*Room, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	tc, err := opts.core()
	if err != nil {
		return nil, err
	}
	rm := &Room{g: g, topic: t, authors: opts.Authors, open: opts.Open, validate: opts.Validate, seq: opts.Seq,
		maxSize: opts.MaxMessageSize, ch: make(chan *Message, g.set.roomQueue), done: make(chan struct{})}
	if rm.seq == nil {
		rm.seq = newSeq(g.set.now())
	}
	rm.ctx, rm.cancel = context.WithCancel(g.ctx)
	g.mu.Lock()
	switch {
	case g.closed:
		err = ErrClosed
	case g.rooms[t] != nil:
		err = fmt.Errorf("%w: topic already joined", ErrInvalidArgument)
	default:
		g.rooms[t] = rm
		g.callLocked(func(now time.Time) { err = mapErr(g.r.Join(now, wire.Topic(t), tc)) })
		if err != nil {
			delete(g.rooms, t)
		}
	}
	g.mu.Unlock()
	if err != nil {
		rm.cancel()
		return nil, err
	}
	if g.swarm == nil {
		return rm, nil
	}
	if err := g.swarm.Join(ctx, t, opts.Swarm); err != nil {
		rm.Leave()
		return nil, fmt.Errorf("kologossip: swarm join: %w", err)
	}
	if g.hooks.swarmJoined != nil {
		g.hooks.swarmJoined()
	}
	rm.swarm.Store(true)
	// A Leave or Close that ran during the swarm join did not leave the swarm topic: leave it here.
	select {
	case <-rm.done:
		if rm.swarm.CompareAndSwap(true, false) {
			g.swarm.Leave(t)
		}
		return nil, rm.err
	default:
	}
	return rm, nil
}

// newSeq numbers a device's messages from start's Unix nanoseconds, one more per message, so a restarted device
// does not reuse numbers; it is safe for concurrent use.
func newSeq(start time.Time) func() uint64 {
	var n atomic.Uint64
	n.Store(uint64(start.UnixNano()))
	return func() uint64 { return n.Add(1) - 1 }
}

// ownChain checks this device's chain now, with the revocations the room's roster or open mode holds for it, so a
// device whose chain expired or was revoked stops publishing messages that every receiver would ignore.
func (g *Gossip) ownChain(t Topic) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	var revs []*koloid.Revocation
	a := authors{g}
	if au, err := a.Lookup(wire.Topic(t), g.person, g.dev.PublicKey()); err == nil {
		revs = au.Revocations
	} else if r, ok := a.open(wire.Topic(t), g.person); ok {
		revs = r
	}
	if err := g.res.Chain(g.set.now(), g.cert, revs); err != nil {
		return fmt.Errorf("%w: %w", ErrOwnChain, err)
	}
	return nil
}

// core checks the options and converts them for the router.
func (o *TopicOptions) core() (*core.TopicConfig, error) {
	if o == nil || (o.Authors == nil && o.Open == nil) {
		return nil, fmt.Errorf("%w: TopicOptions need Authors or Open", ErrInvalidArgument)
	}
	tc := &core.TopicConfig{MaxMessageSize: o.MaxMessageSize}
	if f := o.AllowPeer; f != nil {
		tc.AllowPeer = func(p core.PeerID) (ok bool) {
			defer func() {
				if recover() != nil {
					ok = false
				}
			}()
			return f(bytes.Clone(p[:]))
		}
	}
	if o.Params != nil {
		p, err := o.Params.core()
		if err != nil {
			return nil, err
		}
		tc.Params = &p
	}
	switch {
	case o.NoScore:
		tc.Score = &core.TopicScoreParams{}
	case o.Score != nil && *o.Score == (TopicScoreParams{}):
		return nil, fmt.Errorf("%w: a zero TopicScoreParams scores nothing; set NoScore instead", ErrInvalidConfig)
	case o.Score != nil:
		s := core.TopicScoreParams(*o.Score)
		tc.Score = &s
	}
	return tc, nil
}

// Topic returns the room's topic.
func (rm *Room) Topic() Topic { return rm.topic }

// Revalidate runs the validator again, now, on every message of the room it answered Retry for.
func (rm *Room) Revalidate() {
	rm.g.call(func(now time.Time) { rm.g.r.Revalidate(now, wire.Topic(rm.topic)) })
}

// RefreshPeers asks TopicOptions.AllowPeer about every connected peer again, for example after a removal: a peer it
// refuses now is told that we left the topic and leaves its mesh, and one it admits now is told that we joined it.
func (rm *Room) RefreshPeers() {
	rm.g.call(func(now time.Time) { rm.g.r.Refresh(now, wire.Topic(rm.topic)) })
}

// VerifyEnvelope checks raw, the Raw of a Message, against the author a: that it is an envelope of topic t by a's
// device for a's person, that the device signed it, and that a's certificate chain certifies the device at the
// envelope's own time with a's revocations. The caller judges that time. It returns the message with a nil From.
func VerifyEnvelope(t Topic, raw []byte, a *Author) (*Message, error) {
	if a == nil || a.Cert == nil {
		return nil, fmt.Errorf("%w: VerifyEnvelope needs an Author with a certificate", ErrInvalidArgument)
	}
	env, err := wire.DecodeEnvelope(raw, len(raw))
	switch {
	case err != nil:
		return nil, fmt.Errorf("%w: %w", ErrBadEnvelope, err)
	case Topic(env.Topic) != t:
		return nil, fmt.Errorf("%w: another topic", ErrBadEnvelope)
	case !bytes.Equal(env.Person[:], a.Person) || !bytes.Equal(env.Device[:], a.Cert.Device()):
		return nil, fmt.Errorf("%w: another author", ErrBadEnvelope)
	case env.Time > 1<<63-1:
		return nil, fmt.Errorf("%w: time out of range", ErrBadEnvelope)
	case !auth.Signed(env, raw[:len(raw)-wire.SigSize]):
		return nil, fmt.Errorf("%w: bad signature", ErrBadEnvelope)
	}
	opts := &koloid.VerifyOptions{Person: a.Person, Now: time.UnixMilli(int64(env.Time)), Revocations: a.Revocations}
	if err := a.Cert.Verify(opts); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadEnvelope, err)
	}
	m := newMessage(wire.NewID(raw), env, core.PeerID{})
	m.From = nil
	return m, nil
}

// Publish signs body as the next message of this device in the room and sends it, as Gossip.Publish does.
func (rm *Room) Publish(ctx context.Context, body []byte) (*Message, error) {
	select {
	case <-rm.done:
		return nil, rm.err
	default:
	}
	return rm.g.publish(ctx, rm.topic, rm.seq, body)
}

// Publish signs body as a message of this device in topic t, joined or not, and sends it as GossipSub does:
// flooded or through the mesh or fanout peers. It returns the message as signed, its Raw included, with a nil From.
// Next never returns our own messages; the guide has the details.
func (g *Gossip) Publish(ctx context.Context, t Topic, body []byte) (*Message, error) {
	seq := g.seq
	g.mu.Lock()
	if rm := g.rooms[t]; rm != nil {
		seq = rm.seq
	}
	g.mu.Unlock()
	return g.publish(ctx, t, seq, body)
}

func (g *Gossip) publish(ctx context.Context, t Topic, seq func() uint64, body []byte) (*Message, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	g.mu.Lock()
	limit := g.set.router.MaxMessageSize
	if rm := g.rooms[t]; rm != nil && rm.maxSize > 0 {
		limit = rm.maxSize
	}
	g.mu.Unlock()
	// The envelope adds at least the smallest overhead, so a body over the limit is refused before it is signed.
	if len(body) > limit {
		return nil, fmt.Errorf("%w: a body of %d bytes cannot fit %d", ErrTooLarge, len(body), limit)
	}
	if err := g.ownChain(t); err != nil {
		return nil, err
	}
	n, at := seq(), g.set.now()
	raw, err := auth.Sign(g.dev, g.person, wire.Topic(t), n, at, body)
	if err != nil {
		return nil, mapErr(err)
	}
	var id wire.ID
	if !g.call(func(now time.Time) { id, err = g.r.Publish(now, raw) }) {
		return nil, ErrClosed
	}
	if err != nil {
		return nil, mapErr(err)
	}
	return &Message{ID: MessageID(id), Topic: t, Person: bytes.Clone(g.person), Device: bytes.Clone(g.dev.PublicKey()), Seq: n,
		Time: time.UnixMilli(at.UnixMilli()), Body: bytes.Clone(body), Raw: bytes.Clone(raw)}, nil
}

// Next returns the next message delivered in the room, ErrNotJoined after Leave or ErrClosed after Close.
func (rm *Room) Next(ctx context.Context) (*Message, error) {
	select {
	case <-rm.done:
		return nil, rm.err
	default:
	}
	select {
	case m := <-rm.ch:
		return m, nil
	case <-rm.done:
		return nil, rm.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Leave unsubscribes from the topic, prunes its mesh with the unsubscribe backoff and ends its validators'
// contexts without waiting for them; with Config.Swarm it also leaves the swarm topic.
func (rm *Room) Leave() {
	g := rm.g
	g.mu.Lock()
	if g.rooms[rm.topic] == rm {
		delete(g.rooms, rm.topic)
		g.callLocked(func(now time.Time) { g.r.Leave(now, wire.Topic(rm.topic)) })
	}
	g.mu.Unlock()
	rm.end(ErrNotJoined)
}

// end stops the room once: its validators, Next, and its swarm topic.
func (rm *Room) end(err error) {
	rm.once.Do(func() {
		rm.err = err
		rm.cancel()
		close(rm.done)
		if rm.swarm.CompareAndSwap(true, false) {
			rm.g.swarm.Leave(rm.topic)
		}
	})
}

// Stats returns the room's sizes and delivery counters.
func (rm *Room) Stats() RoomStats {
	g := rm.g
	g.mu.Lock()
	defer g.mu.Unlock()
	ts := g.r.TopicStats(wire.Topic(rm.topic))
	return RoomStats{Peers: ts.Peers, Mesh: ts.Mesh, Outbound: ts.Outbound, Fanout: ts.Fanout,
		Delivered: rm.delivered, Dropped: rm.dropped}
}

// authors dispatches the router's author checks to each room's roster and open mode, with g.mu held.
type authors struct{ g *Gossip }

func (a authors) Lookup(t wire.Topic, person, device ed25519.PublicKey) (au *auth.Author, err error) {
	rm := a.g.rooms[Topic(t)]
	if rm == nil || rm.authors == nil {
		return nil, auth.ErrUnknownAuthor
	}
	defer func() {
		if recover() != nil {
			au, err = nil, auth.ErrUnknownAuthor
		}
	}()
	x, err := rm.authors.Lookup(Topic(t), person, device)
	if err != nil || x == nil {
		return nil, auth.ErrUnknownAuthor
	}
	return (*auth.Author)(x), nil
}

func (a authors) open(t wire.Topic, person ed25519.PublicKey) (revs []*koloid.Revocation, ok bool) {
	rm := a.g.rooms[Topic(t)]
	if rm == nil || rm.open == nil {
		return nil, false
	}
	defer func() {
		if recover() != nil {
			revs, ok = nil, false
		}
	}()
	return rm.open(Topic(t), person)
}

// sink takes the router's effects, with g.mu held.
type sink struct{ g *Gossip }

func (s sink) SendControl(to core.PeerID, c *wire.Control, urgent bool) bool {
	p := s.g.peers[to]
	if p == nil {
		return false
	}
	if len(c.IDontWant) > 0 && c.Size() == (&wire.Control{IDontWant: c.IDontWant}).Size() {
		return p.q.pushIDontWant(c.IDontWant, s.g.set.router.MaxIDontWantLength)
	}
	b, err := c.Encode()
	if err != nil {
		return false
	}
	lane := laneControl
	if urgent {
		lane = laneUrgent
	}
	return p.q.push(lane, b)
}

func (s sink) SendMessage(to core.PeerID, raw []byte) bool {
	p := s.g.peers[to]
	return p != nil && p.q.push(laneMessage, raw)
}

func (s sink) Validate(id wire.ID, n uint64, env *wire.Envelope, from core.PeerID) {
	g := s.g
	rm := g.rooms[Topic(env.Topic)]
	if rm == nil || rm.validate == nil {
		g.verdicts = append(g.verdicts, verdict{id, n, core.Accept})
		return
	}
	// The router keeps a validation in its bounds until ValidationDone, even once canceled.
	ctx, cancel := context.WithTimeout(rm.ctx, g.set.validateTimeout)
	g.validations[n] = cancel
	g.wg.Add(1)
	go func() {
		defer g.wg.Done()
		defer cancel()
		m := newMessage(id, env, from)
		done := make(chan Verdict, 1)
		go func() { done <- validate(ctx, rm.validate, m) }()
		finish := func(v core.Verdict) {
			g.call(func(now time.Time) {
				delete(g.validations, n)
				g.r.ValidationDone(now, id, n, v)
			})
		}
		select {
		case v := <-done:
			finish(v.core())
			return
		case <-ctx.Done():
		}
		// Past its timeout or canceled, the validation keeps its places until the validator returns.
		rm.stuck.Add(1)
		go func() {
			<-done
			rm.stuck.Add(-1)
			finish(core.Ignore)
		}()
	}()
}

func (s sink) Cancel(n uint64) {
	if cancel := s.g.validations[n]; cancel != nil {
		cancel()
	}
}

// Dial queues the peer exchange records of a PRUNE for the dialers; past PXPending waiting they are dropped.
func (s sink) Dial(t wire.Topic, from core.PeerID, recs []wire.PeerRecord) int {
	g := s.g
	if g.dials == nil {
		return 0
	}
	var ip netip.Addr
	if p := g.peers[from]; p != nil {
		ip = p.ip
	}
	n := 0
	for _, rec := range recs {
		select {
		case g.dials <- dialReq{Topic(t), rec, ip}:
			n++
		default:
			g.pxDropped.Add(1)
		}
	}
	return n
}

func (s sink) Deliver(id wire.ID, env *wire.Envelope, from core.PeerID) {
	rm := s.g.rooms[Topic(env.Topic)]
	if rm == nil {
		return
	}
	select {
	case rm.ch <- newMessage(id, env, from):
		rm.delivered++
	default:
		rm.dropped++
	}
}
