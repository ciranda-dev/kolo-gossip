// Package auth signs kolo-gossip envelopes with kolo-id device keys and checks their authors: the application's
// roster first, then a bounded cache of verified chains, then one CERTWANT to the forwarding peer. Its Resolver
// plugs into the core router as its Verifier and Resolver and, like the router, is not safe for concurrent use.
package auth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/ciranda-dev/kolo-gossip/internal/core"
	"github.com/ciranda-dev/kolo-gossip/internal/wire"
	koloid "github.com/ciranda-dev/kolo-id"
)

// Context is the kolo-id signing context of every gossip message.
const Context = "kolo-gossip/message/v0"

var (
	// ErrUnknownAuthor means the author cannot be checked; the message is ignored without penalty.
	ErrUnknownAuthor = core.ErrUnknownAuthor
	// ErrUnresolved means the author's chain must first be fetched from the forwarding peer.
	ErrUnresolved = core.ErrUnresolved
	// ErrVerify means the author's chain does not certify the device for the expected person now; the message is
	// ignored without penalty, since a forwarder may not know a revocation or an expiry yet.
	ErrVerify = errors.New("kologossip: author does not verify")
	// ErrInvalidArgument means an argument is unusable, such as a nil identity or a short person key.
	ErrInvalidArgument = core.ErrInvalidArgument
)

// Author is what the application knows about a device: the person it expects, the device's chain and the
// revocations it accepts.
type Author struct {
	Person      ed25519.PublicKey    // must equal the envelope's person
	Cert        *koloid.DeviceCert   // the device's certificate chain
	Revocations []*koloid.Revocation // records that passed Revocation.Verify, kept from first sight, bounded by the application
}

// Authors is the application's roster. Lookup runs on the router's goroutine, so it answers from memory; it
// returns ErrUnknownAuthor, or any error, for a device it does not know.
type Authors interface {
	Lookup(t wire.Topic, person, device ed25519.PublicKey) (*Author, error)
}

// Open accepts a person the roster does not know and returns the revocations accepted for it.
type Open func(t wire.Topic, person ed25519.PublicKey) (revocations []*koloid.Revocation, ok bool)

// Config configures a Resolver; DefaultConfig gives the defaults.
type Config struct {
	Authors        Authors       // closed mode: only devices the roster knows
	Open           Open          // open mode when set: any valid chain whose person it accepts
	CertCacheBytes int           // verified chains kept, from the roster and from the network separately
	CertTimeout    time.Duration // how long a CERTWANT may stay unanswered
	MaxCertWants   int           // requests outstanding to one peer, and CERTWANT entries answered per peer per heartbeat
	MaxCertAnswers int           // requests sent to one peer per heartbeat; at most half of MaxCertWants
	MaxWaiting     int           // messages waiting for a chain
	MaxChains      int           // chain results kept
	Now            func() time.Time
	Elapsed        func() time.Duration // a monotonic clock that times the roster and the open mode; nil charges them a flat cost
}

// DefaultConfig returns the defaults with no roster and no open mode; set one of them.
func DefaultConfig() *Config {
	return &Config{
		CertCacheBytes: 1 << 20,         // one largest message
		CertTimeout:    3 * time.Second, // the IWANT follow-up time
		MaxCertWants:   10,              // the IHAVE frames handled per peer per heartbeat
		MaxCertAnswers: 5,               // half of it: two of our heartbeats may fall in one of the peer's
		MaxWaiting:     1024,            // the messages the router keeps waiting for validation
		MaxChains:      4096,            // twice the chains of largest size the two caches hold
	}
}

func (c *Config) validate() error {
	switch {
	case c.Authors == nil && c.Open == nil:
		return invalid("need Authors or Open")
	case c.CertCacheBytes < wire.MaxCertSize+entryOverhead:
		return invalid("CertCacheBytes %d under one chain", c.CertCacheBytes)
	case c.CertTimeout <= 0:
		return invalid("CertTimeout %v must be positive", c.CertTimeout)
	case c.MaxCertWants < 2:
		return invalid("MaxCertWants %d must be at least 2", c.MaxCertWants)
	case c.MaxCertAnswers < 1 || 2*c.MaxCertAnswers > c.MaxCertWants:
		return invalid("MaxCertAnswers %d must be 1 to half of MaxCertWants %d", c.MaxCertAnswers, c.MaxCertWants)
	case c.MaxWaiting < 1:
		return invalid("MaxWaiting %d must be at least 1", c.MaxWaiting)
	case c.MaxChains < 1:
		return invalid("MaxChains %d must be at least 1", c.MaxChains)
	}
	return nil
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{core.ErrInvalidConfig}, args...)...)
}

// Stats counts what a Resolver did and holds its current sizes.
type Stats struct {
	Requests, Answered, Unsolicited, BadChains, Timeouts, Throttled uint64
	Served, CacheEvicted, NotHeld, Revoked                          uint64

	CacheChains, CacheBytes, Waiting, Outstanding int
}

// Resolver checks message authors for the core router: Verify answers from the roster or the cache, and the
// Resolver methods fetch a missing chain from the peers that forwarded the message. It counts the operations it
// does, which the router charges to the peer that caused them.
type Resolver struct {
	cfg      Config
	roster   certCache // chains the roster gave, kept to answer CERTWANT
	cache    certCache // chains fetched from the network in open mode
	chains   chainCache
	wants    map[pair][]*want // outstanding requests by author, at most one per peer
	queue    []*want          // in creation order, so in deadline order
	perPeer  map[core.PeerID]int
	credits  map[core.PeerID]int // CERT entries a peer may still send us: one per request we sent it
	answered map[core.PeerID]int // CERTWANT entries handled this heartbeat
	asked    map[core.PeerID]int // requests sent this heartbeat
	own      *cacheEntry         // this node's own chain, served outside the cache so it is never evicted
	waiting  int
	work     core.Ops
	stats    Stats
}

type pair [2 * wire.KeySize]byte

type want struct {
	key      pair
	peer     core.PeerID
	deadline time.Time
	msgs     []waitMsg
}

type waitMsg struct {
	id  wire.ID
	env *wire.Envelope
}

var _ core.Resolver = (*Resolver)(nil)

// New returns a Resolver; a nil cfg is invalid because the roster or the open mode is the application's.
func New(cfg *Config) (*Resolver, error) {
	if cfg == nil {
		return nil, invalid("nil config")
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	r := &Resolver{cfg: *cfg, wants: map[pair][]*want{}, perPeer: map[core.PeerID]int{}, credits: map[core.PeerID]int{},
		answered: map[core.PeerID]int{}, asked: map[core.PeerID]int{}, chains: chainCache{m: map[chainKey]chainResult{}}}
	if r.cfg.Now == nil {
		r.cfg.Now = time.Now
	}
	r.roster = newCertCache(cfg.CertCacheBytes, &r.stats)
	r.cache = newCertCache(cfg.CertCacheBytes, &r.stats)
	return r, nil
}

func keyOf(person, device []byte) pair {
	var k pair
	copy(k[:wire.KeySize], person)
	copy(k[wire.KeySize:], device)
	return k
}

// did counts n operations of kind op for Work.
func (r *Resolver) did(op core.Op, n int) { r.work[op] += n }

// Work returns the operations done since the last call.
func (r *Resolver) Work() core.Ops {
	w := r.work
	r.work = core.Ops{}
	return w
}

// Signed reports whether env is signed by its own device key under Context; signed is the envelope without its
// signature. It needs no state, so the driver runs it outside the router.
func Signed(env *wire.Envelope, signed []byte) bool {
	return koloid.Verify(env.Device[:], Context, signed, env.Sig[:])
}

// Signed implements core.Verifier with the package's Signed.
func (r *Resolver) Signed(env *wire.Envelope, signed []byte) bool { return Signed(env, signed) }

// Verify checks the author of env, whose signature passed Signed: the roster's chain first, then in open mode a
// cached chain; ErrUnresolved asks the router to fetch the chain. Every other error ignores the message.
func (r *Resolver) Verify(env *wire.Envelope, signed []byte) error {
	now := r.cfg.Now()
	person, device := ed25519.PublicKey(env.Person[:]), ed25519.PublicKey(env.Device[:])
	k := keyOf(person, device)
	if r.cfg.Authors != nil {
		start := r.clock()
		a, err := r.cfg.Authors.Lookup(env.Topic, person, device)
		r.callback(start)
		switch {
		case err == nil:
			// An answer without a usable chain for this very person and device is the roster's own gap.
			if a == nil || a.Cert == nil || !bytes.Equal(a.Person, person) || !bytes.Equal(a.Cert.Device(), device) {
				return fmt.Errorf("%w: the roster's answer does not name this person and device", ErrUnknownAuthor)
			}
			if err := r.chain(now, k, a.Cert, a.Revocations); err != nil {
				return fmt.Errorf("%w: %w", ErrVerify, err)
			}
			r.keep(k, a.Cert)
			return nil
		case !errors.Is(err, ErrUnknownAuthor):
			return fmt.Errorf("%w: %w", ErrUnknownAuthor, err)
		}
	}
	revs, ok := r.accept(env.Topic, person)
	if !ok {
		return ErrUnknownAuthor
	}
	r.did(core.OpLookup, 1)
	e := r.cache.get(k)
	if e == nil {
		return ErrUnresolved
	}
	if err := r.chain(now, k, e.cert, revs); err != nil {
		return fmt.Errorf("%w: %w", ErrVerify, err)
	}
	return nil
}

// keep caches a chain the roster gave, encoding it when it is a new object.
func (r *Resolver) keep(k pair, cert *koloid.DeviceCert) {
	r.did(core.OpLookup, 1)
	if el := r.roster.m[k]; el != nil && el.Value.(*cacheEntry).cert == cert {
		r.roster.lru.MoveToFront(el)
		return
	}
	raw := cert.Encode()
	r.did(core.OpAlloc, 2)
	r.did(core.OpBytes, 2*chunks(len(raw)))
	r.roster.put(k, cert, raw)
}

// accept asks the open mode about a person in topic t.
func (r *Resolver) accept(t wire.Topic, person ed25519.PublicKey) ([]*koloid.Revocation, bool) {
	if r.cfg.Open == nil {
		return nil, false
	}
	start := r.clock()
	revs, ok := r.cfg.Open(t, person)
	r.callback(start)
	return revs, ok
}

// clock reads the monotonic clock that times application code, zero without one.
func (r *Resolver) clock() time.Duration {
	if r.cfg.Elapsed == nil {
		return 0
	}
	return r.cfg.Elapsed()
}

// callback counts an application call that started at start: its measured time, at least its flat cost.
func (r *Resolver) callback(start time.Duration) {
	n := 1
	if r.cfg.Elapsed != nil {
		n = max(1, core.Callbacks(r.cfg.Elapsed()-start))
	}
	r.did(core.OpCallback, n)
}

// Chain checks that cert certifies its device for its person at now with revs, as the author check does.
func (r *Resolver) Chain(now time.Time, cert *koloid.DeviceCert, revs []*koloid.Revocation) error {
	return r.chain(now, keyOf(cert.Person(), cert.Device()), cert, revs)
}

// chain checks that cert certifies k's device for k's person at now with revs and returns kolo-id's error. The
// result changes with time only at a link's expiry, so it is cached until the second before the earliest expiry
// (errors for good), keyed by the objects, or by their encodings for a roster that decodes new ones.
func (r *Resolver) chain(now time.Time, k pair, cert *koloid.DeviceCert, revs []*koloid.Revocation) error {
	sec := now.Unix()
	pk := chainKey{cert: cert, rev: nil, n: len(revs), k: k}
	if len(revs) > 0 {
		pk.rev = &revs[0]
	}
	r.did(core.OpLookup, 1)
	if c, ok := r.chains.m[pk]; ok && sec <= c.until {
		return c.err
	}
	h := sha256.New()
	h.Write(k[:])
	n := len(k)
	for _, b := range append([][]byte{cert.Encode()}, encodings(revs)...) {
		h.Write(b)
		n += len(b)
	}
	r.did(core.OpBytes, 2*chunks(n))
	r.did(core.OpAlloc, 1+len(revs))
	var hk chainKey
	h.Sum(hk.sum[:0])
	r.did(core.OpLookup, 1)
	c, ok := r.chains.m[hk]
	if ok && sec <= c.until {
		// Known by content: the objects are not kept, so a roster or open mode that makes new objects at every
		// call pins none of them.
		return c.err
	}
	c = r.verify(now, k, cert, revs)
	if len(r.chains.m) >= 2*r.cfg.MaxChains {
		clear(r.chains.m)
	}
	r.chains.m[hk] = c
	r.chains.m[pk] = c
	return c.err
}

// verify runs kolo-id's check at now and finds until when its result holds.
func (r *Resolver) verify(now time.Time, k pair, cert *koloid.DeviceCert, revs []*koloid.Revocation) chainResult {
	check := func(at int64) error {
		r.did(core.OpChain, 1)
		return cert.Verify(&koloid.VerifyOptions{Person: k[:wire.KeySize], Now: time.Unix(at, 0), Revocations: revs})
	}
	sec := now.Unix()
	err := check(sec)
	if errors.Is(err, koloid.ErrCertRevoked) || errors.Is(err, koloid.ErrCertExpired) {
		r.cache.drop(k)
		r.roster.drop(k)
	}
	if err != nil {
		return chainResult{err: err, until: maxSecond}
	}
	// A chain valid now and at a later second is valid in between. Only the device's own expiry is known, so one
	// more check at it, at most an hour ahead, gives the span; if it fails, a link expires within it and the result
	// holds for this second only.
	hi := sec + recheck
	if exp := cert.ExpiresAt(); !exp.IsZero() {
		hi = min(hi, exp.Unix()-1)
	}
	if hi <= sec || check(hi) == nil {
		return chainResult{until: max(hi, sec)}
	}
	return chainResult{until: sec}
}

// recheck is how far ahead a valid chain's result is checked: two chain checks an hour at most per chain.
const recheck = 3600

// maxSecond is kolo-id's largest time, for results that never change.
const maxSecond = 1<<40 - 1

func encodings(revs []*koloid.Revocation) [][]byte {
	out := make([][]byte, 0, len(revs))
	for _, rv := range revs {
		if rv != nil {
			out = append(out, rv.Encode())
		}
	}
	return out
}

// chainCache holds chain results by the objects that carried them and by their encodings; past 2 x MaxChains
// entries it is emptied, which only costs checks again.
type chainCache struct {
	m map[chainKey]chainResult
}

// chainKey names a certificate and a revocation list by their objects, or by the hash of their encodings when
// sum is set. A list is named by its first element and its length: the application keeps a list it hands out
// unchanged.
type chainKey struct {
	cert *koloid.DeviceCert
	k    pair
	rev  **koloid.Revocation
	n    int
	sum  [sha256.Size]byte
}

type chainResult struct {
	err   error
	until int64 // the last Unix second the result holds
}

func chunks(n int) int { return (n + 63) / 64 }

// Resolve queues a message whose chain is missing and returns a CERTWANT for from unless one is outstanding.
func (r *Resolver) Resolve(now time.Time, id wire.ID, env *wire.Envelope, _ []byte, from core.PeerID) (*wire.CertWant, error) {
	r.did(core.OpLookup, 3)
	if r.waiting >= r.cfg.MaxWaiting {
		r.stats.Throttled++
		return nil, fmt.Errorf("%w: too many messages wait for chains", core.ErrPeerBusy)
	}
	k := keyOf(env.Person[:], env.Device[:])
	w := r.find(k, from)
	var req *wire.CertWant
	if w == nil {
		// Two of our heartbeats may fall within one of the peer's, so we send at most half of what it answers.
		if r.perPeer[from] >= r.cfg.MaxCertWants || r.asked[from] >= r.cfg.MaxCertAnswers {
			r.stats.Throttled++
			return nil, fmt.Errorf("%w: too many requests to one peer", core.ErrPeerBusy)
		}
		r.did(core.OpAlloc, 3)
		r.asked[from]++
		w = &want{key: k, peer: from, deadline: now.Add(r.cfg.CertTimeout)}
		r.wants[k] = append(r.wants[k], w)
		r.queue = append(r.queue, w)
		r.perPeer[from]++
		r.credits[from]++
		r.stats.Requests++
		req = &wire.CertWant{Person: env.Person, Device: env.Device}
	}
	r.did(core.OpAlloc, 1)
	w.msgs = append(w.msgs, waitMsg{id: id, env: env})
	r.waiting++
	return req, nil
}

func (r *Resolver) find(k pair, p core.PeerID) *want {
	r.did(core.OpLookup, 1)
	for _, w := range r.wants[k] {
		if w.peer == p {
			return w
		}
	}
	return nil
}

// drop ends an outstanding request and returns the messages that waited on it.
func (r *Resolver) drop(w *want) []waitMsg {
	r.did(core.OpLookup, 3)
	ws := slices.DeleteFunc(r.wants[w.key], func(x *want) bool { return x == w })
	if len(ws) == 0 {
		delete(r.wants, w.key)
	} else {
		r.wants[w.key] = ws
	}
	if r.perPeer[w.peer]--; r.perPeer[w.peer] <= 0 {
		delete(r.perPeer, w.peer)
	}
	// Credits left for requests that ended unanswered go with them.
	if c := min(r.credits[w.peer], r.perPeer[w.peer]); c > 0 {
		r.credits[w.peer] = c
	} else {
		delete(r.credits, w.peer)
	}
	r.did(core.OpLookup, len(r.queue)/16+1)
	r.queue = slices.DeleteFunc(r.queue, func(x *want) bool { return x == w })
	r.waiting -= len(w.msgs)
	return w.msgs
}

// Own sets this node's own device chain, which CertWant serves to peers that fetch the chain of its messages.
func (r *Resolver) Own(cert *koloid.DeviceCert) {
	r.own = &cacheEntry{key: keyOf(cert.Person(), cert.Device()), cert: cert, raw: cert.Encode()}
}

// CertWant answers up to MaxCertWants of a peer's entries per heartbeat, all an honest peer sends, each with the
// chain it holds or with the 64 bytes of person and device that say it holds none, so an honest forwarder is never
// taken for one that withholds. Entries past the bound get no answer.
func (r *Resolver) CertWant(from core.PeerID, ws []wire.CertWant) [][]byte {
	n := min(len(ws), r.cfg.MaxCertWants-r.answered[from])
	r.did(core.OpLookup, 1)
	if n <= 0 {
		return nil
	}
	r.answered[from] += n
	var out [][]byte
	for _, w := range ws[:n] {
		k := keyOf(w.Person[:], w.Device[:])
		r.did(core.OpLookup, 3)
		if e := r.held(k); e != nil {
			out = append(out, e.raw)
			r.stats.Served++
			continue
		}
		r.did(core.OpAlloc, 1)
		out = append(out, bytes.Clone(k[:]))
	}
	return out
}

// held returns the chain this node holds for k: its own, the roster's, or one fetched.
func (r *Resolver) held(k pair) *cacheEntry {
	if r.own != nil && r.own.key == k {
		return r.own
	}
	if e := r.roster.get(k); e != nil {
		return e
	}
	return r.cache.get(k)
}

// Cert checks chains a peer sent: each request we sent it lets one entry be read, so a peer cannot make us decode
// more than we asked. "Not held" ends that request without penalty; a chain with a bad structure, person or
// signature is a broken request. Each waiting message is then checked with the revocations the open mode holds for
// its topic; a revoked or expired chain ends only that peer's request, not a copy waiting on another peer.
func (r *Resolver) Cert(now time.Time, from core.PeerID, certs [][]byte, budget int64) core.Resolutions {
	var out core.Resolutions
	n := min(len(certs), r.credits[from])
	r.did(core.OpLookup, 1)
	r.stats.Unsolicited += uint64(len(certs) - n)
	if n > 0 {
		r.credits[from] -= n
	}
	for _, b := range certs[:n] {
		// The peer pays for every chain check its answers cause, before it runs: once its budget is spent, its
		// remaining requests end without a penalty and their messages are asked of other peers.
		if r.spent() >= budget {
			r.endAll(from, &out)
			break
		}
		r.did(core.OpBytes, chunks(len(b)))
		r.did(core.OpAlloc, 1)
		if len(b) == len(pair{}) {
			if w := r.find(pair(b), from); w != nil {
				r.stats.NotHeld++
				r.fail(r.drop(w), &out)
			} else {
				r.stats.Unsolicited++
			}
			continue
		}
		r.did(core.OpCert, 1)
		cert, err := koloid.DecodeDeviceCert(b)
		if err != nil {
			r.stats.Unsolicited++
			continue
		}
		k := keyOf(cert.Person(), cert.Device())
		w := r.find(k, from)
		if w == nil {
			r.stats.Unsolicited++
			continue
		}
		r.stats.Answered++
		// kolo-id checks expiry and revocation before signatures, so structure, person and signatures are checked
		// first at the Unix epoch, when no certificate of any link has expired yet: an unsigned fake cannot pass as
		// a merely stale chain.
		r.did(core.OpChain, 1)
		if err := cert.Verify(&koloid.VerifyOptions{Person: k[:wire.KeySize], Now: time.Unix(0, 0)}); err != nil {
			r.stats.BadChains++
			out.Broken = append(out.Broken, w.peer)
			r.fail(r.drop(w), &out)
			continue
		}
		// The chain answers this peer's request; only if it verifies now for one of its messages is it current, and
		// then it answers every request for the device. A stale or revoked chain ends this request alone.
		verified := false
		for _, m := range r.drop(w) {
			if r.spent() >= budget {
				out.Done = append(out.Done, core.Resolution{ID: m.id, Err: ErrUnknownAuthor})
				continue
			}
			err := r.check(now, k, cert, m.env.Topic)
			verified = verified || err == nil
			out.Done = append(out.Done, core.Resolution{ID: m.id, Err: err})
		}
		if !verified {
			continue
		}
		r.did(core.OpAlloc, 2)
		r.did(core.OpBytes, chunks(len(b)))
		r.cache.put(k, cert, bytes.Clone(b))
		for len(r.wants[k]) > 0 {
			for _, m := range r.drop(r.wants[k][0]) {
				err := error(ErrUnknownAuthor)
				if r.spent() < budget {
					err = r.check(now, k, cert, m.env.Topic)
				}
				out.Done = append(out.Done, core.Resolution{ID: m.id, Err: err})
			}
		}
	}
	return out
}

// check is the author check of a message of topic t with a fetched chain: the open mode's revocations for the
// person in that topic.
func (r *Resolver) check(now time.Time, k pair, cert *koloid.DeviceCert, t wire.Topic) error {
	revs, ok := r.accept(t, k[:wire.KeySize])
	if !ok {
		return ErrUnknownAuthor
	}
	err := r.chain(now, k, cert, revs)
	if errors.Is(err, koloid.ErrCertRevoked) || errors.Is(err, koloid.ErrCertExpired) {
		r.stats.Revoked++
	}
	return err
}

func (r *Resolver) fail(ms []waitMsg, out *core.Resolutions) {
	for _, m := range ms {
		out.Done = append(out.Done, core.Resolution{ID: m.id, Err: ErrUnknownAuthor})
	}
}

// Expire ends the requests unanswered by now, each a broken request of its peer, and starts a new heartbeat for
// the CERTWANT bounds.
func (r *Resolver) Expire(now time.Time) core.Resolutions {
	clear(r.answered)
	clear(r.asked)
	var out core.Resolutions
	for len(r.queue) > 0 && r.queue[0].deadline.Before(now) {
		w := r.queue[0]
		r.stats.Timeouts++
		out.Broken = append(out.Broken, w.peer)
		r.fail(r.drop(w), &out)
	}
	return out
}

// End ends every request to p without a penalty: we stopped reading p, or it left.
func (r *Resolver) End(p core.PeerID) core.Resolutions {
	var out core.Resolutions
	r.endAll(p, &out)
	return out
}

func (r *Resolver) endAll(p core.PeerID, out *core.Resolutions) {
	r.did(core.OpLookup, len(r.queue))
	for _, w := range slices.Clone(r.queue) {
		if w.peer == p {
			r.fail(r.drop(w), out)
		}
	}
}

// spent returns the units of the work done since the last Work call.
func (r *Resolver) spent() int64 {
	var u int64
	for op, n := range r.work {
		u += core.Cost(core.Op(op), n)
	}
	return u
}

// Dropped forgets message id on the request to peer to that our own full queue did not send; a request left with
// no message ends.
func (r *Resolver) Dropped(to core.PeerID, id wire.ID, w wire.CertWant) {
	x := r.find(keyOf(w.Person[:], w.Device[:]), to)
	if x == nil {
		return
	}
	n := len(x.msgs)
	x.msgs = slices.DeleteFunc(x.msgs, func(m waitMsg) bool { return m.id == id })
	r.waiting -= n - len(x.msgs)
	if len(x.msgs) == 0 {
		r.drop(x)
	}
}

// Forget drops message id, which the router no longer holds, from every request for its author; a request left
// with none ends without a penalty.
func (r *Resolver) Forget(id wire.ID, env *wire.Envelope) {
	k := keyOf(env.Person[:], env.Device[:])
	ws := slices.Clone(r.wants[k])
	r.did(core.OpLookup, 1+len(ws))
	for _, w := range ws {
		n := len(w.msgs)
		r.did(core.OpLookup, n)
		w.msgs = slices.DeleteFunc(w.msgs, func(m waitMsg) bool { return m.id == id })
		r.waiting -= n - len(w.msgs)
		if len(w.msgs) == 0 {
			r.drop(w)
		}
	}
}

// Leave drops the messages of topic t from every request; a request left with none ends without a penalty.
func (r *Resolver) Leave(t wire.Topic) {
	for _, w := range slices.Clone(r.queue) {
		n := len(w.msgs)
		w.msgs = slices.DeleteFunc(w.msgs, func(m waitMsg) bool { return m.env.Topic == t })
		r.waiting -= n - len(w.msgs)
		if len(w.msgs) == 0 {
			r.drop(w)
		}
	}
}

// Stats returns the counters and current sizes.
func (r *Resolver) Stats() Stats {
	s := r.stats
	s.CacheChains, s.CacheBytes = r.cache.lru.Len()+r.roster.lru.Len(), r.cache.bytes+r.roster.bytes
	s.Waiting, s.Outstanding = r.waiting, len(r.queue)
	return s
}
