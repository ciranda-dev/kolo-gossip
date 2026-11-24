package core

import (
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"math/rand/v2"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/ciranda-dev/kolo-gossip/internal/wire"
)

var t0 = time.Unix(1_800_000_000, 0)

// badSig marks an envelope the fake verifier refuses.
const badSig = 0xBD

type fakeVerifier struct{ calls int }

func (v *fakeVerifier) Signed(env *wire.Envelope, signed []byte) bool {
	v.calls++
	return env.Sig[0] != badSig
}

func (v *fakeVerifier) Work() Ops { return Ops{} }

func (v *fakeVerifier) Verify(env *wire.Envelope, signed []byte) error {
	if env.Sig[0] == unknownSig {
		return ErrUnknownAuthor
	}
	return nil
}

type sentControl struct {
	to     PeerID
	c      *wire.Control
	urgent bool
}

type sentMessage struct {
	to  PeerID
	raw []byte
}

type validation struct {
	id   wire.ID
	from PeerID
	n    uint64
}

type dialCall struct {
	topic wire.Topic
	from  PeerID
	recs  []wire.PeerRecord
}

// recSink records every effect and hashes it, so two runs can be compared.
type recSink struct {
	ctrl     []sentControl
	msgs     []sentMessage
	validate []validation
	deliver  []validation
	canceled []uint64
	dials    []dialCall
	dialCap  int // records Dial takes each call, 0 for all
	full     map[PeerID]bool
	h        hash.Hash
	onCtrl   func(to PeerID, c *wire.Control)
	bench    bool // encode control as the driver does, and keep nothing but validations
}

func newSink() *recSink {
	return &recSink{full: map[PeerID]bool{}, h: sha256.New()}
}

func (s *recSink) SendControl(to PeerID, c *wire.Control, urgent bool) bool {
	if s.onCtrl != nil {
		s.onCtrl(to, c)
	}
	if s.bench {
		_, err := c.Encode()
		return err == nil
	}
	raw, err := c.Encode()
	if err != nil {
		panic(err)
	}
	s.h.Write([]byte{'c'})
	s.h.Write(to[:])
	s.h.Write(raw)
	if s.full[to] {
		return false
	}
	s.ctrl = append(s.ctrl, sentControl{to, c, urgent})
	return true
}

func (s *recSink) SendMessage(to PeerID, raw []byte) bool {
	if s.bench {
		return true
	}
	s.h.Write([]byte{'m'})
	s.h.Write(to[:])
	s.h.Write(raw)
	if s.full[to] {
		return false
	}
	s.msgs = append(s.msgs, sentMessage{to, raw})
	return true
}

func (s *recSink) Validate(id wire.ID, n uint64, env *wire.Envelope, from PeerID) {
	if s.bench {
		s.validate = append(s.validate, validation{id, from, n})
		return
	}
	s.h.Write([]byte{'v'})
	s.h.Write(id[:])
	s.validate = append(s.validate, validation{id, from, n})
}

func (s *recSink) Cancel(n uint64) { s.canceled = append(s.canceled, n) }

func (s *recSink) Dial(t wire.Topic, from PeerID, recs []wire.PeerRecord) int {
	s.dials = append(s.dials, dialCall{t, from, recs})
	if s.dialCap > 0 {
		return min(s.dialCap, len(recs))
	}
	return len(recs)
}

func (s *recSink) Deliver(id wire.ID, env *wire.Envelope, from PeerID) {
	if s.bench {
		return
	}
	s.h.Write([]byte{'d'})
	s.h.Write(id[:])
	s.deliver = append(s.deliver, validation{id, from, 0})
}

func (s *recSink) reset() {
	s.ctrl, s.msgs, s.validate, s.deliver = nil, nil, nil, nil
}

// ctrlTo returns the control frames sent to p.
func (s *recSink) ctrlTo(p PeerID) []*wire.Control {
	var out []*wire.Control
	for _, c := range s.ctrl {
		if c.to == p {
			out = append(out, c.c)
		}
	}
	return out
}

func (s *recSink) msgsTo(p PeerID) int {
	n := 0
	for _, m := range s.msgs {
		if m.to == p {
			n++
		}
	}
	return n
}

func (s *recSink) graftsTo(p PeerID, t wire.Topic) int {
	n := 0
	for _, c := range s.ctrlTo(p) {
		n += count(c.Graft, t)
	}
	return n
}

func (s *recSink) prunesTo(p PeerID, t wire.Topic) []wire.Prune {
	var out []wire.Prune
	for _, c := range s.ctrlTo(p) {
		for _, pr := range c.Prune {
			if pr.Topic == t {
				out = append(out, pr)
			}
		}
	}
	return out
}

func count[T comparable](s []T, v T) int {
	n := 0
	for _, x := range s {
		if x == v {
			n++
		}
	}
	return n
}

func key(i int) PeerID {
	var k PeerID
	binary.BigEndian.PutUint32(k[:], uint32(i)+1)
	return k
}

func topicID(i int) wire.Topic {
	var t wire.Topic
	t[0], t[31] = 0x70, byte(i)
	return t
}

func ip(i int) netip.Addr {
	return netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
}

func addr(i int) netip.AddrPort { return netip.AddrPortFrom(ip(i), 4000) }

// verdict answers the last validation of id the sink saw.
func (f *fixture) verdict(id wire.ID, v Verdict) {
	f.t.Helper()
	for i := len(f.sink.validate) - 1; i >= 0; i-- {
		if f.sink.validate[i].id == id {
			f.r.ValidationDone(f.now, id, f.sink.validate[i].n, v)
			return
		}
	}
	f.r.ValidationDone(f.now, id, 0, v)
}

// envelope builds an encoded envelope by device for topic t at the given time with a body of n bytes.
func envelope(t wire.Topic, device PeerID, seq uint64, at time.Time, n int) []byte {
	e := &wire.Envelope{Topic: t, Person: wire.Key(device), Device: wire.Key(device), Seq: seq, Time: uint64(at.UnixMilli()), Body: make([]byte, n)}
	e.Sig[1] = byte(seq)
	return e.Encode()
}

func badEnvelope(t wire.Topic, device PeerID, seq uint64, at time.Time) []byte {
	e := &wire.Envelope{Topic: t, Device: wire.Key(device), Seq: seq, Time: uint64(at.UnixMilli())}
	e.Sig[0] = badSig
	return e.Encode()
}

type fixture struct {
	t    *testing.T
	r    *Router
	sink *recSink
	v    *fakeVerifier
	now  time.Time
	// spread, if set, are the topics the honest runs publish in turn; otherwise T.
	spread []wire.Topic
}

func newFixture(t *testing.T, cfg *Config) *fixture {
	t.Helper()
	if cfg == nil {
		cfg = DefaultConfig()
	}
	f := &fixture{t: t, sink: newSink(), v: &fakeVerifier{}, now: t0}
	r, err := New(t0, key(0), cfg, rand.New(rand.NewPCG(1, 2)), f.v, f.sink)
	if err != nil {
		t.Fatal(err)
	}
	f.r = r
	return f
}

// settle lets WorkBurst pass, so every peer's buckets are full, as for peers connected for a while.
func (f *fixture) settle() {
	f.now = f.now.Add(f.r.cfg.WorkBurst)
	for _, p := range f.r.peers {
		f.r.Wait(f.now, p.id)
	}
}

// addPeers connects peers 1..n, all subscribed to the given topics; odd peers are outbound.
func (f *fixture) addPeers(n int, topics ...wire.Topic) {
	f.t.Helper()
	for i := 1; i <= n; i++ {
		f.addPeer(i, i%2 == 1, topics...)
	}
}

func (f *fixture) addPeer(i int, outbound bool, topics ...wire.Topic) {
	f.t.Helper()
	if err := f.r.AddPeer(f.now, key(i), outbound, addr(i)); err != nil {
		f.t.Fatal(err)
	}
	var c wire.Control
	for _, t := range topics {
		c.Subs = append(c.Subs, wire.Sub{Topic: t, Subscribe: true})
	}
	f.control(i, &c)
}

func (f *fixture) control(i int, c *wire.Control) {
	f.t.Helper()
	if err := f.r.Control(f.now, key(i), c); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) join(t wire.Topic, tc *TopicConfig) {
	f.t.Helper()
	if err := f.r.Join(f.now, t, tc); err != nil {
		f.t.Fatal(err)
	}
}

// tick advances time by d and runs the router's due work.
func (f *fixture) tick(d time.Duration) {
	f.now = f.now.Add(d)
	f.r.Tick(f.now)
}

// heartbeat advances to the next heartbeat and runs it.
func (f *fixture) heartbeat() {
	f.now = f.r.nextHeartbeat
	f.r.Tick(f.now)
}

// receive delivers raw from peer i and accepts it in validation when it reaches the validator.
func (f *fixture) receive(i int, raw []byte, v Verdict) {
	n := len(f.sink.validate)
	f.r.Message(f.now, key(i), raw)
	if len(f.sink.validate) > n {
		f.r.ValidationDone(f.now, f.sink.validate[n].id, f.sink.validate[n].n, v)
	}
}

func (f *fixture) inMesh(t wire.Topic, i int) bool {
	return slices.Contains(f.r.Mesh(t), key(i))
}

// scoringConfig returns DefaultConfig with scoring on and explicit test parameters (not defaults).
func scoringConfig() *Config {
	cfg := DefaultConfig()
	cfg.Score = &ScoreParams{
		Thresholds:                Thresholds{Gossip: -10, Publish: -20, Graylist: -40, OpportunisticGraft: 1},
		BehaviourPenaltyWeight:    -1,
		BehaviourPenaltyThreshold: 0,
		BehaviourPenaltyDecay:     0.9,
		DecayInterval:             time.Second,
		DecayToZero:               0.01,
		RetainScore:               time.Hour,
		AppWeight:                 1,
	}
	return cfg
}

func topicScore() *TopicScoreParams {
	return &TopicScoreParams{
		TopicWeight:                     1,
		TimeInMeshWeight:                0.01,
		TimeInMeshQuantum:               time.Second,
		TimeInMeshCap:                   10,
		FirstMessageDeliveriesWeight:    1,
		FirstMessageDeliveriesDecay:     0.5,
		FirstMessageDeliveriesCap:       10,
		MeshMessageDeliveriesWeight:     -1,
		MeshMessageDeliveriesDecay:      0.5,
		MeshMessageDeliveriesCap:        10,
		MeshMessageDeliveriesThreshold:  2,
		MeshMessageDeliveriesWindow:     10 * time.Millisecond,
		MeshMessageDeliveriesActivation: 5 * time.Second,
		MeshFailurePenaltyWeight:        -1,
		MeshFailurePenaltyDecay:         0.5,
		InvalidMessageDeliveriesWeight:  -1,
		InvalidMessageDeliveriesDecay:   0.5,
	}
}

func randFor(seed uint64) *rand.Rand {
	return rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
}

func mustAddr(s string) netip.Addr {
	return netip.MustParseAddr(s)
}
