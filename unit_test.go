package kologossip

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"math"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ciranda-dev/kolo-gossip/internal/core"
	"github.com/ciranda-dev/kolo-gossip/internal/wire"
	koloid "github.com/ciranda-dev/kolo-id"
	koloswarm "github.com/ciranda-dev/kolo-swarm"
	kolotransport "github.com/ciranda-dev/kolo-transport"
)

// TestConfigDefaults: a Config with only Cert gives the core defaults, scoring on, flood publishing on and the
// driver defaults; every zero field takes its default.
func TestConfigDefaults(t *testing.T) {
	m := newMember(t)
	s, err := (&Config{Cert: m.cert}).settings()
	if err != nil {
		t.Fatal(err)
	}
	if s.router.Elapsed == nil {
		t.Fatal("application code is not timed")
	}
	s.router.Elapsed = nil
	if !reflect.DeepEqual(s.router, *core.DefaultConfig()) {
		t.Fatalf("router config %+v", s.router)
	}
	a := s.auth
	if a.CertCacheBytes != 1<<20 || a.CertTimeout != 3*time.Second || a.MaxCertWants != 10 || a.MaxCertAnswers != 5 || a.MaxWaiting != 1040 || a.Elapsed == nil {
		t.Fatalf("auth config %+v", a)
	}
	if s.peerQueue != 32 || s.peerQueueBytes != 1<<20 || s.roomQueue != 32 || s.frameTimeout != 30*time.Second ||
		s.validateTimeout != 2*time.Minute {
		t.Fatalf("driver config %+v", s)
	}
	big, err := (&Config{Cert: m.cert, MaxMessageSize: 4 << 20, MaxCacheBytes: 64 << 20}).settings()
	if err != nil || big.peerQueueBytes != 4<<20 || big.router.MaxPeerValidatingBytes != 4<<20 || big.router.MaxValidatingBytes != 65*4<<20 {
		t.Fatalf("PeerQueueBytes and the validation shares must hold one largest message: %v %+v", err, big)
	}
	ctl, err := (&Config{Cert: m.cert, MaxControlSize: 2 << 20}).settings()
	if err != nil || ctl.peerQueueBytes != 2<<20 {
		t.Fatalf("PeerQueueBytes must hold one largest control frame: %v %d", err, ctl.peerQueueBytes)
	}
}

// TestConfigOverrides: set fields reach the router and the resolver; NoScore turns scoring off.
func TestConfigOverrides(t *testing.T) {
	m := newMember(t)
	p := DefaultParams()
	p.D, p.Dhi = 7, 13
	cfg := &Config{Cert: m.cert, Params: p, NoScore: true, NoFloodPublish: true, HeartbeatInterval: 2 * time.Second,
		MaxSeen: 5, MaxMessageSize: 2048, PeerQueue: 3, PeerQueueBytes: 600 << 10, RoomQueue: 4, CertTimeout: time.Second,
		MaxWaiting: 2, IWantFollowupTime: time.Second, MaxPeerTopics: 4, MaxIDontWantIDs: 7, MaxPeerValidating: 9, FrameTimeout: time.Second, ValidateTimeout: 2 * time.Second, Score: DefaultScore(),
		LockWork: 100 * time.Millisecond, PeerWork: 50 * time.Millisecond, WorkBurst: 3 * time.Second}
	s, err := cfg.settings()
	if err != nil {
		t.Fatal(err)
	}
	r := s.router
	if r.Score != nil || r.FloodPublish || r.Params.D != 7 || r.Params.Dhi != 13 || r.HeartbeatInterval != 2*time.Second ||
		r.MaxSeen != 5 || r.MaxMessageSize != 2048 || r.IWantFollowupTime != time.Second || r.MaxPeerTopics != 4 ||
		r.MaxIDontWantIDs != 7 || r.MaxPeerValidating != 9 || r.LockWork != int64(100*time.Millisecond/core.Unit) ||
		r.PeerWork != int64(50*time.Millisecond/core.Unit) || r.WorkBurst != 3*time.Second {
		t.Fatalf("router config %+v", r)
	}
	if s.peerQueue != 3 || s.peerQueueBytes != 600<<10 || s.roomQueue != 4 || s.auth.CertTimeout != time.Second ||
		s.auth.MaxWaiting != 2 || s.frameTimeout != time.Second || s.validateTimeout != 2*time.Second {
		t.Fatalf("settings %+v", s)
	}
	g, err := New(m.device, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	if !g.Allow(ident(t).PublicKey(), netip.AddrPort{}) || g.Score(ident(t).PublicKey()) != 0 {
		t.Fatal("scoring off must allow everyone and score 0")
	}
}

// TestParamsGossipPeersDefault: a hand-built Params without GossipPeers takes the default budget, at least its Dlazy,
// in a Config and in a topic's options; only a Bootstrap Params without a mesh keeps 0, no cap.
func TestParamsGossipPeersDefault(t *testing.T) {
	m := newMember(t)
	def := DefaultParams().GossipPeers
	mesh := func(dlazy, gossipPeers int, bootstrap bool) *Params {
		return &Params{D: 6, Dlo: 4, Dhi: 12, Dlazy: dlazy, Dscore: 6, Dout: 2, GossipFactor: 0.75, GossipPeers: gossipPeers, Bootstrap: bootstrap}
	}
	for name, c := range map[string]struct {
		p    *Params
		want int
	}{
		"hand-built":     {mesh(6, 0, false), def},
		"Dlazy over 43":  {mesh(def+7, 0, false), def + 7},
		"set":            {mesh(6, 9, false), 9},
		"bootstrap mesh": {mesh(6, 0, true), def},
		"bootstrap":      {&Params{Bootstrap: true}, 0},
	} {
		cfg := &Config{Cert: m.cert, Params: c.p}
		s, err := cfg.settings()
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if got := s.router.Params.GossipPeers; got != c.want {
			t.Errorf("%s: GossipPeers %d, want %d", name, got, c.want)
		}
		g, err := New(m.device, cfg)
		if err != nil {
			t.Errorf("%s: New: %v", name, err)
			continue
		}
		g.Close()
		tc, err := (&TopicOptions{Authors: newRoster(), Params: c.p}).core()
		if err != nil || tc.Params.GossipPeers != c.want {
			t.Errorf("%s: topic options: %v %+v", name, err, tc)
		}
	}
}

// TestConfigErrors: every inconsistent configuration is refused.
func TestConfigErrors(t *testing.T) {
	m, other := newMember(t), newMember(t)
	sw, err := koloswarm.New(context.Background(), "127.0.0.1:0", other.device, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer sw.Close()
	bad := DefaultScore()
	bad.Thresholds.Gossip = 1
	noRetain := DefaultScore()
	noRetain.RetainScore = 0
	cases := map[string]*Config{
		"nil":                nil,
		"no cert":            {},
		"other device":       {Cert: other.cert},
		"other swarm key":    {Cert: m.cert, Swarm: sw},
		"negative":           {Cert: m.cert, MaxSeen: -1},
		"negative duration":  {Cert: m.cert, HeartbeatInterval: -time.Second},
		"window":             {Cert: m.cert, MaxAge: 2 * time.Minute},
		"params":             {Cert: m.cert, Params: &Params{D: 6, Dlo: 7, Dhi: 12}},
		"score":              {Cert: m.cert, Score: bad},
		"queue":              {Cert: m.cert, PeerQueue: -1},
		"room queue":         {Cert: m.cert, RoomQueue: -1},
		"queue bytes":        {Cert: m.cert, PeerQueueBytes: 1000},
		"message over queue": {Cert: m.cert, PeerQueueBytes: 600 << 10},
		"cert cache":         {Cert: m.cert, CertCacheBytes: -1},
		"cert timeout":       {Cert: m.cert, CertTimeout: -1},
		"frame timeout":      {Cert: m.cert, FrameTimeout: -1},
		"validate timeout":   {Cert: m.cert, ValidateTimeout: -1},
		"validate past seen": {Cert: m.cert, ValidateTimeout: 3 * time.Minute},
		"lock work":          {Cert: m.cert, LockWork: -1},
		"peer work":          {Cert: m.cert, PeerWork: -time.Second},
		"work burst":         {Cert: m.cert, WorkBurst: time.Millisecond},
		"share over half":    {Cert: m.cert, MaxValidating: 100, MaxPeerValidating: 60},
		"zero params":        {Cert: m.cert, Params: &Params{}},
		"zero score":         {Cert: m.cert, Score: &ScoreParams{}},
		"no retention":       {Cert: m.cert, Score: noRetain},
		"peer validating":    {Cert: m.cert, MaxPeerValidating: -1},
	}
	for name, cfg := range cases {
		if _, err := New(m.device, cfg); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for field, cfg := range map[string]*Config{
		"MaxSeen":           {Cert: m.cert, MaxSeen: -1},
		"HeartbeatInterval": {Cert: m.cert, HeartbeatInterval: -time.Second},
		"MaxWaiting":        {Cert: m.cert, MaxWaiting: -1},
		"PeerQueue":         {Cert: m.cert, PeerQueue: -1},
	} {
		if _, err := New(m.device, cfg); err == nil || !strings.Contains(err.Error(), field) {
			t.Errorf("the error for %s does not name it: %v", field, err)
		}
	}
	if _, err := New(nil, &Config{Cert: m.cert}); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("nil identity: %v", err)
	}
	expired := newMember(t)
	offer, err := expired.person.OfferDeviceCert(expired.device.PublicKey(), &koloid.IssueOptions{Serial: 1,
		IssuedAt: time.Now().Add(-2 * time.Hour), ExpiresAt: time.Now().Add(-time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if expired.cert, err = expired.device.AcceptDeviceCert(offer, expired.person.PublicKey()); err != nil {
		t.Fatal(err)
	}
	if _, err := New(expired.device, &Config{Cert: expired.cert}); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("expired cert: %v", err)
	}
}

// TestAppScore: the application score reaches the router; a panic or a value that is not finite scores 0.
func TestAppScore(t *testing.T) {
	var p core.PeerID
	p[0] = 9
	for _, c := range []struct {
		f    func(ed25519.PublicKey) float64
		want float64
	}{
		{func(k ed25519.PublicKey) float64 { return float64(k[0]) }, 9},
		{func(ed25519.PublicKey) float64 { panic("boom") }, 0},
		{func(ed25519.PublicKey) float64 { return math.NaN() }, 0},
		{func(ed25519.PublicKey) float64 { return math.Inf(-1) }, 0},
	} {
		s := DefaultScore()
		s.AppScore = c.f
		cs, err := s.core()
		if err != nil {
			t.Fatal(err)
		}
		if got := cs.AppScore(p); got != c.want {
			t.Errorf("got %v, want %v", got, c.want)
		}
	}
	if cs, _ := DefaultScore().core(); cs.AppScore != nil {
		t.Error("a nil AppScore must stay nil")
	}
	if *DefaultTopicScore() != TopicScoreParams(*core.DefaultTopicScore()) {
		t.Error("topic score defaults")
	}
}

// TestValidate: the verdicts pass through; a nil validator accepts; a panic, an unknown verdict (the zero Verdict
// included) or a done context is Ignore, so a broken validator never penalises honest peers.
func TestValidate(t *testing.T) {
	m := &Message{}
	ctx := context.Background()
	for _, v := range []Verdict{Accept, Reject, Ignore, Retry} {
		if got := validate(ctx, func(context.Context, *Message) Verdict { return v }, m); got != v {
			t.Errorf("verdict %d became %d", v, got)
		}
	}
	if validate(ctx, nil, m) != Accept {
		t.Error("nil validator")
	}
	if validate(ctx, func(context.Context, *Message) Verdict { panic("boom") }, m) != Ignore {
		t.Error("panic")
	}
	for _, v := range []Verdict{0, -1, 5, 100} {
		if validate(ctx, func(context.Context, *Message) Verdict { return v }, m) != Ignore {
			t.Errorf("unknown verdict %d", v)
		}
	}
	done, cancel := context.WithCancel(ctx)
	cancel()
	called := false
	if validate(done, func(context.Context, *Message) Verdict { called = true; return Accept }, m) != Ignore || called {
		t.Error("done context")
	}
}

// TestNewMessage: the application gets copies, so it cannot change the bytes the router forwards.
func TestNewMessage(t *testing.T) {
	m := newMember(t)
	raw := sign(t, m, testTopic("x"), 4, []byte("body"))
	env, err := wire.DecodeEnvelope(raw, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	var from core.PeerID
	from[0] = 3
	msg := newMessage(wire.NewID(raw), env, from)
	if msg.ID != MessageID(wire.NewID(raw)) || msg.Topic != testTopic("x") || !bytes.Equal(msg.Person, m.person.PublicKey()) ||
		!bytes.Equal(msg.Device, m.device.PublicKey()) || msg.Seq != 4 || string(msg.Body) != "body" || msg.From[0] != 3 || !bytes.Equal(msg.Raw, raw) {
		t.Fatalf("message %+v", msg)
	}
	msg.Body[0], msg.Person[0], msg.Device[0], msg.Raw[0] = 'X', ^msg.Person[0], ^msg.Device[0], 9
	if raw[0] != 0 || string(env.Body) != "body" || env.Person[0] != m.person.PublicKey()[0] || env.Device[0] != m.device.PublicKey()[0] {
		t.Fatal("the application can change the envelope")
	}
}

// TestSendQueue: control frames are bounded in number and every frame in bytes, so many small messages (the answer
// to one IWANT) fit; frames being written still count; urgent control goes before other control, and messages wait
// for their own writer.
func TestSendQueue(t *testing.T) {
	q := newSendQueue(2, 100)
	if !q.push(laneControl, []byte("c1")) || !q.push(laneUrgent, []byte("u1")) || q.push(laneControl, nil) {
		t.Fatal("control frame bound")
	}
	for i := range 10 {
		if !q.push(laneMessage, make([]byte, 9)) {
			t.Fatalf("message %d refused within the byte bound", i)
		}
	}
	if q.push(laneMessage, make([]byte, 7)) {
		t.Fatal("byte bound")
	}
	ctx := context.Background()
	got, size := q.wait(ctx, wire.KindControl)
	if len(got) != 2 || string(got[0]) != "u1" || string(got[1]) != "c1" || size != 4 {
		t.Fatalf("control batch %q, %d bytes", got, size)
	}
	if q.push(laneControl, nil) {
		t.Fatal("frames being written must still count")
	}
	q.sent(wire.KindControl, 2, 4)
	if !q.push(laneControl, []byte("c2")) {
		t.Fatal("released frames must free the bound")
	}
	got, size = q.wait(ctx, wire.KindMessage)
	if len(got) != 10 || size != 90 {
		t.Fatalf("message batch %d frames, %d bytes", len(got), size)
	}
	q.sent(wire.KindMessage, 10, 90)
	if q.frames != 1 || q.bytes != 2 {
		t.Fatalf("counted %d frames, %d bytes", q.frames, q.bytes)
	}
	done, cancel := context.WithCancel(ctx)
	cancel()
	if got, _ := q.wait(done, wire.KindMessage); got != nil {
		t.Fatal("wait must end with its context")
	}
	woke := make(chan [][]byte)
	go func() {
		got, _ := q.wait(ctx, wire.KindMessage)
		woke <- got
	}()
	q.push(laneMessage, []byte("m"))
	if got := <-woke; len(got) != 1 || string(got[0]) != "m" {
		t.Fatalf("woken with %q", got)
	}
}

// TestReadStream: the stream reader maps clean ends, cut streams and broken encodings.
func TestReadStream(t *testing.T) {
	g, _ := fuzzGossip(t)
	p, done := fuzzPeer(t, g)
	defer done()
	ctl := append(header(wire.KindControl), wire.AppendFrame(nil, control(t, &wire.Control{}))...)
	for _, c := range []struct {
		name string
		in   []byte
		want error
	}{
		{"clean end", ctl, nil},
		{"empty", nil, errEnded},
		{"cut frame", ctl[:len(ctl)-1], errEnded},
		{"bad kind", []byte{0, 'z'}, ErrProtocol},
		{"bad frame", append(header(wire.KindControl), wire.AppendFrame(nil, []byte{1})...), ErrProtocol},
	} {
		p.kinds = [2]bool{}
		err := g.readStream(p, bufio.NewReader(bytes.NewReader(c.in)), nil)
		if c.want == nil && err != nil || c.want != nil && !errors.Is(err, c.want) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	err := g.readStream(p, bufio.NewReader(bytes.NewReader(ctl)), nil)
	if !errors.Is(err, ErrProtocol) {
		t.Fatalf("a second control stream: %v", err)
	}
}

// fakeConn is a connection whose streams never open: enough for ServeConn's arguments and peer table.
type fakeConn struct {
	key    ed25519.PublicKey
	ctx    context.Context
	remote net.Addr
	closed atomic.Bool
}

func (c *fakeConn) RemotePublicKey() ed25519.PublicKey { return c.key }
func (c *fakeConn) OpenStream(ctx context.Context) (*kolotransport.Stream, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
func (c *fakeConn) AcceptStream(ctx context.Context) (*kolotransport.Stream, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
func (c *fakeConn) OpenUniStream(ctx context.Context) (*kolotransport.SendStream, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
func (c *fakeConn) AcceptUniStream(ctx context.Context) (*kolotransport.ReceiveStream, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
func (c *fakeConn) Context() context.Context            { return c.ctx }
func (c *fakeConn) Close() error                        { return nil }
func (c *fakeConn) CloseWithError(uint64, string) error { c.closed.Store(true); return nil }
func (c *fakeConn) RemoteAddr() net.Addr                { return c.remote }

// TestServeConnArguments: a key that is not 32 bytes or an IPv6 address is refused; a relayed connection
// without an address is served; a second ServeConn for a key replaces the first.
func TestServeConnArguments(t *testing.T) {
	checkGoroutines(t)
	m := newMember(t)
	g, err := New(m.device, &Config{Cert: m.cert})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	key := ident(t).PublicKey()
	v4 := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1}
	for name, c := range map[string]*fakeConn{
		"short key": {key: key[:31], ctx: ctx, remote: v4},
		"IPv6":      {key: key, ctx: ctx, remote: &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 1}},
		"own key":   {key: m.device.PublicKey(), ctx: ctx, remote: v4},
	} {
		if err := g.ServeConn(ctx, c, true); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A key refused over MaxPeers leaves no trace: it is served once there is room.
	small, err := New(m.device, &Config{Cert: m.cert, MaxPeers: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer small.Close()
	one, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- small.ServeConn(one, &fakeConn{key: ident(t).PublicKey(), ctx: ctx}, true) }()
	waitFor(t, 5*time.Second, "the first peer", func() bool { return small.Stats().Router.Peers == 1 })
	if err := small.ServeConn(ctx, &fakeConn{key: key, ctx: ctx}, true); !errors.Is(err, ErrLimit) {
		t.Fatalf("over MaxPeers: %v", err)
	}
	stop()
	<-done
	bounded, stop2 := context.WithTimeout(ctx, 5*time.Second)
	defer stop2()
	go func() { done <- small.ServeConn(bounded, &fakeConn{key: key, ctx: ctx}, true) }()
	waitFor(t, 5*time.Second, "the refused key served", func() bool { return small.Stats().Router.Peers == 1 })
	stop2()
	<-done

	first := make(chan error, 1)
	fc := &fakeConn{key: key, ctx: ctx}
	go func() { first <- g.ServeConn(ctx, fc, true) }()
	waitFor(t, 5*time.Second, "the first ServeConn", func() bool { return g.Stats().Router.Peers == 1 })
	second := make(chan error, 1)
	go func() { second <- g.ServeConn(ctx, &fakeConn{key: key, ctx: ctx, remote: v4}, false) }()
	if err := <-first; err != nil || fc.closed.Load() {
		t.Fatalf("the replaced ServeConn returned %v or closed the connection", err)
	}
	waitFor(t, 5*time.Second, "the second ServeConn", func() bool { return g.Stats().Router.Peers == 1 })
	cancel()
	if err := <-second; !errors.Is(err, context.Canceled) {
		t.Fatalf("ServeConn after its context ended: %v", err)
	}
	if g.Stats().Router.Peers != 0 {
		t.Fatal("peer kept after ServeConn returned")
	}
}

// panicRoster panics on every lookup.
type panicRoster struct{}

func (panicRoster) Lookup(Topic, ed25519.PublicKey, ed25519.PublicKey) (*Author, error) {
	panic("roster")
}

// TestPanickingCallbacks: a roster or open mode that panics ignores the message instead of crashing the node.
func TestPanickingCallbacks(t *testing.T) {
	for name, opts := range map[string]*TopicOptions{
		"roster": {Authors: panicRoster{}},
		"open":   {Open: func(Topic, ed25519.PublicKey) ([]*koloid.Revocation, bool) { panic("open") }},
	} {
		g, author := fuzzGossip(t)
		p, done := fuzzPeer(t, g)
		defer done()
		g.mu.Lock()
		rm := g.rooms[fuzzTopic]
		rm.authors, rm.open = opts.Authors, opts.Open
		g.mu.Unlock()
		in := append(header(wire.KindMessage), wire.AppendFrame(nil, sign(t, author, fuzzTopic, 1, nil))...)
		if err := g.readStream(p, bufio.NewReader(bytes.NewReader(in)), nil); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if s := g.Stats().Router; s.UnknownAuthor != 1 || s.Delivered != 0 {
			t.Fatalf("%s: %+v", name, s)
		}
	}
}

// TestSeq: sequence numbers start at the Unix nanosecond time and grow by one, also when used concurrently.
func TestSeq(t *testing.T) {
	start := time.Unix(1_800_000_000, 5)
	next := newSeq(start)
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 100 {
				next()
			}
		})
	}
	wg.Wait()
	if n := next(); n != uint64(start.UnixNano())+400 {
		t.Fatalf("seq %d after 400, want %d", n, uint64(start.UnixNano())+400)
	}
}

// TestIDontWantCoalesced: IDONTWANT ids queued while the writer is busy join the last IDONTWANT frame, up to
// MaxIDontWantLength ids each, so a busy room sends few frames.
func TestIDontWantCoalesced(t *testing.T) {
	q := newSendQueue(32, 1<<20)
	for i := range 25 {
		if !q.pushIDontWant([]wire.ID{{byte(i)}}, 10) {
			t.Fatal("refused")
		}
	}
	got, _ := q.wait(context.Background(), wire.KindControl)
	if len(got) != 3 {
		t.Fatalf("%d frames for 25 ids, want 3", len(got))
	}
	for i, b := range got {
		c, err := wire.DecodeControl(b, 1<<20)
		if err != nil || len(c.IDontWant) != []int{10, 10, 5}[i] {
			t.Fatalf("frame %d: %v %d ids", i, err, len(c.IDontWant))
		}
	}
	q.pushIDontWant([]wire.ID{{1}}, 10)
	q.push(laneUrgent, []byte("x"))
	q.pushIDontWant([]wire.ID{{2}}, 10)
	if got, _ := q.wait(context.Background(), wire.KindControl); len(got) != 3 || string(got[1]) != "x" {
		t.Fatal("ids joined a frame that is not the last one or not IDONTWANT only")
	}
}

// TestSinkCoalescesIDontWant: the router's IDONTWANT-only frames take the joining path; any other frame does not.
func TestSinkCoalescesIDontWant(t *testing.T) {
	q := newSendQueue(32, 1<<20)
	g := &Gossip{set: &settings{router: *core.DefaultConfig()}, peers: map[core.PeerID]*peer{{1}: {q: q}}}
	s := sink{g}
	for i := range 3 {
		s.SendControl(core.PeerID{1}, &wire.Control{IDontWant: []wire.ID{{byte(i)}}}, false)
	}
	s.SendControl(core.PeerID{1}, &wire.Control{IWant: []wire.ID{{9}}}, true)
	if got, _ := q.wait(context.Background(), wire.KindControl); len(got) != 2 {
		t.Fatalf("%d frames, want one IDONTWANT frame and the IWANT", len(got))
	}
}
