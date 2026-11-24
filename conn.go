package kologossip

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ciranda-dev/kolo-gossip/internal/auth"
	"github.com/ciranda-dev/kolo-gossip/internal/core"
	"github.com/ciranda-dev/kolo-gossip/internal/wire"
)

// Close and stream reset codes; codeProtocol is the QUIC application error code of a peer that broke the protocol.
const (
	codeNormal   = 0
	codeProtocol = 0x6b67
)

var (
	// errEnded means the peer's gossip ended: its connection, a stream, or our side.
	errEnded = errors.New("kologossip: peer ended")
	// errStalled means the peer stopped partway through a frame or a stream header, or opened no stream, for
	// FrameTimeout.
	errStalled = errors.New("kologossip: peer stalled")
)

// peer is one served connection.
type peer struct {
	id     core.PeerID
	ip     netip.Addr // where it connects from, zero when relayed
	conn   Conn
	q      *sendQueue
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}

	replaced atomic.Bool // a newer ServeConn for the key ended this one

	mu      sync.Mutex
	err     error    // why the peer ended, the first reason
	ending  bool     // streams opened from now on are reset at once
	resets  []func() // reset the streams opened so far
	streams int      // streams accepted
	kinds   [2]bool  // control and message streams read
}

// ServeConn runs gossip with the peer of conn, which must be its only AcceptUniStream caller, until ctx ends, the
// connection or the peer's gossip ends or a newer ServeConn for the key replaces it (nil), the Gossip closes
// (ErrClosed), a MaxPeers the application set is reached (ErrLimit; conn is closed), the peer is graylisted (ErrGraylisted;
// conn is closed) or breaks the protocol (ErrProtocol; conn is closed). outbound is koloswarm.Peer.Outbound; the
// guide has the details.
func (g *Gossip) ServeConn(ctx context.Context, conn Conn, outbound bool) error {
	if conn == nil {
		return fmt.Errorf("%w: nil Conn", ErrInvalidArgument)
	}
	key := conn.RemotePublicKey()
	if len(key) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: remote key of %d bytes", ErrInvalidArgument, len(key))
	}
	addr, err := g.remoteAddr(conn, outbound)
	if err != nil {
		return err
	}
	pctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer context.AfterFunc(conn.Context(), cancel)()
	defer context.AfterFunc(g.ctx, cancel)()
	p, err := g.addPeer(pctx, cancel, core.PeerID(key), conn, outbound, addr)
	if err != nil {
		if errors.Is(err, core.ErrLimit) {
			// An unserved peer would hold a swarm place with gossip off, so close it; the swarm may reconnect later.
			conn.CloseWithError(codeNormal, "")
		}
		return mapErr(err)
	}
	var wg sync.WaitGroup
	run := func(f func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.fail(f())
		}()
	}
	run(func() error { return g.write(p, wire.KindControl) })
	run(func() error { return g.write(p, wire.KindMessage) })
	run(func() error { return g.accept(p, run) })
	<-pctx.Done()
	p.reset()
	wg.Wait()
	g.removePeer(p)
	switch {
	case errors.Is(p.err, ErrProtocol):
		conn.CloseWithError(codeProtocol, "kologossip: protocol violation")
		return p.err
	case g.ctx.Err() != nil:
		return ErrClosed
	case ctx.Err() != nil:
		return ctx.Err()
	case errors.Is(p.err, ErrGraylisted), errors.Is(p.err, errStalled):
		// Close it, or it would hold a swarm place with gossip off; the swarm reconnects after its backoff (see Allow).
		conn.CloseWithError(codeNormal, "")
		if errors.Is(p.err, ErrGraylisted) {
			return p.err
		}
	}
	// A peer that ended its gossip itself keeps the connection, which may carry other protocols.
	return nil
}

// remoteAddr returns the IPv4 address conn comes from, or the zero AddrPort when it has none (relayed). The port
// is kept only when the peer accepts connections there: when the peer holds an outbound place and we opened conn
// from a socket other than our swarm's, so we dialed that address. Port 0 means it is not known.
func (g *Gossip) remoteAddr(c Conn, outbound bool) (netip.AddrPort, error) {
	ra, ok := c.(interface{ RemoteAddr() net.Addr })
	if !ok {
		return netip.AddrPort{}, nil
	}
	ua, ok := ra.RemoteAddr().(*net.UDPAddr)
	if !ok {
		return netip.AddrPort{}, nil
	}
	// The OS may report an IPv4 address in 16 bytes.
	ap := ua.AddrPort()
	ip := ap.Addr().Unmap()
	if !ip.Is4() {
		return netip.AddrPort{}, fmt.Errorf("%w: remote address %v is not IPv4", ErrInvalidArgument, ip)
	}
	var port uint16
	la, ok := c.(interface{ LocalAddr() net.Addr })
	if g.swarm != nil && outbound && ok {
		local, ok1 := la.LocalAddr().(*net.UDPAddr)
		own, ok2 := g.swarm.Addr().(*net.UDPAddr)
		if ok1 && ok2 && local.Port != own.Port {
			port = ap.Port()
		}
	}
	return netip.AddrPortFrom(ip, port), nil
}

// addPeer registers a peer with the router, first ending a peer already served under the same key.
func (g *Gossip) addPeer(ctx context.Context, cancel context.CancelFunc, id core.PeerID, conn Conn, outbound bool, addr netip.AddrPort) (*peer, error) {
	for {
		g.mu.Lock()
		if g.closed {
			g.mu.Unlock()
			return nil, ErrClosed
		}
		old := g.peers[id]
		if old == nil {
			break
		}
		g.mu.Unlock()
		old.replaced.Store(true)
		old.cancel()
		select {
		case <-old.done:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	defer g.mu.Unlock()
	p := &peer{id: id, ip: addr.Addr(), conn: conn, q: newSendQueue(g.set.peerQueue, g.set.peerQueueBytes), ctx: ctx,
		cancel: cancel, done: make(chan struct{})}
	g.peers[id] = p
	var err error
	g.callLocked(func(now time.Time) { err = g.r.AddPeer(now, id, outbound, addr) })
	if err != nil {
		delete(g.peers, id)
		return nil, err
	}
	g.wg.Add(1)
	return p, nil
}

// removePeer ends the router's state of p; its score is retained.
func (g *Gossip) removePeer(p *peer) {
	g.mu.Lock()
	if g.peers[p.id] == p {
		delete(g.peers, p.id)
		g.callLocked(func(now time.Time) { g.r.RemovePeer(now, p.id) })
	}
	if errors.Is(p.err, ErrProtocol) {
		g.protocolClosed++
	}
	g.mu.Unlock()
	close(p.done)
	g.wg.Done()
}

// fail ends the peer; the first reason is kept.
func (p *peer) fail(err error) {
	if err == nil {
		err = errEnded
	}
	p.mu.Lock()
	if p.err == nil {
		p.err = err
	}
	p.mu.Unlock()
	p.cancel()
}

// track registers the reset of a new stream; false means the peer is ending and the stream must be reset now.
func (p *peer) track(reset func()) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ending {
		return false
	}
	p.resets = append(p.resets, reset)
	return true
}

// reset resets every stream, which unblocks their reads and writes.
func (p *peer) reset() {
	p.mu.Lock()
	p.ending = true
	resets := p.resets
	p.mu.Unlock()
	for _, f := range resets {
		f()
	}
}

// write opens our stream of kind k and writes the frames queued for it until the peer ends.
func (g *Gossip) write(p *peer, k wire.Kind) error {
	st, err := p.conn.OpenUniStream(p.ctx)
	if err != nil {
		return nil
	}
	if !p.track(func() { st.CancelWrite(codeNormal) }) {
		st.CancelWrite(codeNormal)
		return nil
	}
	w := bufio.NewWriter(st)
	w.Write(wire.AppendStreamHeader(nil, k))
	if w.Flush() != nil {
		return nil
	}
	var n [binary.MaxVarintLen64]byte
	for {
		frames, size := p.q.wait(p.ctx, k)
		if frames == nil {
			return nil
		}
		for _, f := range frames {
			w.Write(binary.AppendUvarint(n[:0], uint64(len(f))))
			w.Write(f)
		}
		err := w.Flush()
		p.q.sent(k, len(frames), size)
		if err != nil {
			return nil
		}
	}
}

// accept reads the peer's streams: one control and one message stream; a third is a protocol violation.
func (g *Gossip) accept(p *peer, run func(func() error)) error {
	// A peer that opens no stream for FrameTimeout would hold its place with gossip off.
	quiet := time.AfterFunc(g.set.frameTimeout, func() {
		p.mu.Lock()
		opened := p.kinds[0] || p.kinds[1]
		p.mu.Unlock()
		if !opened {
			p.fail(errStalled)
		}
	})
	defer quiet.Stop()
	for {
		st, err := p.conn.AcceptUniStream(p.ctx)
		if err != nil {
			return nil
		}
		if !p.track(func() { st.CancelRead(codeNormal) }) {
			st.CancelRead(codeNormal)
			return nil
		}
		p.mu.Lock()
		p.streams++
		n := p.streams
		p.mu.Unlock()
		if n > 2 {
			return fmt.Errorf("%w: more than two streams", ErrProtocol)
		}
		sr := &stallReader{r: st, deadline: st.SetReadDeadline, timeout: g.set.frameTimeout}
		run(func() error { return g.readStream(p, bufio.NewReader(sr), sr) })
	}
}

// stallReader bounds how long a stream may go without a byte while a stream header or a frame is under way.
type stallReader struct {
	r        io.Reader
	deadline func(time.Time) error
	timeout  time.Duration
	on       bool
}

func (s *stallReader) Read(b []byte) (int, error) {
	if s.on {
		s.deadline(time.Now().Add(s.timeout))
	}
	return s.r.Read(b)
}

// set starts or ends the stall bound.
func (s *stallReader) set(on bool) {
	if s == nil {
		return
	}
	s.on = on
	if !on {
		s.deadline(time.Time{})
	}
}

// readStream reads one of the peer's streams: its header, then frames into the router, until it ends. stall, if
// not nil, is the stream under r: a header or a frame under way may go FrameTimeout without a byte. Past one of
// its budgets the peer is not read until the next heartbeat.
func (g *Gossip) readStream(p *peer, r wire.Reader, stall *stallReader) error {
	stall.set(true)
	k, err := wire.ReadStreamHeader(r)
	if err != nil {
		return readErr(err)
	}
	stall.set(false)
	i, size := 0, g.set.router.MaxControlSize
	if k == wire.KindMessage {
		i, size = 1, g.set.router.MaxMessageSize
	}
	p.mu.Lock()
	twice := p.kinds[i]
	p.kinds[i] = true
	p.mu.Unlock()
	if twice {
		return fmt.Errorf("%w: second stream of kind %q", ErrProtocol, k)
	}
	var wait time.Duration
	for {
		if wait > 0 && !g.waitWork(p, wait) {
			return errEnded
		}
		b, err := wire.ReadFrame(r, size, func() { stall.set(true) })
		if err != nil {
			return readErr(err)
		}
		stall.set(false)
		if k == wire.KindMessage {
			wait, err = g.message(p, b)
		} else {
			wait, err = g.control(p, b, size)
		}
		if err != nil {
			return err
		}
	}
}

// waitWork waits d, then as long as the router says p's buckets are still empty; false means the peer ended.
func (g *Gossip) waitWork(p *peer, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	for d > 0 {
		g.waited.Add(1)
		t.Reset(d)
		select {
		case <-t.C:
		case <-p.ctx.Done():
			return false
		}
		if !g.call(func(now time.Time) { d = g.r.Wait(now, p.id) }) {
			return false
		}
	}
	return true
}

// message hands an envelope to the router; the peer's reader computes the id and the signature outside the router's
// lock, charged to the peer. It reports how long the peer must wait before its next frame is read.
func (g *Gossip) message(p *peer, b []byte) (time.Duration, error) {
	id := wire.NewID(b)
	var check bool
	wait, err := g.peerCall(p, func(now time.Time) error {
		check = g.r.MessageWithID(now, p.id, b, id)
		return nil
	})
	if !check || err != nil {
		return wait, err
	}
	signed := false
	if env, err := wire.DecodeEnvelope(b, len(b)); err == nil {
		signed = auth.Signed(env, b[:len(b)-wire.SigSize])
	}
	return g.peerCall(p, func(now time.Time) error {
		g.r.MessageSigned(now, p.id, b, id, signed)
		return nil
	})
}

// control decodes a control frame and hands it to the router with its size, so the decoding is charged too.
func (g *Gossip) control(p *peer, b []byte, size int) (time.Duration, error) {
	c, err := wire.DecodeControlCerts(b, size, g.set.auth.MaxCertWants)
	if err != nil {
		return 0, fmt.Errorf("%w: %w", ErrProtocol, err)
	}
	return g.peerCall(p, func(now time.Time) error { return mapErr(g.r.ControlFrame(now, p.id, c, len(b))) })
}

// peerCall runs f on the router for p and reports how long p must wait for its buckets; it ends p if it is now
// graylisted.
func (g *Gossip) peerCall(p *peer, f func(now time.Time) error) (time.Duration, error) {
	var err error
	var wait time.Duration
	gray := false
	if !g.call(func(now time.Time) {
		err = f(now)
		gray, wait = g.r.Graylisted(p.id), g.r.Wait(now, p.id)
	}) {
		return 0, errEnded
	}
	if err == nil && gray {
		err = ErrGraylisted
	}
	return wait, err
}

// readErr maps a read error: a bad encoding or size breaks the protocol, anything else ends the stream.
func readErr(err error) error {
	for _, e := range []error{wire.ErrMalformed, wire.ErrTooLarge, wire.ErrVersion, wire.ErrKind} {
		if errors.Is(err, e) {
			return fmt.Errorf("%w: %w", ErrProtocol, err)
		}
	}
	switch {
	case errors.Is(err, io.EOF):
		return nil
	case errors.Is(err, os.ErrDeadlineExceeded):
		return errStalled
	}
	return errEnded
}

// The lanes of a send queue: urgent control first, then control, on the control stream; messages on their own.
const (
	laneUrgent = iota
	laneControl
	laneMessage
)

// sendQueue holds the frames waiting for one peer's two streams: control frames within a frame bound, all frames
// within a byte bound. Messages are bounded by bytes alone, as one IWANT answer may hold thousands.
type sendQueue struct {
	maxFrames, maxBytes int

	mu            sync.Mutex
	lanes         [3][][]byte
	frames, bytes int
	dontwant      []wire.ID        // ids of the last urgent frame when it is IDONTWANT only, so more can join it
	wake          [2]chan struct{} // control writer, message writer
}

func newSendQueue(maxFrames, maxBytes int) *sendQueue {
	return &sendQueue{maxFrames: maxFrames, maxBytes: maxBytes,
		wake: [2]chan struct{}{make(chan struct{}, 1), make(chan struct{}, 1)}}
}

// push queues b in lane; false means the queue is full and b was dropped.
func (q *sendQueue) push(lane int, b []byte) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.pushLocked(lane, b)
}

func (q *sendQueue) pushLocked(lane int, b []byte) bool {
	if (lane != laneMessage && q.frames >= q.maxFrames) || q.bytes > q.maxBytes-len(b) {
		return false
	}
	q.lanes[lane] = append(q.lanes[lane], b)
	if lane != laneMessage {
		q.frames++
	}
	if lane == laneUrgent {
		q.dontwant = nil
	}
	q.bytes += len(b)
	w := 0
	if lane == laneMessage {
		w = 1
	}
	select {
	case q.wake[w] <- struct{}{}:
	default:
	}
	return true
}

// pushIDontWant queues IDONTWANT ids, joining the last urgent frame while it carries only IDONTWANT and has room
// for limit ids, so a busy writer sends one frame for many ids instead of one each; false means the queue is full.
func (q *sendQueue) pushIDontWant(ids []wire.ID, limit int) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if n := len(q.lanes[laneUrgent]); n > 0 && q.dontwant != nil && len(q.dontwant)+len(ids) <= limit {
		merged := append(q.dontwant, ids...)
		b, err := (&wire.Control{IDontWant: merged}).Encode()
		if grow := len(b) - len(q.lanes[laneUrgent][n-1]); err == nil && q.bytes <= q.maxBytes-grow {
			q.bytes += grow
			q.lanes[laneUrgent][n-1] = b
			q.dontwant = merged
			return true
		}
	}
	b, err := (&wire.Control{IDontWant: ids}).Encode()
	if err != nil || !q.pushLocked(laneUrgent, b) {
		return false
	}
	q.dontwant = slices.Clone(ids)
	return true
}

// wait returns the frames queued for the stream of kind k, urgent ones first, and their size; nil when ctx ends.
func (q *sendQueue) wait(ctx context.Context, k wire.Kind) ([][]byte, int) {
	w := 0
	if k == wire.KindMessage {
		w = 1
	}
	for {
		q.mu.Lock()
		var out [][]byte
		if w == 0 {
			out = append(q.lanes[laneUrgent], q.lanes[laneControl]...)
			q.lanes[laneUrgent], q.lanes[laneControl], q.dontwant = nil, nil, nil
		} else {
			out, q.lanes[laneMessage] = q.lanes[laneMessage], nil
		}
		q.mu.Unlock()
		if len(out) > 0 {
			size := 0
			for _, b := range out {
				size += len(b)
			}
			return out, size
		}
		select {
		case <-q.wake[w]:
		case <-ctx.Done():
			return nil, 0
		}
	}
}

// sent releases the frames a writer of kind k wrote.
func (q *sendQueue) sent(k wire.Kind, frames, size int) {
	q.mu.Lock()
	if k == wire.KindControl {
		q.frames -= frames
	}
	q.bytes -= size
	q.mu.Unlock()
}
