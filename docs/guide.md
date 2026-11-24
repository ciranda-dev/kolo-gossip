# Guide

kolo-gossip spreads signed messages to every member of a topic, hop by hop. This page shows how an application uses it. The wire format is in [protocol.md](protocol.md) and every bound in [limits.md](limits.md). A complete program is in [examples/basic](../examples/basic/main.go): `go run ./examples/basic -host 127.0.0.1`.

## Keys

A node gossips as one kolo-id device key, the same key its kolo-swarm runs as, because peers know it by the key of its connection: they skip the author by that key when they forward, and a node takes a copy of a message under its own key as its own. `Config.Cert` is that device's certificate chain; its person is the author of every message the node publishes.

```go
g, err := kologossip.New(device, &kologossip.Config{Cert: cert, Swarm: sw})
```

`New` checks that the chain is for this device and verifies it now. With `Config.Swarm`, it also checks that the swarm runs as the same key. Without `Config.Swarm` the library cannot see the key of its own connections (a `Conn` carries only the remote key), so the application must use the same key; a second instance of a key, or a restart, only makes the node ignore copies of its own messages.

## Clock

`Config.Now` is the clock of signing, of the author time windows (`MaxAge`, `MaxSkew`), of the chain checks and of the heartbeat's due times; nil is `time.Now`. A test or a simulation with its own clock sets it; every node of one run must use the same one, or its messages fall outside the others' windows. The heartbeat's timer still waits in real time: after the clock jumps, the next heartbeat runs at the next timer, at most `HeartbeatInterval` later. Timing of the network (stream deadlines, `FrameTimeout`, `CertTimeout` in real time) is not affected.

## Connections

The library never dials: the application gives it connections. With kolo-swarm, serve every peer the swarm connects:

```go
for {
	ev, err := sw.Next(ctx)
	if err != nil {
		return
	}
	if ev.Kind == koloswarm.Connected {
		go func(p *koloswarm.Peer) {
			if err := g.ServeConn(ctx, p.Conn(), p.Outbound()); errors.Is(err, kologossip.ErrInvalidArgument) {
				p.Conn().CloseWithError(0, "") // a connection gossip cannot serve: an IPv6 address or our own key
			}
		}(ev.Peer)
	}
}
```

`ServeConn` opens a control and a message stream to the peer and reads the peer's two, so it must be the only caller of the connection's `AcceptUniStream`; an application that runs other stream libraries on the same connection gives gossip its own part of a stream multiplexer, whose `CloseWithError` closes only that part. It returns nil when a newer `ServeConn` for the same key replaces it, `ctx.Err()` when `ctx` ends and `ErrClosed` when the Gossip closes; in those cases the connection stays open. When a `MaxPeers` the application set is reached (`ErrLimit`; by default there is none, and kolo-swarm's place budget bounds the connections), or the peer stalls for `FrameTimeout` (partway through a frame or a stream header, or before opening a stream; nil), falls below the graylist threshold (`ErrGraylisted`, checked after each frame and at every heartbeat) or breaks the protocol (`ErrProtocol`), `ServeConn` closes the connection, so it does not stay up with gossip off: kolo-swarm then reports it lost and may connect again after its backoff, which `Allow` decides, and the loop above serves the new connection. When the peer ends its own streams, `ServeConn` returns nil and leaves the connection, which may carry other protocols, to the application. It returns `ErrInvalidArgument` at once, and leaves the connection open, for an IPv6 address or our own key; the loop above closes such a connection, which gossip cannot serve. Peers that connect and leave are never refused: only a `MaxPeers` the application set refuses a peer. Every frame's work is charged to its peer's two buckets, one for the router's lock (a share of `LockWork`) and one for its own reader (a share of `ReaderWork`, at most `PeerWork`), each holding `WorkBurst` of refill. The shares are half equal for every connected peer, a quarter for mesh places and a quarter for the valid messages the mesh peers delivered, so many peers never starve the mesh. While one is empty the peer's streams are not read: flow control slows it, and its score does not change. An honest mesh peer has several times what it needs at the design rate from 64 to 1,258 peers and 1 to 50 topics (`docs/limits.md`, Honest headroom); a key starts with only what a node-wide newcomer pool gives, and the work of connecting and of leaving is charged to the key itself; a key that leaves in debt keeps its debt (for `RetainScore`, or `WorkBurst` with scoring off) and pays it when it returns, while a key that left without debt returns as a fresh key; an answer to our own IWANT that brings the message costs the asked peer nothing. The outbound flag feeds the outbound mesh quota (D_out), and it is a condition for offering the peer in peer exchange (see below); with kolo-swarm it is `Peer.Outbound`.

Chain `Allow` into the swarm so that it refuses the keys gossip graylisted. The swarm asks before the Gossip exists, so keep the Gossip in an atomic pointer:

```go
var gp atomic.Pointer[kologossip.Gossip]
cfg := &koloswarm.Config{Allow: func(k ed25519.PublicKey, a netip.AddrPort) bool {
	g := gp.Load()
	return g == nil || g.Allow(k, a)
}}
```

## Rooms

```go
room, err := g.Join(ctx, topic, &kologossip.TopicOptions{Authors: roster, Validate: validate})
```

`Join` subscribes to the topic, tells every served peer and grafts a mesh. With `Config.Swarm` set it also joins the swarm topic (`TopicOptions.Swarm`, default announce and look up), and `Room.Leave` leaves it, which closes the connections that shared no other topic. Leave `Config.Swarm` nil when the application joins the swarm topic itself, for example because a kolo-braid on the same topic uses it.

A room needs `Authors`, `Open` or both:

- Closed mode, `Authors`: the roster. `Lookup(topic, person, device)` returns the `Author` (the person it expects and the device's chain, both required, and the revocations it accepts) or `ErrUnknownAuthor`. A device the roster does not know, and an `Author` without the person or the chain, are ignored without penalty and the chain is never taken from the network. A revoked or expired device is ignored without penalty too: revocations reach nodes at the application's pace, so a node that already knows one must not punish the peers that do not and forward the device's messages. The cost is that a revoked device's messages reach the nodes that do not know yet, and the others drop them: the first copy costs a signature check within the sender's budget, later copies nothing for `IgnoredTTL`.
- Open mode, `Open`: called for a person the roster does not know; it returns whether to accept the person and the revocations it holds for them. The device's chain is then fetched with one CERTWANT from the peer that forwarded the message (it waits up to `CertTimeout`, 3 s), checked with those revocations, and cached. A device's first message therefore pays one round trip. A peer that answers with a chain the revocations void ends only its own request; a peer that no longer holds the chain says so and is not penalised.

Revocations come only from the application. Keep every verified revocation from the time you first see it.

`Lookup` and `Open` run with the Gossip's lock held, once per new message, and `ScoreParams.AppScore` once per peer per heartbeat: answer from memory and never call the Gossip from them. Return the same `Author` objects for a device, and never change them: the chain check is then found by those objects (about 60 ns), while new objects cost their encoding hash (about 20 us with 100 revocations). Either way a result is kept until the chain's earliest expiry, so a chain is verified once, not at every message. Their work is timed with the monotonic clock and charged to the peer that sent the message, at least a flat cost per call: a slow roster slows the peers that make us call it, so keep them fast. A panic in them ignores the message (or scores 0). `Publish` also checks the node's own chain with the revocations its room's roster or open mode holds for it, and refuses to sign once the chain expired or was revoked (`ErrOwnChain`, wrapping kolo-id's reason).

## Validators

`TopicOptions.Validate` decides what the library leaves to the application: membership of the person, bans, roles, rate and content. It runs on its own goroutine after the size, time window, signature and author checks, at most `MaxValidating` at once (`MaxPeerValidating` messages and `MaxPeerValidatingBytes` from one peer, and no more than the global bound divided by the senders holding messages; senders outside the topic's mesh that we did not ask hold at most half of the global bounds together; a peer over its share has only its copy dropped, so the next peer's copy is taken). Its context ends after `ValidateTimeout` (default and at most `SeenTTL`), on `Leave`, on `Close`, and when the router drops the message: when its sender left and the one departed share for all senders that left is full (the newly departed messages are dropped, the older ones keep their places). A dropped message that was waiting for its author's chain leaves the author check at once too, so keys that come and go cannot keep it full for new authors. A validator must honour its context. A dropped validation stays counted in `MaxValidating` and `MaxValidatingBytes` until its validator returns, so a validator that ignores its context holds a global place until then, and the global bounds cap the validators that run, stuck or not; past them new messages are throttled. A validator that runs past its timeout keeps its message charged to the share of the peer that sent it until it returns, however long that takes; it then counts as Ignore (a verdict after `SeenTTL` too) and meanwhile as stuck in `Stats.StuckValidators`, as does a dropped one that runs on in a room still joined. Each validation has its own number, and a verdict applies only to the validation it answers. The validator's time is not charged to the sender: its CPU is the application's, outside the work budgets, and a sender can make it run only as fast as its reader bucket pays for new messages (at least a signature check each) and its share holds them. A message becomes seen only when the validator accepts or rejects it. After an Ignore the message is validated again as the copy of a peer that sent it meanwhile, at most twice, since the validator sees the forwarder: a content-based Ignore costs up to three validations, each in its own sender's share. `Close` never waits for a validator that ignores its context.

| Verdict | Effect |
|---|---|
| `Accept` | delivered to `Room.Next` and forwarded |
| `Reject` | dropped; the sender and every peer that sent a copy lose score (P4); three invalid messages bring a peer to the graylist threshold and a fourth below it |
| `Ignore` | dropped without penalty; also the result of a panic, of an unknown verdict (the zero `Verdict` included) or of a validator that returns after its timeout |
| `Retry` | kept, not delivered and not forwarded, and validated again on `Room.Revalidate` or after `RetryInterval`; dropped at `SeenTTL` |

A nil validator accepts every message whose author checks out.

`Retry` is for a message the application cannot judge yet but may later, such as one sealed for an epoch the member has not reached. The message stays held with no validator running: it counts in `MaxValidating`, `MaxValidatingBytes` and its sender's `MaxPeerValidating` share (a sender whose messages are all held for `Retry` has its next ones throttled, copy by copy, until it is decided), copies of it from other peers are duplicates and are not validated, and its id is not seen. It is validated again, as a new validation of the same message and sender, when the application calls `Room.Revalidate` (every held message of the room at once) and at the first heartbeat that is at least `RetryInterval` (default `HeartbeatInterval`) after its last `Retry`; each run is charged to the sender like a first validation. A `Retry` that arrives after `SeenTTL` since the message first came counts as `Ignore`, and a held message that reaches `SeenTTL` is dropped without a verdict; `Leave` drops them too. `Stats.Router.Retried` counts the `Retry` answers. A peer that sends only messages the validator retries pays nothing in score: bound its share and the global bounds instead.

## Publishing and reading

```go
sent, err := room.Publish(ctx, body)
m, err := room.Next(ctx)
```

`Publish` signs the body with the next sequence number of this device in the room (`TopicOptions.Seq` supplies your own counter; `Gossip.Publish` on a joined topic uses the room's) and sends it: with flood publishing to every peer that announced the topic, else to the mesh. A body over the topic's `MaxMessageSize` is `ErrTooLarge`, checked before signing; a message with the same bytes as one already sent (a `Seq` that repeats within one millisecond) is `ErrDuplicate`. It returns the message as signed (`ID`, `Person`, `Device`, `Seq`, `Time`, `Body` and `Raw`, with a nil `From`), and nil on any error. Publish never blocks on the network: a peer whose queue is full misses the copy, and the mesh repairs it with IHAVE and IWANT. Our own messages are not returned by `Next`.

`Next` returns the messages in the order they pass validation, each with its author (`Person`, `Device`, `Seq`, `Time`), `Raw`, the signed envelope as the author sent it, and `From`, the neighbour that delivered it. No order is guaranteed: the library keeps no history and orders nothing. A reader that falls more than `RoomQueue` messages behind loses messages for its room only (`RoomStats.Dropped`); the node still forwards them.

`Gossip.Publish(ctx, topic, body)` publishes to a topic the node did not join, as the specification's fanout does. The node needs connections to the topic's members, for example a swarm join with `Lookup` only, and the members' roster must accept its device.

A message received by a peer just before it grafted a new mesh link is not pushed over that link; the new mesh peer gets the next heartbeat's IHAVE of the ids of the last `HistoryGossip` heartbeats instead and asks for what it lacks. Older messages do not reach a node that connects later: applications that need every message use pins for history.

### Storing a message and checking it later

`Message.Raw` is the whole signed envelope, for an application that stores what it validated. `VerifyEnvelope(topic, raw, author)` checks it again, later and without a connection: the envelope decodes, is for `topic` and for the `Author`'s person and device, the device signed it, and the author's certificate chain certifies the device at the envelope's own time with the `Author`'s revocations (so an old message by a device whose chain has since expired still verifies; the application judges the time). It returns the `Message` with a nil `From`, or an error that is `ErrBadEnvelope` or wraps kolo-id's reason (`ErrCertRevoked`, `ErrCertExpired`). Taking the `Author` from the application's own record of who was a member is the application's part.

## Peers of a topic

The swarm's `Allow` is node-wide: it admits a peer to the node, and then every topic the node joined is announced to it and every message is open to it. `TopicOptions.AllowPeer(peer)` narrows that for one topic (nil admits every peer, as before). A peer it refuses is never told that we joined the topic (no subscription, GRAFT, PRUNE or IHAVE of it), is never grafted into its mesh, is skipped by flood publishing, fanout and gossip, gets no IWANT answer for a message of the topic, and its own frames about the topic are ignored without penalty, as if we had not joined. A node in an open topic and a closed one therefore does not reveal the closed topic's id, members' envelopes or timing to a device that is only admitted to the open one.

It is asked once when a peer connects (for each joined topic that has one, charged to that peer as one application call), once for each connected peer at `Join`, and again for every connected peer on `Room.RefreshPeers()`, which the application calls when its answer changes. A peer that is refused then is sent an unsubscribe and leaves the mesh (with a PRUNE and the unsubscribe backoff); a peer that is admitted then is told that we joined, and is grafted at a heartbeat once no backoff holds. `AllowPeer` runs with the Gossip's lock held, like `Lookup`: answer from memory and never call the Gossip; a panic refuses the peer. One answer per refused (peer, topic) pair is kept (32 bytes) while the peer is connected, and only our own answers create one, so no peer can grow it.

CERTWANT is not scoped by topic: a refused peer that already knows a person and device key can still be answered with that device's chain, as any connected peer is. It learns nothing of the topic from it.

## Scoring

Scoring is on with `DefaultScore` and `DefaultTopicScore`, values our simulator measured; `Config.Score` and `TopicOptions.Score` set others, and nil always means the default. Set `ScoreParams.AppScore` to add the application's view of a peer (P5), such as a positive score for roster members. `Config.NoScore` turns scoring off; `TopicOptions.NoScore` leaves one topic unscored, and then its invalid messages cost nothing. `Gossip.Score` returns a peer's score, kept unchanged for `ScoreParams.RetainScore` (10 minutes) after it disconnects, so reconnecting does not clear a penalty.

## Peer exchange

A PRUNE may list other peers of its topic, so the pruned peer can find new links. With `Config.Swarm` set, the Gossip dials the records of a PRUNE it receives when the topic is joined, scoring is on and the sender's score is at least `ScoreParams.Thresholds.AcceptPX` (12 by default, one above `TopicScoreCap`, so only a peer the application vouches for through `AppScore` qualifies; 0 dials no peer exchange at all, as a hand-built `Thresholds` has). It reads at most `PrunePeers` (16) records of one PRUNE entry, chosen at random, and leaves out our own key, connected keys and repeats. Each record is dialed with `Swarm.Connect(ctx, topic, key, addr, from)`, `from` being the PRUNE sender's IPv4 address (zero when it is relayed), for at most `Config.PXTimeout` (30 s), by `Config.PXDialers` (8) dialers, with at most `Config.PXPending` (128) records waiting (`Stats.PXDropped` counts the rest); an error skips the record, without a retry. Each record the dialers take costs the PRUNE's sender a dial's work on its reader bucket; a record dropped because `PXPending` records wait already, or because there is no `Config.Swarm`, costs nothing. A connection the swarm admits reaches the application as a `Connected` event, like any other. Records are unsigned; the dial is authenticated by kolo-secure, so a wrong address costs one failed dial. Without `Config.Swarm` nothing is dialed, and with `Config.NoScore` nothing either, since nothing vouches for the sender.

`Config.PeerExchange` (off by default, as GossipSub v1.1 advises outside bootstrap nodes) makes the PRUNE we send list up to `PrunePeers` random peers of the topic with a score of at least 0, never the pruned peer: when the heartbeat prunes an oversubscribed mesh, on `Leave`, and when it refuses a GRAFT because the mesh is full. A peer pruned for its negative score, a GRAFT in backoff and a frame that also grafts a topic we are not in get none. Only peers whose listening port is known are listed: those that hold an outbound place (the `outbound` argument of `ServeConn`) and whose connection we opened from a socket other than our swarm's, so we dialed that address.

## Statistics

`Gossip.Stats` returns the router's counters (messages, duplicates, rejects and ignores by reason, drops, IHAVE, IWANT, IDONTWANT and CERTWANT traffic) and sizes, the author chain counters and `ProtocolClosed`, the connections closed for protocol violations; `StuckValidators`, the validators still running past their timeout or their cancel; `PXDials`, `PXConnected` and `PXDropped` for peer exchange records, `Retried` for the validator's `Retry` answers, and `RouterStats.PXAccepted`, those passed to the dialers. `Room.Stats` returns the room's peers, mesh, outbound mesh peers and fanout, and its delivered and dropped counts.

## Closing

`Close` stops every room and every `ServeConn` and waits for their goroutines. It leaves the swarm topics joined through `Config.Swarm`, which closes the connections that shared no other topic; it closes no other connection and not the swarm, which belong to the application. Its peers see our streams end and close their side of each connection.

## What gossip reveals

Mesh peers learn which topics a key joined and when it publishes; every envelope names the author's person and device keys in clear. Encrypt bodies in the application when they are private. A topic with `AllowPeer` reveals this only to the peers it admits.
