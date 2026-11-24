# Protocol

kolo-gossip follows the GossipSub v1.0 and v1.1 specifications with the IDONTWANT message of v1.2 (see [References](#references)). It is not wire compatible with other implementations: it uses the kolo-codec encoding and kolo-secure connections, and follows the algorithm and defaults of the specifications, not their bytes. Every integer below is a canonical kolo-codec uvarint; every value has exactly one valid encoding, and a decoder refuses short input, trailing bytes and counts that cannot fit in the bytes left.

## Streams

A gossip peer is one authenticated connection, usually a kolo-swarm peer. Each side opens two unidirectional streams to the other:

| Kind | Byte | Carries |
|---|---|---|
| Control | `c` (0x63) | Control frames |
| Message | `m` (0x6d) | Envelopes, including answers to IWANT |

A stream starts with a header: `uvarint version (0)` then the kind byte. Then it carries frames: `uvarint length || body`. A control frame is at most `MaxControlSize` bytes, a message frame at most `MaxMessageSize`; the length is checked before the body is read. Two streams keep IDONTWANT, GRAFT and PRUNE from waiting behind a large message.

A peer that opens a third stream, a second stream of one kind, a stream with an unknown version or kind, a frame over its limit, a non-canonical length, a control frame that does not decode, a control frame with more than 32 GRAFT or PRUNE entries or more than `MaxCertWants` certificates breaks the protocol (a peer may announce any number of topics; subscriptions to topics we hold no state for are kept up to `MaxPeerTopics` and the rest dropped, never a violation): the connection is closed with the QUIC application error code `0x6b67` and the message `kologossip: protocol violation`. A stream header or a frame that stops for `FrameTimeout` once started, a peer that opens no stream for `FrameTimeout`, and a peer that falls below the graylist threshold end gossip with that peer and close the connection with code 0 and no message. A stream that ends or is reset ends gossip with that peer and leaves the connection open.

## Envelope

| Field | Encoding |
|---|---|
| version | uvarint, 0 |
| topic | 32 bytes |
| person | 32 bytes, the author's kolo-id person key |
| device | 32 bytes, the author's device key |
| seq | uvarint, the device's sequence number |
| time | uvarint, the author's Unix time in milliseconds |
| body | uvarint length then the bytes |
| signature | 64 bytes |

The signature is kolo-id's Ed25519ctx signature by the device key under the context `kolo-gossip/message/v0`, over every byte before it. With the default sequence numbers (Unix nanoseconds) the overhead is 177 to 179 bytes plus the body; a `TopicOptions.Seq` with small numbers makes it as small as 169 bytes for author times of this decade.

The message id is `SHA-256("kolo-gossip/message-id/v0" || envelope)`, over the whole envelope including the signature. A forged copy can never take a real message's id, so the id of an ignored message can be remembered without blocking a real one, and an answer to IWANT is checked by hashing it.

The certificate chain is not carried. A receiver asks the room's roster (`Authors`), then, in open mode only, a cache of chains it verified, then sends one CERTWANT to the peer that forwarded the message. The peer answers each CERTWANT entry with the chain, or, when it holds none, with the 64 bytes of person and device: a CERT entry of exactly that length means "not held" and ends the request without a penalty. A node answers up to `MaxCertWants` CERTWANT entries per peer per heartbeat, with the chain or "not held", and entries past that get no answer; a requester sends at most `MaxCertAnswers` (half of it) requests to one peer per heartbeat, so two of its heartbeats within one of ours never ask more than we answer. A node reads one CERT entry per request it sent the peer, so it decodes no more than it asked for. A requester whose limits for one peer are full drops only that peer's copy. A request unanswered for a heartbeat is joined by one to the next peer that sent a copy, every heartbeat; a request that ends without a chain, or whose peer we stopped reading or that left, leaves the message to its other requests or to the next such peer at once, and with none left the message is forgotten, so a later copy from any peer is taken. A message the router drops while it waits (its sender left past the departed share, `Leave`, or its expiry) leaves every request for its author, and a request left with none ends without a penalty. A chain releases each waiting message with the open mode's answer for that message's own topic. A chain received is first checked for its structure, person and signatures at a time no certificate has expired, then with the same check as a roster's chain, so only a genuine stale or revoked chain escapes the penalty.

## Control frame

Eight lists, each a uvarint count followed by its entries, always in this order:

| List | Entry |
|---|---|
| subscriptions | topic (32), bool: joined (1) or left (0) |
| GRAFT | topic (32) |
| PRUNE | topic (32), backoff in seconds (uvarint), peer records: count, then key (32), IPv4 address (4), port (uvarint, not 0) |
| IHAVE | topic (32), count, ids (32 each) |
| IWANT | ids (32 each) |
| IDONTWANT | ids (32 each) |
| CERTWANT | person (32), device (32) |
| CERT | uvarint length (1 to 514), a kolo-id device certificate chain, or person (32) and device (32) for "not held" |

Peer records in PRUNE are peer exchange, as in GossipSub v1.1: unsigned, since the dial that uses one is authenticated by kolo-secure and a wrong address costs one failed dial. A receiver reads them only for a topic it joined, only with scoring on and only from a peer whose score is at least `AcceptPX` (12 by default; 0 dials none); it takes at most `PrunePeers` (16) records of an entry, at random, leaves out its own key, keys it is connected to and repeats, and dials the rest through its swarm for that topic. A sender lists records only when `Config.PeerExchange` is on: in a PRUNE from the heartbeat for an oversubscribed mesh, from `Leave`, and refusing a GRAFT because the mesh is full, up to `PrunePeers` random peers subscribed to the topic, with a score of at least 0 and a known listening port (a peer that holds an outbound place and that we dialed from a socket other than our swarm's), never the pruned peer. A PRUNE for a negative score, for a GRAFT in backoff, or answering a frame that also grafts a topic we are not in carries none.

A control frame we send never exceeds what its receiver reads: at most `MaxCertWants` certificates, 32 GRAFT entries and 32 PRUNE entries. A sender with more puts them in further frames.

## Receive pipeline

For a message, cheapest checks first. A message is marked seen only once its validator accepts or rejects it, so nothing a peer can make without an author's key, and nothing a validator ignores, enters the seen cache.

1. The frame length is within the stream's limit (else protocol violation). The reader computes the id; when the router finds the id new, the reader checks the signature outside the router's lock and hands the frame in again with the result.
2. A sender below the graylist threshold: the frame is dropped, and gossip with the sender ends.
3. The topic is not joined, the topic's `AllowPeer` refused the sender, or the envelope is over the topic's `MaxMessageSize`: dropped without penalty.
4. The envelope does not decode: invalid (P4 for the sender).
5. The id is seen, or held for its validator or its author's chain: a duplicate, which only feeds the mesh delivery accounting (or costs P4 if the validator rejected the message).
6. The id was ignored recently for a reason that holds for every copy (below): dropped without any check.
7. The author time is outside `now - MaxAge` to `now + MaxSkew`: ignored.
8. The signature by the envelope's device key: a bad one is invalid (P4).
9. Our own device key: a genuine copy of our own message (a restart, or a second instance of our key) is ignored without penalty.
10. The seen cache plus the messages held reach `MaxSeen`: this copy is dropped (SeenFull).
11. The sender's share of the validation bounds (`MaxPeerValidating`, `MaxPeerValidatingBytes`) or the bounds themselves are full: this copy is dropped, before any author check, and a copy from another peer is taken. The senders holding messages share the bounds fairly, and senders outside the topic's mesh that we did not ask hold at most half of them.
12. The author: the roster's chain, or in open mode a cached or fetched chain, must certify the device for the claimed person now, with the application's revocations (`koloid` `DeviceCert.Verify`). A device the roster does not know, a roster answer without a chain for this person and device, and a revoked or expired chain are ignored without penalty, and a large one gets an IDONTWANT to the mesh: a forwarder may not know a revocation or an expiry yet, and an honest node forwards only what passed its own checks. In open mode the message waits for one CERTWANT answer.
13. If it has at least `IDontWantThreshold` bytes, IDONTWANT goes to every other mesh peer at once.
14. The application's `Validator`: Accept, Reject (invalid, P4 for the sender and every peer that sent a copy), Ignore or Retry. Accept and Reject mark the id seen. After an Ignore the message is validated again as the copy of the next peer that sent it meanwhile, at most twice. After a Retry the message stays held in the validation bounds, its copies are duplicates (step 5), and it is validated again when the application asks (`Room.Revalidate`) or after `RetryInterval`, until `SeenTTL` since it first arrived.
15. Accept: cache, deliver to `Room.Next`, and forward to the mesh except the sender, the author and peers that sent IDONTWANT for it, unless the author time is within one heartbeat of either edge of the window.

An ignored message's id is remembered for `IgnoredTTL` (5 s), so its copies cost nothing and IHAVE does not ask for it, only for outcomes that hold for every copy: its bytes or its author (steps 8, 9 and 12). Anything that depends on our load or on the sender (steps 7, 10 and 11, a chain request refused or ended, a validator Ignore) drops only that copy and is not remembered: the next copy is checked again, at its own sender's cost. Nothing in steps 3, 6, 7 and 9 to 12 costs the forwarding peer score; the work of every step is charged to its buckets (`docs/limits.md`), and while one is empty its streams are not read. An answer to our own IWANT that brings the message gives the asked peer back its cost; no other copy gets anything back.

Our own published messages go, with flood publishing (the default), to every peer that announced the topic and scores at least the publish threshold, joined or not. Without flood publishing they go to the mesh of a joined topic, or to up to D fanout peers of a topic we did not join; fanout peers are kept for `FanoutTTL` after the last publish.

## Mesh and gossip

As in the specifications: on join a node grafts up to D peers; each heartbeat it prunes peers with a negative score, grafts up to D when below Dlo, keeps the best Dscore by score and fills to D at random when above Dhi, keeps at least Dout outbound peers, grafts better peers when the mesh median score is low, and announces the ids of the last `HistoryGossip` windows with IHAVE to at least Dlazy (or `GossipFactor` of) its other peers above the gossip threshold. A PRUNE carries a backoff in seconds, and may carry peer exchange (Control frame); a GRAFT during backoff is refused and costs a behaviour penalty. A node asks an id of at most two peers at once and one peer at most the smaller of `MaxIHaveLength` and `DesignRate` ids at once, and keeps up to two more peers that announce it: while the id is missing one of them is asked each heartbeat, and a place freed by a peer that waits or leaves is filled at the next heartbeat; an ask ends when the id arrives from anyone, after `IWantFollowupTime`, or when its peer waits for its buckets or leaves. An IHAVE whose promised message does not arrive within `IWantFollowupTime`, and a CERTWANT left unanswered for `CertTimeout`, cost a behaviour penalty; the promises and requests of a peer we stop reading, or that leaves, end without one, and are asked of others at once, so ending them gains the peer nothing.

A topic with `TopicOptions.AllowPeer` is announced, grafted, published and gossiped to, and answered to, only for the peers it admits; for a refused peer it is as if the topic were not joined: its subscription announcement and every GRAFT, PRUNE, IHAVE, IWANT and message it sends for the topic are ignored without penalty, and nothing of the topic is sent to it. Nothing on the wire changes: no field, frame or order is added, and a refused peer is simply sent fewer of the frames above. `Retry`, `Config.Now`, `Message.Raw` and `VerifyEnvelope` change no byte either: `Raw` is the envelope above and `VerifyEnvelope` checks the signature it carries.

A message received before a peer was grafted is not pushed to it afterwards, and the heartbeat's IHAVE goes only to peers outside the mesh, both as the specification defines. So a peer that enters a mesh, by its GRAFT or ours, gets the next heartbeat's IHAVE of the topic, the ids of the last `HistoryGossip` windows, like a peer outside the mesh: a message that reached us just before the graft is not lost to a node whose only path is that link. This IHAVE to a mesh peer is a deviation from the specification; no field or frame changes.

## References

- Vyzovitis, Napora, McCormick, Dias and Psaras, [arXiv:2007.02754](https://arxiv.org/abs/2007.02754), 2020: the published design and evaluation of the GossipSub v1.1 protocol. Takes the mesh with its graft and prune rules, the heartbeat, the fanout, gossip emission with the message cache, peer scoring with its thresholds, flood publishing, prune backoff with peer exchange, the outbound mesh quota, opportunistic grafting and the spam measures, and the attack scenarios and metrics of our simulator.
- The protocol's specification documents, version 1.0 (revision r2, 2020-03-12), 1.1 (revision r8, 2021-12-14) and 1.2 (revision r2, 2026-08-30, which adds the IDONTWANT control message), read at commit `c750236de43cd8b246a824b377dfdb26bae686db`. Test comments cite them by file and line.

Not implemented: explicit peering agreements, flood-only peers, the epidemic broadcast tree extension, the v1.3 extensions and partial messages, unsigned and lax signature policies, the topic descriptor options, and the peer gater of other implementations.
