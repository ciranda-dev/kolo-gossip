# Design

Status: implemented. This page summarizes the design: what the library is, and what it is not. The wire format is in [protocol.md](protocol.md) and the use in [guide.md](guide.md).

## What it is for

Some Kolo uses need one small message to reach many members of a topic: a chat room with thousands of people, a presence update, a notice that a log has grown. Sending it one by one from the author to every member does not scale, and a relay in the middle sees every message and is a single point of failure. kolo-gossip passes the message from member to member instead.

It is for small messages. Media bytes stay in kolo-moq, and file bytes stay in kolo-blobs.

## How it works

The design follows the protocol of the paper and specifications in References, in its algorithm and its parameter set:

- Each node keeps a mesh of a few peers per topic and pushes full messages to them.
- Once per heartbeat a node also tells its other connected peers the ids of the messages it has seen recently, and they ask for the ones they miss.
- Mesh links are added and removed with graft and prune, with a backoff after a prune. A prune may carry peer exchange, which lets a pruned peer find other links: a node dials such records only from a peer whose score is high enough (by default, one the application vouches for), and lists its own peers only when the application turns it on.
- Each node scores its peers locally. Invalid messages, a mesh that delivers less than it should, and repeated misbehavior lower a score; a low score gets a peer pruned and then ignored.
- A node publishes its own messages to more peers than the mesh, and keeps a minimum number of links that it opened itself, so that attackers who open links to it cannot take over its mesh.
- Large messages can be announced before they are sent so that a peer that already has one says so and is not sent a second copy.

The core is a state machine without any input or output, driven by events and a clock. The network part is a thin driver on top of kolo-swarm connections. The same core runs under a simulator with virtual time, which chose the measured defaults.

## Not wire compatible

kolo-gossip does not talk to other implementations of the protocol. It uses Kolo's own codec (kolo-codec) and Kolo's secure channel. It follows the algorithm and the defaults of the specification, not its bytes.

## Messages and signatures

- The author is a device. A message carries the device public key, the person key, a sequence number, a time, the body and a signature.
- The signature is made by the device key from kolo-id under the context `kolo-gossip/message/v0`. A message is verified before it is forwarded.
- The device certificate is not sent with every message. A receiver looks it up in the topic's roster, caches it, and asks the forwarding peer once if it is missing. A revoked device is ignored without penalty to the forwarder, which may not know the revocation yet.
- Each device has its own sequence counter per topic, so order per device is exact and gaps are visible.

## Validators

The application supplies the validators. A validator looks at a message and returns accept, ignore or reject. Reject lowers the sender's score. The application decides membership, bans and rate; the library holds no member list and has no cap on the number of authors or members.

## What it does not do

- No history. A node that was offline does not get the messages it missed from gossip. Pins keep the history (see below).
- No ordering. There is no total order for gossip messages. An application shows messages by author time with the message id as tie breaker, and uses the per-device sequence number to see gaps. Agreed state, such as membership and bans, goes through kolo-braid.
- No relay. If a deployment needs always-on servers, they are ordinary members.
- No promise that a message is delivered to a member who is offline or on a link that is down.

## With the other Kolo libraries

| Library | What it does with kolo-gossip |
|---|---|
| kolo-swarm | Finds peers for a topic and carries the connections the mesh uses. |
| kolo-id | Device keys sign messages; certificates and revocations tell receivers which devices may post. |
| kolo-codec | Encodes the message envelope and the control frames. |
| kolo-pin | Can keep a room's messages for members who were offline: an application writes the signed envelopes unchanged to a log on pins, and a returning member checks each author's signature, so the writer is trusted for completeness, never for authorship. The bodies are ciphertext only if the application encrypts them. |
| kolo-braid | Keeps the agreed state of a room, such as roles and bans, with a small set of admin devices. It never holds every member as a writer. |
| kolo-moq | Carries live media. Media bytes stay in kolo-moq; gossip only announces. |
| kolo-mls | Not wired: kolo-gossip does not use kolo-mls. An application can publish MLS messages as bodies; gossip signs and forwards them like any body, and validators never decrypt. A Commit larger than `MaxMessageSize` (1 MiB) does not fit. |

## Metadata

The mesh peers of a topic, and the nodes that serve its discovery records, can see who takes part in the topic and when messages are sent. The envelope shows which device sent each message. The design does not hide these, and the guide says so.

## Scale

Nothing about scale is promised beyond what was measured. The library's simulator (`internal/sim`, seed 1, the router of this release with a cost model for signature and chain checks) met the criteria of every scenario, from Sybil floods and eclipse attempts to churn and partitions, at 100, 1,000 and 10,000 nodes in one topic with 64 connection places (the failure scenario S9 reports its delivery and has no criterion of its own). Larger topics, real networks and other seeds are not measured.

Since the ceilings on peers and topics were removed, the simulator models topics (`-topics`, each node joining `-rooms` of them), the places of a node (`-places`, half of them inbound), a busy topic (`-busy`) and the work buckets of every node (`-work`: a frame waits for the receiver's buckets as the driver makes it wait; `-work=false` turns the buckets off; the rotation of gossip targets changed every trace, so traces recorded before it are not reproduced). A message is owed only to the nodes that joined its topic, and in a run with rooms it reaches only the nodes linked to its author through honest nodes that joined its topic. Sybil routers join every topic. Every run is seed 1 with the default score parameters, one process at a time, niced, on a shared machine with a load average of 3 to 20, so the times are wall times at that load. The heap limit of the simulator counts the live heap, not garbage the collector has not swept.

| Run | Nodes | Topics (rooms) | Places | Scenarios | Result |
|---|---|---|---|---|---|
| A0 | 1,000 | 1 | 64 | S1 to S13, M1 | 26 of 26 results pass (8 minutes) |
| A | 1,000 | 50 (all) | 64 | S1, S2, S3, S4, S7, S8, S10, S11, S12, M1 | 17 of 17 pass (27 minutes) |
| B | 1,000 | 50 (all) | 256 | the same | 17 of 17 pass (108 minutes, peak resident memory 9.0 GB, live heap limit 9.5 GB); the full size fits this machine (24 GB) now that the limit counts live heap |
| C | 1,000 | 1 | 256 | S1, S2, S4, S12, one busy topic | 8 of 8 pass |
| C0 | 1,000 | 1 | 256 | the same with `GossipPeers` off | 8 of 8 pass, every number equal to C (IHAVE bytes per node per second 29,923 in S1, 13,165 in S2 silent-5): a busy topic of 1 message a second is under the gossip budget, so the cap does not bind in either run |
| D | 1,000 | 50 (5 each) | 256 | S1, S2, S9 | 10 of 10 pass: S2 silent-1, silent-5, silent-20 and censor-5 delivered every message owed to a reachable node (138 of 138, 114 of 114, 86 of 86, 114 of 114; censored authors in full), where the tree before the gossip fixes delivered 138 of 138, 70 of 114, 67 of 86 and 107 of 114. The 99th percentile of latency was 966 ms in silent-5 and 9,890 ms in silent-20 |
| once | 1,000 | 50 (all) | 64 | S5, S6, S9, S13 | all pass (S13 is report only) |
| A0big | 10,000 | 1 | 64 | S1 to S13, M1 | 26 of 26 results pass (80 minutes in two processes; S9 fail-90 reports 0 of 35 messages in full and has no criterion of its own) |
| Dscore | 500 | 50 (all) | 256 | S2 with Dscore 6 | seed 1: 130 of 130, 124 of 124, 119 of 119 and 124 of 124 messages (silent-1, silent-5, silent-20, censor-5) reached every eligible node; seed 2: 117 of 117, 110 of 110, 110 of 110 and 110 of 110 |

- Memory (M1, 10 messages a second, router heap per node): 121,276 bytes at 1 topic and 64 places at 1,000 nodes and 126,379 at 10,000 (the 128 KiB target is 131,072), 561,705 at 50 topics and 64 places, 1,462,330 at 50 topics and 256 places: 29,247 bytes per topic, 12.1 times the one-topic value, under 50 times it and under 50 targets (6.55 MB). At 1 message a second: 60,972 and 60,747, 511,214 and 1,357,679 bytes. A topic keeps the peers its last IHAVE went to (32 bytes a peer), which raised the per-topic cost from 9,153 and 21,031 bytes before the rotation of gossip targets.
- No honest mesh peer waited for its buckets after the warm-up in any scenario of any run (the rule of the design stays as it was). In the first 0.09 to 0.30 s at 256 places in B, when all 1,000 nodes connect and join together and every key is new to every other, up to 596 frames of mesh peers in a run waited at most 9.7 ms each (none at 64 places or in C, D and the 500-node runs); the run reports them apart. Whether to size the newcomer pool for a node's simultaneous first connections, or to fail these waits, is the owner's decision.
- IHAVE traffic per honest node, S1 at 1,000 nodes: 6,970 bytes a second at 1 topic and 64 places, 9,850 at 50 topics and 64 places, 46,762 at 50 topics and 256 places, 29,923 at 1 busy topic and 256 places. A node below its gossip budget gossips as the specification says, so at 256 places the 50-topic figure is 4.3 times the 10,860 of the tree that capped every topic at 43 targets; at the design rate the cap still binds (`TestGossipPeersCap`).
- Dscore: the sweep of the tree before the gossip fixes (500 nodes, 50 topics, 256 places, Dscore 4 to 8) delivered every message only at 7, because a fixed cap of 43 gossip targets reached a given honest neighbor of a topic with probability 0.2 a heartbeat instead of 0.75. A review run of the fixed tree in a scratch copy delivered 119 of 119 messages of the 20-to-1 flood at 4, 5, 6, 7 and 8. On the landed tree Dscore 6 delivered every message in B, D and the two seeds above; the other values were not rerun on it, and the default stays 6.

Not measured: runs of 30,000 nodes, other seeds (but Dscore 6 at 500 nodes), the Dscore sweep on the landed tree, honest nodes that dial per topic as kolo-swarm does (the simulator's dial without regard to topics), and the honest idle memory of a peer.

Phones sleep and change networks, so they cannot stay mesh members for long; an application that needs a backbone runs always-on members as ordinary peers, which the application score can favour.

## Status of the plan

1. Done: the design note and the threat model (spam, Sybil nodes, eclipse attacks, forged and replayed messages, revoked devices, metadata).
2. Done: the core, the codec, signing and author checks, scoring, the network driver, tests, fuzzing and these docs.
3. Done: a discrete-event simulation at 100, 1,000 and 10,000 nodes, which chose the score parameters and two overlay values (see [limits.md](limits.md)).

Every default has a written source. See [limits.md](limits.md).

## References

- Vyzovitis, Napora, McCormick, Dias and Psaras, [arXiv:2007.02754](https://arxiv.org/abs/2007.02754), 2020: the published design and evaluation of the GossipSub v1.1 protocol. kolo-gossip takes from it the mesh with its graft and prune rules, the heartbeat, the fanout and gossip emission with the message cache, peer scoring with its thresholds, flood publishing, prune backoff with peer exchange, the outbound mesh quota and opportunistic grafting, and for the simulator the attack scenarios, the metrics and the shape of the overlay parameter set; it gives no peer-score values.
- The protocol's specification documents, version 1.0 (revision r2, 2020-03-12), 1.1 (revision r8, 2021-12-14) and 1.2 (revision r2, 2026-08-30, which adds the IDONTWANT control message), read at commit `c750236de43cd8b246a824b377dfdb26bae686db`. Test comments cite them by file and line, such as `gossipsub-v1.1.md:289-332`.

Not implemented: explicit peering agreements, flood-only peers, the epidemic broadcast tree extension, the v1.3 extensions and partial messages, the unsigned and lax signature policies (every message is signed), the topic descriptor authentication and encryption options, and the peer gater of other implementations.

kolo-gossip is not wire compatible with other implementations: it follows the algorithm and the defaults of these specifications, not their bytes.
