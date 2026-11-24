// Package kologossip spreads signed messages to every member of a topic, hop by hop, without a relay. It follows
// a published mesh gossip protocol, version 1.1 with the IDONTWANT rule of 1.2 (docs/design.md, References): each
// node keeps a mesh of a few peers per topic, forwards full messages along it, announces recent message ids to
// other peers so gaps are repaired, and scores its peers to resist spam, Sybil and eclipse attacks.
//
// Every message is signed by the author's kolo-id device key under the context "kolo-gossip/message/v0" and checked
// against the person the application expects: a roster (Authors, closed mode) or, in open mode, a chain fetched
// from the forwarding peer. The application's Validator decides membership, roles, rate and content. The library
// keeps no history and gives no order.
//
// A Gossip takes its connections from the application: call ServeConn for each kolo-swarm peer. The API is
// experimental and may change before v1.0.0.
package kologossip
