# kolo-gossip

Spread signed messages to every member of a topic, hop by hop, without a relay.

[![status: experimental](https://img.shields.io/badge/status-experimental-orange)](#status)
[![license: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)
[![go: 1.26+](https://img.shields.io/badge/go-1.26%2B-00ADD8)](go.mod)

## What it is

kolo-gossip lets the members of a topic pass messages to each other, so that a message from one member reaches every member without a server in the middle. It follows a published mesh gossip protocol, version 1.1 with the IDONTWANT message of 1.2 ([References](docs/design.md#references)): each node keeps a mesh of a few peers per topic and pushes full messages along it, announces the ids of recent messages to its other peers so that gaps are repaired, scores its peers so that spam, Sybil and eclipse attacks lose their links, and dials the peers a well-scored peer lists when it prunes a mesh link (peer exchange).

Every message is signed by the author's [kolo-id](https://github.com/ciranda-dev/kolo-id) device key under its own context and checked against the person the application expects: a roster for closed rooms, or a chain fetched from the forwarding peer in open rooms. The application's validator decides who may post. The library keeps no history and gives no order: pins keep history and the application orders what it shows.

It runs on [kolo-swarm](https://github.com/ciranda-dev/kolo-swarm) connections, which the application hands it. It is Go only, builds without cgo, and is IPv4 only. It is not wire compatible with other implementations of that protocol: it follows their algorithm and defaults, not their bytes.

## Install

```sh
go get github.com/ciranda-dev/kolo-gossip
```

## Quick start

A kolo-dht server and two nodes on loopback find each other, join a closed room and exchange a message.

```go
// Command basic runs a kolo-dht server and two gossip nodes on one IPv4 host (by default loopback); the nodes find
// each other through the server, join one room and exchange a signed message.
//
//	go run ./examples/basic [-host 127.0.0.1]
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	kolodht "github.com/ciranda-dev/kolo-dht"
	kologossip "github.com/ciranda-dev/kolo-gossip"
	koloid "github.com/ciranda-dev/kolo-id"
	koloswarm "github.com/ciranda-dev/kolo-swarm"
)

// roster is a closed room: the devices the application accepts as authors.
type roster map[string]*kologossip.Author

func (r roster) Lookup(_ kologossip.Topic, person, device ed25519.PublicKey) (*kologossip.Author, error) {
	if a := r[string(person)+string(device)]; a != nil {
		return a, nil
	}
	return nil, kologossip.ErrUnknownAuthor
}

// member is a person key with one device it certified.
func member(r roster) (*koloid.Identity, *koloid.DeviceCert) {
	person, err := koloid.Generate()
	if err != nil {
		log.Fatal(err)
	}
	device, err := koloid.Generate()
	if err != nil {
		log.Fatal(err)
	}
	offer, err := person.OfferDeviceCert(device.PublicKey(), &koloid.IssueOptions{Serial: 1})
	if err != nil {
		log.Fatal(err)
	}
	cert, err := device.AcceptDeviceCert(offer, person.PublicKey())
	if err != nil {
		log.Fatal(err)
	}
	r[string(person.PublicKey())+string(device.PublicKey())] = &kologossip.Author{Person: person.PublicKey(), Cert: cert}
	return device, cert
}

// start runs a swarm and a gossip node as device and serves every peer the swarm connects.
func start(ctx context.Context, host string, server netip.AddrPort, device *koloid.Identity, cert *koloid.DeviceCert) *kologossip.Gossip {
	// The swarm refuses keys the gossip graylisted; it asks before the gossip exists.
	var gp atomic.Pointer[kologossip.Gossip]
	sw, err := koloswarm.New(ctx, net.JoinHostPort(host, "0"), device, &koloswarm.Config{
		BootstrapNodes: []string{server.String()},
		Allow: func(k ed25519.PublicKey, a netip.AddrPort) bool {
			g := gp.Load()
			return g == nil || g.Allow(k, a)
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	if err := sw.Bootstrap(ctx, nil); err != nil {
		log.Fatal(err)
	}
	g, err := kologossip.New(device, &kologossip.Config{Cert: cert, Swarm: sw})
	if err != nil {
		log.Fatal(err)
	}
	gp.Store(g)
	go func() {
		for {
			ev, err := sw.Next(ctx)
			if err != nil {
				return
			}
			if ev.Kind == koloswarm.Connected {
				go g.ServeConn(ctx, ev.Peer.Conn(), ev.Peer.Outbound())
			}
		}
	}()
	go func() {
		<-ctx.Done()
		g.Close()
		sw.Close()
	}()
	return g
}

func main() {
	host := flag.String("host", "127.0.0.1", "IPv4 address the server and the nodes listen on")
	flag.Parse()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	sid, err := koloid.Generate()
	if err != nil {
		log.Fatal(err)
	}
	server, err := kolodht.New(ctx, net.JoinHostPort(*host, "0"), sid, &kolodht.Config{Server: true})
	if err != nil {
		log.Fatal(err)
	}
	defer server.Close()
	saddr := server.Addr().(*net.UDPAddr).AddrPort()
	saddr = netip.AddrPortFrom(saddr.Addr().Unmap(), saddr.Port())

	r := roster{}
	aliceDev, aliceCert := member(r)
	bobDev, bobCert := member(r)
	alice := start(ctx, *host, saddr, aliceDev, aliceCert)
	bob := start(ctx, *host, saddr, bobDev, bobCert)

	topic := kologossip.Topic(sha256.Sum256([]byte("kolo example room")))
	ra, err := alice.Join(ctx, topic, &kologossip.TopicOptions{Authors: r})
	if err != nil {
		log.Fatal(err)
	}
	rb, err := bob.Join(ctx, topic, &kologossip.TopicOptions{Authors: r})
	if err != nil {
		log.Fatal(err)
	}
	for ra.Stats().Mesh == 0 {
		select {
		case <-ctx.Done():
			log.Fatal(ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
	if _, err := ra.Publish(ctx, []byte("hello room")); err != nil {
		log.Fatal(err)
	}
	m, err := rb.Next(ctx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("bob got %q from person %x, seq %d\n", m.Body, m.Person[:8], m.Seq)
}
```

```text
$ go run ./examples/basic
bob got "hello room" from person <16 hex characters>, seq <a number>
```

## API

| Symbol | What it does |
|---|---|
| `New` | Start gossip as a device key with its certificate chain (`Config.Cert`) |
| `Gossip.ServeConn` | Run gossip on one connection, such as a kolo-swarm peer's, until it ends |
| `Gossip.Join`, `Room.Leave` | Join or leave a topic; with `Config.Swarm`, also the swarm topic |
| `Room.Publish`, `Gossip.Publish` | Sign and send a message to a joined topic, or to a topic not joined (fanout); they return the signed `Message` |
| `Room.Next` | Return the next message delivered in the room |
| `TopicOptions` | A room's roster (`Authors`, closed mode), `Open` mode, `Validator`, `AllowPeer`, overlay and score parameters, size limit and sequence counter |
| `TopicOptions.AllowPeer`, `Room.RefreshPeers` | A per-topic peer filter: a refused peer is told nothing of the topic and gets none of its messages; `RefreshPeers` asks again |
| `Author`, `Authors`, `Open` | What the application knows about a device, and who may author |
| `Validator`, `Verdict`, `Room.Revalidate` | The application's check: `Accept`, `Reject`, `Ignore` or `Retry` (kept and validated again) |
| `Message`, `MessageID`, `Topic` | A delivered message with its signed envelope (`Raw`), its id and its 32-byte topic |
| `VerifyEnvelope` | Check a stored `Message.Raw` against its author's certificate chain |
| `Config.Now` | The clock for signing, time windows and heartbeats |
| `Gossip.Allow` | Refuse graylisted keys; chain it into `koloswarm.Config.Allow` |
| `Gossip.Score`, `Gossip.Stats`, `Room.Stats` | Peer scores, counters and sizes |
| `Gossip.Close` | Stop every room and connection loop and wait for them |
| `Config`, `Params`, `ScoreParams`, `TopicScoreParams`, `Thresholds` | Bounds, overlay and score parameters; `DefaultParams`, `DefaultScore` and `DefaultTopicScore` give the defaults, `Config.NoScore` and `TopicOptions.NoScore` turn scoring off |
| `Config.PeerExchange`, `Config.PrunePeers`, `Thresholds.AcceptPX` | List our peers in the PRUNE we send (off by default); how many records a PRUNE carries; the score from which a PRUNE's records are dialed through `Config.Swarm` (0 dials none) |

Errors are sentinels for `errors.Is`: `ErrInvalidConfig`, `ErrInvalidArgument`, `ErrClosed`, `ErrNotJoined`, `ErrTooLarge`, `ErrLimit`, `ErrDuplicate`, `ErrProtocol`, `ErrGraylisted`, `ErrOwnChain`, `ErrUnknownAuthor` and `ErrBadEnvelope`.

## Documentation

- [Guide](docs/guide.md): keys, connections, rooms, closed and open mode, validators, publishing and reading, scoring, peer exchange and statistics.
- [Limits](docs/limits.md): every option with its default and source, the work budgets, peer exchange bounds and memory.
- [Protocol](docs/protocol.md): streams, the envelope, control frames, the receive pipeline and the references.
- [Design](docs/design.md): how it fits with the other Kolo libraries and what it does not do.

## Status

Experimental. The API may change before v1.0.0.

## License

Licensed under either of the [Apache License, Version 2.0](LICENSE) or the [MIT license](LICENSE-MIT), at your option.
