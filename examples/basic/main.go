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
