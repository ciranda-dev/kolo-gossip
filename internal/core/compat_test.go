package core

import "github.com/ciranda-dev/kolo-gossip/internal/wire"

// The helpers below are the only test code that reads the share and subscription lists, so the tests of the
// removed ceilings can run against a tree without them.

func rateOf(f *fixture, i int) (lock, out int64) { return f.r.rates(f.r.byID[key(i)]) }

func peerRates(f *fixture, p *peer) (lock, out int64) { return f.r.rates(p) }

func listsOf(f *fixture, i int) (topics, other []wire.Topic) {
	p := f.r.byID[key(i)]
	return p.topics, p.other
}

// setShares sets the snapshot of peers 1..len(meshN): their mesh places and delivered messages.
func setShares(f *fixture, meshN []int32, delivered []int64) {
	f.r.meshPlaces, f.r.delivered = 0, 0
	for i := range meshN {
		p := f.r.byID[key(i+1)]
		p.meshN, p.delivered = meshN[i], delivered[i]
		f.r.meshPlaces += int(meshN[i])
		f.r.delivered += delivered[i]
	}
}

func dropped(f *fixture) uint64 { return f.r.Stats().SubscriptionsDropped }

func readerWork(cfg *Config) int64 { return cfg.ReaderWork }

func manyPeers(cfg *Config) {}
