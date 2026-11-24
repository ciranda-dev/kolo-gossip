package core

import (
	"bytes"
	"testing"
	"time"

	"github.com/ciranda-dev/kolo-gossip/internal/wire"
)

// fuzzConfig has small bounds so that random event sequences reach every one of them.
func fuzzConfig() *Config {
	cfg := DefaultConfig()
	cfg.MaxMessageSize = 4096
	cfg.MaxCacheBytes = 8192
	cfg.MaxCacheMessages = 5
	cfg.MaxSeen = 20
	cfg.MaxBackoff = 3
	cfg.MaxTopics = 3
	cfg.MaxPeerTopics = 4
	cfg.MaxPeers = 6
	cfg.MaxValidating = 7
	cfg.MaxValidatingBytes = 7 * 4096
	cfg.MaxPeerValidating = 1
	cfg.MaxPeerValidatingBytes = 4096
	cfg.MaxRetained = 2
	cfg.MaxIHaveLength = 6
	cfg.MaxIHaveMessages = 2
	cfg.MaxIDontWantLength = 2
	cfg.MaxIDontWantMessages = 3
	cfg.IDontWantThreshold = 400
	cfg.MaxControlSize = minControlSize
	cfg.Params = Params{D: 3, Dlo: 2, Dhi: 4, Dlazy: 2, Dscore: 2, Dout: 1, GossipFactor: 0.25, GossipPeers: 4}
	cfg.Score = scoringConfig().Score
	cfg.Score.AppScore = func(p PeerID) float64 { return float64(int(p[3]%5) - 2) }
	cfg.Score.IPColocationWeight = -1
	cfg.Score.IPColocationThreshold = 1
	cfg.LockWork, cfg.PeerWork = 20_000, 50_000 // small buckets, so peers do wait
	return cfg
}

type fuzzInput struct {
	b []byte
}

func (in *fuzzInput) byte() byte {
	if len(in.b) == 0 {
		return 0
	}
	c := in.b[0]
	in.b = in.b[1:]
	return c
}

// runRouterFuzz drives one router with events decoded from data and returns the hash of its effects.
func runRouterFuzz(t *testing.T, data []byte, cfg *Config) []byte {
	sink := newSink()
	r, err := New(t0, key(0), cfg, randFor(7), &fakeVerifier{}, sink)
	if err != nil {
		t.Fatal(err)
	}
	in := &fuzzInput{b: data}
	now := t0
	var known []wire.ID
	topic := func() wire.Topic { return topicID(int(in.byte() % 5)) }
	flip := false // the answer of every AllowPeer turns over at Refresh
	id := func() wire.ID {
		if b := in.byte(); len(known) > 0 && b%2 == 0 {
			return known[int(b/2)%len(known)]
		}
		return ids(in.byte(), 1)[0]
	}
	for steps := 0; len(in.b) > 0 && steps < 400; steps++ {
		op := in.byte()
		p := key(1 + int(in.byte()%8))
		switch op % 12 {
		case 0:
			_ = r.AddPeer(now, p, op&0x10 != 0, addr(int(op>>6)))
		case 1:
			r.RemovePeer(now, p)
		case 2:
			c := &wire.Control{}
			for range in.byte() % 4 {
				switch in.byte() % 6 {
				case 0:
					c.Subs = append(c.Subs, wire.Sub{Topic: topic(), Subscribe: in.byte()%3 != 0})
				case 1:
					c.Graft = append(c.Graft, topic())
				case 2:
					c.Prune = append(c.Prune, wire.Prune{Topic: topic(), Backoff: uint64(in.byte()) << (in.byte() % 64)})
				case 3:
					c.IHave = append(c.IHave, wire.IHave{Topic: topic(), IDs: []wire.ID{id(), id(), id()}})
				case 4:
					c.IWant = append(c.IWant, id(), id())
				case 5:
					c.IDontWant = append(c.IDontWant, id(), id(), id())
				}
			}
			_ = r.Control(now, p, c)
		case 3:
			author := key(int(in.byte() % 10))
			at := now.Add(time.Duration(int8(in.byte())) * time.Second)
			var raw []byte
			if in.byte()%5 == 0 {
				raw = badEnvelope(topic(), author, uint64(in.byte()), at)
			} else {
				raw = envelope(topic(), author, uint64(in.byte()), at, int(in.byte())*20)
			}
			if in.byte()%7 == 0 {
				raw = raw[:len(raw)/2]
			}
			known = append(known, wire.NewID(raw))
			r.Message(now, p, raw)
		case 4:
			now = now.Add(time.Duration(in.byte()) * 50 * time.Millisecond)
			r.Tick(now)
			// A peer that has to wait ends its promises and requests: the release path runs too.
			r.Wait(now, p)
		case 5:
			var tc *TopicConfig
			if in.byte()%2 == 0 {
				tc = &TopicConfig{Score: topicScore()}
			}
			if m := in.byte() % 3; m > 0 {
				if tc == nil {
					tc = &TopicConfig{}
				}
				tc.AllowPeer = func(p PeerID) bool { return (p[3]%3 != m-1) != flip }
			}
			_ = r.Join(now, topic(), tc)
		case 6:
			r.Leave(now, topic())
		case 7:
			raw := envelope(topic(), key(0), uint64(in.byte()), now, int(in.byte())*20)
			if pid, err := r.Publish(now, raw); err == nil {
				known = append(known, pid)
			}
		case 8:
			if len(sink.validate) > 0 {
				v := sink.validate[int(in.byte())%len(sink.validate)]
				r.ValidationDone(now, v.id, v.n, Verdict(in.byte()%4))
			}
		case 9:
			n := int(in.byte())
			if c, err := wire.DecodeControl(in.b[:min(len(in.b), n)], r.cfg.MaxControlSize); err == nil {
				_ = r.Control(now, p, c)
			}
		case 10:
			flip = !flip
			r.Refresh(now, topic())
		case 11:
			r.Revalidate(now, topic())
		}
		if err := r.checkBounds(); err != nil {
			t.Fatalf("step %d: %v", steps, err)
		}
		if r.validating < 0 || r.validatingBytes < 0 || r.cache.bytes < 0 {
			t.Fatal("negative counter")
		}
	}
	return sink.h.Sum(nil)
}

func FuzzRouter(f *testing.F) {
	f.Add([]byte{0, 1, 0x10, 2, 5, 1, 2, 1, 1, 0, 1, 3, 1, 2, 30, 1, 1, 5, 4, 1, 25, 8, 0, 0, 0})
	f.Add(bytes.Repeat([]byte{0, 3, 5, 1, 3, 2, 4, 9, 7, 1, 2, 3, 4, 8, 1, 0}, 8))
	f.Add([]byte{5, 0, 0, 1, 0, 0, 0, 0, 2, 0, 3, 1, 1, 3, 0, 1, 2, 3, 4, 5, 6, 4, 0, 255})
	f.Add([]byte("2C20700022z219000000090000zC19010010z01900010yCy20"))
	f.Add([]byte("100000000000000000000000"))
	f.Add([]byte("900007000200000000090001900029001000001009000890007\"009001190000900019000290008!0000001090007!000000009010090010\"00900009001090001901009"))
	f.Fuzz(func(t *testing.T, data []byte) {
		// Small bounds reach every one of them; the defaults, with no cap on peers and topics, reach the rest.
		for _, cfg := range []func() *Config{fuzzConfig, DefaultConfig} {
			if !bytes.Equal(runRouterFuzz(t, data, cfg()), runRouterFuzz(t, data, cfg())) {
				t.Fatal("same events gave different effects")
			}
		}
	})
}
