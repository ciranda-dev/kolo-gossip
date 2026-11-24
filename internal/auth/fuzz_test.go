package auth

import (
	"bytes"
	"errors"
	"testing"

	"github.com/ciranda-dev/kolo-gossip/internal/wire"
	koloid "github.com/ciranda-dev/kolo-id"
)

// FuzzCertChain feeds chain bytes from the network, alone and inside a control frame, to a Resolver with one
// outstanding request: nothing panics, only a chain that verifies for the requested person is cached, and a
// waiting message passes only with such a chain.
func FuzzCertChain(f *testing.F) {
	q, b := newPerson(f, 20), newPerson(f, 30)
	raw := q.sign(f, 1, t0, "x")
	for _, c := range []*koloid.DeviceCert{q.deviceCert, q.approverCert, b.deviceCert} {
		f.Add(c.Encode())
		f.Add(c.Encode()[:100])
		frame, err := (&wire.Control{Cert: [][]byte{c.Encode(), {1}}}).Encode()
		if err != nil {
			f.Fatal(err)
		}
		f.Add(frame)
	}
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		lists := [][][]byte{{data}}
		if c, err := wire.DecodeControl(data, 512<<10); err == nil {
			lists = append(lists, c.Cert)
			// The same frame through the router, with a message waiting for q's chain.
			n := openNode(t, 1, q)
			n.message(1, raw)
			n.r.Control(t0, peerKey(1), c)
			if n.validated(raw) && n.res.Stats().CacheChains != 1 {
				t.Fatal("the router released a message without a verified chain")
			}
		}
		for _, certs := range lists {
			r := newResolver(t, &clock{t0}, nil, newOpener(q).open, nil)
			env, signed := decode(t, raw)
			if _, err := r.Resolve(t0, wire.NewID(raw), env, signed, peerKey(1)); err != nil {
				t.Fatal(err)
			}
			out := r.Cert(t0, peerKey(1), certs, 1<<40)
			s := r.Stats()
			if s.Answered+s.Unsolicited != uint64(len(certs)) || s.Answered > 1 {
				t.Fatalf("read %d of %d chains with one request", s.Answered, len(certs))
			}
			for _, e := range r.cache.m {
				c := e.Value.(*cacheEntry)
				if err := c.cert.Verify(&koloid.VerifyOptions{Person: q.pub(), Now: t0}); err != nil || !bytes.Equal(c.cert.Device(), q.device.PublicKey()) {
					t.Fatalf("cached a chain that does not verify: %v", err)
				}
			}
			for _, d := range out.Done {
				if d.Err == nil && s.CacheChains != 1 {
					t.Fatal("a message passed without a verified chain")
				}
			}
			if len(out.Done)+s.Waiting != 1 || (s.Waiting == 0) != (s.Outstanding == 0) {
				t.Fatalf("waiting accounting: %d done, %+v", len(out.Done), s)
			}
		}
	})
}

// FuzzVerify runs envelope bytes through the router and the Resolver in closed and open mode: nothing panics
// and only the exact bytes a device signed ever reach the validator.
func FuzzVerify(f *testing.F) {
	p, q := newPerson(f, 10), newPerson(f, 20)
	signed := map[string]bool{}
	for i, s := range []*person{p, q} {
		for _, body := range []string{"", "hello", string(make([]byte, 300))} {
			raw := s.sign(f, uint64(i), t0, body)
			signed[string(raw)] = true
			f.Add(raw)
		}
	}
	f.Add([]byte{0})
	f.Add([]byte("\x0000000000000000000000000000000000ne\xe6\t\xcc\x13\xdc\xec\xfc\xa8\xa5\xf1}<\xde\xeaQ\x85@\xa7n\xfb\x19J\x9b\xfd\x83\x8a\bٯ.\x8c\x8cG2t\xa7\xc8\xe2\x02\x91z\x92\xf1\x9e\xfa\xe0\x0f\x7fc.\xdemvyH\x88\x80aD\x17:\xeb00\x05000000000000000000000000000000000000000000000000000000000000000000000"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		closed := newNode(t, newRoster(p), nil, 1, nil, nil)
		open := newNode(t, nil, newOpener(q).open, 1, nil, nil)
		open.res.cache.put(keyOf(q.pub(), q.device.PublicKey()), q.deviceCert, q.deviceCert.Encode())
		for _, n := range []*node{closed, open} {
			n.message(1, raw)
			if n.validated(raw) && !signed[string(raw)] {
				t.Fatal("bytes no device signed reached the validator")
			}
		}
		env, err := wire.DecodeEnvelope(raw, 1<<20)
		if err != nil {
			return
		}
		body := raw[:len(raw)-wire.SigSize]
		err = closed.res.Verify(env, body)
		if closed.res.Signed(env, body) && err == nil && !signed[string(raw)] {
			t.Fatal("unsigned bytes verify")
		}
		if err != nil && !errors.Is(err, ErrVerify) && !errors.Is(err, ErrUnknownAuthor) {
			t.Fatalf("untyped error %v", err)
		}
	})
}
