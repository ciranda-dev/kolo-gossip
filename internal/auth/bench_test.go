package auth

import (
	"slices"
	"testing"

	"github.com/ciranda-dev/kolo-gossip/internal/core"
	"github.com/ciranda-dev/kolo-gossip/internal/wire"
	koloid "github.com/ciranda-dev/kolo-id"
)

// BenchmarkVerifyRoster measures the author check of one message from a roster author with an approver-issued
// chain, as the router runs it for every new message.
func BenchmarkVerifyRoster(b *testing.B) {
	p := newPerson(b, 10)
	r := newResolver(b, &clock{t0}, newRoster(p), nil, nil)
	env, signed := decode(b, p.sign(b, 1, t0, "body"))
	b.ResetTimer()
	for b.Loop() {
		if err := r.Verify(env, signed); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkCertAnswer measures one CERT answer that releases 100 messages waiting for the same author's chain.
func BenchmarkCertAnswer(b *testing.B) {
	q := newPerson(b, 20)
	var envs []*wire.Envelope
	var signeds [][]byte
	for i := range 100 {
		env, signed := decode(b, q.sign(b, uint64(i), t0, "body"))
		envs, signeds = append(envs, env), append(signeds, signed)
	}
	raw := q.deviceCert.Encode()
	b.ResetTimer()
	for b.Loop() {
		b.StopTimer()
		r := newResolver(b, &clock{t0}, nil, newOpener(q).open, func(c *Config) { c.MaxWaiting = 200 })
		for i, env := range envs {
			if _, err := r.Resolve(t0, wire.ID{byte(i)}, env, signeds[i], peerKey(1)); err != nil {
				b.Fatal(err)
			}
		}
		b.StartTimer()
		if res := r.Cert(t0, peerKey(1), [][]byte{raw}, 1<<40); len(res.Done) != 100 {
			b.Fatal(len(res.Done))
		}
	}
}

// BenchmarkSigned measures the signature check of one message, which the driver runs outside the router.
func BenchmarkSigned(b *testing.B) {
	p := newPerson(b, 10)
	env, signed := decode(b, p.sign(b, 1, t0, "body"))
	for b.Loop() {
		if !Signed(env, signed) {
			b.Fatal("not signed")
		}
	}
}

// BenchmarkVerifyRevocations measures the author check of one message whose roster entry carries 100
// revocations, the case where hashing the encodings would cost the most.
func BenchmarkVerifyRevocations(b *testing.B) {
	p := newPerson(b, 10)
	var revs []*koloid.Revocation
	for i := range 100 {
		rv, err := p.key.RevokeDevice(&koloid.RevokeOptions{Person: p.pub(), Device: newPerson(b, byte(30+i%100)).device.PublicKey(), UpToSerial: 1, At: t0})
		if err != nil {
			b.Fatal(err)
		}
		revs = append(revs, rv)
	}
	ros := newRoster()
	ros.add(p.pub(), p.device.PublicKey(), &Author{Person: p.pub(), Cert: p.deviceCert, Revocations: revs})
	r := newResolver(b, &clock{t0}, ros, nil, nil)
	env, signed := decode(b, p.sign(b, 1, t0, "body"))
	b.ResetTimer()
	for b.Loop() {
		if err := r.Verify(env, signed); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkVerifyDecodedRevocations measures the author check for a roster that decodes new objects with 100
// revocations on every lookup: the result is found by the encodings' hash. The decoding is the roster's.
func BenchmarkVerifyDecodedRevocations(b *testing.B) {
	p := newPerson(b, 10)
	d := decodingRoster{p: p, cert: p.deviceCert.Encode()}
	for i := range 100 {
		rv, err := p.key.RevokeDevice(&koloid.RevokeOptions{Person: p.pub(), Device: newPerson(b, byte(30+i%100)).device.PublicKey(), UpToSerial: 1, At: t0})
		if err != nil {
			b.Fatal(err)
		}
		d.revs = append(d.revs, rv.Encode())
	}
	r := newResolver(b, &clock{t0}, d, nil, nil)
	env, signed := decode(b, p.sign(b, 1, t0, "body"))
	b.ResetTimer()
	for b.Loop() {
		if err := r.Verify(env, signed); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkChainKey measures the content key of a chain with 100 revocations, the work under the lock for each
// message from a roster that decodes new objects on every lookup, the decoding aside.
func BenchmarkChainKey(b *testing.B) {
	p := newPerson(b, 10)
	var revs []*koloid.Revocation
	for i := range 100 {
		rv, err := p.key.RevokeDevice(&koloid.RevokeOptions{Person: p.pub(), Device: newPerson(b, byte(30+i%100)).device.PublicKey(), UpToSerial: 1, At: t0})
		if err != nil {
			b.Fatal(err)
		}
		revs = append(revs, rv)
	}
	r := newResolver(b, &clock{t0}, newRoster(), nil, nil)
	var k pair
	r.chain(t0, k, p.deviceCert, revs)
	for b.Loop() {
		for key := range r.chains.m {
			if key.sum == ([32]byte{}) {
				delete(r.chains.m, key)
			}
		}
		r.chain(t0, k, p.deviceCert, revs)
	}
}

// BenchmarkAuthPaths runs each author path with its most expensive frame on a fresh node and reports its time and
// the units it charges peer 1: a path is calibrated when ns/op is at most 10 x units/op.
func BenchmarkAuthPaths(b *testing.B) {
	names := make([]string, 0, len(authPaths))
	for name := range authPaths {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		b.Run(name, func(b *testing.B) {
			var units int64
			for b.Loop() {
				b.StopTimer()
				n, send, _ := authPaths[name](&testing.T{})
				n.r.AuditOps()
				b.StartTimer()
				send()
				b.StopTimer()
				_, charged := n.r.Audit()
				for op, k := range charged {
					units += core.Cost(op, int(k))
				}
				b.StartTimer()
			}
			b.ReportMetric(float64(units)/float64(b.N), "units/op")
		})
	}
}
