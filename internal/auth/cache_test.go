package auth

import (
	"bytes"
	"testing"

	koloid "github.com/ciranda-dev/kolo-id"
)

// TestCertCache: the cache keeps at most CertCacheBytes, drops the least recently used first, and keep does
// not re-encode a chain it already holds.
func TestCertCache(t *testing.T) {
	var ps []*person
	for i := range 4 {
		ps = append(ps, newPerson(t, byte(20+10*i)))
	}
	cost := len(ps[0].deviceCert.Encode()) + entryOverhead
	r := newResolver(t, &clock{t0}, newRoster(), nil, func(c *Config) { c.CertCacheBytes = 3 * cost })
	c := &r.cache
	key := func(p *person) pair { return keyOf(p.pub(), p.device.PublicKey()) }
	for _, p := range ps[:3] {
		c.keep(key(p), p.deviceCert)
	}
	if c.bytes != 3*cost || c.lru.Len() != 3 {
		t.Fatalf("cache %d bytes, %d chains", c.bytes, c.lru.Len())
	}
	c.get(key(ps[0]))
	c.keep(key(ps[3]), ps[3].deviceCert)
	if c.get(key(ps[1])) != nil || c.get(key(ps[0])) == nil || c.get(key(ps[3])) == nil || r.Stats().CacheEvicted != 1 {
		t.Fatal("the least recently used chain must go first")
	}
	if c.bytes > c.limit {
		t.Fatalf("over the bound: %d", c.bytes)
	}
	e := c.get(key(ps[3]))
	c.keep(key(ps[3]), ps[3].deviceCert)
	if c.get(key(ps[3])) != e {
		t.Fatal("keep replaced an identical chain")
	}
	renewed := certify(t, ps[3].approver, ps[3].device, &koloid.IssueOptions{Parent: ps[3].approverCert, Serial: 2, IssuedAt: issued})
	c.keep(key(ps[3]), renewed)
	if got := c.get(key(ps[3])); got.cert != renewed || !bytes.Equal(got.raw, renewed.Encode()) || c.bytes != 3*cost {
		t.Fatal("keep must replace a changed chain")
	}
	small := newCertCache(cost-1, &Stats{})
	small.put(key(ps[0]), ps[0].deviceCert, ps[0].deviceCert.Encode())
	if small.lru.Len() != 0 || small.bytes != 0 {
		t.Fatal("a chain over the whole bound was cached")
	}
}
