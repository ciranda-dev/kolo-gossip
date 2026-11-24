package auth

import (
	"container/list"

	"github.com/ciranda-dev/kolo-gossip/internal/wire"
	koloid "github.com/ciranda-dev/kolo-id"
)

// entryOverhead counts the two keys of an entry next to its chain bytes.
const entryOverhead = 2 * wire.KeySize

type cacheEntry struct {
	key  pair
	cert *koloid.DeviceCert
	raw  []byte
}

// certCache keeps verified chains by person and device within limit bytes, least recently used dropped first.
type certCache struct {
	limit int
	bytes int
	m     map[pair]*list.Element
	lru   *list.List // most recently used first
	stats *Stats
}

func newCertCache(limit int, st *Stats) certCache {
	return certCache{limit: limit, m: map[pair]*list.Element{}, lru: list.New(), stats: st}
}

func (c *certCache) get(k pair) *cacheEntry {
	el := c.m[k]
	if el == nil {
		return nil
	}
	c.lru.MoveToFront(el)
	return el.Value.(*cacheEntry)
}

// keep caches a chain the roster gave, so it can answer CERTWANT, unless that chain is already cached.
func (c *certCache) keep(k pair, cert *koloid.DeviceCert) {
	if el := c.m[k]; el != nil && el.Value.(*cacheEntry).cert == cert {
		c.lru.MoveToFront(el)
		return
	}
	c.put(k, cert, cert.Encode())
}

func (c *certCache) put(k pair, cert *koloid.DeviceCert, raw []byte) {
	c.drop(k)
	cost := len(raw) + entryOverhead
	if cost > c.limit {
		return
	}
	for c.bytes > c.limit-cost {
		c.remove(c.lru.Back())
		c.stats.CacheEvicted++
	}
	c.m[k] = c.lru.PushFront(&cacheEntry{key: k, cert: cert, raw: raw})
	c.bytes += cost
}

func (c *certCache) drop(k pair) {
	if el := c.m[k]; el != nil {
		c.remove(el)
	}
}

func (c *certCache) remove(el *list.Element) {
	e := c.lru.Remove(el).(*cacheEntry)
	delete(c.m, e.key)
	c.bytes -= len(e.raw) + entryOverhead
}
