package wire

import (
	"fmt"
	"math/bits"
	"net/netip"

	kolocodec "github.com/ciranda-dev/kolo-codec"
)

// MaxCertSize is the largest device certificate, one issued by an approver (kolo-id).
const MaxCertSize = 514

// Smallest encodings of list items, used to bound each count by the bytes left before allocating.
const (
	minSub      = 32 + 1
	minGraft    = 32
	minPrune    = 32 + 1 + 1
	minPX       = KeySize + 4 + 1
	minIHave    = 32 + 1
	minCertWant = 2 * KeySize
	minCert     = 1 + 1
)

// Control is one control frame: lists of subscription changes and mesh and gossip messages, encoded in this order.
type Control struct {
	Subs      []Sub
	Graft     []Topic
	Prune     []Prune
	IHave     []IHave
	IWant     []ID
	IDontWant []ID
	CertWant  []CertWant
	Cert      [][]byte
}

// Sub announces that the sender joined (Subscribe true) or left a topic.
type Sub struct {
	Topic     Topic
	Subscribe bool
}

// Prune removes the receiver from the sender's mesh for Topic for Backoff seconds and may list other peers.
type Prune struct {
	Topic   Topic
	Backoff uint64
	PX      []PeerRecord
}

// PeerRecord is a peer exchange entry: a key and the IPv4 address to dial it at.
type PeerRecord struct {
	Key  Key
	Addr netip.AddrPort
}

// IHave lists message ids the sender holds for Topic.
type IHave struct {
	Topic Topic
	IDs   []ID
}

// CertWant asks for the certificate chain of a device of a person.
type CertWant struct {
	Person Key
	Device Key
}

// Empty reports whether c carries nothing.
func (c *Control) Empty() bool {
	return len(c.Subs) == 0 && len(c.Graft) == 0 && len(c.Prune) == 0 && len(c.IHave) == 0 &&
		len(c.IWant) == 0 && len(c.IDontWant) == 0 && len(c.CertWant) == 0 && len(c.Cert) == 0
}

// Items returns the list entries of c, IHAVE ids and PRUNE peer records included: each costs its decoding an
// allocation or a copy.
func (c *Control) Items() int {
	n := len(c.Subs) + len(c.Graft) + len(c.Prune) + len(c.IHave) + len(c.IWant) + len(c.IDontWant) + len(c.CertWant) + len(c.Cert)
	for _, p := range c.Prune {
		n += len(p.PX)
	}
	for _, h := range c.IHave {
		n += len(h.IDs)
	}
	return n
}

// Size returns the length of c's encoding.
func (c *Control) Size() int {
	n := uvlen(len(c.Subs)) + len(c.Subs)*minSub
	n += uvlen(len(c.Graft)) + len(c.Graft)*minGraft
	n += uvlen(len(c.Prune))
	for _, p := range c.Prune {
		n += PruneSize(&p)
	}
	n += uvlen(len(c.IHave))
	for _, h := range c.IHave {
		n += IHaveSize(len(h.IDs))
	}
	n += uvlen(len(c.IWant)) + len(c.IWant)*IDSize
	n += uvlen(len(c.IDontWant)) + len(c.IDontWant)*IDSize
	n += uvlen(len(c.CertWant)) + len(c.CertWant)*minCertWant
	n += uvlen(len(c.Cert))
	for _, b := range c.Cert {
		n += uvlen(len(b)) + len(b)
	}
	return n
}

// PruneSize returns the encoded size of one Prune entry.
func PruneSize(p *Prune) int {
	n := 32 + UvarintLen(p.Backoff) + uvlen(len(p.PX))
	for _, r := range p.PX {
		n += KeySize + 4 + UvarintLen(uint64(r.Addr.Port()))
	}
	return n
}

// IHaveSize returns the encoded size of one IHave entry with n ids.
func IHaveSize(n int) int {
	return 32 + uvlen(n) + n*IDSize
}

// Encode returns the canonical encoding of c, or ErrInvalid for a non-IPv4 or zero-port peer record or an empty
// or oversized certificate.
func (c *Control) Encode() ([]byte, error) {
	var e kolocodec.Encoder
	e.PutUvarint(uint64(len(c.Subs)))
	for _, s := range c.Subs {
		e.PutFixed(s.Topic[:])
		e.PutBool(s.Subscribe)
	}
	e.PutUvarint(uint64(len(c.Graft)))
	for _, t := range c.Graft {
		e.PutFixed(t[:])
	}
	e.PutUvarint(uint64(len(c.Prune)))
	for _, p := range c.Prune {
		e.PutFixed(p.Topic[:])
		e.PutUvarint(p.Backoff)
		e.PutUvarint(uint64(len(p.PX)))
		for _, r := range p.PX {
			ip := r.Addr.Addr()
			if !ip.Is4() || r.Addr.Port() == 0 {
				return nil, fmt.Errorf("%w: peer record address %v", ErrInvalid, r.Addr)
			}
			e.PutFixed(r.Key[:])
			e.PutFixed(ip.AsSlice())
			e.PutUvarint(uint64(r.Addr.Port()))
		}
	}
	e.PutUvarint(uint64(len(c.IHave)))
	for _, h := range c.IHave {
		e.PutFixed(h.Topic[:])
		putIDs(&e, h.IDs)
	}
	putIDs(&e, c.IWant)
	putIDs(&e, c.IDontWant)
	e.PutUvarint(uint64(len(c.CertWant)))
	for _, w := range c.CertWant {
		e.PutFixed(w.Person[:])
		e.PutFixed(w.Device[:])
	}
	e.PutUvarint(uint64(len(c.Cert)))
	for _, b := range c.Cert {
		if len(b) == 0 || len(b) > MaxCertSize {
			return nil, fmt.Errorf("%w: certificate of %d bytes", ErrInvalid, len(b))
		}
		e.PutBytes(b)
	}
	return e.Bytes(), nil
}

// DecodeControl decodes a control frame of at most limit bytes.
func DecodeControl(b []byte, limit int) (*Control, error) {
	return DecodeControlCerts(b, limit, len(b))
}

// DecodeControlCerts is DecodeControl refusing a frame of more than maxCerts certificates before it allocates
// them: each is a copy, so a frame of many tiny ones would cost far more than its bytes.
func DecodeControlCerts(b []byte, limit, maxCerts int) (*Control, error) {
	if len(b) > limit {
		return nil, fmt.Errorf("%w: control frame of %d bytes over %d", ErrTooLarge, len(b), limit)
	}
	d := kolocodec.NewDecoder(b)
	c := new(Control)
	n, err := count(d, minSub)
	if err != nil {
		return nil, err
	}
	c.Subs = make([]Sub, n)
	for i := range c.Subs {
		if err := fixed(d, c.Subs[i].Topic[:]); err != nil {
			return nil, err
		}
		if c.Subs[i].Subscribe, err = d.Bool(); err != nil {
			return nil, malformed(err)
		}
	}
	if c.Graft, err = topics(d); err != nil {
		return nil, err
	}
	if n, err = count(d, minPrune); err != nil {
		return nil, err
	}
	c.Prune = make([]Prune, n)
	for i := range c.Prune {
		if err := decodePrune(d, &c.Prune[i]); err != nil {
			return nil, err
		}
	}
	if n, err = count(d, minIHave); err != nil {
		return nil, err
	}
	c.IHave = make([]IHave, n)
	for i := range c.IHave {
		if err := fixed(d, c.IHave[i].Topic[:]); err != nil {
			return nil, err
		}
		if c.IHave[i].IDs, err = ids(d); err != nil {
			return nil, err
		}
	}
	if c.IWant, err = ids(d); err != nil {
		return nil, err
	}
	if c.IDontWant, err = ids(d); err != nil {
		return nil, err
	}
	if n, err = count(d, minCertWant); err != nil {
		return nil, err
	}
	c.CertWant = make([]CertWant, n)
	for i := range c.CertWant {
		if err := fixed(d, c.CertWant[i].Person[:]); err != nil {
			return nil, err
		}
		if err := fixed(d, c.CertWant[i].Device[:]); err != nil {
			return nil, err
		}
	}
	if n, err = count(d, minCert); err != nil {
		return nil, err
	}
	if n > maxCerts {
		return nil, fmt.Errorf("%w: %d certificates in a frame, over %d", ErrTooLarge, n, maxCerts)
	}
	c.Cert = make([][]byte, n)
	for i := range c.Cert {
		if c.Cert[i], err = d.Bytes(MaxCertSize); err != nil {
			return nil, malformed(err)
		}
		if len(c.Cert[i]) == 0 {
			return nil, fmt.Errorf("%w: empty certificate", ErrMalformed)
		}
	}
	if err := d.Done(); err != nil {
		return nil, malformed(err)
	}
	return c, nil
}

func decodePrune(d *kolocodec.Decoder, p *Prune) error {
	if err := fixed(d, p.Topic[:]); err != nil {
		return err
	}
	var err error
	if p.Backoff, err = d.Uvarint(); err != nil {
		return malformed(err)
	}
	n, err := count(d, minPX)
	if err != nil {
		return err
	}
	p.PX = make([]PeerRecord, n)
	for i := range p.PX {
		if err := fixed(d, p.PX[i].Key[:]); err != nil {
			return err
		}
		var ip [4]byte
		if err := fixed(d, ip[:]); err != nil {
			return err
		}
		port, err := d.UvarintMax(1<<16 - 1)
		if err != nil {
			return malformed(err)
		}
		if port == 0 {
			return fmt.Errorf("%w: peer record port 0", ErrMalformed)
		}
		p.PX[i].Addr = netip.AddrPortFrom(netip.AddrFrom4(ip), uint16(port))
	}
	return nil
}

func count(d *kolocodec.Decoder, itemSize int) (int, error) {
	n, err := d.UvarintMax(uint64(d.Len() / itemSize))
	if err != nil {
		return 0, malformed(err)
	}
	return int(n), nil
}

func topics(d *kolocodec.Decoder) ([]Topic, error) {
	n, err := count(d, minGraft)
	if err != nil {
		return nil, err
	}
	ts := make([]Topic, n)
	for i := range ts {
		if err := fixed(d, ts[i][:]); err != nil {
			return nil, err
		}
	}
	return ts, nil
}

func ids(d *kolocodec.Decoder) ([]ID, error) {
	n, err := count(d, IDSize)
	if err != nil {
		return nil, err
	}
	out := make([]ID, n)
	for i := range out {
		if err := fixed(d, out[i][:]); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func putIDs(e *kolocodec.Encoder, ids []ID) {
	e.PutUvarint(uint64(len(ids)))
	for _, id := range ids {
		e.PutFixed(id[:])
	}
}

func uvlen(n int) int {
	return UvarintLen(uint64(n))
}

// UvarintLen returns the encoded length of v as a uvarint.
func UvarintLen(v uint64) int {
	return max(1, (bits.Len64(v)+6)/7)
}
