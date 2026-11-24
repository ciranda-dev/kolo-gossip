package wire

import (
	"bytes"
	"errors"
	"math"
	"net/netip"
	"testing"

	kolocodec "github.com/ciranda-dev/kolo-codec"
)

func fullControl() *Control {
	var t1, t2 Topic
	t1[0], t2[0] = 1, 2
	var k Key
	k[5] = 9
	var id1, id2 ID
	id1[0], id2[31] = 3, 4
	return &Control{
		Subs:  []Sub{{t1, true}, {t2, false}},
		Graft: []Topic{t1},
		Prune: []Prune{
			{Topic: t1, Backoff: 60, PX: []PeerRecord{{k, netip.MustParseAddrPort("127.0.0.1:4001")}}},
			{Topic: t2, Backoff: math.MaxUint64},
		},
		IHave:     []IHave{{t1, []ID{id1, id2}}, {t2, nil}},
		IWant:     []ID{id1},
		IDontWant: []ID{id2, id1},
		CertWant:  []CertWant{{k, k}},
		Cert:      [][]byte{{1, 2, 3}, bytes.Repeat([]byte{5}, MaxCertSize)},
	}
}

func TestControlRoundTrip(t *testing.T) {
	for _, c := range []*Control{{}, fullControl()} {
		raw, err := c.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if c.Size() != len(raw) {
			t.Fatalf("Size %d, encoding %d", c.Size(), len(raw))
		}
		got, err := DecodeControl(raw, len(raw))
		if err != nil {
			t.Fatal(err)
		}
		again, err := got.Encode()
		if err != nil || !bytes.Equal(again, raw) {
			t.Fatalf("re-encoding differs: %v", err)
		}
	}
	if got, _ := DecodeControl(make([]byte, 8), 8); !got.Empty() {
		t.Fatal("eight zero counts are not empty")
	}
	if fullControl().Empty() {
		t.Fatal("full control reported empty")
	}
}

func TestControlEncodeErrors(t *testing.T) {
	for _, ap := range []string{"[::1]:1", "[::ffff:1.2.3.4]:1", "1.2.3.4:0"} {
		c := &Control{Prune: []Prune{{PX: []PeerRecord{{Addr: netip.MustParseAddrPort(ap)}}}}}
		if _, err := c.Encode(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", ap, err)
		}
	}
	if _, err := (&Control{Prune: []Prune{{PX: []PeerRecord{{}}}}}).Encode(); !errors.Is(err, ErrInvalid) {
		t.Errorf("zero address: %v", err)
	}
	for _, n := range []int{0, MaxCertSize + 1} {
		if _, err := (&Control{Cert: [][]byte{make([]byte, n)}}).Encode(); !errors.Is(err, ErrInvalid) {
			t.Errorf("certificate of %d bytes: %v", n, err)
		}
	}
}

// encodeRaw builds control bytes field by field so that tests can place invalid values.
func encodeRaw(f func(e *kolocodec.Encoder)) []byte {
	var e kolocodec.Encoder
	f(&e)
	return e.Bytes()
}

func zeros(e *kolocodec.Encoder, n int) {
	for range n {
		e.PutUvarint(0)
	}
}

func TestDecodeControlErrors(t *testing.T) {
	topic := make([]byte, 32)
	cases := []struct {
		name string
		in   []byte
		want []error
	}{
		{"empty", nil, []error{ErrMalformed, kolocodec.ErrShortBuffer}},
		{"seven counts", make([]byte, 7), []error{ErrMalformed, kolocodec.ErrShortBuffer}},
		{"trailing byte", make([]byte, 9), []error{ErrMalformed, kolocodec.ErrTrailingBytes}},
		{"non-canonical count", append([]byte{0x80, 0}, make([]byte, 7)...), []error{ErrMalformed, kolocodec.ErrNonCanonical}},
		{"sub count over input", encodeRaw(func(e *kolocodec.Encoder) { e.PutUvarint(1); zeros(e, 7) }), []error{ErrMalformed, kolocodec.ErrTooLarge}},
		{"sub bool 2", encodeRaw(func(e *kolocodec.Encoder) {
			e.PutUvarint(1)
			e.PutFixed(topic)
			e.PutFixed([]byte{2})
			zeros(e, 7)
		}), []error{ErrMalformed, kolocodec.ErrNonCanonical}},
		{"graft count over input", encodeRaw(func(e *kolocodec.Encoder) { zeros(e, 1); e.PutUvarint(1); zeros(e, 6) }), []error{ErrMalformed, kolocodec.ErrTooLarge}},
		{"prune count over input", encodeRaw(func(e *kolocodec.Encoder) { zeros(e, 2); e.PutUvarint(1); zeros(e, 5) }), []error{ErrMalformed, kolocodec.ErrTooLarge}},
		{"prune backoff overflow", encodeRaw(func(e *kolocodec.Encoder) {
			zeros(e, 2)
			e.PutUvarint(1)
			e.PutFixed(topic)
			e.PutFixed(bytes.Repeat([]byte{0xff}, 10))
			zeros(e, 6)
		}), []error{ErrMalformed, kolocodec.ErrTooLarge}},
		{"px port 0", encodeRaw(func(e *kolocodec.Encoder) {
			zeros(e, 2)
			e.PutUvarint(1)
			e.PutFixed(topic)
			e.PutUvarint(0)
			e.PutUvarint(1)
			e.PutFixed(make([]byte, 36))
			e.PutUvarint(0)
			zeros(e, 5)
		}), []error{ErrMalformed}},
		{"px port over 65535", encodeRaw(func(e *kolocodec.Encoder) {
			zeros(e, 2)
			e.PutUvarint(1)
			e.PutFixed(topic)
			e.PutUvarint(0)
			e.PutUvarint(1)
			e.PutFixed(make([]byte, 36))
			e.PutUvarint(1 << 16)
			zeros(e, 5)
		}), []error{ErrMalformed, kolocodec.ErrTooLarge}},
		{"px short key", encodeRaw(func(e *kolocodec.Encoder) {
			zeros(e, 2)
			e.PutUvarint(1)
			e.PutFixed(topic)
			e.PutUvarint(0)
			e.PutUvarint(1)
			e.PutFixed(make([]byte, 30))
		}), []error{ErrMalformed}},
		{"ihave count over input", encodeRaw(func(e *kolocodec.Encoder) { zeros(e, 3); e.PutUvarint(1); zeros(e, 4) }), []error{ErrMalformed, kolocodec.ErrTooLarge}},
		{"ihave ids over input", encodeRaw(func(e *kolocodec.Encoder) {
			zeros(e, 3)
			e.PutUvarint(1)
			e.PutFixed(topic)
			e.PutUvarint(2)
			e.PutFixed(make([]byte, 32))
			zeros(e, 4)
		}), []error{ErrMalformed, kolocodec.ErrTooLarge}},
		{"iwant count over input", encodeRaw(func(e *kolocodec.Encoder) { zeros(e, 4); e.PutUvarint(1); zeros(e, 3) }), []error{ErrMalformed, kolocodec.ErrTooLarge}},
		{"idontwant short id", encodeRaw(func(e *kolocodec.Encoder) {
			zeros(e, 5)
			e.PutUvarint(1)
			e.PutFixed(make([]byte, 33))
		}), []error{ErrMalformed}},
		{"certwant count over input", encodeRaw(func(e *kolocodec.Encoder) {
			zeros(e, 6)
			e.PutUvarint(1)
			e.PutFixed(make([]byte, 40))
		}), []error{ErrMalformed, kolocodec.ErrTooLarge}},
		{"empty cert", encodeRaw(func(e *kolocodec.Encoder) { zeros(e, 7); e.PutUvarint(1); e.PutUvarint(0); e.PutUvarint(0) }), []error{ErrMalformed}},
		{"cert over 514", encodeRaw(func(e *kolocodec.Encoder) { zeros(e, 7); e.PutUvarint(1); e.PutBytes(make([]byte, MaxCertSize+1)) }), []error{ErrMalformed, kolocodec.ErrTooLarge}},
	}
	for _, c := range cases {
		_, err := DecodeControl(c.in, 1<<20)
		if err == nil {
			t.Errorf("%s: no error", c.name)
			continue
		}
		for _, w := range c.want {
			if !errors.Is(err, w) {
				t.Errorf("%s: %v, want %v", c.name, err, w)
			}
		}
	}
	raw, _ := fullControl().Encode()
	if _, err := DecodeControl(raw, len(raw)-1); !errors.Is(err, ErrTooLarge) {
		t.Errorf("over max: %v", err)
	}
	for i := range raw {
		if _, err := DecodeControl(raw[:i], len(raw)); err == nil {
			t.Fatalf("prefix of %d bytes decoded", i)
		}
	}
}

// TestDecodeControlBoundedAllocation checks that a count is bounded by the bytes left, never by its own value.
func TestDecodeControlBoundedAllocation(t *testing.T) {
	in := encodeRaw(func(e *kolocodec.Encoder) { zeros(e, 4); e.PutUvarint(1 << 40); zeros(e, 3) })
	allocs := testing.AllocsPerRun(10, func() {
		if _, err := DecodeControl(in, 1<<20); err == nil {
			t.Fatal("decoded")
		}
	})
	if allocs > 20 {
		t.Fatalf("%v allocations", allocs)
	}
}

func TestControlSizeHelpers(t *testing.T) {
	p := &Prune{Backoff: math.MaxUint64, PX: []PeerRecord{{Addr: netip.MustParseAddrPort("10.0.0.1:65535")}}}
	raw, err := (&Control{Prune: []Prune{*p}}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	if want := len(raw) - 8; PruneSize(p) != want {
		t.Fatalf("PruneSize %d, want %d", PruneSize(p), want)
	}
	raw, _ = (&Control{IHave: []IHave{{IDs: make([]ID, 200)}}}).Encode()
	if want := len(raw) - 8; IHaveSize(200) != want {
		t.Fatalf("IHaveSize %d, want %d", IHaveSize(200), want)
	}
}

// TestDecodeControlCerts: a frame of more certificates than allowed is refused before they are copied.
func TestDecodeControlCerts(t *testing.T) {
	c := &Control{Cert: [][]byte{{1}, {2}, {3}}}
	raw, err := c.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeControlCerts(raw, len(raw), 2); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("three certificates over two: %v", err)
	}
	if got, err := DecodeControlCerts(raw, len(raw), 3); err != nil || len(got.Cert) != 3 {
		t.Fatal(err)
	}
}

// TestItems: Items counts every list entry, IHAVE ids and PRUNE records included.
func TestItems(t *testing.T) {
	c := &Control{Subs: make([]Sub, 2), Prune: []Prune{{PX: make([]PeerRecord, 3)}}, IHave: []IHave{{IDs: make([]ID, 4)}}, Cert: [][]byte{{1}}}
	if n := c.Items(); n != 2+1+3+1+4+1 {
		t.Fatalf("%d items", n)
	}
}
