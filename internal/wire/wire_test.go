package wire

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"

	kolocodec "github.com/ciranda-dev/kolo-codec"
)

const testMax = 1 << 20

func testEnvelope(body []byte) *Envelope {
	e := &Envelope{Seq: 1_800_000_000_000_000_000, Time: 1_800_000_000_000, Body: body}
	for i := range 32 {
		e.Topic[i] = byte(i)
		e.Person[i] = byte(i + 32)
		e.Device[i] = byte(i + 64)
	}
	for i := range e.Sig {
		e.Sig[i] = byte(i + 96)
	}
	return e
}

func TestEnvelopeRoundTrip(t *testing.T) {
	for _, body := range [][]byte{nil, {1}, bytes.Repeat([]byte{7}, 300)} {
		e := testEnvelope(body)
		raw := e.Encode()
		got, err := DecodeEnvelope(raw, testMax)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got.Encode(), raw) {
			t.Fatal("re-encoding differs")
		}
		if got.Topic != e.Topic || got.Person != e.Person || got.Device != e.Device || got.Seq != e.Seq ||
			got.Time != e.Time || !bytes.Equal(got.Body, e.Body) || got.Sig != e.Sig {
			t.Fatalf("fields differ: %+v", got)
		}
		if !bytes.Equal(raw[:len(raw)-SigSize], e.Signed()) {
			t.Fatal("signed bytes are not the encoding without the signature")
		}
	}
}

// TestEnvelopeSizes: 177 to 179 bytes of overhead for 2026 times and UnixNano sequences, 169 with a one-byte
// sequence number.
func TestEnvelopeSizes(t *testing.T) {
	for _, c := range []struct{ body, overhead int }{
		{0, 177}, {127, 177}, {128, 178}, {16383, 178}, {16384, 179}, {testMax - 179, 179},
	} {
		raw := testEnvelope(make([]byte, c.body)).Encode()
		if got := len(raw) - c.body; got != c.overhead {
			t.Errorf("body %d: overhead %d, want %d", c.body, got, c.overhead)
		}
	}
	if raw := testEnvelope(make([]byte, testMax-179)).Encode(); len(raw) != testMax {
		t.Fatalf("largest body gives %d bytes", len(raw))
	}
	if _, err := DecodeEnvelope(testEnvelope(make([]byte, testMax-178)).Encode(), testMax); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("one byte over the max: %v", err)
	}
	small := testEnvelope(nil)
	small.Seq = 1
	if got := len(small.Encode()); got != 169 {
		t.Fatalf("a one-byte sequence number gives %d bytes of overhead, want 169", got)
	}
}

func TestNewID(t *testing.T) {
	raw := testEnvelope([]byte("hi")).Encode()
	want := sha256.Sum256(append([]byte("kolo-gossip/message-id/v0"), raw...))
	if NewID(raw) != ID(want) {
		t.Fatal("id is not SHA-256 of the label and the envelope")
	}
	other := bytes.Clone(raw)
	other[len(other)-1] ^= 1
	if NewID(other) == NewID(raw) {
		t.Fatal("a changed signature kept the id")
	}
}

func TestEnvelopeTopic(t *testing.T) {
	e := testEnvelope(nil)
	got, ok := EnvelopeTopic(e.Encode())
	if !ok || got != e.Topic {
		t.Fatal("topic not read")
	}
	if _, ok := EnvelopeTopic(e.Encode()[:32]); ok {
		t.Fatal("short input read")
	}
	if _, ok := EnvelopeTopic(append([]byte{1}, e.Encode()[1:]...)); ok {
		t.Fatal("other version read")
	}
}

func TestDecodeEnvelopeErrors(t *testing.T) {
	raw := testEnvelope([]byte("body")).Encode()
	seqAt := 1 + 96
	var overflow kolocodec.Encoder
	overflow.PutFixed(raw[:seqAt])
	overflow.PutFixed([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02})
	cases := []struct {
		name string
		in   []byte
		max  int
		want []error
	}{
		{"over max", raw, len(raw) - 1, []error{ErrTooLarge}},
		{"empty", nil, testMax, []error{ErrMalformed, kolocodec.ErrShortBuffer}},
		{"non-canonical version", append([]byte{0x80, 0x00}, raw[1:]...), testMax, []error{ErrMalformed, kolocodec.ErrNonCanonical}},
		{"version 1", append([]byte{1}, raw[1:]...), testMax, []error{ErrVersion}},
		{"short topic", raw[:20], testMax, []error{ErrMalformed, kolocodec.ErrShortBuffer}},
		{"short device", raw[:80], testMax, []error{ErrMalformed, kolocodec.ErrShortBuffer}},
		{"short seq", raw[:seqAt+3], testMax, []error{ErrMalformed, kolocodec.ErrShortBuffer}},
		{"seq overflow", overflow.Bytes(), testMax, []error{ErrMalformed, kolocodec.ErrTooLarge}},
		{"short time", raw[:seqAt+9+2], testMax, []error{ErrMalformed, kolocodec.ErrShortBuffer}},
		{"short body", raw[:seqAt+9+6+2], testMax, []error{ErrMalformed, kolocodec.ErrShortBuffer}},
		{"short signature", raw[:len(raw)-1], testMax, []error{ErrMalformed, kolocodec.ErrShortBuffer}},
		{"trailing byte", append(bytes.Clone(raw), 0), testMax, []error{ErrMalformed, kolocodec.ErrTrailingBytes}},
	}
	for _, c := range cases {
		_, err := DecodeEnvelope(c.in, c.max)
		for _, w := range c.want {
			if !errors.Is(err, w) {
				t.Errorf("%s: %v, want %v", c.name, err, w)
			}
		}
	}
	bodyLen := bytes.Clone(raw)
	bodyLen[seqAt+9+6] = 0x7f
	if _, err := DecodeEnvelope(bodyLen, testMax); !errors.Is(err, ErrMalformed) {
		t.Errorf("body length past the end: %v", err)
	}
}
