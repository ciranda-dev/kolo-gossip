// Package wire encodes and decodes kolo-gossip envelopes, control frames and stream headers with kolo-codec.
// Every value has one valid encoding and every length is checked before allocation.
package wire

import (
	"crypto/sha256"
	"errors"
	"fmt"

	kolocodec "github.com/ciranda-dev/kolo-codec"
)

// Field sizes and the envelope version.
const (
	KeySize = 32
	IDSize  = 32
	SigSize = 64
	Version = 0
)

// IDLabel is the domain label hashed in front of the envelope bytes to form a message id.
const IDLabel = "kolo-gossip/message-id/v0"

var (
	// ErrMalformed means the input is not a valid encoding: short, non-canonical, trailing bytes or a bad count.
	ErrMalformed = errors.New("kologossip: malformed frame")
	// ErrTooLarge means the input or a value is over its limit.
	ErrTooLarge = errors.New("kologossip: frame too large")
	// ErrVersion means the version is not one this package reads.
	ErrVersion = errors.New("kologossip: unknown version")
	// ErrKind means a stream header names an unknown stream kind.
	ErrKind = errors.New("kologossip: unknown stream kind")
	// ErrInvalid means a value cannot be encoded, such as a non-IPv4 address or an empty certificate.
	ErrInvalid = errors.New("kologossip: invalid value")
)

// Topic is a 32-byte topic id chosen by the application.
type Topic [32]byte

// Key is a 32-byte Ed25519 public key.
type Key [KeySize]byte

// ID is a message id: SHA-256 of IDLabel and the whole encoded envelope.
type ID [IDSize]byte

// Envelope is a signed gossip message as its author sent it.
type Envelope struct {
	Topic  Topic
	Person Key
	Device Key
	Seq    uint64
	Time   uint64 // author's Unix milliseconds
	Body   []byte
	Sig    [SigSize]byte
}

// Signed returns the bytes the author signs: the encoding without the signature.
func (e *Envelope) Signed() []byte {
	var enc kolocodec.Encoder
	e.putSigned(&enc)
	return enc.Bytes()
}

// Encode returns the canonical encoding of e.
func (e *Envelope) Encode() []byte {
	var enc kolocodec.Encoder
	e.putSigned(&enc)
	enc.PutFixed(e.Sig[:])
	return enc.Bytes()
}

func (e *Envelope) putSigned(enc *kolocodec.Encoder) {
	enc.PutUvarint(Version)
	enc.PutFixed(e.Topic[:])
	enc.PutFixed(e.Person[:])
	enc.PutFixed(e.Device[:])
	enc.PutUvarint(e.Seq)
	enc.PutUvarint(e.Time)
	enc.PutBytes(e.Body)
}

// DecodeEnvelope decodes an envelope of at most limit bytes; the signature is the last SigSize bytes.
func DecodeEnvelope(b []byte, limit int) (*Envelope, error) {
	if len(b) > limit {
		return nil, fmt.Errorf("%w: envelope of %d bytes over %d", ErrTooLarge, len(b), limit)
	}
	d := kolocodec.NewDecoder(b)
	v, err := d.Uvarint()
	if err != nil {
		return nil, malformed(err)
	}
	if v != Version {
		return nil, fmt.Errorf("%w: envelope version %d", ErrVersion, v)
	}
	e := new(Envelope)
	for _, f := range [][]byte{e.Topic[:], e.Person[:], e.Device[:]} {
		if err := fixed(d, f); err != nil {
			return nil, err
		}
	}
	if e.Seq, err = d.Uvarint(); err != nil {
		return nil, malformed(err)
	}
	if e.Time, err = d.Uvarint(); err != nil {
		return nil, malformed(err)
	}
	if e.Body, err = d.Bytes(limit); err != nil {
		return nil, malformed(err)
	}
	if err := fixed(d, e.Sig[:]); err != nil {
		return nil, err
	}
	if err := d.Done(); err != nil {
		return nil, malformed(err)
	}
	return e, nil
}

// EnvelopeTopic returns the topic field of encoded envelope bytes without decoding the rest.
func EnvelopeTopic(b []byte) (Topic, bool) {
	var t Topic
	if len(b) < 1+len(t) || b[0] != Version {
		return t, false
	}
	copy(t[:], b[1:])
	return t, true
}

// NewID returns the message id of encoded envelope bytes.
func NewID(raw []byte) ID {
	h := sha256.New()
	h.Write([]byte(IDLabel))
	h.Write(raw)
	var id ID
	h.Sum(id[:0])
	return id
}

func fixed(d *kolocodec.Decoder, dst []byte) error {
	b, err := d.Fixed(len(dst))
	if err != nil {
		return malformed(err)
	}
	copy(dst, b)
	return nil
}

func malformed(err error) error {
	return fmt.Errorf("%w: %w", ErrMalformed, err)
}
