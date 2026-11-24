package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"

	kolocodec "github.com/ciranda-dev/kolo-codec"
)

// Kind is the kind of a gossip stream, written once after the version at its start.
type Kind byte

// The two stream kinds: control frames, and message frames (envelopes).
const (
	KindControl Kind = 'c'
	KindMessage Kind = 'm'
)

// Reader is what frames are read from, such as a *bufio.Reader.
type Reader interface {
	io.Reader
	io.ByteReader
}

// AppendStreamHeader appends the stream header: uvarint(Version) then the kind byte.
func AppendStreamHeader(dst []byte, k Kind) []byte {
	dst = binary.AppendUvarint(dst, Version)
	return append(dst, byte(k))
}

// ReadStreamHeader reads a stream header and returns its kind.
func ReadStreamHeader(r io.ByteReader) (Kind, error) {
	v, err := readUvarint(r)
	if err != nil {
		return 0, err
	}
	if v != Version {
		return 0, fmt.Errorf("%w: stream version %d", ErrVersion, v)
	}
	b, err := r.ReadByte()
	if err != nil {
		return 0, unexpected(err)
	}
	switch k := Kind(b); k {
	case KindControl, KindMessage:
		return k, nil
	default:
		return 0, fmt.Errorf("%w: %#x", ErrKind, b)
	}
}

// AppendFrame appends one frame: uvarint(len(body)) then body.
func AppendFrame(dst, body []byte) []byte {
	dst = binary.AppendUvarint(dst, uint64(len(body)))
	return append(dst, body...)
}

// ReadFrame reads one frame of at most limit bytes. The body grows only as its bytes arrive, so a large announced
// length costs memory only once it is sent. started, if not nil, runs once the first byte of the frame was read.
// It returns io.EOF only when the stream ends cleanly between frames.
func ReadFrame(r Reader, limit int, started func()) ([]byte, error) {
	b, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	if started != nil {
		started()
	}
	n, err := uvarintFrom(b, r)
	if err != nil {
		return nil, err
	}
	if limit < 0 || n > uint64(limit) {
		return nil, fmt.Errorf("%w: frame of %d bytes over %d", ErrTooLarge, n, limit)
	}
	body := make([]byte, 0, min(int(n), firstChunk))
	for len(body) < int(n) {
		if len(body) == cap(body) {
			body = slices.Grow(body, min(int(n)-len(body), len(body)))
		}
		k, err := r.Read(body[len(body):min(cap(body), int(n))])
		body = body[:len(body)+k]
		if err != nil && len(body) < int(n) {
			return nil, unexpected(err)
		}
	}
	return body, nil
}

// firstChunk is the buffer a frame body starts with: bufio's default size.
const firstChunk = 4096

func readUvarint(r io.ByteReader) (uint64, error) {
	b, err := r.ReadByte()
	if err != nil {
		return 0, unexpected(err)
	}
	return uvarintFrom(b, r)
}

// uvarintFrom reads the rest of a uvarint whose first byte is b and decodes it with kolo-codec's canonical rules.
func uvarintFrom(b byte, r io.ByteReader) (uint64, error) {
	buf := []byte{b}
	for b >= 0x80 && len(buf) < binary.MaxVarintLen64 {
		var err error
		if b, err = r.ReadByte(); err != nil {
			return 0, unexpected(err)
		}
		buf = append(buf, b)
	}
	d := kolocodec.NewDecoder(buf)
	v, err := d.Uvarint()
	if err != nil {
		return 0, malformed(err)
	}
	return v, nil
}

func unexpected(err error) error {
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}
