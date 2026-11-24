package wire

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"testing"

	kolocodec "github.com/ciranda-dev/kolo-codec"
)

func TestStreamHeader(t *testing.T) {
	for _, k := range []Kind{KindControl, KindMessage} {
		h := AppendStreamHeader(nil, k)
		if !bytes.Equal(h, []byte{0, byte(k)}) {
			t.Fatalf("header %x", h)
		}
		got, err := ReadStreamHeader(bytes.NewReader(h))
		if err != nil || got != k {
			t.Fatalf("got %v, %v", got, err)
		}
	}
	cases := []struct {
		name string
		in   []byte
		want []error
	}{
		{"empty", nil, []error{io.ErrUnexpectedEOF}},
		{"no kind", []byte{0}, []error{io.ErrUnexpectedEOF}},
		{"version 1", []byte{1, 'c'}, []error{ErrVersion}},
		{"non-canonical version", []byte{0x80, 0, 'c'}, []error{ErrMalformed, kolocodec.ErrNonCanonical}},
		{"cut version", []byte{0x80}, []error{io.ErrUnexpectedEOF}},
		{"overflow version", bytes.Repeat([]byte{0xff}, 10), []error{ErrMalformed, kolocodec.ErrTooLarge}},
		{"unknown kind", []byte{0, 'x'}, []error{ErrKind}},
	}
	for _, c := range cases {
		_, err := ReadStreamHeader(bytes.NewReader(c.in))
		for _, w := range c.want {
			if !errors.Is(err, w) {
				t.Errorf("%s: %v, want %v", c.name, err, w)
			}
		}
	}
}

func TestFrames(t *testing.T) {
	var buf []byte
	bodies := [][]byte{{}, {1, 2, 3}, bytes.Repeat([]byte{9}, 300)}
	for _, b := range bodies {
		buf = AppendFrame(buf, b)
	}
	r := bufio.NewReader(bytes.NewReader(buf))
	for _, b := range bodies {
		got, err := ReadFrame(r, 300, nil)
		if err != nil || !bytes.Equal(got, b) {
			t.Fatalf("got %x, %v", got, err)
		}
	}
	if _, err := ReadFrame(r, 300, nil); err != io.EOF {
		t.Fatalf("clean end: %v", err)
	}
}

func TestReadFrameErrors(t *testing.T) {
	cases := []struct {
		name  string
		in    []byte
		limit int
		want  []error
	}{
		{"over max", AppendFrame(nil, make([]byte, 11)), 10, []error{ErrTooLarge}},
		{"negative max", AppendFrame(nil, nil), -1, []error{ErrTooLarge}},
		{"cut length", []byte{0x80}, 10, []error{io.ErrUnexpectedEOF}},
		{"cut body", []byte{5, 1, 2}, 10, []error{io.ErrUnexpectedEOF}},
		{"non-canonical length", []byte{0x81, 0, 1}, 10, []error{ErrMalformed, kolocodec.ErrNonCanonical}},
		{"overflow length", bytes.Repeat([]byte{0xff}, 11), 10, []error{ErrMalformed, kolocodec.ErrTooLarge}},
	}
	for _, c := range cases {
		_, err := ReadFrame(bufio.NewReader(bytes.NewReader(c.in)), c.limit, nil)
		for _, w := range c.want {
			if !errors.Is(err, w) {
				t.Errorf("%s: %v, want %v", c.name, err, w)
			}
		}
	}
}

// TestReadFrameChecksLengthFirst checks that an oversized frame is refused after its length prefix only.
func TestReadFrameChecksLengthFirst(t *testing.T) {
	in := AppendFrame(nil, make([]byte, 1<<20))
	r := bytes.NewReader(in)
	if _, err := ReadFrame(bufio.NewReaderSize(r, 16), 1<<10, nil); !errors.Is(err, ErrTooLarge) {
		t.Fatal(err)
	}
	if read := len(in) - r.Len(); read > 16 {
		t.Fatalf("read %d bytes of an oversized frame", read)
	}
}

// trickle hands out data one call at a time and records the largest buffer it was asked to fill.
type trickle struct {
	data    []byte
	largest int
}

func (t *trickle) Read(p []byte) (int, error) {
	t.largest = max(t.largest, len(p))
	if len(t.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, t.data[:min(len(t.data), 1000)])
	t.data = t.data[n:]
	return n, nil
}

func (t *trickle) ReadByte() (byte, error) {
	var b [1]byte
	if _, err := t.Read(b[:]); err != nil {
		return 0, err
	}
	return b[0], nil
}

// TestReadFrameGrows: a frame that announces 1 MiB and sends 10 bytes costs a buffer of at most 4 KiB; a frame
// that arrives in full is read whole; started runs once, after the first byte.
func TestReadFrameGrows(t *testing.T) {
	r := &trickle{data: append(AppendFrame(nil, make([]byte, 1<<20))[:4], make([]byte, 10)...)}
	calls := 0
	if _, err := ReadFrame(r, 2<<20, func() { calls++ }); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("cut frame: %v", err)
	}
	if r.largest > 4096 || calls != 1 {
		t.Fatalf("buffer of %d bytes for 10 bytes received, started %d times", r.largest, calls)
	}
	body := bytes.Repeat([]byte{7}, 100_000)
	r = &trickle{data: AppendFrame(nil, body)}
	got, err := ReadFrame(r, 1<<20, nil)
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("whole frame: %v", err)
	}
	if _, err := ReadFrame(&trickle{}, 10, func() { calls++ }); err != io.EOF || calls != 1 {
		t.Fatal("started ran before any byte")
	}
}
