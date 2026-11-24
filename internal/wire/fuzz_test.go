package wire

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"testing"
)

func FuzzEnvelope(f *testing.F) {
	f.Add(testEnvelope(nil).Encode())
	f.Add(testEnvelope([]byte("hello")).Encode())
	f.Add([]byte{0})
	f.Fuzz(func(t *testing.T, raw []byte) {
		e, err := DecodeEnvelope(raw, 1<<16)
		if err != nil {
			if !errors.Is(err, ErrMalformed) && !errors.Is(err, ErrTooLarge) && !errors.Is(err, ErrVersion) {
				t.Fatalf("untyped error %v", err)
			}
			return
		}
		again := e.Encode()
		if !bytes.Equal(again, raw) {
			t.Fatal("decoded input does not re-encode to itself")
		}
		if NewID(again) != NewID(raw) {
			t.Fatal("id changed")
		}
		if tp, ok := EnvelopeTopic(raw); !ok || tp != e.Topic {
			t.Fatal("EnvelopeTopic disagrees")
		}
	})
}

func FuzzControlFrame(f *testing.F) {
	raw, _ := fullControl().Encode()
	f.Add(raw)
	f.Add(make([]byte, 8))
	f.Fuzz(func(t *testing.T, raw []byte) {
		c, err := DecodeControl(raw, 1<<16)
		if err != nil {
			if !errors.Is(err, ErrMalformed) && !errors.Is(err, ErrTooLarge) {
				t.Fatalf("untyped error %v", err)
			}
			return
		}
		again, err := c.Encode()
		if err != nil {
			t.Fatalf("decoded frame does not encode: %v", err)
		}
		if !bytes.Equal(again, raw) {
			t.Fatal("decoded input does not re-encode to itself")
		}
		if c.Size() != len(raw) {
			t.Fatalf("Size %d, input %d", c.Size(), len(raw))
		}
	})
}

func FuzzStreamHeader(f *testing.F) {
	f.Add(AppendFrame(AppendStreamHeader(nil, KindControl), []byte{1, 2}))
	f.Add(AppendStreamHeader(nil, KindMessage))
	f.Add([]byte{0x80, 0x80})
	f.Fuzz(func(t *testing.T, raw []byte) {
		r := bufio.NewReader(bytes.NewReader(raw))
		k, err := ReadStreamHeader(r)
		if err != nil {
			if !errors.Is(err, ErrMalformed) && !errors.Is(err, ErrVersion) && !errors.Is(err, ErrKind) &&
				!errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("untyped error %v", err)
			}
			return
		}
		out := AppendStreamHeader(nil, k)
		for {
			body, err := ReadFrame(r, 64, nil)
			if err == io.EOF {
				break
			}
			if err != nil {
				if !errors.Is(err, ErrMalformed) && !errors.Is(err, ErrTooLarge) && !errors.Is(err, io.ErrUnexpectedEOF) {
					t.Fatalf("untyped error %v", err)
				}
				return
			}
			out = AppendFrame(out, body)
		}
		if !bytes.Equal(out, raw) {
			t.Fatal("header and frames do not re-encode to the input")
		}
	})
}
