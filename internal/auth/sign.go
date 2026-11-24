package auth

import (
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/ciranda-dev/kolo-gossip/internal/wire"
	koloid "github.com/ciranda-dev/kolo-id"
)

// Sign builds the envelope of body in topic t by dev, a device of person, at time at, signs its Signed bytes
// under Context and returns its encoding.
func Sign(dev *koloid.Identity, person ed25519.PublicKey, t wire.Topic, seq uint64, at time.Time, body []byte) ([]byte, error) {
	if dev == nil || len(person) != wire.KeySize {
		return nil, fmt.Errorf("%w: need an identity and a %d-byte person key", ErrInvalidArgument, wire.KeySize)
	}
	ms := at.UnixMilli()
	if ms < 0 {
		return nil, fmt.Errorf("%w: time before 1970", ErrInvalidArgument)
	}
	e := &wire.Envelope{Topic: t, Seq: seq, Time: uint64(ms), Body: body}
	copy(e.Person[:], person)
	copy(e.Device[:], dev.PublicKey())
	sig, err := dev.Sign(Context, e.Signed())
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidArgument, err)
	}
	copy(e.Sig[:], sig)
	return e.Encode(), nil
}
