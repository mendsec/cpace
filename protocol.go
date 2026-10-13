// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Fabrintek Engenharia Digital Ltda

package cpace

import (
	"crypto/hmac"
	"crypto/sha512"
	"crypto/subtle"
	"errors"

	"github.com/gtank/ristretto255"
)

// Errors a caller can act on.
var (
	// ErrAuthFailed means the other party did not prove it holds the same
	// password, channel identifier and session identifier: the password
	// was mistyped, or someone in the middle tried to take part. The two
	// cases cannot be told apart, on purpose.
	ErrAuthFailed = errors.New("cpace: the other party does not hold the same password")
	// ErrMalformed means a message is not one of this protocol's, or is
	// out of place.
	ErrMalformed = errors.New("cpace: malformed message")
	// ErrNoPassword means a Config has no password.
	ErrNoPassword = errors.New("cpace: no password")
)

// Config is one party's inputs. Both parties must give the same PRS, CI and
// SID, or the exchange fails as a wrong password does.
type Config struct {
	// PRS is the password-related string both parties share. It never
	// travels.
	PRS []byte
	// CI is the channel identifier: what this exchange is for, and the
	// parties' identities when both know them in advance, initiator first
	// (draft section 10.1). It is hashed, never sent.
	CI []byte
	// SID is the session identifier. It should be unique to the session
	// and known to both parties (draft section 10.9); it may be empty.
	SID []byte
	// AD is this party's associated data. It is sent in the clear and
	// authenticated: the other party learns it as Result.PeerAD only if
	// the exchange succeeds. A party's own identity or public key goes
	// here when CI cannot carry it.
	AD []byte
}

// Result is what a successful exchange gives each party.
type Result struct {
	// ISK is the 64-byte intermediate session key. Run it through a KDF
	// before use (draft section 10.3).
	ISK []byte
	// PeerAD is the other party's associated data, authenticated.
	PeerAD []byte
}

// Message tags. Each message starts with one, so that a message out of place
// is refused rather than misread.
const (
	tagStart   = 0x01 // initiator → responder: Ya, ADa
	tagReply   = 0x02 // responder → initiator: Yb, ADb, Tb
	tagConfirm = 0x03 // initiator → responder: Ta
)

// macSize is the length of a key-confirmation tag: HMAC-SHA-512.
const macSize = sha512.Size

// maxField bounds a field's length in a message, so that a message can
// never ask for more than it carries; associated data longer than this is
// refused.
const maxField = 1 << 16

// Initiator is the party that speaks first.
type Initiator struct {
	cfg  Config
	y    *ristretto255.Scalar
	ya   []byte
	done bool
}

// NewInitiator starts an exchange and returns the first message, for the
// responder.
func NewInitiator(cfg Config) (*Initiator, []byte, error) {
	if err := checkConfig(cfg); err != nil {
		return nil, nil, err
	}
	y, err := sampleScalar(randReader)
	if err != nil {
		return nil, nil, err
	}
	ya := scalarMult(y, calculateGenerator(cfg.PRS, cfg.CI, cfg.SID))
	msg := append([]byte{tagStart}, lvCat(ya, cfg.AD)...)
	return &Initiator{cfg: cfg, y: y, ya: ya}, msg, nil
}

// Finish reads the responder's reply. If the responder proves it holds the
// same password, Finish returns the last message, for the responder, and the
// result; otherwise ErrAuthFailed, and nothing is to be sent. An Initiator
// finishes once.
func (i *Initiator) Finish(reply []byte) ([]byte, Result, error) {
	if i.done {
		return nil, Result{}, ErrMalformed
	}
	i.done = true
	f, ok := parse(reply, tagReply, 3)
	if !ok || len(f[0]) != groupSizeBytes || len(f[2]) != macSize {
		return nil, Result{}, ErrMalformed
	}
	yb, adb, tb := f[0], f[1], f[2]
	key, err := isk(i.cfg.SID, scalarMultVfy(i.y, yb), i.ya, i.cfg.AD, yb, adb)
	if err != nil {
		return nil, Result{}, ErrAuthFailed
	}
	mk := macKey(i.cfg.SID, key)
	if !hmac.Equal(tb, tag(mk, yb, adb)) {
		return nil, Result{}, ErrAuthFailed
	}
	confirm := append([]byte{tagConfirm}, lvCat(tag(mk, i.ya, i.cfg.AD))...)
	return confirm, Result{ISK: key, PeerAD: clone(adb)}, nil
}

// Responder is the party that answers.
type Responder struct {
	ya, ada []byte
	mk, key []byte
	done    bool
}

// NewResponder answers the initiator's first message and returns the reply,
// for the initiator. The exchange is not authenticated until Finish accepts
// the initiator's confirmation.
func NewResponder(cfg Config, start []byte) (*Responder, []byte, error) {
	if err := checkConfig(cfg); err != nil {
		return nil, nil, err
	}
	f, ok := parse(start, tagStart, 2)
	if !ok || len(f[0]) != groupSizeBytes {
		return nil, nil, ErrMalformed
	}
	ya, ada := f[0], f[1]
	y, err := sampleScalar(randReader)
	if err != nil {
		return nil, nil, err
	}
	yb := scalarMult(y, calculateGenerator(cfg.PRS, cfg.CI, cfg.SID))
	key, err := isk(cfg.SID, scalarMultVfy(y, ya), ya, ada, yb, cfg.AD)
	if err != nil {
		return nil, nil, ErrAuthFailed
	}
	mk := macKey(cfg.SID, key)
	reply := append([]byte{tagReply}, lvCat(yb, cfg.AD, tag(mk, yb, cfg.AD))...)
	return &Responder{ya: clone(ya), ada: clone(ada), mk: mk, key: key}, reply, nil
}

// Finish reads the initiator's confirmation. It returns the result if the
// initiator proves it holds the same password, and ErrAuthFailed otherwise.
// A Responder finishes once; a second call fails.
func (r *Responder) Finish(confirm []byte) (Result, error) {
	if r.done {
		return Result{}, ErrMalformed
	}
	r.done = true
	f, ok := parse(confirm, tagConfirm, 1)
	if !ok || len(f[0]) != macSize {
		return Result{}, ErrMalformed
	}
	if !hmac.Equal(f[0], tag(r.mk, r.ya, r.ada)) {
		return Result{}, ErrAuthFailed
	}
	return Result{ISK: r.key, PeerAD: r.ada}, nil
}

func checkConfig(cfg Config) error {
	if len(cfg.PRS) == 0 {
		return ErrNoPassword
	}
	if len(cfg.AD) > maxField {
		return ErrMalformed
	}
	return nil
}

// macKey is the draft's key-confirmation key (section 10.4):
// H.hash(b"CPaceMac" || sid || ISK).
func macKey(sid, isk []byte) []byte {
	h := sha512.New()
	h.Write([]byte("CPaceMac"))
	h.Write(sid)
	h.Write(isk)
	return h.Sum(nil)
}

// tag is a key-confirmation tag over one party's message, as section 10.4
// has it: MAC(mac_key, lv_cat(Y, AD)).
func tag(macKey, y, ad []byte) []byte {
	m := hmac.New(sha512.New, macKey)
	m.Write(lvCat(y, ad))
	return m.Sum(nil)
}

// parse reads a message: its tag, then exactly n length-prefixed fields.
func parse(msg []byte, want byte, n int) ([][]byte, bool) {
	if len(msg) == 0 || msg[0] != want {
		return nil, false
	}
	rest := msg[1:]
	fields := make([][]byte, 0, n)
	for len(rest) > 0 {
		if len(fields) == n {
			return nil, false
		}
		l, used, ok := readLen(rest)
		if !ok || l > len(rest)-used {
			return nil, false
		}
		fields = append(fields, rest[used:used+l])
		rest = rest[used+l:]
	}
	return fields, len(fields) == n
}

// readLen reads a LEB128 length of at most maxField.
func readLen(b []byte) (n, used int, ok bool) {
	for i := 0; i < len(b) && i < 3; i++ {
		n |= int(b[i]&0x7f) << (7 * i)
		if b[i]&0x80 == 0 {
			return n, i + 1, n <= maxField
		}
	}
	return 0, 0, false
}

func clone(b []byte) []byte { return append([]byte(nil), b...) }

func subtleEqual(a, b []byte) bool { return subtle.ConstantTimeCompare(a, b) == 1 }
