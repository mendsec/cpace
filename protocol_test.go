// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Fabrintek Engenharia Digital Ltda

package cpace

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func cfg(prs, ad string) Config {
	return Config{PRS: []byte(prs), CI: []byte("cpace test"), SID: []byte("0123456789abcdef"), AD: []byte(ad)}
}

// run carries the three messages between a and b directly.
func run(t *testing.T, a, b Config) (Result, Result, error, error) {
	t.Helper()
	ini, start, err := NewInitiator(a)
	if err != nil {
		t.Fatal(err)
	}
	res, reply, err := NewResponder(b, start)
	if err != nil {
		return Result{}, Result{}, nil, err
	}
	confirm, ra, errA := ini.Finish(reply)
	if errA != nil {
		_, errB := res.Finish(nil)
		return ra, Result{}, errA, errB
	}
	rb, errB := res.Finish(confirm)
	return ra, rb, errA, errB
}

// The whole exchange, with the draft's scalars, gives the draft's messages
// and ISK (appendix B.3.2 to B.3.5).
func TestTheExchangeReproducesTheDraftsISK(t *testing.T) {
	defer func(r io.Reader) { randReader = r }(randReader)
	randReader = bytes.NewReader(append(unhex(t, vecYa), unhex(t, vecYb)...))

	a := Config{PRS: vecPRS, CI: vecCI, SID: unhex(t, vecSid), AD: vecADa}
	b := Config{PRS: vecPRS, CI: vecCI, SID: unhex(t, vecSid), AD: vecADb}
	ini, start, err := NewInitiator(a)
	if err != nil {
		t.Fatal(err)
	}
	wantYa := unhex(t, "d6bac480f2c386c394efc7c47adb9925dcd2630b64f240c50f8d0eec482b9157")
	if want := append([]byte{tagStart}, lvCat(wantYa, vecADa)...); !bytes.Equal(start, want) {
		t.Fatalf("start = %x, want %x", start, want)
	}
	res, reply, err := NewResponder(b, start)
	if err != nil {
		t.Fatal(err)
	}
	confirm, ra, err := ini.Finish(reply)
	if err != nil {
		t.Fatal(err)
	}
	rb, err := res.Finish(confirm)
	if err != nil {
		t.Fatal(err)
	}
	want := unhex(t, `b69effbf61b51d56401c0f65601abe428de8206feaaf0e32198896dc
		ae7b35cd2b38950a39dfd5d4a79164614c2984f7daa460b588c1e80c
		3fa2068af7900447`)
	if !bytes.Equal(ra.ISK, want) || !bytes.Equal(rb.ISK, want) {
		t.Errorf("ISK = %x and %x, want %x", ra.ISK, rb.ISK, want)
	}
	if !bytes.Equal(ra.PeerAD, vecADb) || !bytes.Equal(rb.PeerAD, vecADa) {
		t.Errorf("PeerAD = %q and %q", ra.PeerAD, rb.PeerAD)
	}
}

func TestTheSamePasswordAgrees(t *testing.T) {
	ra, rb, errA, errB := run(t, cfg("5071", "alice"), cfg("5071", "bob"))
	if errA != nil || errB != nil {
		t.Fatalf("the exchange failed: %v, %v", errA, errB)
	}
	if len(ra.ISK) != 64 || !bytes.Equal(ra.ISK, rb.ISK) {
		t.Errorf("the ISKs differ: %x, %x", ra.ISK, rb.ISK)
	}
	if string(ra.PeerAD) != "bob" || string(rb.PeerAD) != "alice" {
		t.Errorf("PeerAD = %q, %q", ra.PeerAD, rb.PeerAD)
	}
	ra2, _, _, _ := run(t, cfg("5071", "alice"), cfg("5071", "bob"))
	if bytes.Equal(ra.ISK, ra2.ISK) {
		t.Error("two runs gave the same ISK")
	}
}

func TestEmptyAssociatedDataAndSessionWork(t *testing.T) {
	a, b := Config{PRS: []byte("pw")}, Config{PRS: []byte("pw")}
	if _, _, errA, errB := run(t, a, b); errA != nil || errB != nil {
		t.Fatalf("%v, %v", errA, errB)
	}
}

func TestAWrongPasswordFailsOnBothEnds(t *testing.T) {
	_, _, errA, errB := run(t, cfg("5071", "a"), cfg("5072", "b"))
	if !errors.Is(errA, ErrAuthFailed) {
		t.Errorf("the initiator got %v, want ErrAuthFailed", errA)
	}
	if errB == nil {
		t.Error("the responder accepted an exchange the initiator refused")
	}
}

func TestADifferentChannelOrSessionFails(t *testing.T) {
	a, b := cfg("5071", "a"), cfg("5071", "b")
	b.CI = []byte("another purpose")
	if _, _, errA, _ := run(t, a, b); !errors.Is(errA, ErrAuthFailed) {
		t.Errorf("a different CI gave %v", errA)
	}
	b = cfg("5071", "b")
	b.SID = []byte("fedcba9876543210")
	if _, _, errA, _ := run(t, a, b); !errors.Is(errA, ErrAuthFailed) {
		t.Errorf("a different SID gave %v", errA)
	}
}

// Associated data altered on the way is caught: it is in the transcript the
// tags cover.
func TestAlteredAssociatedDataIsRefused(t *testing.T) {
	a, b := cfg("5071", "alice"), cfg("5071", "bob")
	ini, start, _ := NewInitiator(a)
	_, reply, err := NewResponder(b, start)
	if err != nil {
		t.Fatal(err)
	}
	f, _ := parse(reply, tagReply, 3)
	forged := append([]byte{tagReply}, lvCat(f[0], []byte("mallory"), f[2])...)
	if _, _, err := ini.Finish(forged); !errors.Is(err, ErrAuthFailed) {
		t.Errorf("a reply with altered AD gave %v", err)
	}

	ini, start, _ = NewInitiator(a)
	f, _ = parse(start, tagStart, 2)
	swapped := append([]byte{tagStart}, lvCat(f[0], []byte("mallory"))...)
	res, reply, err := NewResponder(b, swapped)
	if err != nil {
		t.Fatal(err)
	}
	confirm, _, err := ini.Finish(reply)
	if !errors.Is(err, ErrAuthFailed) {
		t.Errorf("the initiator accepted a reply to an altered start: %v", err)
	}
	if _, err := res.Finish(confirm); err == nil {
		t.Error("the responder accepted a start whose AD was altered")
	}
}

// A man in the middle runs the exchange with each party under a guessed
// password. Without the right one, both parties fail.
func TestAManInTheMiddleWithoutThePasswordFails(t *testing.T) {
	a, b, m := cfg("5071", "alice"), cfg("5071", "bob"), cfg("1234", "mallory")
	ini, start, _ := NewInitiator(a)
	_, toA, err := NewResponder(m, start)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ini.Finish(toA); !errors.Is(err, ErrAuthFailed) {
		t.Errorf("the initiator accepted the middle: %v", err)
	}
	mi, toB, _ := NewInitiator(m)
	res, reply, err := NewResponder(b, toB)
	if err != nil {
		t.Fatal(err)
	}
	confirm, _, err := mi.Finish(reply)
	if !errors.Is(err, ErrAuthFailed) {
		t.Errorf("the middle passed the responder's tag with a wrong password: %v", err)
	}
	if _, err := res.Finish(confirm); err == nil {
		t.Error("the responder accepted the middle")
	}
}

func TestAConfirmationFromAnotherRunIsRefused(t *testing.T) {
	a, b := cfg("5071", "a"), cfg("5071", "b")
	ini1, start1, _ := NewInitiator(a)
	_, reply1, _ := NewResponder(b, start1)
	confirm1, _, err := ini1.Finish(reply1)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ini1.Finish(reply1); err == nil {
		t.Error("an initiator finished twice")
	}
	_, start2, _ := NewInitiator(a)
	res2, _, _ := NewResponder(b, start2)
	if _, err := res2.Finish(confirm1); !errors.Is(err, ErrAuthFailed) {
		t.Errorf("another run's confirmation gave %v", err)
	}
	if _, err := res2.Finish(confirm1); err == nil {
		t.Error("a responder finished twice")
	}
}

func TestTheIdentityElementIsRefused(t *testing.T) {
	start := append([]byte{tagStart}, lvCat(make([]byte, 32), []byte("a"))...)
	if _, _, err := NewResponder(cfg("5071", "b"), start); !errors.Is(err, ErrAuthFailed) {
		t.Errorf("a start with Ya = G.I gave %v", err)
	}
	ini, _, _ := NewInitiator(cfg("5071", "a"))
	reply := append([]byte{tagReply}, lvCat(make([]byte, 32), []byte("b"), make([]byte, macSize))...)
	if _, _, err := ini.Finish(reply); !errors.Is(err, ErrAuthFailed) {
		t.Errorf("a reply with Yb = G.I gave %v", err)
	}
}

func TestMalformedMessagesAreRefused(t *testing.T) {
	b := cfg("5071", "b")
	for _, msg := range [][]byte{
		nil,
		{tagReply},
		{tagStart},
		append([]byte{tagStart}, lvCat(make([]byte, 31), []byte("a"))...),
		append([]byte{tagStart}, lvCat(make([]byte, 32))...),
		append([]byte{tagStart}, lvCat(make([]byte, 32), nil, nil)...),
		append(append([]byte{tagStart}, lvCat(make([]byte, 32), []byte("a"))...), 0x05),
		{tagStart, 0xff, 0xff, 0xff, 0x7f},
		{tagStart, 0x80, 0x80, 0x08},
	} {
		if _, _, err := NewResponder(b, msg); !errors.Is(err, ErrMalformed) {
			t.Errorf("NewResponder(%x) = %v, want ErrMalformed", msg, err)
		}
	}
	ini, _, _ := NewInitiator(cfg("5071", "a"))
	if _, _, err := ini.Finish([]byte{tagConfirm}); !errors.Is(err, ErrMalformed) {
		t.Errorf("Finish(confirm) = %v, want ErrMalformed", err)
	}
}

func TestAConfigNeedsAPassword(t *testing.T) {
	if _, _, err := NewInitiator(Config{}); !errors.Is(err, ErrNoPassword) {
		t.Errorf("NewInitiator without a password: %v", err)
	}
	if _, _, err := NewResponder(Config{}, nil); !errors.Is(err, ErrNoPassword) {
		t.Errorf("NewResponder without a password: %v", err)
	}
	if _, _, err := NewInitiator(Config{PRS: []byte("pw"), AD: make([]byte, maxField+1)}); !errors.Is(err, ErrMalformed) {
		t.Errorf("oversized AD: %v", err)
	}
}

func FuzzNewResponder(f *testing.F) {
	f.Add([]byte{tagStart})
	_, start, _ := NewInitiator(cfg("5071", "a"))
	f.Add(start)
	f.Fuzz(func(_ *testing.T, msg []byte) {
		_, _, _ = NewResponder(cfg("5071", "b"), msg)
	})
}

func FuzzInitiatorFinish(f *testing.F) {
	_, start, _ := NewInitiator(cfg("5071", "a"))
	_, reply, _ := NewResponder(cfg("5071", "b"), start)
	f.Add(reply)
	f.Fuzz(func(t *testing.T, msg []byte) {
		i, _, _ := NewInitiator(cfg("5071", "a"))
		if _, _, err := i.Finish(msg); err == nil {
			t.Fatal("a fuzzed reply authenticated")
		}
	})
}
