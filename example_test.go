// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Fabrintek Engenharia Digital Ltda

package cpace_test

import (
	"bytes"
	"fmt"

	"github.com/mendsec/cpace"
)

func Example() {
	ci := []byte("example.org remote support")
	sid := []byte("3f6c9a1d2b7e4058")

	// The party who typed the code starts.
	alice := cpace.Config{PRS: []byte("5071"), CI: ci, SID: sid, AD: []byte("alice's public key")}
	ini, start, err := cpace.NewInitiator(alice)
	if err != nil {
		panic(err)
	}

	// The party who read it out answers. start, reply and confirm are what
	// travel between them.
	bob := cpace.Config{PRS: []byte("5071"), CI: ci, SID: sid, AD: []byte("bob's public key")}
	res, reply, err := cpace.NewResponder(bob, start)
	if err != nil {
		panic(err)
	}

	confirm, a, err := ini.Finish(reply)
	if err != nil {
		panic(err) // ErrAuthFailed: a wrong code, or someone in the middle
	}
	b, err := res.Finish(confirm)
	if err != nil {
		panic(err)
	}

	fmt.Println(bytes.Equal(a.ISK, b.ISK))
	fmt.Println(string(a.PeerAD))
	fmt.Println(string(b.PeerAD))
	// Output:
	// true
	// bob's public key
	// alice's public key
}
