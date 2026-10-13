// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Fabrintek Engenharia Digital Ltda

// Package cpace implements CPace, the balanced password-authenticated key
// exchange of draft-irtf-cfrg-cpace-21, in its CPACE-RISTRETTO255-SHA512
// cipher suite.
//
// Two parties who share a low-entropy password -- a short code read out over
// the phone -- agree on a strong shared key over a channel they do not trust.
// Someone in the middle gets one guess at the password per attempt, learns
// nothing it can test offline, and makes the exchange fail on both ends.
//
// # The exchange
//
// This package runs the initiator-responder setting of the draft, with the
// explicit key confirmation of its section 10.4, in three messages:
//
//	initiator                                 responder
//	NewInitiator  -- start:   Ya, ADa  -->    NewResponder
//	              <-- reply:  Yb, ADb, Tb --
//	Finish        -- confirm: Ta       -->    Finish
//
// The messages are opaque bytes; carry them however you like. The password
// (PRS), the channel identifier (CI) and the session identifier (SID) never
// travel; the associated data (AD) travels in the clear and is authenticated.
// A party that finishes knows that the other holds the same PRS, CI and SID,
// and has the other's AD as it was sent. Confirmation tags are checked
// before anything is returned, so a wrong password fails on both ends: the
// initiator on the reply, the responder on the confirmation.
//
// # What it rests on
//
// The group is ristretto255 (RFC 9496) from github.com/gtank/ristretto255,
// on filippo.io/edwards25519; this package does no arithmetic of its own.
// Every step -- prepend_len, lv_cat, the generator string, the generator,
// Ya, Yb, K, transcript_ir, ISK, and the handling of invalid points -- is
// checked byte for byte against the draft's test vectors (appendices A.1
// and B.3), and so is a whole exchange run with the draft's scalars.
//
// # Using it well
//
//   - Limit attempts and show every failure: with a 4-digit password, each
//     attempt is one chance in 10,000 for an attacker.
//   - Put both parties' identities in CI when both know them in advance
//     (initiator first); otherwise put each party's identity, or public
//     key, in its own AD and check what Result.PeerAD says (section 10.1).
//   - Use a SID unique to the session that both parties know, such as
//     randomness both contributed (section 10.9).
//   - Run Result.ISK through a KDF before use (section 10.3).
package cpace
