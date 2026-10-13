<div align="center">

  <h1>cpace</h1>
  <p><strong>CPace, the balanced PAKE of draft-irtf-cfrg-cpace-21, in Go. Checked byte for byte against the draft's test vectors.</strong></p>

  [![Go Reference](https://pkg.go.dev/badge/github.com/mendsec/cpace.svg)](https://pkg.go.dev/github.com/mendsec/cpace)
  [![CI](https://github.com/mendsec/cpace/actions/workflows/ci.yml/badge.svg)](https://github.com/mendsec/cpace/actions/workflows/ci.yml)
  [![Security](https://github.com/mendsec/cpace/actions/workflows/security.yml/badge.svg)](https://github.com/mendsec/cpace/actions/workflows/security.yml)
  [![License](https://img.shields.io/github/license/mendsec/cpace)](LICENSE)
</div>

<br>

Two parties who share a short password — a code read out over the phone — agree on a strong key over a channel they do not trust. Someone in the middle gets **one guess per attempt**, learns **nothing it can test offline**, and makes the exchange **fail on both ends**.

```go
import "github.com/mendsec/cpace"
```

## Status

- **Specification:** [draft-irtf-cfrg-cpace-21](https://datatracker.ietf.org/doc/draft-irtf-cfrg-cpace/) (April 2026), cipher suite **CPACE-RISTRETTO255-SHA512**. CPace is a CFRG draft, not yet an RFC; when the draft changes, this package follows it, and the version says so.
- **Verification:** every step is checked against the draft's own test vectors (below). The code has **not had an independent audit**. Read it — it is short — before you rely on it.
- **API:** pre-1.0; it may change.

## Usage

```go
// The party who typed the code.
ini, start, err := cpace.NewInitiator(cpace.Config{
	PRS: []byte("5071"),                    // the shared password; never sent
	CI:  []byte("example.org support"),     // what this is for; never sent
	SID: sessionID,                         // unique to the session, known to both
	AD:  alicePublicKey,                    // sent, and authenticated
})

// The party who read it out.
res, reply, err := cpace.NewResponder(bobConfig, start)

// Back at the initiator: checks the responder's confirmation tag.
confirm, resultA, err := ini.Finish(reply) // cpace.ErrAuthFailed on a wrong code

// Back at the responder: checks the initiator's.
resultB, err := res.Finish(confirm)

// resultA.ISK == resultB.ISK; resultA.PeerAD is Bob's AD, resultB.PeerAD Alice's.
```

`start`, `reply` and `confirm` are opaque bytes: carry them over a WebSocket, a relay, a QR code, anything.

A typical use is **binding public keys at first contact**: each party puts its signing key in `AD`, and after `Finish` each knows the other's key came from whoever holds the same code. A carrier that swaps the keys makes the exchange fail. [remotekit](https://github.com/barahn/remotekit)'s `pake` package does exactly that for [Chirp](https://github.com/barahn/chirp).

### Using it well

- **Limit attempts and show every failure.** A 4-digit code gives an attacker one chance in 10,000 per attempt — a good bound only if attempts are bounded.
- **Identities:** put both in `CI` when both are known in advance (initiator first); otherwise put each party's own in its `AD` and check `PeerAD` (draft §10.1).
- **SID:** unique to the session and known to both, such as randomness both contributed (§10.9).
- **ISK:** run it through a KDF, such as HKDF, before use (§10.3).

## The exchange

The draft's initiator-responder setting, with the explicit key confirmation of §10.4:

```
initiator                                   responder
NewInitiator   -- start:   Ya, ADa  -->     NewResponder
               <-- reply:  Yb, ADb, Tb --
Finish         -- confirm: Ta       -->     Finish
```

| Value | Definition |
|---|---|
| generator `g` | ristretto255 one-way map of SHA-512(`generator_string(DSI, PRS, CI, SID)`) |
| `Ya`, `Yb` | `ya·g`, `yb·g`, with `y` sampled as the draft recommends (252 random bits) |
| `K` | `ya·Yb` = `yb·Ya`; the exchange aborts if `Y` does not decode or `K` is the identity |
| ISK | SHA-512(`lv_cat(DSI‖"_ISK", SID, K)` ‖ `transcript_ir(Ya, ADa, Yb, ADb)`) |
| `mac_key` | SHA-512(`"CPaceMac"` ‖ SID ‖ ISK) |
| `Ta`, `Tb` | HMAC-SHA-512(`mac_key`, `lv_cat(Y, AD)`) of each party's own message |

**Wire format:** one tag byte (`0x01` start, `0x02` reply, `0x03` confirm), then the fields, each prefixed with its length in LEB128 — the draft's own `lv_cat`. Fields are at most 64 KiB.

## Correctness

The tests reproduce the draft's appendices, byte for byte:

| Draft | What is checked |
|---|---|
| A.1.2, A.1.4 | `prepend_len` (LEB128, including the 127/128 boundary), `lv_cat` |
| B.3.1 | `generator_string`, its SHA-512, the generator |
| B.3.2, B.3.3 | `Ya`, `Yb` from the draft's scalars |
| B.3.4 | `K` on both sides |
| B.3.5 | `transcript_ir` and ISK |
| B.3.10, B.3.11 | `scalar_mult_vfy` on a valid point, a non-canonical encoding and the identity |

A whole exchange through the public API, with the draft's scalars, ends in the draft's ISK. Beyond the vectors, tests cover:

- a wrong password, CI or SID, failing on both ends;
- AD altered in either direction;
- a man in the middle running each side under its own guess;
- replayed confirmations;
- malformed messages.

Both entry points that read untrusted bytes are fuzzed.

## What it rests on

| | |
|---|---|
| Group | [`github.com/gtank/ristretto255`](https://github.com/gtank/ristretto255) — RFC 9496, BSD-3-Clause |
| Field and curve | [`filippo.io/edwards25519`](https://github.com/FiloSottile/edwards25519) — BSD-3-Clause |
| Hash, HMAC | Go's standard library |

This package does no arithmetic of its own, and all operations on secrets are constant-time in those libraries.

### Why another implementation

When this was written (October 2026), none of the Go implementations followed the current draft:

- **`bytemare/cpace`** builds the generator string and ISK differently and tests against vectors it generates itself.
- **`filippo.io/cpace`** follows draft-haase-cpace-01 (2020).
- **`schollz/pake`** is a SPAKE2 variant, not CPace.

The review is in [barahn/remotekit#96](https://github.com/barahn/remotekit/issues/96).

## Development

```bash
go test -race ./...
go test -run xxx -fuzz FuzzNewResponder -fuzztime 30s
golangci-lint run
```

The default branch is `develop`; releases are tagged from `main`. See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## License

Apache-2.0. Copyright © 2026 Fabrintek Engenharia Digital Ltda. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
