# Notes for agents working in this repository

* **Default branch:** `develop`. Branch from it and open pull requests against it. Releases are tagged from `main`.
* **Sign-off:** every commit needs `git commit -s` (DCO); CI checks it.
* **Specification:** draft-irtf-cfrg-cpace-21. Anything that changes what is hashed, sent or compared must match the draft and keep `vectors_test.go` and `TestTheExchangeReproducesTheDraftsISK` passing. Never edit a test vector to make a test pass: the vectors are the draft's, not ours.
* **No arithmetic here.** Group operations come from `github.com/gtank/ristretto255`. Do not add field or curve code.
* **Licence headers:** every Go file starts with `// SPDX-License-Identifier: Apache-2.0` and `// Copyright (C) 2026 Fabrintek Engenharia Digital Ltda`.
