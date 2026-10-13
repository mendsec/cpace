# Contributing to cpace

cpace is Apache-2.0 and open to contributions. It is small on purpose: one
cipher suite, one setting of the draft, and nothing that is not checked
against the draft's test vectors.

## What fits

- Following a new revision of draft-irtf-cfrg-cpace, with its vectors.
- Another cipher suite of the draft, **with the draft's vectors for it** and
  group arithmetic from a maintained, reviewed library. Arithmetic written
  here is not accepted.
- Fixes, tests, fuzzing, documentation.

A change to what is hashed, sent or compared must cite the section of the
draft it follows.

## Contributor License Agreement

All contributors agree to these terms before a pull request is merged. They
are the same as in Fabrintek's other repositories, so a contributor agrees
once.

1. **Definitions**
   - *"You"* (or *"Contributor"*) means the copyright owner or legal entity
     authorized by the copyright owner submitting the Contribution.
   - *"Contribution"* means any source code, documentation, art assets, or
     other materials submitted via Git commit, pull request, or issue tracker
     to the project.
2. **Grant of Copyright License**: You hereby grant to the project maintainer
   (**Fabrintek Engenharia Digital Ltda**) a perpetual, worldwide,
   non-exclusive, no-charge, royalty-free, irrevocable copyright license to
   reproduce, prepare derivative works of, publicly display, publicly perform,
   sublicense, and distribute your Contributions and such derivative works.
3. **Grant of Patent License**: You hereby grant a perpetual, worldwide,
   non-exclusive, no-charge, royalty-free, irrevocable patent license to make,
   have made, use, offer to sell, sell, import, and otherwise transfer the
   Work, where such license applies only to those patent claims licensable by
   You that are necessarily infringed by Your Contribution(s).
4. **Originality & Authority**: You represent that each of Your Contributions
   is your original creation, and that you have the full legal right to grant
   the licenses set forth above. If your employer has rights to intellectual
   property that includes your Contributions, you represent that you have
   received permission to make Contributions on behalf of that employer.
5. **Open Source Commitment**: Contributions to cpace are published under the
   **Apache License 2.0**. Fabrintek commits to keeping cpace available under
   that licence or a compatible open-source successor.

## Sign-off is required

Every commit must carry a `Signed-off-by` trailer (the
[Developer Certificate of Origin](https://developercertificate.org/)):

```bash
git commit -s -m "fix: refuse a reply with trailing bytes"
```

CI checks it. The sign-off certifies where the code came from; the CLA above
is agreed by opening a pull request.

## Workflow

- Branch from `develop` and open the pull request against `develop`.
- `go test -race ./...`, `golangci-lint run` and the fuzz targets must pass.
- Releases are tagged from `main`.
