# Security Policy

## Reporting a vulnerability

**Do not open a public issue.** Use GitHub's
[private vulnerability reporting](https://github.com/mendsec/cpace/security/advisories/new),
or email [security@fabrintek.com.br](mailto:security@fabrintek.com.br).

This package authenticates people who meet for the first time. A bug here
usually means someone in the middle getting in without the password, or
learning something that lets them test passwords offline. Treat anything that
touches the messages, the transcript or the confirmation tags as
security-sensitive.

Include what you have: the affected version or commit, what an attacker gains,
and a reproduction case if you have one. A report without a proof of concept
is still worth sending.

### What to expect

| Stage | Target |
| --- | --- |
| Acknowledgement | 3 working days |
| Initial assessment and severity | 10 working days |
| Fix or documented mitigation for a confirmed high/critical issue | 90 days |

Coordinated disclosure: please give the 90-day window before publishing. If a
fix is not shipping in that time, you are free to disclose. Reporters are
credited unless they ask not to be.

## Supported versions

| Version | Supported |
| --- | --- |
| `develop` (tip) | ✅ |
| latest `v0.x` tag | ✅ |
| older tags | fixes land on `develop`; no backports |

## Scope

In scope: deviations from draft-irtf-cfrg-cpace-21, message parsing,
confirmation, anything that leaks the password or lets an exchange succeed
without it. Weaknesses in the draft itself belong to the CFRG
(cfrg@ietf.org); in ristretto255 or edwards25519, to those projects.
