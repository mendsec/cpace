# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-10-13

### Added
- CPace, draft-irtf-cfrg-cpace-21, cipher suite CPACE-RISTRETTO255-SHA512,
  initiator-responder setting, with the explicit key confirmation of
  section 10.4: `NewInitiator`, `NewResponder`, `Initiator.Finish`,
  `Responder.Finish`.
- Tests against the draft's appendices A.1 and B.3, including a whole
  exchange that ends in the draft's ISK; fuzz targets for both parsers.
