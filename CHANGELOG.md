# Changelog

All notable changes to `@attestto/vc-sdk` will be documented in this file.

This project adheres to [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-04-17

### Added
- **OID4VCI** (OpenID for Verifiable Credential Issuance): Pre-authorized code flow — create offers, exchange tokens, issue credentials.
- **OID4VP** (OpenID for Verifiable Presentations): Authorization request parsing, presentation submission building, response posting.
- **SD-JWT** (Selective Disclosure JWT): Issue SD-JWT VCs with per-claim disclosure, holder key binding, verifier selective reveal.
- 119 tests across OID4VCI, OID4VP, SD-JWT, and generic issuance/verification.

### Fixed
- Exports field ordering: `types` condition now comes before `import`/`require` for correct TypeScript resolution.

## [0.1.0] - 2026-04-12

### Added
- Initial release: Universal W3C VC v2.0 SDK.
- **VCIssuer:** Issue signed VCs with Ed25519 or ES256. Linked Data proofs and JWT format.
- **VCVerifier:** Structural validation, context routing, expiration checks, cryptographic signature verification.
- **Key management:** `generateKeyPair()`, `sign()`, `verify()`, base64url and hex utilities.
- Schema plugin interface (`issuer.use()`) for domain-specific context injection.
- Zero native dependencies.
- Dual ESM/CJS build via tsup.
