# Changelog

All notable changes to `@attestto/vc-sdk` will be documented in this file.

This project adheres to [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-07-19

Security release. Verification was fail-open (an unsigned or unresolvable credential could report `valid: true`) and did not bind the signature to the credential issuer (a credential could claim a trusted `issuer` while being signed by an attacker's unrelated key). Both are now closed, fail-closed by default.

### Security
- **Issuer binding (SOC-32).** `verify()` now requires that at least one valid proof is bound to the credential issuer — the proof's `verificationMethod` DID equals `credential.issuer`, or an optional `VerifierConfig.verifyIssuerBinding(issuer, verificationMethod)` hook authorizes it (for DID-document `assertionMethod` delegation). Every proof must still verify cryptographically; multi-party co-signers from other DIDs remain supported. Blocks the "claim a trusted issuer, sign with your own key" forgery.
- **Fail-closed verification (SOC-35).** A missing proof, missing resolver, unresolvable key, or bad signature now produces an **error** (not a warning), so `valid` can never be `true` for an unverifiable credential.

### Added
- `VerificationResult.signatureVerified: boolean` — whether a cryptographic proof was actually verified (distinct from structural validity).
- `VerifyOptions.requireSignature?: boolean` (default `true`) — opt-out only for explicit structural-only checks.
- `VerifierConfig.verifyIssuerBinding?` hook for delegated-key (`assertionMethod`) issuer authorization.

### Changed
- **BREAKING (verification semantics):** `valid: true` now requires a verified signature bound to the issuer. Two consumer impacts:
  - Callers that relied on the fail-open path (proof present, no resolver → `valid: true`) must now supply a resolver or set `requireSignature: false`.
  - **Delegated signing keys:** if a credential's `verificationMethod` DID differs from its `issuer` DID (e.g. issuer `did:web:x` signing with a separate `assertionMethod` key), you MUST provide `verifyIssuerBinding` — otherwise the default direct-binding check rejects it. Downstream (`cr-vc-sdk`, `attestto-app`) must wire this hook if they use delegated keys.

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
