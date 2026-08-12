# Changelog

All notable changes to `@attestto/vc-sdk` will be documented in this file.

This project adheres to [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-08-11

Security release. The verifier substituted `#key-1` when a proof's `verificationMethod` carried no key fragment, so a proof that named no key at all was checked against a key the **verifier** picked. If the subject's DID Document happened to contain a `#key-1`, an unbound proof verified against it. On the signing side, `keyId` defaulted to `#key-1` for a DID of any method, producing well-formed credentials and presentations that named a verification method the signer's own document does not contain. Both halves now refuse instead of guessing.

### Security
- **The verifier no longer chooses the key (SOC-174).** `checkProofs` previously read `hashIdx > 0 ? vm.substring(hashIdx) : '#key-1'`. A `verificationMethod` with no fragment now fails the `proof.verificationMethod` check and is rejected **before key resolution is attempted**, so the resolver is never asked for a key the proof did not name. Which key signed a credential is the proof's statement to make, not the verifier's to fill in.

### Changed
- **BREAKING (signer): `keyId` is now required** on `IssuerConfig`, `PresentationOptions` and `ProofOptions`, and must be a fragment starting with `#`. It previously defaulted to `#key-1`.
  - `new VCIssuer({ did, privateKey })` now throws. Pass the fragment the key actually has: `new VCIssuer({ did, privateKey, keyId: '#solana-key' })`.
  - `buildPresentation()` and `buildProofJwt()` throw for the same reason. `buildPresentation()` still reports zero credentials first, so that error is unchanged.
  - `#key-1` is one DID method's convention, not a universal fragment. `did:sns` names its owner key `#solana-key` (method specification section 8.5), `did:key` and `did:jwk` use `#0`, and a `did:web` document names whatever it names. There is no method for which the old default was correct.

### Notes
- No downstream repo is affected on upgrade alone: `attestto-desktop` and `attestto-mobile` pin `@attestto/vc-sdk@0.2.0` and `attestto-app` ranges `^0.2.0`, none of which resolve to `0.4.0`. Each must pass `keyId` when it upgrades.
- This release does not make the SDK read the fragment from a resolved DID Document. It removes the guess and requires the caller, which holds the key, to state its id. Reading `verificationMethod` out of a resolved document remains the consumer's job.
- 164 tests pass. The 9 added in `tests/key-fragment.test.ts` cover both halves; the verifier case asserts that resolution is never **attempted** for a fragment-less proof, because asserting only `valid: false` would pass with the defect present (the fixture signature is invalid either way).

## [0.3.0] - 2026-07-19

Security release. Verification was fail-open (an unsigned or unresolvable credential could report `valid: true`) and did not bind the signature to the credential issuer (a credential could claim a trusted `issuer` while being signed by an attacker's unrelated key). Both are now closed, fail-closed by default.

### Security
- **Issuer binding (SOC-32).** `verify()` now requires that at least one valid proof is bound to the credential issuer: the proof's `verificationMethod` DID equals `credential.issuer`, or an optional `VerifierConfig.verifyIssuerBinding(issuer, verificationMethod)` hook authorizes it (for DID-document `assertionMethod` delegation). Every proof must still verify cryptographically; multi-party co-signers from other DIDs remain supported. Blocks the "claim a trusted issuer, sign with your own key" forgery.
- **Fail-closed verification (SOC-35).** A missing proof, missing resolver, unresolvable key, or bad signature now produces an **error** (not a warning), so `valid` can never be `true` for an unverifiable credential.

### Added
- `VerificationResult.signatureVerified: boolean`, reporting whether a cryptographic proof was actually verified (distinct from structural validity).
- `VerifyOptions.requireSignature?: boolean` (default `true`), an opt-out only for explicit structural-only checks.
- `VerifierConfig.verifyIssuerBinding?` hook for delegated-key (`assertionMethod`) issuer authorization.

### Changed
- **BREAKING (verification semantics):** `valid: true` now requires a verified signature bound to the issuer. Two consumer impacts:
  - Callers that relied on the fail-open path (proof present, no resolver → `valid: true`) must now supply a resolver or set `requireSignature: false`.
  - **Delegated signing keys:** if a credential's `verificationMethod` DID differs from its `issuer` DID (e.g. issuer `did:web:x` signing with a separate `assertionMethod` key), you MUST provide `verifyIssuerBinding`, otherwise the default direct-binding check rejects it. Downstream (`cr-vc-sdk`, `attestto-app`) must wire this hook if they use delegated keys.

## [0.2.0] - 2026-04-17

### Added
- **OID4VCI** (OpenID for Verifiable Credential Issuance): Pre-authorized code flow: create offers, exchange tokens, issue credentials.
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
