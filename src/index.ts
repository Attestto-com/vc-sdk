/**
 * @attestto/vc-sdk
 *
 * Universal SDK for issuing and verifying W3C Verifiable Credentials.
 * Works with any schema — plug in domain-specific types via SchemaPlugin.
 *
 * Domain schemas (plug-and-play):
 *   cr-vc-schemas  — Costa Rica driving ecosystem
 *   (future) cr-banking-schemas, cr-health-schemas, cr-education-schemas, etc.
 */

export { VCIssuer } from './issuer.js'
export { VCVerifier } from './verifier.js'
export type { PublicKeyResolver, VerifierConfig } from './verifier.js'
export { generateKeyPair, sign, verify, toBase64url, fromBase64url, toHex } from './keys.js'
export type { KeyPair } from './keys.js'
export type {
  VerifiableCredential,
  CredentialStatus,
  Proof,
  IssuerConfig,
  IssueOptions,
  VerificationResult,
  VerificationCheck,
  VerifyOptions,
  SchemaPlugin,
} from './types.js'
