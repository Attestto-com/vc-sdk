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

// ── E2E Encryption (Chat) ──────────────────────────────────────────────────
export {
  edToX25519Public,
  edToX25519Private,
  generateX25519KeyPair,
  x25519SharedSecret,
  deriveChannelKey,
  buildNonce,
  encrypt,
  decrypt,
} from './crypto.js'
export type { X25519KeyPair } from './crypto.js'

// ── Chat Credential Schemas ────────────────────────────────────────────────
export {
  agreementSchema,
  presenceSchema,
  chatSchemas,
} from './chat-schemas.js'
export type {
  AgreementParty,
  AgreementTerm,
  ConversationRef,
  ReferencedAttachment,
  PresenceProof,
  AgreementSubject,
  PresenceSubject,
} from './chat-schemas.js'
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

// ── OpenID4VCI ───────────────────────────────────────────────────────────────

// Credential Offer
export {
  parseCredentialOffer,
  hasPreAuthorizedCode,
  hasAuthorizationCode,
  requiresTxCode,
  CredentialOfferError,
  PRE_AUTHORIZED_CODE_GRANT,
} from './oid4vci.js'
export type {
  CredentialOfferPayload,
  CredentialOfferGrants,
  GrantAuthorizationCode,
  GrantPreAuthorizedCode,
  TxCode,
  ParsedCredentialOffer,
} from './oid4vci.js'

// Token Endpoint
export {
  getIssuerMetadataUrl,
  parseIssuerMetadata,
  getTokenEndpoint,
  buildPreAuthorizedTokenRequest,
  buildAuthorizationCodeTokenRequest,
  encodeTokenRequest,
  parseTokenResponse,
  buildProofJwt,
  buildCredentialRequest,
  parseCredentialResponse,
  TokenError,
} from './oid4vci-token.js'
export type {
  IssuerMetadata,
  CredentialConfiguration,
  PreAuthorizedTokenRequest,
  AuthorizationCodeTokenRequest,
  TokenRequest,
  TokenResponse,
  TokenErrorResponse,
  CredentialRequest,
  CredentialResponse,
  ProofOptions,
} from './oid4vci-token.js'

// ── OpenID4VP ────────────────────────────────────────────────────────────────

// Authorization Request
export {
  parseAuthorizationRequest,
  isDirectPost,
  needsJarFetch,
  getRequestedCredentials,
  getRequestedClaims,
  AuthorizationRequestError,
} from './oid4vp.js'
export type {
  AuthorizationRequest,
  ParsedAuthorizationRequest,
  DcqlQuery,
  DcqlCredentialQuery,
  DcqlClaimQuery,
  DcqlCredentialSetQuery,
  DcqlTrustedAuthority,
  ResponseMode,
} from './oid4vp.js'

// Presentation Builder + Submission
export {
  matchCredentials,
  buildPresentation,
  buildDirectPostBody,
  encodeDirectPostBody,
  preparePresentation,
  PresentationError,
} from './oid4vp-present.js'
export type {
  VerifiablePresentation,
  DcqlMatchResult,
  PresentationOptions,
  DirectPostBody,
  PresentationSubmission,
} from './oid4vp-present.js'

// ── SD-JWT Selective Disclosure ──────────────────────────────────────────────

export {
  createSdJwt,
  createNestedSdJwt,
  selectDisclosures,
  verifyDisclosures,
  hashDisclosure,
  encodeSdJwt,
  decodeSdJwt,
  SdJwtError,
} from './sd-jwt.js'
export type {
  Disclosure,
  SdJwtVc,
  SdJwtPresentation,
  DisclosureVerification,
} from './sd-jwt.js'
