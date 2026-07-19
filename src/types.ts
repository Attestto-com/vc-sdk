/**
 * Universal types for W3C Verifiable Credentials
 *
 * No domain-specific types — those belong in schema plugins
 * (cr-vc-schemas, cr-banking-schemas, cr-health-schemas, etc.)
 */

/** W3C Verifiable Credential envelope */
export interface VerifiableCredential<T extends Record<string, unknown> = Record<string, unknown>> {
  '@context': string[]
  id: string
  type: string[]
  issuer: string
  issuanceDate: string
  expirationDate?: string
  credentialSubject: {
    id: string
  } & T
  credentialStatus?: CredentialStatus
  proof?: Proof | Proof[]
}

/** W3C StatusList2021 entry */
export interface CredentialStatus {
  id: string
  type: 'StatusList2021Entry'
  statusPurpose: 'revocation' | 'suspension'
  statusListIndex: string
  statusListCredential: string
}

/** Linked Data Proof */
export interface Proof {
  type: string
  created: string
  verificationMethod: string
  proofPurpose: string
  proofValue?: string
  jws?: string
}

/** Issuer configuration */
export interface IssuerConfig {
  /** DID of the issuer (any method: did:web, did:sns, did:key, etc.) */
  did: string
  /** Private key for signing */
  privateKey: Uint8Array | string
  /** Key algorithm (default: Ed25519) */
  algorithm?: 'Ed25519' | 'ES256'
  /** Key ID fragment (default: #key-1) */
  keyId?: string
}

/** Options for issuing a credential */
export interface IssueOptions {
  /** Credential type(s) — any string, e.g. 'DrivingLicense', 'UniversityDegree', 'BankKYC' */
  type: string | string[]
  /** JSON-LD context(s) — at minimum W3C VC context is always included */
  context?: string | string[]
  /** DID of the subject (holder) */
  subjectDid: string
  /** Credential subject data — any shape, matches your schema */
  claims: Record<string, unknown>
  /** Optional expiration date (ISO 8601) */
  expirationDate?: string
  /** Optional credential status for revocation */
  credentialStatus?: CredentialStatus
  /** Optional credential ID (auto-generated UUID if not provided) */
  id?: string
}

/** Verification result */
export interface VerificationResult {
  /**
   * Overall validity. By default this requires a cryptographically valid proof
   * bound to the credential issuer — an unsigned or unverifiable credential is
   * NOT valid (fail-closed). Set `VerifyOptions.requireSignature = false` to
   * evaluate structural validity only.
   */
  valid: boolean
  /**
   * Whether a cryptographically valid proof, bound to the credential issuer,
   * was verified. Independent of `valid` so callers can distinguish structural
   * validity from signature validity even when `requireSignature` is false.
   */
  signatureVerified: boolean
  checks: VerificationCheck[]
  errors: string[]
  warnings: string[]
}

/** Individual verification check */
export interface VerificationCheck {
  check: string
  passed: boolean
  message?: string
}

/** Options for verifying a credential */
export interface VerifyOptions {
  /** Check expiration date (default: true) */
  checkExpiration?: boolean
  /** Check credential status / revocation */
  checkStatus?: boolean
  /** Expected credential type */
  expectedType?: string
  /** Expected issuer DID */
  expectedIssuer?: string
  /** Required JSON-LD context */
  expectedContext?: string
  /**
   * Require a cryptographically valid, issuer-bound proof for `valid: true`
   * (default: true / fail-closed). Set to `false` to allow structural-only
   * validation of unsigned or unverifiable credentials (e.g. inspecting a draft
   * before it is signed); `signatureVerified` still reports the real state.
   */
  requireSignature?: boolean
}

/**
 * Schema plugin interface — domain-specific schema packages implement this
 *
 * Example: cr-vc-schemas would register:
 *   { context: 'https://schemas.attestto.org/cr/driving/v1', types: ['DrivingLicense', ...] }
 */
export interface SchemaPlugin {
  /** JSON-LD context URL */
  context: string
  /** Credential types this plugin handles */
  types: string[]
  /** Optional: map credential type to property name in credentialSubject */
  propertyMap?: Record<string, string>
}
