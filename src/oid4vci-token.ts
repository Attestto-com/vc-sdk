/**
 * OpenID4VCI — Token endpoint client
 *
 * Builds token requests and parses token responses for OID4VCI issuance flows.
 * Does NOT perform HTTP — caller provides fetch. This keeps the SDK runtime-agnostic.
 *
 * Implements: OID4VCI spec sections 6 (Token Endpoint)
 */

import type { CredentialOfferPayload, GrantPreAuthorizedCode } from './oid4vci.js'
import { PRE_AUTHORIZED_CODE_GRANT } from './oid4vci.js'
import { sign as cryptoSign, toBase64url } from './keys.js'

// ── Types ────────────────────────────────────────────────────────────────────

/** Issuer metadata fetched from .well-known/openid-credential-issuer */
export interface IssuerMetadata {
  credential_issuer: string
  credential_endpoint: string
  token_endpoint?: string
  authorization_servers?: string[]
  nonce_endpoint?: string
  deferred_credential_endpoint?: string
  credential_configurations_supported?: Record<string, CredentialConfiguration>
}

export interface CredentialConfiguration {
  format: string
  scope?: string
  credential_definition?: {
    type?: string[]
    credentialSubject?: Record<string, unknown>
  }
  display?: Array<{ name: string; locale?: string }>
}

/** Token request for pre-authorized code flow */
export interface PreAuthorizedTokenRequest {
  grant_type: typeof PRE_AUTHORIZED_CODE_GRANT
  'pre-authorized_code': string
  tx_code?: string
}

/** Token request for authorization code flow */
export interface AuthorizationCodeTokenRequest {
  grant_type: 'authorization_code'
  code: string
  redirect_uri?: string
  code_verifier?: string
}

export type TokenRequest = PreAuthorizedTokenRequest | AuthorizationCodeTokenRequest

/** Token response from the authorization server */
export interface TokenResponse {
  access_token: string
  token_type: string
  expires_in?: number
  c_nonce?: string
  c_nonce_expires_in?: number
  authorization_details?: unknown[]
}

/** Token error response */
export interface TokenErrorResponse {
  error: string
  error_description?: string
}

/** Credential request sent to the credential endpoint */
export interface CredentialRequest {
  credential_configuration_id: string
  proof?: {
    proof_type: 'jwt'
    jwt: string
  }
}

/** Credential response from the issuer */
export interface CredentialResponse {
  credentials?: Array<{ credential: string | Record<string, unknown> }>
  credential?: string | Record<string, unknown>
  transaction_id?: string
  c_nonce?: string
  c_nonce_expires_in?: number
}

/** Options for building a proof of possession JWT */
export interface ProofOptions {
  /** Holder's DID */
  holderDid: string
  /** Credential issuer URL (audience) */
  issuerUrl: string
  /** c_nonce from token response */
  nonce: string
  /** Holder's private key */
  privateKey: Uint8Array
  /** Key algorithm (default: Ed25519) */
  algorithm?: 'Ed25519' | 'ES256'
  /** Key ID fragment (default: #key-1) */
  keyId?: string
}

// ── Issuer Metadata ──────────────────────────────────────────────────────────

/** Build the well-known URL for fetching issuer metadata */
export function getIssuerMetadataUrl(credentialIssuer: string): string {
  const base = credentialIssuer.endsWith('/') ? credentialIssuer.slice(0, -1) : credentialIssuer
  return `${base}/.well-known/openid-credential-issuer`
}

/** Parse and validate issuer metadata JSON */
export function parseIssuerMetadata(json: Record<string, unknown>): IssuerMetadata {
  if (typeof json.credential_issuer !== 'string') {
    throw new TokenError('Issuer metadata missing credential_issuer')
  }
  if (typeof json.credential_endpoint !== 'string') {
    throw new TokenError('Issuer metadata missing credential_endpoint')
  }
  return json as unknown as IssuerMetadata
}

/** Resolve the token endpoint from issuer metadata */
export function getTokenEndpoint(metadata: IssuerMetadata): string {
  if (metadata.token_endpoint) return metadata.token_endpoint
  // Default: issuer URL + /token
  const base = metadata.credential_issuer.endsWith('/')
    ? metadata.credential_issuer.slice(0, -1)
    : metadata.credential_issuer
  return `${base}/token`
}

// ── Token Request Builders ───────────────────────────────────────────────────

/** Build a token request for the pre-authorized code flow */
export function buildPreAuthorizedTokenRequest(
  offer: CredentialOfferPayload,
  txCode?: string,
): PreAuthorizedTokenRequest {
  const grant = offer.grants?.[PRE_AUTHORIZED_CODE_GRANT] as GrantPreAuthorizedCode | undefined
  if (!grant) {
    throw new TokenError('Offer does not contain a pre-authorized_code grant')
  }

  const request: PreAuthorizedTokenRequest = {
    grant_type: PRE_AUTHORIZED_CODE_GRANT,
    'pre-authorized_code': grant['pre-authorized_code'],
  }

  if (txCode !== undefined) {
    request.tx_code = txCode
  }

  return request
}

/** Build a token request for the authorization code flow */
export function buildAuthorizationCodeTokenRequest(
  code: string,
  redirectUri?: string,
  codeVerifier?: string,
): AuthorizationCodeTokenRequest {
  const request: AuthorizationCodeTokenRequest = {
    grant_type: 'authorization_code',
    code,
  }
  if (redirectUri) request.redirect_uri = redirectUri
  if (codeVerifier) request.code_verifier = codeVerifier
  return request
}

/** Encode a token request as application/x-www-form-urlencoded body */
export function encodeTokenRequest(request: TokenRequest): string {
  const params = new URLSearchParams()
  for (const [key, value] of Object.entries(request)) {
    if (value !== undefined) params.set(key, String(value))
  }
  return params.toString()
}

// ── Token Response Parser ────────────────────────────────────────────────────

/** Parse a token response (checks for error responses) */
export function parseTokenResponse(
  json: Record<string, unknown>,
): TokenResponse {
  if (json.error) {
    throw new TokenError(
      `Token error: ${json.error}${json.error_description ? ` — ${json.error_description}` : ''}`,
    )
  }
  if (typeof json.access_token !== 'string') {
    throw new TokenError('Token response missing access_token')
  }
  return {
    access_token: json.access_token,
    token_type: (json.token_type as string) ?? 'Bearer',
    expires_in: json.expires_in as number | undefined,
    c_nonce: json.c_nonce as string | undefined,
    c_nonce_expires_in: json.c_nonce_expires_in as number | undefined,
    authorization_details: json.authorization_details as unknown[] | undefined,
  }
}

// ── Proof of Possession ──────────────────────────────────────────────────────

/**
 * Build a JWT proof of possession for the credential endpoint.
 * The proof binds the credential to the holder's key.
 */
export function buildProofJwt(options: ProofOptions): string {
  const { holderDid, issuerUrl, nonce, privateKey, algorithm = 'Ed25519', keyId = '#key-1' } = options

  const header = {
    alg: algorithm === 'Ed25519' ? 'EdDSA' : 'ES256',
    typ: 'openid4vci-proof+jwt',
    kid: `${holderDid}${keyId}`,
  }

  const now = Math.floor(Date.now() / 1000)
  const payload = {
    iss: holderDid,
    aud: issuerUrl,
    iat: now,
    nonce,
  }

  const headerB64 = toBase64url(new TextEncoder().encode(JSON.stringify(header)))
  const payloadB64 = toBase64url(new TextEncoder().encode(JSON.stringify(payload)))
  const signingInput = `${headerB64}.${payloadB64}`
  const signature = cryptoSign(new TextEncoder().encode(signingInput), privateKey, algorithm)
  const signatureB64 = toBase64url(signature)

  return `${signingInput}.${signatureB64}`
}

// ── Credential Request Builder ───────────────────────────────────────────────

/** Build a credential request for the credential endpoint */
export function buildCredentialRequest(
  configId: string,
  proofJwt?: string,
): CredentialRequest {
  const request: CredentialRequest = {
    credential_configuration_id: configId,
  }
  if (proofJwt) {
    request.proof = { proof_type: 'jwt', jwt: proofJwt }
  }
  return request
}

/** Parse a credential response */
export function parseCredentialResponse(
  json: Record<string, unknown>,
): CredentialResponse {
  if (json.error) {
    throw new TokenError(
      `Credential error: ${json.error}${json.error_description ? ` — ${json.error_description}` : ''}`,
    )
  }
  return {
    credentials: json.credentials as CredentialResponse['credentials'],
    credential: json.credential as CredentialResponse['credential'],
    transaction_id: json.transaction_id as string | undefined,
    c_nonce: json.c_nonce as string | undefined,
    c_nonce_expires_in: json.c_nonce_expires_in as number | undefined,
  }
}

// ── Error ────────────────────────────────────────────────────────────────────

export class TokenError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'TokenError'
  }
}
