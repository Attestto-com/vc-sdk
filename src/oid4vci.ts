/**
 * OpenID for Verifiable Credential Issuance (OID4VCI) — Credential Offer parser
 *
 * Implements: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html
 * Sections: 4.1 (Credential Offer), 4.1.1 (Credential Offer Parameters)
 */

// ── Types ────────────────────────────────────────────────────────────────────

export const PRE_AUTHORIZED_CODE_GRANT =
  'urn:ietf:params:oauth:grant-type:pre-authorized_code' as const

export interface TxCode {
  input_mode?: 'numeric' | 'text'
  length?: number
  description?: string
}

export interface GrantAuthorizationCode {
  issuer_state?: string
  authorization_server?: string
}

export interface GrantPreAuthorizedCode {
  'pre-authorized_code': string
  tx_code?: TxCode
  interval?: number
  authorization_server?: string
}

export interface CredentialOfferGrants {
  authorization_code?: GrantAuthorizationCode
  [PRE_AUTHORIZED_CODE_GRANT]?: GrantPreAuthorizedCode
}

export interface CredentialOfferPayload {
  credential_issuer: string
  credential_configuration_ids: string[]
  grants?: CredentialOfferGrants
}

export interface ParsedCredentialOffer {
  payload: CredentialOfferPayload
  /** Whether the offer was passed by value or fetched by reference */
  source: 'value' | 'reference'
  /** Original URI if parsed from a deep link */
  originalUri?: string
}

// ── Parser ───────────────────────────────────────────────────────────────────

const OFFER_SCHEME = 'openid-credential-offer://'

/**
 * Parse a credential offer from a JSON string, object, or `openid-credential-offer://` URI.
 *
 * Supports:
 * - Raw JSON string or object (by value)
 * - `openid-credential-offer://?credential_offer=<encoded JSON>` (by value via URI)
 * - `openid-credential-offer://?credential_offer_uri=<URL>` (by reference — returns the URI, caller must fetch)
 */
export function parseCredentialOffer(
  input: string | Record<string, unknown>,
): ParsedCredentialOffer {
  // Object input — validate directly
  if (typeof input === 'object' && input !== null) {
    return { payload: validatePayload(input), source: 'value' }
  }

  const str = input.trim()

  // Deep link URI
  if (str.startsWith(OFFER_SCHEME) || str.startsWith('openid-credential-offer:')) {
    return parseOfferUri(str)
  }

  // Plain JSON
  if (str.startsWith('{')) {
    const parsed = JSON.parse(str) as Record<string, unknown>
    return { payload: validatePayload(parsed), source: 'value' }
  }

  // HTTPS URL — treat as credential_offer_uri
  if (str.startsWith('https://')) {
    throw new CredentialOfferError(
      'credential_offer_uri detected — fetch the URL and pass the JSON result to parseCredentialOffer()',
    )
  }

  throw new CredentialOfferError(`Unrecognized credential offer format: ${str.slice(0, 80)}`)
}

function parseOfferUri(uri: string): ParsedCredentialOffer {
  const qIdx = uri.indexOf('?')
  if (qIdx === -1) {
    throw new CredentialOfferError('Credential offer URI has no query parameters')
  }

  const params = new URLSearchParams(uri.slice(qIdx + 1))

  // By value
  const offerJson = params.get('credential_offer')
  if (offerJson) {
    const parsed = JSON.parse(offerJson) as Record<string, unknown>
    return { payload: validatePayload(parsed), source: 'value', originalUri: uri }
  }

  // By reference
  const offerUri = params.get('credential_offer_uri')
  if (offerUri) {
    throw new CredentialOfferError(
      `credential_offer_uri detected: ${offerUri} — fetch this URL and pass the JSON result to parseCredentialOffer()`,
    )
  }

  throw new CredentialOfferError(
    'Credential offer URI must contain credential_offer or credential_offer_uri parameter',
  )
}

// ── Validation ───────────────────────────────────────────────────────────────

function validatePayload(obj: Record<string, unknown>): CredentialOfferPayload {
  if (typeof obj.credential_issuer !== 'string' || !obj.credential_issuer) {
    throw new CredentialOfferError('credential_issuer is required and must be a non-empty string')
  }

  if (!Array.isArray(obj.credential_configuration_ids) || obj.credential_configuration_ids.length === 0) {
    throw new CredentialOfferError('credential_configuration_ids is required and must be a non-empty array')
  }

  for (const id of obj.credential_configuration_ids) {
    if (typeof id !== 'string' || !id) {
      throw new CredentialOfferError('Each credential_configuration_id must be a non-empty string')
    }
  }

  const payload: CredentialOfferPayload = {
    credential_issuer: obj.credential_issuer,
    credential_configuration_ids: obj.credential_configuration_ids as string[],
  }

  if (obj.grants !== undefined) {
    payload.grants = validateGrants(obj.grants as Record<string, unknown>)
  }

  return payload
}

function validateGrants(grants: Record<string, unknown>): CredentialOfferGrants {
  const result: CredentialOfferGrants = {}

  if (grants.authorization_code !== undefined) {
    const ac = grants.authorization_code as Record<string, unknown>
    result.authorization_code = {}
    if (ac.issuer_state !== undefined) {
      result.authorization_code.issuer_state = String(ac.issuer_state)
    }
    if (ac.authorization_server !== undefined) {
      result.authorization_code.authorization_server = String(ac.authorization_server)
    }
  }

  const preAuth = grants[PRE_AUTHORIZED_CODE_GRANT] as Record<string, unknown> | undefined
  if (preAuth !== undefined) {
    if (typeof preAuth['pre-authorized_code'] !== 'string' || !preAuth['pre-authorized_code']) {
      throw new CredentialOfferError(
        'pre-authorized_code grant requires a non-empty pre-authorized_code string',
      )
    }

    const grant: GrantPreAuthorizedCode = {
      'pre-authorized_code': preAuth['pre-authorized_code'] as string,
    }

    if (preAuth.tx_code !== undefined) {
      const tx = preAuth.tx_code as Record<string, unknown>
      grant.tx_code = {}
      if (tx.input_mode !== undefined) grant.tx_code.input_mode = tx.input_mode as 'numeric' | 'text'
      if (tx.length !== undefined) grant.tx_code.length = Number(tx.length)
      if (tx.description !== undefined) grant.tx_code.description = String(tx.description)
    }

    if (preAuth.interval !== undefined) grant.interval = Number(preAuth.interval)
    if (preAuth.authorization_server !== undefined) {
      grant.authorization_server = String(preAuth.authorization_server)
    }

    result[PRE_AUTHORIZED_CODE_GRANT] = grant
  }

  return result
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/** Check if an offer includes a pre-authorized code grant */
export function hasPreAuthorizedCode(offer: CredentialOfferPayload): boolean {
  return offer.grants?.[PRE_AUTHORIZED_CODE_GRANT] !== undefined
}

/** Check if an offer includes an authorization code grant */
export function hasAuthorizationCode(offer: CredentialOfferPayload): boolean {
  return offer.grants?.authorization_code !== undefined
}

/** Check if a pre-authorized code grant requires a transaction code (PIN) */
export function requiresTxCode(offer: CredentialOfferPayload): boolean {
  return offer.grants?.[PRE_AUTHORIZED_CODE_GRANT]?.tx_code !== undefined
}

// ── Error ────────────────────────────────────────────────────────────────────

export class CredentialOfferError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'CredentialOfferError'
  }
}
