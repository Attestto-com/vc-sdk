/**
 * SD-JWT (Selective Disclosure JWT) for Verifiable Credentials
 *
 * Implements the core SD-JWT mechanism per:
 * https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-13.html
 *
 * Three roles:
 * 1. Issuer: creates SD-JWT with hashed claims + disclosures
 * 2. Holder: selects which disclosures to include when presenting
 * 3. Verifier: reconstructs disclosed claims and verifies hashes
 */

import { sha256 } from '@noble/hashes/sha256'
import { randomBytes } from '@noble/hashes/utils'
import { toBase64url, fromBase64url } from './keys.js'

// ── Types ────────────────────────────────────────────────────────────────────

/** A single disclosure: [salt, claim_name, claim_value] */
export type Disclosure = [string, string, unknown]

/** SD-JWT with embedded disclosures */
export interface SdJwtVc {
  /** The JWT payload with _sd hashes replacing disclosed claims */
  payload: Record<string, unknown>
  /** All disclosures (issuer keeps these; sends to holder) */
  disclosures: Disclosure[]
  /** _sd_alg used (always sha-256) */
  hashAlgorithm: 'sha-256'
}

/** A presentation: subset of disclosures selected by holder */
export interface SdJwtPresentation {
  /** Original payload (with _sd hashes) */
  payload: Record<string, unknown>
  /** Only the disclosures the holder chose to reveal */
  disclosures: Disclosure[]
}

/** Verification result for a single disclosure */
export interface DisclosureVerification {
  claimName: string
  claimValue: unknown
  hashMatch: boolean
}

// ── Issuer: Create SD-JWT ────────────────────────────────────────────────────

/**
 * Create an SD-JWT payload from claims, making specified fields selectively disclosable.
 *
 * @param claims - The full credential claims (flat object)
 * @param selectiveFields - Which field names to make selectively disclosable
 * @returns SdJwtVc with hashed payload + disclosures
 *
 * Fields NOT in selectiveFields are included in cleartext (always visible).
 * Fields IN selectiveFields are replaced with _sd hashes.
 */
export function createSdJwt(
  claims: Record<string, unknown>,
  selectiveFields: string[],
): SdJwtVc {
  const disclosures: Disclosure[] = []
  const sdHashes: string[] = []
  const payload: Record<string, unknown> = {}

  for (const [key, value] of Object.entries(claims)) {
    if (selectiveFields.includes(key)) {
      // Create disclosure: [salt, claim_name, claim_value]
      const salt = toBase64url(randomBytes(16))
      const disclosure: Disclosure = [salt, key, value]
      disclosures.push(disclosure)

      // Hash the disclosure
      const hash = hashDisclosure(disclosure)
      sdHashes.push(hash)
    } else {
      // Non-selective: include in cleartext
      payload[key] = value
    }
  }

  if (sdHashes.length > 0) {
    payload._sd = sdHashes
  }
  payload._sd_alg = 'sha-256'

  return { payload, disclosures, hashAlgorithm: 'sha-256' }
}

/**
 * Create an SD-JWT for nested claims (e.g. credentialSubject.nombre).
 * Applies selective disclosure to fields within a nested object.
 *
 * @param claims - Full claims object (can be nested)
 * @param selectivePaths - Dot-separated paths to make selective (e.g. "credentialSubject.cedula")
 */
export function createNestedSdJwt(
  claims: Record<string, unknown>,
  selectivePaths: string[],
): SdJwtVc {
  const disclosures: Disclosure[] = []
  const result = processObject(claims, '', selectivePaths, disclosures)

  return {
    payload: result as Record<string, unknown>,
    disclosures,
    hashAlgorithm: 'sha-256',
  }
}

function processObject(
  obj: Record<string, unknown>,
  prefix: string,
  selectivePaths: string[],
  disclosures: Disclosure[],
): Record<string, unknown> {
  const output: Record<string, unknown> = {}
  const sdHashes: string[] = []

  for (const [key, value] of Object.entries(obj)) {
    const fullPath = prefix ? `${prefix}.${key}` : key

    if (selectivePaths.includes(fullPath)) {
      // This field is selectively disclosable
      const salt = toBase64url(randomBytes(16))
      const disclosure: Disclosure = [salt, key, value]
      disclosures.push(disclosure)
      sdHashes.push(hashDisclosure(disclosure))
    } else if (
      typeof value === 'object' && value !== null && !Array.isArray(value) &&
      selectivePaths.some((p) => p.startsWith(fullPath + '.'))
    ) {
      // Nested object that contains selective fields — recurse
      output[key] = processObject(
        value as Record<string, unknown>,
        fullPath,
        selectivePaths,
        disclosures,
      )
    } else {
      // Non-selective: include as-is
      output[key] = value
    }
  }

  if (sdHashes.length > 0) {
    output._sd = sdHashes
    output._sd_alg = 'sha-256'
  }

  return output
}

// ── Holder: Select Disclosures ───────────────────────────────────────────────

/**
 * Create a presentation by selecting which disclosures to reveal.
 *
 * @param sdJwt - The full SD-JWT from the issuer
 * @param revealFields - Claim names to reveal (others stay hidden)
 */
export function selectDisclosures(
  sdJwt: SdJwtVc,
  revealFields: string[],
): SdJwtPresentation {
  const selected = sdJwt.disclosures.filter(([, name]) => revealFields.includes(name))
  return {
    payload: sdJwt.payload,
    disclosures: selected,
  }
}

// ── Verifier: Verify + Reconstruct ───────────────────────────────────────────

/**
 * Verify disclosures against the _sd hashes in the payload and reconstruct claims.
 *
 * Returns the verified claims (only those with matching hashes) merged with
 * the cleartext payload fields.
 */
export function verifyDisclosures(
  presentation: SdJwtPresentation,
): { claims: Record<string, unknown>; verifications: DisclosureVerification[] } {
  const verifications: DisclosureVerification[] = []
  const disclosed: Record<string, unknown> = {}

  // Collect all _sd hashes from the payload (recursively)
  const allHashes = collectSdHashes(presentation.payload)

  for (const disclosure of presentation.disclosures) {
    const [, name, value] = disclosure
    const hash = hashDisclosure(disclosure)
    const match = allHashes.has(hash)

    verifications.push({ claimName: name, claimValue: value, hashMatch: match })
    if (match) {
      disclosed[name] = value
    }
  }

  // Merge cleartext fields (everything except _sd, _sd_alg) with disclosed
  const claims = mergeCleartext(presentation.payload, disclosed)

  return { claims, verifications }
}

function collectSdHashes(obj: Record<string, unknown>): Set<string> {
  const hashes = new Set<string>()

  if (Array.isArray(obj._sd)) {
    for (const h of obj._sd) {
      if (typeof h === 'string') hashes.add(h)
    }
  }

  // Recurse into nested objects
  for (const [key, value] of Object.entries(obj)) {
    if (key === '_sd' || key === '_sd_alg') continue
    if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
      for (const h of collectSdHashes(value as Record<string, unknown>)) {
        hashes.add(h)
      }
    }
  }

  return hashes
}

function mergeCleartext(
  payload: Record<string, unknown>,
  disclosed: Record<string, unknown>,
): Record<string, unknown> {
  const result: Record<string, unknown> = { ...disclosed }

  for (const [key, value] of Object.entries(payload)) {
    if (key === '_sd' || key === '_sd_alg') continue
    if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
      // Recurse for nested objects — merge any nested disclosures
      const nested = mergeCleartext(value as Record<string, unknown>, disclosed)
      result[key] = nested
    } else {
      result[key] = value
    }
  }

  return result
}

// ── Hash Utilities ───────────────────────────────────────────────────────────

/** Hash a disclosure using SHA-256 → base64url */
export function hashDisclosure(disclosure: Disclosure): string {
  const encoded = toBase64url(new TextEncoder().encode(JSON.stringify(disclosure)))
  const hash = sha256(new TextEncoder().encode(encoded))
  return toBase64url(hash)
}

/**
 * Encode an SD-JWT as a compact string: payload~disclosure1~disclosure2~
 * (Tilde-delimited format per SD-JWT spec)
 */
export function encodeSdJwt(presentation: SdJwtPresentation): string {
  const payloadB64 = toBase64url(new TextEncoder().encode(JSON.stringify(presentation.payload)))
  const disclosureStrings = presentation.disclosures.map((d) =>
    toBase64url(new TextEncoder().encode(JSON.stringify(d))),
  )
  return [payloadB64, ...disclosureStrings, ''].join('~')
}

/**
 * Decode an SD-JWT compact string back into payload + disclosures
 */
export function decodeSdJwt(compact: string): SdJwtPresentation {
  const parts = compact.split('~').filter(Boolean)
  if (parts.length === 0) throw new SdJwtError('Empty SD-JWT string')

  const payloadJson = new TextDecoder().decode(fromBase64url(parts[0]))
  const payload = JSON.parse(payloadJson) as Record<string, unknown>

  const disclosures: Disclosure[] = parts.slice(1).map((part) => {
    const json = new TextDecoder().decode(fromBase64url(part))
    return JSON.parse(json) as Disclosure
  })

  return { payload, disclosures }
}

// ── Error ────────────────────────────────────────────────────────────────────

export class SdJwtError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'SdJwtError'
  }
}
