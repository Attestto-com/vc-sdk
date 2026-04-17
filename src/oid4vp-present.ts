/**
 * OpenID4VP — Verifiable Presentation builder + submission
 *
 * Builds VPs from holder credentials, matches against DCQL queries,
 * signs with Ed25519/ES256, and builds direct_post submission bodies.
 *
 * Does NOT perform HTTP — caller provides fetch.
 */

import type { VerifiableCredential, Proof } from './types.js'
import type { AuthorizationRequest, DcqlQuery, DcqlCredentialQuery } from './oid4vp.js'
import { sign as cryptoSign, toBase64url } from './keys.js'

// ── Types ────────────────────────────────────────────────────────────────────

/** W3C Verifiable Presentation */
export interface VerifiablePresentation {
  '@context': string[]
  type: string[]
  holder: string
  verifiableCredential: VerifiableCredential[]
  proof?: Proof
}

/** Result of matching credentials against a DCQL query */
export interface DcqlMatchResult {
  /** Whether all required credential sets are satisfied */
  satisfied: boolean
  /** Matched credentials per query ID */
  matches: Map<string, VerifiableCredential[]>
  /** Query IDs that had no matching credentials */
  missing: string[]
}

/** Options for building a VP */
export interface PresentationOptions {
  /** Holder's DID */
  holderDid: string
  /** Holder's private key for signing the VP */
  privateKey: Uint8Array
  /** Key algorithm (default: Ed25519) */
  algorithm?: 'Ed25519' | 'ES256'
  /** Key ID fragment (default: #key-1) */
  keyId?: string
  /** Nonce from the authorization request (bound into the VP proof) */
  nonce: string
  /** Domain / audience (typically the verifier's client_id) */
  domain?: string
}

/** Direct POST submission body */
export interface DirectPostBody {
  vp_token: string
  state?: string
  presentation_submission?: PresentationSubmission
}

/** Maps submitted VPs to the authorization request */
export interface PresentationSubmission {
  id: string
  definition_id: string
  descriptor_map: Array<{
    id: string
    format: string
    path: string
  }>
}

// ── DCQL Credential Matching ─────────────────────────────────────────────────

/**
 * Match wallet credentials against a DCQL query.
 * Returns which credentials satisfy each query and whether all required sets are met.
 */
export function matchCredentials(
  query: DcqlQuery,
  credentials: VerifiableCredential[],
): DcqlMatchResult {
  const matches = new Map<string, VerifiableCredential[]>()
  const missing: string[] = []

  for (const cq of query.credentials) {
    const matched = credentials.filter((vc) => credentialMatchesQuery(vc, cq))
    if (matched.length > 0) {
      matches.set(cq.id, matched)
    } else {
      missing.push(cq.id)
    }
  }

  // Check credential_sets satisfaction
  let satisfied = true
  if (query.credential_sets) {
    for (const cs of query.credential_sets) {
      const required = cs.required !== false // default true
      if (!required) continue

      // At least one option (AND-group) must be fully satisfied
      const optionSatisfied = cs.options.some((andGroup) =>
        andGroup.every((id) => matches.has(id)),
      )
      if (!optionSatisfied) {
        satisfied = false
        break
      }
    }
  } else {
    // No credential_sets — all credential queries are implicitly required
    satisfied = missing.length === 0
  }

  return { satisfied, matches, missing }
}

function credentialMatchesQuery(
  vc: VerifiableCredential,
  query: DcqlCredentialQuery,
): boolean {
  // Match by vct_values (credential type)
  if (query.meta?.vct_values) {
    const vcTypes = vc.type
    const hasMatchingType = query.meta.vct_values.some((vct) => vcTypes.includes(vct))
    if (!hasMatchingType) return false
  }

  // Match by claims presence
  if (query.claims) {
    for (const claim of query.claims) {
      const value = resolvePath(vc, claim.path)
      if (value === undefined) return false

      // Value filter
      if (claim.values !== undefined) {
        if (!claim.values.includes(value)) return false
      }
    }
  }

  return true
}

function resolvePath(obj: unknown, path: (string | number | null)[]): unknown {
  let current: unknown = obj
  for (const segment of path) {
    if (current === null || current === undefined) return undefined
    if (segment === null) {
      // null in path = array wildcard (any element)
      if (!Array.isArray(current)) return undefined
      return current.length > 0 ? current[0] : undefined
    }
    if (typeof current === 'object') {
      current = (current as Record<string, unknown>)[String(segment)]
    } else {
      return undefined
    }
  }
  return current
}

// ── VP Builder ───────────────────────────────────────────────────────────────

/**
 * Build and sign a Verifiable Presentation.
 * Wraps selected credentials in a VP envelope with an Ed25519/ES256 proof.
 */
export function buildPresentation(
  credentials: VerifiableCredential[],
  options: PresentationOptions,
): VerifiablePresentation {
  const { holderDid, privateKey, algorithm = 'Ed25519', keyId = '#key-1', nonce, domain } = options

  if (credentials.length === 0) {
    throw new PresentationError('Cannot build a presentation with zero credentials')
  }

  const vp: VerifiablePresentation = {
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    type: ['VerifiablePresentation'],
    holder: holderDid,
    verifiableCredential: credentials,
  }

  // Sign the VP
  const proofPayload: Record<string, unknown> = {
    ...vp,
    proof: undefined, // exclude proof from signed payload
  }

  // Include nonce and domain in the canonical payload
  const canonical = JSON.stringify({
    ...proofPayload,
    nonce,
    domain,
  })

  const signature = cryptoSign(new TextEncoder().encode(canonical), privateKey, algorithm)

  vp.proof = {
    type: algorithm === 'Ed25519' ? 'Ed25519Signature2020' : 'EcdsaSecp256r1Signature2019',
    created: new Date().toISOString(),
    verificationMethod: `${holderDid}${keyId}`,
    proofPurpose: 'authentication',
    proofValue: toBase64url(signature),
  }

  return vp
}

// ── Direct POST Submission ───────────────────────────────────────────────────

/**
 * Build a direct_post submission body from a VP and authorization request.
 */
export function buildDirectPostBody(
  vp: VerifiablePresentation,
  request: AuthorizationRequest,
  matchedQueryIds?: string[],
): DirectPostBody {
  const body: DirectPostBody = {
    vp_token: JSON.stringify(vp),
  }

  if (request.state) {
    body.state = request.state
  }

  // Build presentation_submission if DCQL was used
  if (request.dcql_query && matchedQueryIds) {
    body.presentation_submission = {
      id: `ps-${Date.now()}`,
      definition_id: 'dcql',
      descriptor_map: matchedQueryIds.map((id, idx) => ({
        id,
        format: 'ldp_vp',
        path: `$.verifiableCredential[${idx}]`,
      })),
    }
  }

  return body
}

/**
 * Encode a direct_post body as application/x-www-form-urlencoded.
 */
export function encodeDirectPostBody(body: DirectPostBody): string {
  const params = new URLSearchParams()
  params.set('vp_token', body.vp_token)
  if (body.state) params.set('state', body.state)
  if (body.presentation_submission) {
    params.set('presentation_submission', JSON.stringify(body.presentation_submission))
  }
  return params.toString()
}

// ── Convenience: Full flow from request → VP → submission ────────────────────

/**
 * End-to-end: match credentials against a DCQL query, build + sign a VP,
 * and produce a direct_post body ready for submission.
 *
 * Returns null if the query cannot be satisfied.
 */
export function preparePresentation(
  request: AuthorizationRequest,
  credentials: VerifiableCredential[],
  options: Omit<PresentationOptions, 'nonce' | 'domain'>,
): { vp: VerifiablePresentation; body: DirectPostBody } | null {
  if (!request.dcql_query) {
    throw new PresentationError('Authorization request has no dcql_query — cannot match credentials')
  }

  const matchResult = matchCredentials(request.dcql_query, credentials)
  if (!matchResult.satisfied) return null

  // Collect matched credentials in query order
  const selected: VerifiableCredential[] = []
  const queryIds: string[] = []

  for (const cq of request.dcql_query.credentials) {
    const matched = matchResult.matches.get(cq.id)
    if (matched && matched.length > 0) {
      selected.push(matched[0]) // first match per query
      queryIds.push(cq.id)
    }
  }

  const vp = buildPresentation(selected, {
    ...options,
    nonce: request.nonce,
    domain: request.client_id,
  })

  const body = buildDirectPostBody(vp, request, queryIds)

  return { vp, body }
}

// ── Error ────────────────────────────────────────────────────────────────────

export class PresentationError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'PresentationError'
  }
}
