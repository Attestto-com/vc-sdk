/**
 * OpenID for Verifiable Presentations (OID4VP) — Authorization Request parser
 *
 * Implements: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
 * Uses DCQL (Digital Credentials Query Language) as the query format.
 */

// ── Types ────────────────────────────────────────────────────────────────────

export type ResponseMode = 'fragment' | 'direct_post' | 'direct_post.jwt'

export interface DcqlClaimQuery {
  id?: string
  path: (string | number | null)[]
  values?: unknown[]
}

export interface DcqlTrustedAuthority {
  type: 'aki' | 'etsi_tl' | 'openid_federation' | string
  values: string[]
}

export interface DcqlCredentialQuery {
  id: string
  format: 'dc+sd-jwt' | 'vc+sd-jwt' | 'mso_mdoc' | 'jwt_vc_json' | 'ldp_vc' | string
  meta?: {
    vct_values?: string[]
    doctype_value?: string
  }
  claims?: DcqlClaimQuery[]
  claim_sets?: string[][]
  multiple?: boolean
  require_cryptographic_holder_binding?: boolean
  trusted_authorities?: DcqlTrustedAuthority[]
}

export interface DcqlCredentialSetQuery {
  options: string[][]
  required?: boolean
}

export interface DcqlQuery {
  credentials: DcqlCredentialQuery[]
  credential_sets?: DcqlCredentialSetQuery[]
}

export interface AuthorizationRequest {
  response_type: 'vp_token'
  client_id: string
  nonce: string
  state?: string
  response_mode?: ResponseMode
  redirect_uri?: string
  response_uri?: string
  dcql_query?: DcqlQuery
  scope?: string
  client_metadata?: Record<string, unknown>
  request_uri?: string
  request_uri_method?: 'get' | 'post'
  transaction_data?: string[]
}

export interface ParsedAuthorizationRequest {
  request: AuthorizationRequest
  /** Whether the request was inline or needs JAR fetch */
  source: 'inline' | 'request_uri'
  /** Original URI if parsed from a deep link */
  originalUri?: string
}

// ── Parser ───────────────────────────────────────────────────────────────────

const VP_SCHEME = 'openid4vp://'

/**
 * Parse an OID4VP authorization request from a URI, query string, or JSON object.
 *
 * Supports:
 * - `openid4vp://?response_type=vp_token&...` (deep link / QR)
 * - `https://verifier.example.com/authorize?response_type=vp_token&...` (same-device redirect)
 * - Plain object with authorization request fields
 */
export function parseAuthorizationRequest(
  input: string | Record<string, unknown>,
): ParsedAuthorizationRequest {
  if (typeof input === 'object' && input !== null) {
    return { request: validateRequest(input), source: 'inline' }
  }

  const str = input.trim()

  // Deep link or HTTPS URL with query params
  if (str.startsWith(VP_SCHEME) || str.startsWith('openid4vp:') || str.startsWith('https://')) {
    return parseRequestUri(str)
  }

  // Plain JSON
  if (str.startsWith('{')) {
    const parsed = JSON.parse(str) as Record<string, unknown>
    return { request: validateRequest(parsed), source: 'inline' }
  }

  // Query string only (no scheme)
  if (str.includes('response_type=')) {
    const params = new URLSearchParams(str)
    return { request: validateRequest(paramsToObject(params)), source: 'inline' }
  }

  throw new AuthorizationRequestError(`Unrecognized authorization request format: ${str.slice(0, 80)}`)
}

function parseRequestUri(uri: string): ParsedAuthorizationRequest {
  const qIdx = uri.indexOf('?')
  if (qIdx === -1) {
    throw new AuthorizationRequestError('Authorization request URI has no query parameters')
  }

  const params = new URLSearchParams(uri.slice(qIdx + 1))

  // JAR (JWT-Secured Authorization Request) by reference
  const requestUri = params.get('request_uri')
  if (requestUri) {
    const clientId = params.get('client_id')
    if (!clientId) {
      throw new AuthorizationRequestError('client_id is required alongside request_uri')
    }
    return {
      request: {
        response_type: 'vp_token',
        client_id: clientId,
        nonce: '', // Will be populated after fetching the JAR
        request_uri: requestUri,
        request_uri_method: (params.get('request_uri_method') as 'get' | 'post') || undefined,
      },
      source: 'request_uri',
      originalUri: uri,
    }
  }

  const obj = paramsToObject(params)
  return { request: validateRequest(obj), source: 'inline', originalUri: uri }
}

function paramsToObject(params: URLSearchParams): Record<string, unknown> {
  const obj: Record<string, unknown> = {}
  const JSON_KEYS = new Set(['dcql_query', 'client_metadata'])
  params.forEach((value, key) => {
    if (JSON_KEYS.has(key)) {
      try { obj[key] = JSON.parse(value) } catch { obj[key] = value }
    } else if (key === 'transaction_data') {
      try { obj[key] = JSON.parse(value) } catch { obj[key] = [value] }
    } else {
      obj[key] = value
    }
  })
  return obj
}

// ── Validation ───────────────────────────────────────────────────────────────

function validateRequest(obj: Record<string, unknown>): AuthorizationRequest {
  if (obj.response_type !== 'vp_token') {
    throw new AuthorizationRequestError(
      `response_type must be "vp_token", got "${String(obj.response_type)}"`,
    )
  }

  if (typeof obj.client_id !== 'string' || !obj.client_id) {
    throw new AuthorizationRequestError('client_id is required and must be a non-empty string')
  }

  if (typeof obj.nonce !== 'string' || !obj.nonce) {
    throw new AuthorizationRequestError('nonce is required and must be a non-empty string')
  }

  const request: AuthorizationRequest = {
    response_type: 'vp_token',
    client_id: obj.client_id,
    nonce: obj.nonce,
  }

  if (obj.state !== undefined) request.state = String(obj.state)
  if (obj.redirect_uri !== undefined) request.redirect_uri = String(obj.redirect_uri)
  if (obj.response_uri !== undefined) request.response_uri = String(obj.response_uri)
  if (obj.scope !== undefined) request.scope = String(obj.scope)
  if (obj.request_uri !== undefined) request.request_uri = String(obj.request_uri)

  // Response mode
  if (obj.response_mode !== undefined) {
    const mode = String(obj.response_mode)
    if (mode !== 'fragment' && mode !== 'direct_post' && mode !== 'direct_post.jwt') {
      throw new AuthorizationRequestError(
        `Unsupported response_mode: "${mode}". Expected fragment, direct_post, or direct_post.jwt`,
      )
    }
    request.response_mode = mode
  }

  // Validate direct_post requires response_uri
  if (request.response_mode === 'direct_post' || request.response_mode === 'direct_post.jwt') {
    if (!request.response_uri) {
      throw new AuthorizationRequestError(
        `response_uri is required when response_mode is "${request.response_mode}"`,
      )
    }
  }

  // DCQL query
  if (obj.dcql_query !== undefined) {
    request.dcql_query = validateDcqlQuery(obj.dcql_query as Record<string, unknown>)
  }

  // Client metadata
  if (obj.client_metadata !== undefined) {
    request.client_metadata = obj.client_metadata as Record<string, unknown>
  }

  // Transaction data
  if (obj.transaction_data !== undefined) {
    if (!Array.isArray(obj.transaction_data)) {
      throw new AuthorizationRequestError('transaction_data must be an array of strings')
    }
    request.transaction_data = obj.transaction_data as string[]
  }

  return request
}

function validateDcqlQuery(obj: Record<string, unknown>): DcqlQuery {
  if (!Array.isArray(obj.credentials) || obj.credentials.length === 0) {
    throw new AuthorizationRequestError('dcql_query.credentials is required and must be a non-empty array')
  }

  const credentials: DcqlCredentialQuery[] = []

  for (const cred of obj.credentials) {
    const c = cred as Record<string, unknown>
    if (typeof c.id !== 'string' || !c.id) {
      throw new AuthorizationRequestError('Each DCQL credential query must have a non-empty id')
    }
    if (typeof c.format !== 'string' || !c.format) {
      throw new AuthorizationRequestError('Each DCQL credential query must have a non-empty format')
    }

    const query: DcqlCredentialQuery = {
      id: c.id,
      format: c.format,
    }

    if (c.meta !== undefined) query.meta = c.meta as DcqlCredentialQuery['meta']
    if (c.multiple !== undefined) query.multiple = Boolean(c.multiple)
    if (c.require_cryptographic_holder_binding !== undefined) {
      query.require_cryptographic_holder_binding = Boolean(c.require_cryptographic_holder_binding)
    }

    if (Array.isArray(c.claims)) {
      query.claims = (c.claims as Record<string, unknown>[]).map((claim) => {
        if (!Array.isArray(claim.path)) {
          throw new AuthorizationRequestError('Each DCQL claim must have a path array')
        }
        const q: DcqlClaimQuery = { path: claim.path as (string | number | null)[] }
        if (claim.id !== undefined) q.id = String(claim.id)
        if (claim.values !== undefined) q.values = claim.values as unknown[]
        return q
      })
    }

    if (Array.isArray(c.claim_sets)) {
      query.claim_sets = c.claim_sets as string[][]
    }

    if (Array.isArray(c.trusted_authorities)) {
      query.trusted_authorities = (c.trusted_authorities as Record<string, unknown>[]).map((ta) => ({
        type: String(ta.type),
        values: ta.values as string[],
      }))
    }

    credentials.push(query)
  }

  const dcql: DcqlQuery = { credentials }

  if (Array.isArray(obj.credential_sets)) {
    dcql.credential_sets = (obj.credential_sets as Record<string, unknown>[]).map((cs) => ({
      options: cs.options as string[][],
      required: cs.required !== undefined ? Boolean(cs.required) : undefined,
    }))
  }

  return dcql
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/** Check if the request uses direct_post response mode */
export function isDirectPost(request: AuthorizationRequest): boolean {
  return request.response_mode === 'direct_post' || request.response_mode === 'direct_post.jwt'
}

/** Check if the request needs a JAR fetch (request_uri present) */
export function needsJarFetch(parsed: ParsedAuthorizationRequest): boolean {
  return parsed.source === 'request_uri'
}

/** Get the list of requested credential format+type pairs from a DCQL query */
export function getRequestedCredentials(
  query: DcqlQuery,
): Array<{ id: string; format: string; types?: string[] }> {
  return query.credentials.map((c) => ({
    id: c.id,
    format: c.format,
    types: c.meta?.vct_values,
  }))
}

/** Get required claim paths from a DCQL credential query */
export function getRequestedClaims(query: DcqlCredentialQuery): string[][] {
  if (!query.claims) return []
  return query.claims.map((c) => c.path.map(String))
}

// ── Error ────────────────────────────────────────────────────────────────────

export class AuthorizationRequestError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'AuthorizationRequestError'
  }
}
