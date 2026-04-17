import { describe, it, expect } from 'vitest'
import {
  parseAuthorizationRequest,
  isDirectPost,
  needsJarFetch,
  getRequestedCredentials,
  getRequestedClaims,
  AuthorizationRequestError,
} from '../src/oid4vp.js'
import type { DcqlQuery, DcqlCredentialQuery } from '../src/oid4vp.js'

// ── Fixtures ─────────────────────────────────────────────────────────────────

const BASIC_REQUEST = {
  response_type: 'vp_token',
  client_id: 'https://verifier.attestto.com',
  nonce: 'n-0S6_WzA2Mj',
  state: 'af0ifjsldkj',
  response_mode: 'direct_post',
  response_uri: 'https://verifier.attestto.com/response',
}

const DCQL_QUERY: DcqlQuery = {
  credentials: [
    {
      id: 'cedula_cr',
      format: 'ldp_vc',
      meta: { vct_values: ['CedulaIdentidadCR'] },
      claims: [
        { id: 'name', path: ['credentialSubject', 'nombre'] },
        { id: 'apellidos', path: ['credentialSubject', 'apellidos'] },
        { id: 'cedula', path: ['credentialSubject', 'cedula'] },
      ],
    },
    {
      id: 'driving_license',
      format: 'ldp_vc',
      meta: { vct_values: ['DrivingLicenseCR'] },
      claims: [
        { path: ['credentialSubject', 'licenseNumber'] },
        { path: ['credentialSubject', 'categories'] },
      ],
    },
  ],
  credential_sets: [
    { options: [['cedula_cr']], required: true },
    { options: [['driving_license']], required: false },
  ],
}

const REQUEST_WITH_DCQL = {
  ...BASIC_REQUEST,
  dcql_query: DCQL_QUERY,
}

// ── Tests ────────────────────────────────────────────────────────────────────

describe('OID4VP: parseAuthorizationRequest', () => {
  describe('from object', () => {
    it('parses a basic direct_post request', () => {
      const result = parseAuthorizationRequest(BASIC_REQUEST)
      expect(result.source).toBe('inline')
      expect(result.request.response_type).toBe('vp_token')
      expect(result.request.client_id).toBe('https://verifier.attestto.com')
      expect(result.request.nonce).toBe('n-0S6_WzA2Mj')
      expect(result.request.state).toBe('af0ifjsldkj')
      expect(result.request.response_mode).toBe('direct_post')
      expect(result.request.response_uri).toBe('https://verifier.attestto.com/response')
    })

    it('parses a request with DCQL query', () => {
      const result = parseAuthorizationRequest(REQUEST_WITH_DCQL)
      expect(result.request.dcql_query).toBeDefined()
      expect(result.request.dcql_query!.credentials).toHaveLength(2)
      expect(result.request.dcql_query!.credentials[0].id).toBe('cedula_cr')
      expect(result.request.dcql_query!.credentials[0].format).toBe('ldp_vc')
      expect(result.request.dcql_query!.credentials[0].claims).toHaveLength(3)
    })

    it('parses DCQL credential_sets', () => {
      const result = parseAuthorizationRequest(REQUEST_WITH_DCQL)
      const sets = result.request.dcql_query!.credential_sets!
      expect(sets).toHaveLength(2)
      expect(sets[0].options).toEqual([['cedula_cr']])
      expect(sets[0].required).toBe(true)
      expect(sets[1].required).toBe(false)
    })

    it('parses DCQL claim values filter', () => {
      const request = {
        ...BASIC_REQUEST,
        dcql_query: {
          credentials: [{
            id: 'age_check',
            format: 'dc+sd-jwt',
            claims: [{ path: ['age_over_18'], values: [true] }],
          }],
        },
      }
      const result = parseAuthorizationRequest(request)
      expect(result.request.dcql_query!.credentials[0].claims![0].values).toEqual([true])
    })

    it('parses fragment response_mode', () => {
      const result = parseAuthorizationRequest({
        response_type: 'vp_token',
        client_id: 'https://v.com',
        nonce: 'abc',
        response_mode: 'fragment',
        redirect_uri: 'https://v.com/callback',
      })
      expect(result.request.response_mode).toBe('fragment')
      expect(result.request.redirect_uri).toBe('https://v.com/callback')
    })

    it('parses trusted_authorities', () => {
      const request = {
        ...BASIC_REQUEST,
        dcql_query: {
          credentials: [{
            id: 'cert',
            format: 'ldp_vc',
            trusted_authorities: [
              { type: 'aki', values: ['MIIBIj...'] },
            ],
          }],
        },
      }
      const result = parseAuthorizationRequest(request)
      const ta = result.request.dcql_query!.credentials[0].trusted_authorities!
      expect(ta).toHaveLength(1)
      expect(ta[0].type).toBe('aki')
    })
  })

  describe('from URI', () => {
    it('parses openid4vp:// deep link', () => {
      const params = new URLSearchParams({
        response_type: 'vp_token',
        client_id: 'https://v.com',
        nonce: 'xyz',
        response_mode: 'direct_post',
        response_uri: 'https://v.com/response',
      })
      const uri = `openid4vp://?${params.toString()}`
      const result = parseAuthorizationRequest(uri)
      expect(result.source).toBe('inline')
      expect(result.originalUri).toBe(uri)
      expect(result.request.client_id).toBe('https://v.com')
    })

    it('parses HTTPS redirect URI', () => {
      const params = new URLSearchParams({
        response_type: 'vp_token',
        client_id: 'https://v.com',
        nonce: 'xyz',
        response_mode: 'direct_post',
        response_uri: 'https://v.com/response',
      })
      const uri = `https://v.com/authorize?${params.toString()}`
      const result = parseAuthorizationRequest(uri)
      expect(result.request.nonce).toBe('xyz')
    })

    it('detects request_uri (JAR by reference)', () => {
      const uri = 'openid4vp://?client_id=https://v.com&request_uri=https://v.com/jar/123'
      const result = parseAuthorizationRequest(uri)
      expect(result.source).toBe('request_uri')
      expect(result.request.request_uri).toBe('https://v.com/jar/123')
      expect(result.request.client_id).toBe('https://v.com')
    })

    it('parses DCQL from URI query param', () => {
      const dcql = JSON.stringify({
        credentials: [{ id: 'id_card', format: 'ldp_vc' }],
      })
      const params = new URLSearchParams({
        response_type: 'vp_token',
        client_id: 'https://v.com',
        nonce: 'abc',
        dcql_query: dcql,
      })
      const uri = `openid4vp://?${params.toString()}`
      const result = parseAuthorizationRequest(uri)
      expect(result.request.dcql_query!.credentials[0].id).toBe('id_card')
    })
  })

  describe('from JSON string', () => {
    it('parses a JSON string', () => {
      const result = parseAuthorizationRequest(JSON.stringify(BASIC_REQUEST))
      expect(result.request.client_id).toBe('https://verifier.attestto.com')
    })
  })

  describe('validation errors', () => {
    it('rejects wrong response_type', () => {
      expect(() =>
        parseAuthorizationRequest({ response_type: 'code', client_id: 'x', nonce: 'y' }),
      ).toThrow('response_type must be "vp_token"')
    })

    it('rejects missing client_id', () => {
      expect(() =>
        parseAuthorizationRequest({ response_type: 'vp_token', nonce: 'y' }),
      ).toThrow('client_id is required')
    })

    it('rejects missing nonce', () => {
      expect(() =>
        parseAuthorizationRequest({ response_type: 'vp_token', client_id: 'x' }),
      ).toThrow('nonce is required')
    })

    it('rejects unsupported response_mode', () => {
      expect(() =>
        parseAuthorizationRequest({
          response_type: 'vp_token', client_id: 'x', nonce: 'y',
          response_mode: 'query',
        }),
      ).toThrow('Unsupported response_mode')
    })

    it('rejects direct_post without response_uri', () => {
      expect(() =>
        parseAuthorizationRequest({
          response_type: 'vp_token', client_id: 'x', nonce: 'y',
          response_mode: 'direct_post',
        }),
      ).toThrow('response_uri is required')
    })

    it('rejects DCQL with empty credentials', () => {
      expect(() =>
        parseAuthorizationRequest({
          response_type: 'vp_token', client_id: 'x', nonce: 'y',
          dcql_query: { credentials: [] },
        }),
      ).toThrow('dcql_query.credentials')
    })

    it('rejects DCQL credential without id', () => {
      expect(() =>
        parseAuthorizationRequest({
          response_type: 'vp_token', client_id: 'x', nonce: 'y',
          dcql_query: { credentials: [{ format: 'ldp_vc' }] },
        }),
      ).toThrow('non-empty id')
    })

    it('rejects DCQL claim without path', () => {
      expect(() =>
        parseAuthorizationRequest({
          response_type: 'vp_token', client_id: 'x', nonce: 'y',
          dcql_query: {
            credentials: [{
              id: 'c1', format: 'ldp_vc',
              claims: [{ values: [true] }],
            }],
          },
        }),
      ).toThrow('path array')
    })

    it('rejects request_uri without client_id', () => {
      const uri = 'openid4vp://?request_uri=https://v.com/jar/123'
      expect(() => parseAuthorizationRequest(uri)).toThrow('client_id is required')
    })

    it('rejects unrecognized format', () => {
      expect(() => parseAuthorizationRequest('garbage-input')).toThrow('Unrecognized')
    })
  })
})

describe('OID4VP: helper functions', () => {
  it('isDirectPost detects direct_post mode', () => {
    expect(isDirectPost({ ...BASIC_REQUEST, response_type: 'vp_token' as const })).toBe(true)
    expect(isDirectPost({
      response_type: 'vp_token', client_id: 'x', nonce: 'y',
      response_mode: 'fragment',
    })).toBe(false)
    expect(isDirectPost({
      response_type: 'vp_token', client_id: 'x', nonce: 'y',
    })).toBe(false)
  })

  it('needsJarFetch detects request_uri source', () => {
    expect(needsJarFetch({ request: BASIC_REQUEST as any, source: 'inline' })).toBe(false)
    expect(needsJarFetch({ request: BASIC_REQUEST as any, source: 'request_uri' })).toBe(true)
  })

  it('getRequestedCredentials extracts format + types', () => {
    const creds = getRequestedCredentials(DCQL_QUERY)
    expect(creds).toHaveLength(2)
    expect(creds[0]).toEqual({ id: 'cedula_cr', format: 'ldp_vc', types: ['CedulaIdentidadCR'] })
    expect(creds[1]).toEqual({ id: 'driving_license', format: 'ldp_vc', types: ['DrivingLicenseCR'] })
  })

  it('getRequestedClaims extracts claim paths', () => {
    const claims = getRequestedClaims(DCQL_QUERY.credentials[0])
    expect(claims).toEqual([
      ['credentialSubject', 'nombre'],
      ['credentialSubject', 'apellidos'],
      ['credentialSubject', 'cedula'],
    ])
  })

  it('getRequestedClaims returns empty for no claims', () => {
    const q: DcqlCredentialQuery = { id: 'x', format: 'ldp_vc' }
    expect(getRequestedClaims(q)).toEqual([])
  })
})
