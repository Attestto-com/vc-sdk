import { describe, it, expect } from 'vitest'
import {
  matchCredentials,
  buildPresentation,
  buildDirectPostBody,
  encodeDirectPostBody,
  preparePresentation,
  PresentationError,
  generateKeyPair,
  fromBase64url,
  verify,
} from '../src/index.js'
import type {
  VerifiableCredential,
  DcqlQuery,
  AuthorizationRequest,
} from '../src/index.js'

// ── Fixtures ─────────────────────────────────────────────────────────────────

const keys = generateKeyPair('Ed25519')

const CEDULA_VC: VerifiableCredential = {
  '@context': ['https://www.w3.org/2018/credentials/v1'],
  type: ['VerifiableCredential', 'CedulaIdentidadCR'],
  id: 'urn:uuid:cedula-001',
  issuer: 'did:web:tse.go.cr',
  issuanceDate: '2026-01-01T00:00:00Z',
  credentialSubject: {
    id: 'did:web:holder.attestto.id',
    nombre: 'Maria',
    apellidos: 'Ejemplo Ramirez',
    cedula: '1-1234-0567',
  },
}

const LICENSE_VC: VerifiableCredential = {
  '@context': ['https://www.w3.org/2018/credentials/v1'],
  type: ['VerifiableCredential', 'DrivingLicenseCR'],
  id: 'urn:uuid:license-001',
  issuer: 'did:web:cosevi.go.cr',
  issuanceDate: '2026-02-01T00:00:00Z',
  credentialSubject: {
    id: 'did:web:holder.attestto.id',
    licenseNumber: 'LIC-2026-001',
    categories: ['B1', 'A1'],
  },
}

const PASSPORT_VC: VerifiableCredential = {
  '@context': ['https://www.w3.org/2018/credentials/v1'],
  type: ['VerifiableCredential', 'PassportCR'],
  id: 'urn:uuid:passport-001',
  issuer: 'did:web:tse.go.cr',
  issuanceDate: '2026-03-01T00:00:00Z',
  credentialSubject: {
    id: 'did:web:holder.attestto.id',
    documentNumber: 'P12345',
  },
}

const ALL_CREDS = [CEDULA_VC, LICENSE_VC, PASSPORT_VC]

const DCQL_CEDULA_ONLY: DcqlQuery = {
  credentials: [
    {
      id: 'cedula',
      format: 'ldp_vc',
      meta: { vct_values: ['CedulaIdentidadCR'] },
      claims: [
        { path: ['credentialSubject', 'nombre'] },
        { path: ['credentialSubject', 'cedula'] },
      ],
    },
  ],
}

const DCQL_CEDULA_AND_LICENSE: DcqlQuery = {
  credentials: [
    { id: 'cedula', format: 'ldp_vc', meta: { vct_values: ['CedulaIdentidadCR'] } },
    { id: 'license', format: 'ldp_vc', meta: { vct_values: ['DrivingLicenseCR'] } },
  ],
  credential_sets: [
    { options: [['cedula']], required: true },
    { options: [['license']], required: false },
  ],
}

const DCQL_IMPOSSIBLE: DcqlQuery = {
  credentials: [
    { id: 'bank_vc', format: 'ldp_vc', meta: { vct_values: ['BankAccountVC'] } },
  ],
}

const BASIC_VP_REQUEST: AuthorizationRequest = {
  response_type: 'vp_token',
  client_id: 'https://verifier.attestto.com',
  nonce: 'test-nonce-123',
  state: 'test-state',
  response_mode: 'direct_post',
  response_uri: 'https://verifier.attestto.com/response',
  dcql_query: DCQL_CEDULA_AND_LICENSE,
}

// ── Tests ────────────────────────────────────────────────────────────────────

describe('OID4VP Present: matchCredentials', () => {
  it('matches a single credential by type', () => {
    const result = matchCredentials(DCQL_CEDULA_ONLY, ALL_CREDS)
    expect(result.satisfied).toBe(true)
    expect(result.matches.get('cedula')).toHaveLength(1)
    expect(result.matches.get('cedula')![0].id).toBe('urn:uuid:cedula-001')
    expect(result.missing).toEqual([])
  })

  it('matches multiple credentials', () => {
    const result = matchCredentials(DCQL_CEDULA_AND_LICENSE, ALL_CREDS)
    expect(result.satisfied).toBe(true)
    expect(result.matches.get('cedula')).toHaveLength(1)
    expect(result.matches.get('license')).toHaveLength(1)
  })

  it('reports missing credentials', () => {
    const result = matchCredentials(DCQL_IMPOSSIBLE, ALL_CREDS)
    expect(result.satisfied).toBe(false)
    expect(result.missing).toEqual(['bank_vc'])
  })

  it('satisfies when optional set is missing', () => {
    const query: DcqlQuery = {
      credentials: [
        { id: 'cedula', format: 'ldp_vc', meta: { vct_values: ['CedulaIdentidadCR'] } },
        { id: 'bank', format: 'ldp_vc', meta: { vct_values: ['BankAccountVC'] } },
      ],
      credential_sets: [
        { options: [['cedula']], required: true },
        { options: [['bank']], required: false },
      ],
    }
    const result = matchCredentials(query, ALL_CREDS)
    expect(result.satisfied).toBe(true)
    expect(result.missing).toEqual(['bank'])
  })

  it('fails when required set is missing', () => {
    const query: DcqlQuery = {
      credentials: [
        { id: 'bank', format: 'ldp_vc', meta: { vct_values: ['BankAccountVC'] } },
      ],
      credential_sets: [
        { options: [['bank']], required: true },
      ],
    }
    const result = matchCredentials(query, ALL_CREDS)
    expect(result.satisfied).toBe(false)
  })

  it('matches claims by path presence', () => {
    const query: DcqlQuery = {
      credentials: [{
        id: 'with_categories',
        format: 'ldp_vc',
        claims: [{ path: ['credentialSubject', 'categories'] }],
      }],
    }
    const result = matchCredentials(query, ALL_CREDS)
    expect(result.satisfied).toBe(true)
    expect(result.matches.get('with_categories')![0].id).toBe('urn:uuid:license-001')
  })

  it('rejects when claim path is missing', () => {
    const query: DcqlQuery = {
      credentials: [{
        id: 'need_email',
        format: 'ldp_vc',
        claims: [{ path: ['credentialSubject', 'email'] }],
      }],
    }
    const result = matchCredentials(query, ALL_CREDS)
    expect(result.satisfied).toBe(false)
  })

  it('matches claim values filter', () => {
    const query: DcqlQuery = {
      credentials: [{
        id: 'specific_issuer',
        format: 'ldp_vc',
        claims: [{ path: ['issuer'], values: ['did:web:cosevi.go.cr'] }],
      }],
    }
    const result = matchCredentials(query, ALL_CREDS)
    expect(result.satisfied).toBe(true)
    expect(result.matches.get('specific_issuer')![0].id).toBe('urn:uuid:license-001')
  })

  it('returns empty match for empty wallet', () => {
    const result = matchCredentials(DCQL_CEDULA_ONLY, [])
    expect(result.satisfied).toBe(false)
    expect(result.missing).toEqual(['cedula'])
  })
})

describe('OID4VP Present: buildPresentation', () => {
  it('builds a VP with proof', () => {
    const vp = buildPresentation([CEDULA_VC], {
      holderDid: 'did:web:holder.attestto.id',
      privateKey: keys.privateKey,
      nonce: 'test-nonce',
    })

    expect(vp['@context']).toContain('https://www.w3.org/2018/credentials/v1')
    expect(vp.type).toContain('VerifiablePresentation')
    expect(vp.holder).toBe('did:web:holder.attestto.id')
    expect(vp.verifiableCredential).toHaveLength(1)
    expect(vp.proof).toBeDefined()
    expect(vp.proof!.type).toBe('Ed25519Signature2020')
    expect(vp.proof!.proofPurpose).toBe('authentication')
    expect(vp.proof!.verificationMethod).toBe('did:web:holder.attestto.id#key-1')
    expect(vp.proof!.proofValue).toBeTruthy()
  })

  it('wraps multiple credentials', () => {
    const vp = buildPresentation([CEDULA_VC, LICENSE_VC], {
      holderDid: 'did:web:holder.attestto.id',
      privateKey: keys.privateKey,
      nonce: 'n',
    })
    expect(vp.verifiableCredential).toHaveLength(2)
  })

  it('throws for zero credentials', () => {
    expect(() =>
      buildPresentation([], {
        holderDid: 'did:web:h.com',
        privateKey: keys.privateKey,
        nonce: 'n',
      }),
    ).toThrow('zero credentials')
  })

  it('signature is verifiable', () => {
    const vp = buildPresentation([CEDULA_VC], {
      holderDid: 'did:web:holder.attestto.id',
      privateKey: keys.privateKey,
      nonce: 'verify-me',
      domain: 'https://verifier.com',
    })

    // Reconstruct the canonical payload
    const { proof, ...vpWithoutProof } = vp
    const canonical = JSON.stringify({
      ...vpWithoutProof,
      nonce: 'verify-me',
      domain: 'https://verifier.com',
    })
    const sig = fromBase64url(proof!.proofValue!)
    const valid = verify(new TextEncoder().encode(canonical), sig, keys.publicKey, 'Ed25519')
    expect(valid).toBe(true)
  })
})

describe('OID4VP Present: buildDirectPostBody', () => {
  it('builds a body with vp_token and state', () => {
    const vp = buildPresentation([CEDULA_VC], {
      holderDid: 'did:web:h.com',
      privateKey: keys.privateKey,
      nonce: 'n',
    })
    const body = buildDirectPostBody(vp, BASIC_VP_REQUEST, ['cedula'])
    expect(body.vp_token).toBeTruthy()
    expect(body.state).toBe('test-state')
    expect(body.presentation_submission).toBeDefined()
    expect(body.presentation_submission!.descriptor_map).toHaveLength(1)
    expect(body.presentation_submission!.descriptor_map[0].id).toBe('cedula')
  })

  it('encodes as form-urlencoded', () => {
    const vp = buildPresentation([CEDULA_VC], {
      holderDid: 'did:web:h.com',
      privateKey: keys.privateKey,
      nonce: 'n',
    })
    const body = buildDirectPostBody(vp, BASIC_VP_REQUEST)
    const encoded = encodeDirectPostBody(body)
    expect(encoded).toContain('vp_token=')
    expect(encoded).toContain('state=test-state')
  })
})

describe('OID4VP Present: preparePresentation (end-to-end)', () => {
  it('produces a VP + body from a satisfied request', () => {
    const result = preparePresentation(BASIC_VP_REQUEST, ALL_CREDS, {
      holderDid: 'did:web:holder.attestto.id',
      privateKey: keys.privateKey,
    })

    expect(result).not.toBeNull()
    expect(result!.vp.verifiableCredential.length).toBeGreaterThanOrEqual(1)
    expect(result!.body.vp_token).toBeTruthy()
    expect(result!.body.state).toBe('test-state')
  })

  it('returns null when query is unsatisfiable', () => {
    const request: AuthorizationRequest = {
      ...BASIC_VP_REQUEST,
      dcql_query: DCQL_IMPOSSIBLE,
    }
    const result = preparePresentation(request, ALL_CREDS, {
      holderDid: 'did:web:h.com',
      privateKey: keys.privateKey,
    })
    expect(result).toBeNull()
  })

  it('throws when request has no dcql_query', () => {
    const request: AuthorizationRequest = {
      response_type: 'vp_token',
      client_id: 'x',
      nonce: 'y',
    }
    expect(() =>
      preparePresentation(request, ALL_CREDS, {
        holderDid: 'did:web:h.com',
        privateKey: keys.privateKey,
      }),
    ).toThrow('no dcql_query')
  })

  it('binds nonce from request into VP proof', () => {
    const result = preparePresentation(BASIC_VP_REQUEST, ALL_CREDS, {
      holderDid: 'did:web:holder.attestto.id',
      privateKey: keys.privateKey,
    })

    // The nonce is bound into the signed canonical payload
    const { proof, ...vpWithoutProof } = result!.vp
    const canonical = JSON.stringify({
      ...vpWithoutProof,
      nonce: 'test-nonce-123',
      domain: 'https://verifier.attestto.com',
    })
    const sig = fromBase64url(proof!.proofValue!)
    expect(verify(new TextEncoder().encode(canonical), sig, keys.publicKey)).toBe(true)
  })
})
