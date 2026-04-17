import { describe, it, expect } from 'vitest'
import {
  createSdJwt,
  createNestedSdJwt,
  selectDisclosures,
  verifyDisclosures,
  hashDisclosure,
  encodeSdJwt,
  decodeSdJwt,
  SdJwtError,
} from '../src/index.js'
import type { Disclosure } from '../src/index.js'

// ── Fixtures ─────────────────────────────────────────────────────────────────

const CEDULA_CLAIMS = {
  nombre: 'Maria',
  apellidos: 'Ejemplo Ramirez',
  cedula: '1-1234-0567',
  nacionalidad: 'costarricense',
  fechaNacimiento: '1990-05-15',
}

const NESTED_VC_CLAIMS = {
  '@context': ['https://www.w3.org/2018/credentials/v1'],
  type: ['VerifiableCredential', 'CedulaIdentidadCR'],
  issuer: 'did:web:tse.go.cr',
  credentialSubject: {
    id: 'did:web:holder.attestto.id',
    nombre: 'Maria',
    apellidos: 'Ejemplo Ramirez',
    cedula: '1-1234-0567',
    nacionalidad: 'costarricense',
  },
}

// ── createSdJwt ──────────────────────────────────────────────────────────────

describe('SD-JWT: createSdJwt', () => {
  it('creates payload with _sd hashes for selective fields', () => {
    const result = createSdJwt(CEDULA_CLAIMS, ['cedula', 'fechaNacimiento'])

    expect(result.payload._sd).toHaveLength(2)
    expect(result.payload._sd_alg).toBe('sha-256')
    expect(result.disclosures).toHaveLength(2)

    // Non-selective fields are in cleartext
    expect(result.payload.nombre).toBe('Maria')
    expect(result.payload.apellidos).toBe('Ejemplo Ramirez')
    expect(result.payload.nacionalidad).toBe('costarricense')

    // Selective fields are NOT in cleartext
    expect(result.payload.cedula).toBeUndefined()
    expect(result.payload.fechaNacimiento).toBeUndefined()
  })

  it('creates disclosures with salt, name, value', () => {
    const result = createSdJwt(CEDULA_CLAIMS, ['cedula'])
    const [salt, name, value] = result.disclosures[0]

    expect(typeof salt).toBe('string')
    expect(salt.length).toBeGreaterThan(10) // base64url of 16 random bytes
    expect(name).toBe('cedula')
    expect(value).toBe('1-1234-0567')
  })

  it('returns no _sd when no selective fields', () => {
    const result = createSdJwt(CEDULA_CLAIMS, [])
    expect(result.payload._sd).toBeUndefined()
    expect(result.disclosures).toHaveLength(0)
    expect(result.payload.nombre).toBe('Maria')
  })

  it('handles all fields being selective', () => {
    const result = createSdJwt(CEDULA_CLAIMS, Object.keys(CEDULA_CLAIMS))
    expect(result.payload._sd).toHaveLength(5)
    expect(result.disclosures).toHaveLength(5)
    // Only _sd and _sd_alg remain
    expect(Object.keys(result.payload).sort()).toEqual(['_sd', '_sd_alg'])
  })

  it('generates unique salts per disclosure', () => {
    const result = createSdJwt(CEDULA_CLAIMS, ['nombre', 'apellidos', 'cedula'])
    const salts = result.disclosures.map(([s]) => s)
    expect(new Set(salts).size).toBe(3) // all unique
  })
})

// ── createNestedSdJwt ────────────────────────────────────────────────────────

describe('SD-JWT: createNestedSdJwt', () => {
  it('applies selective disclosure to nested paths', () => {
    const result = createNestedSdJwt(NESTED_VC_CLAIMS, [
      'credentialSubject.cedula',
      'credentialSubject.fechaNacimiento',
    ])

    // Top-level fields are in cleartext
    expect(result.payload['@context']).toBeDefined()
    expect(result.payload.issuer).toBe('did:web:tse.go.cr')

    // credentialSubject has _sd for hidden fields
    const cs = result.payload.credentialSubject as Record<string, unknown>
    expect(cs._sd).toHaveLength(1) // only cedula (fechaNacimiento doesn't exist in fixture)
    expect(cs.id).toBe('did:web:holder.attestto.id')
    expect(cs.nombre).toBe('Maria')
    expect(cs.cedula).toBeUndefined() // hidden

    expect(result.disclosures).toHaveLength(1)
    expect(result.disclosures[0][1]).toBe('cedula')
  })

  it('preserves non-selective nested objects', () => {
    const result = createNestedSdJwt(NESTED_VC_CLAIMS, [])
    expect(result.payload.credentialSubject).toEqual(NESTED_VC_CLAIMS.credentialSubject)
    expect(result.disclosures).toHaveLength(0)
  })
})

// ── selectDisclosures ────────────────────────────────────────────────────────

describe('SD-JWT: selectDisclosures', () => {
  it('selects only requested disclosures', () => {
    const sdJwt = createSdJwt(CEDULA_CLAIMS, ['nombre', 'cedula', 'fechaNacimiento'])
    const presentation = selectDisclosures(sdJwt, ['nombre'])

    expect(presentation.disclosures).toHaveLength(1)
    expect(presentation.disclosures[0][1]).toBe('nombre')
    expect(presentation.payload).toBe(sdJwt.payload) // same reference
  })

  it('returns empty disclosures when none selected', () => {
    const sdJwt = createSdJwt(CEDULA_CLAIMS, ['cedula'])
    const presentation = selectDisclosures(sdJwt, [])
    expect(presentation.disclosures).toHaveLength(0)
  })

  it('returns all when all selected', () => {
    const sdJwt = createSdJwt(CEDULA_CLAIMS, ['nombre', 'cedula'])
    const presentation = selectDisclosures(sdJwt, ['nombre', 'cedula'])
    expect(presentation.disclosures).toHaveLength(2)
  })
})

// ── verifyDisclosures ────────────────────────────────────────────────────────

describe('SD-JWT: verifyDisclosures', () => {
  it('verifies disclosed claims against _sd hashes', () => {
    const sdJwt = createSdJwt(CEDULA_CLAIMS, ['nombre', 'cedula'])
    const presentation = selectDisclosures(sdJwt, ['nombre', 'cedula'])

    const { claims, verifications } = verifyDisclosures(presentation)

    expect(verifications).toHaveLength(2)
    expect(verifications.every((v) => v.hashMatch)).toBe(true)
    expect(claims.nombre).toBe('Maria')
    expect(claims.cedula).toBe('1-1234-0567')
  })

  it('includes cleartext fields in reconstructed claims', () => {
    const sdJwt = createSdJwt(CEDULA_CLAIMS, ['cedula'])
    const presentation = selectDisclosures(sdJwt, ['cedula'])

    const { claims } = verifyDisclosures(presentation)
    expect(claims.nombre).toBe('Maria')
    expect(claims.apellidos).toBe('Ejemplo Ramirez')
    expect(claims.cedula).toBe('1-1234-0567')
  })

  it('detects tampered disclosure', () => {
    const sdJwt = createSdJwt(CEDULA_CLAIMS, ['cedula'])
    const presentation = selectDisclosures(sdJwt, ['cedula'])

    // Tamper: change the value
    const tampered: Disclosure = [presentation.disclosures[0][0], 'cedula', '9-9999-9999']
    presentation.disclosures[0] = tampered

    const { verifications } = verifyDisclosures(presentation)
    expect(verifications[0].hashMatch).toBe(false)
  })

  it('handles no disclosures (all hidden)', () => {
    const sdJwt = createSdJwt(CEDULA_CLAIMS, ['cedula'])
    const presentation = selectDisclosures(sdJwt, [])

    const { claims, verifications } = verifyDisclosures(presentation)
    expect(verifications).toHaveLength(0)
    expect(claims.cedula).toBeUndefined() // still hidden
    expect(claims.nombre).toBe('Maria') // cleartext
  })
})

// ── hashDisclosure ───────────────────────────────────────────────────────────

describe('SD-JWT: hashDisclosure', () => {
  it('produces deterministic hashes', () => {
    const d: Disclosure = ['salt123', 'name', 'value']
    const h1 = hashDisclosure(d)
    const h2 = hashDisclosure(d)
    expect(h1).toBe(h2)
  })

  it('produces different hashes for different salts', () => {
    const d1: Disclosure = ['salt-a', 'name', 'value']
    const d2: Disclosure = ['salt-b', 'name', 'value']
    expect(hashDisclosure(d1)).not.toBe(hashDisclosure(d2))
  })

  it('produces base64url output', () => {
    const d: Disclosure = ['salt', 'key', 'val']
    const h = hashDisclosure(d)
    expect(h).toMatch(/^[A-Za-z0-9_-]+$/)
  })
})

// ── encodeSdJwt / decodeSdJwt ────────────────────────────────────────────────

describe('SD-JWT: encode/decode compact format', () => {
  it('round-trips through encode → decode', () => {
    const sdJwt = createSdJwt(CEDULA_CLAIMS, ['nombre', 'cedula'])
    const presentation = selectDisclosures(sdJwt, ['nombre'])

    const compact = encodeSdJwt(presentation)
    expect(compact).toContain('~')
    expect(compact.endsWith('~')).toBe(true)

    const decoded = decodeSdJwt(compact)
    expect(decoded.payload._sd).toEqual(presentation.payload._sd)
    expect(decoded.disclosures).toHaveLength(1)
    expect(decoded.disclosures[0][1]).toBe('nombre')
    expect(decoded.disclosures[0][2]).toBe('Maria')
  })

  it('encodes with no disclosures', () => {
    const presentation = { payload: { foo: 'bar' }, disclosures: [] }
    const compact = encodeSdJwt(presentation)
    expect(compact.split('~').filter(Boolean)).toHaveLength(1) // just payload
  })

  it('throws on empty input', () => {
    expect(() => decodeSdJwt('')).toThrow(SdJwtError)
  })

  it('full issuer → holder → verifier flow', () => {
    // Issuer creates SD-JWT
    const sdJwt = createSdJwt(CEDULA_CLAIMS, ['cedula', 'fechaNacimiento'])

    // Holder selects to reveal only nombre (not in selective fields, so always visible)
    // and cedula (selective, chosen to reveal)
    const presentation = selectDisclosures(sdJwt, ['cedula'])

    // Encode for transport
    const compact = encodeSdJwt(presentation)

    // Verifier decodes and verifies
    const decoded = decodeSdJwt(compact)
    const { claims, verifications } = verifyDisclosures(decoded)

    // cedula was revealed and verified
    expect(claims.cedula).toBe('1-1234-0567')
    expect(verifications.find((v) => v.claimName === 'cedula')?.hashMatch).toBe(true)

    // fechaNacimiento was NOT revealed
    expect(claims.fechaNacimiento).toBeUndefined()

    // Cleartext fields are present
    expect(claims.nombre).toBe('Maria')
    expect(claims.apellidos).toBe('Ejemplo Ramirez')
  })
})
