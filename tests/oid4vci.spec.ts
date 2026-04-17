import { describe, it, expect } from 'vitest'
import {
  parseCredentialOffer,
  hasPreAuthorizedCode,
  hasAuthorizationCode,
  requiresTxCode,
  CredentialOfferError,
  PRE_AUTHORIZED_CODE_GRANT,
} from '../src/oid4vci.js'

// ── Fixtures ─────────────────────────────────────────────────────────────────

const BASIC_OFFER = {
  credential_issuer: 'https://issuer.attestto.com',
  credential_configuration_ids: ['CedulaIdentidadCR'],
}

const PRE_AUTH_OFFER = {
  credential_issuer: 'https://cosevi.go.cr',
  credential_configuration_ids: ['DrivingLicenseCR', 'TheoreticalTestResult'],
  grants: {
    [PRE_AUTHORIZED_CODE_GRANT]: {
      'pre-authorized_code': 'SplxlOBeZQQYbYS6WxSbIA',
      tx_code: {
        length: 4,
        input_mode: 'numeric' as const,
        description: 'Codigo enviado por SMS',
      },
    },
  },
}

const AUTH_CODE_OFFER = {
  credential_issuer: 'https://colegio-abogados.or.cr',
  credential_configuration_ids: ['ColegioAbogadosCRVC'],
  grants: {
    authorization_code: {
      issuer_state: 'eyJhbGciOiJSU0Et',
    },
  },
}

const DUAL_GRANT_OFFER = {
  credential_issuer: 'https://issuer.attestto.com',
  credential_configuration_ids: ['IdentityVC'],
  grants: {
    authorization_code: {},
    [PRE_AUTHORIZED_CODE_GRANT]: {
      'pre-authorized_code': 'abc123',
    },
  },
}

// ── Tests ────────────────────────────────────────────────────────────────────

describe('OID4VCI: parseCredentialOffer', () => {
  describe('from JSON object', () => {
    it('parses a minimal offer', () => {
      const result = parseCredentialOffer(BASIC_OFFER)
      expect(result.source).toBe('value')
      expect(result.payload.credential_issuer).toBe('https://issuer.attestto.com')
      expect(result.payload.credential_configuration_ids).toEqual(['CedulaIdentidadCR'])
      expect(result.payload.grants).toBeUndefined()
    })

    it('parses a pre-authorized code offer with tx_code', () => {
      const result = parseCredentialOffer(PRE_AUTH_OFFER)
      const grant = result.payload.grants?.[PRE_AUTHORIZED_CODE_GRANT]
      expect(grant).toBeDefined()
      expect(grant!['pre-authorized_code']).toBe('SplxlOBeZQQYbYS6WxSbIA')
      expect(grant!.tx_code?.length).toBe(4)
      expect(grant!.tx_code?.input_mode).toBe('numeric')
      expect(grant!.tx_code?.description).toBe('Codigo enviado por SMS')
    })

    it('parses an authorization code offer', () => {
      const result = parseCredentialOffer(AUTH_CODE_OFFER)
      expect(result.payload.grants?.authorization_code?.issuer_state).toBe('eyJhbGciOiJSU0Et')
    })

    it('parses a dual-grant offer', () => {
      const result = parseCredentialOffer(DUAL_GRANT_OFFER)
      expect(result.payload.grants?.authorization_code).toBeDefined()
      expect(result.payload.grants?.[PRE_AUTHORIZED_CODE_GRANT]).toBeDefined()
    })

    it('preserves multiple credential_configuration_ids', () => {
      const result = parseCredentialOffer(PRE_AUTH_OFFER)
      expect(result.payload.credential_configuration_ids).toEqual([
        'DrivingLicenseCR',
        'TheoreticalTestResult',
      ])
    })
  })

  describe('from JSON string', () => {
    it('parses a JSON string', () => {
      const result = parseCredentialOffer(JSON.stringify(BASIC_OFFER))
      expect(result.payload.credential_issuer).toBe('https://issuer.attestto.com')
    })
  })

  describe('from openid-credential-offer:// URI', () => {
    it('parses credential_offer by value', () => {
      const uri = `openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify(BASIC_OFFER))}`
      const result = parseCredentialOffer(uri)
      expect(result.source).toBe('value')
      expect(result.originalUri).toBe(uri)
      expect(result.payload.credential_issuer).toBe('https://issuer.attestto.com')
    })

    it('throws for credential_offer_uri (by reference)', () => {
      const uri = 'openid-credential-offer://?credential_offer_uri=https://issuer.example.com/offer/123'
      expect(() => parseCredentialOffer(uri)).toThrow(CredentialOfferError)
      expect(() => parseCredentialOffer(uri)).toThrow('credential_offer_uri detected')
    })

    it('throws for URI without query params', () => {
      expect(() => parseCredentialOffer('openid-credential-offer://')).toThrow('no query parameters')
    })
  })

  describe('validation errors', () => {
    it('rejects missing credential_issuer', () => {
      expect(() =>
        parseCredentialOffer({ credential_configuration_ids: ['X'] }),
      ).toThrow('credential_issuer is required')
    })

    it('rejects empty credential_configuration_ids', () => {
      expect(() =>
        parseCredentialOffer({ credential_issuer: 'https://x.com', credential_configuration_ids: [] }),
      ).toThrow('credential_configuration_ids is required and must be a non-empty array')
    })

    it('rejects non-string credential_configuration_ids', () => {
      expect(() =>
        parseCredentialOffer({
          credential_issuer: 'https://x.com',
          credential_configuration_ids: [123 as unknown as string],
        }),
      ).toThrow('non-empty string')
    })

    it('rejects pre-authorized_code grant without code', () => {
      expect(() =>
        parseCredentialOffer({
          credential_issuer: 'https://x.com',
          credential_configuration_ids: ['X'],
          grants: { [PRE_AUTHORIZED_CODE_GRANT]: {} },
        }),
      ).toThrow('pre-authorized_code')
    })

    it('rejects unrecognized format', () => {
      expect(() => parseCredentialOffer('not-a-valid-input')).toThrow('Unrecognized')
    })
  })
})

describe('OID4VCI: helper functions', () => {
  it('hasPreAuthorizedCode detects pre-auth grant', () => {
    expect(hasPreAuthorizedCode(PRE_AUTH_OFFER)).toBe(true)
    expect(hasPreAuthorizedCode(AUTH_CODE_OFFER)).toBe(false)
    expect(hasPreAuthorizedCode(BASIC_OFFER)).toBe(false)
  })

  it('hasAuthorizationCode detects auth code grant', () => {
    expect(hasAuthorizationCode(AUTH_CODE_OFFER)).toBe(true)
    expect(hasAuthorizationCode(PRE_AUTH_OFFER)).toBe(false)
  })

  it('requiresTxCode detects tx_code presence', () => {
    expect(requiresTxCode(PRE_AUTH_OFFER)).toBe(true)
    expect(requiresTxCode(DUAL_GRANT_OFFER)).toBe(false)
  })
})
