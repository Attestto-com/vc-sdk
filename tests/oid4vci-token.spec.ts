import { describe, it, expect } from 'vitest'
import {
  getIssuerMetadataUrl,
  parseIssuerMetadata,
  getTokenEndpoint,
  buildPreAuthorizedTokenRequest,
  buildAuthorizationCodeTokenRequest,
  encodeTokenRequest,
  parseTokenResponse,
  buildProofJwt,
  buildCredentialRequest,
  parseCredentialResponse,
  TokenError,
  PRE_AUTHORIZED_CODE_GRANT,
  generateKeyPair,
  fromBase64url,
} from '../src/index.js'

// ── Fixtures ─────────────────────────────────────────────────────────────────

const OFFER = {
  credential_issuer: 'https://issuer.attestto.com',
  credential_configuration_ids: ['CedulaIdentidadCR'],
  grants: {
    [PRE_AUTHORIZED_CODE_GRANT]: {
      'pre-authorized_code': 'SplxlOBeZQQYbYS6WxSbIA',
      tx_code: { length: 4, input_mode: 'numeric' as const },
    },
  },
}

const ISSUER_METADATA = {
  credential_issuer: 'https://issuer.attestto.com',
  credential_endpoint: 'https://issuer.attestto.com/credentials',
  token_endpoint: 'https://issuer.attestto.com/token',
}

// ── Tests ────────────────────────────────────────────────────────────────────

describe('OID4VCI Token: Issuer Metadata', () => {
  it('builds well-known URL', () => {
    expect(getIssuerMetadataUrl('https://issuer.attestto.com')).toBe(
      'https://issuer.attestto.com/.well-known/openid-credential-issuer',
    )
  })

  it('strips trailing slash', () => {
    expect(getIssuerMetadataUrl('https://issuer.attestto.com/')).toBe(
      'https://issuer.attestto.com/.well-known/openid-credential-issuer',
    )
  })

  it('parses valid metadata', () => {
    const meta = parseIssuerMetadata(ISSUER_METADATA)
    expect(meta.credential_issuer).toBe('https://issuer.attestto.com')
    expect(meta.credential_endpoint).toBe('https://issuer.attestto.com/credentials')
  })

  it('rejects metadata without credential_issuer', () => {
    expect(() => parseIssuerMetadata({ credential_endpoint: 'x' })).toThrow('credential_issuer')
  })

  it('rejects metadata without credential_endpoint', () => {
    expect(() => parseIssuerMetadata({ credential_issuer: 'x' })).toThrow('credential_endpoint')
  })

  it('resolves token endpoint from metadata', () => {
    expect(getTokenEndpoint(ISSUER_METADATA as any)).toBe('https://issuer.attestto.com/token')
  })

  it('falls back to /token when no token_endpoint', () => {
    const meta = { credential_issuer: 'https://x.com', credential_endpoint: 'https://x.com/creds' }
    expect(getTokenEndpoint(meta as any)).toBe('https://x.com/token')
  })
})

describe('OID4VCI Token: Request Builders', () => {
  it('builds pre-authorized token request', () => {
    const req = buildPreAuthorizedTokenRequest(OFFER)
    expect(req.grant_type).toBe(PRE_AUTHORIZED_CODE_GRANT)
    expect(req['pre-authorized_code']).toBe('SplxlOBeZQQYbYS6WxSbIA')
    expect(req.tx_code).toBeUndefined()
  })

  it('includes tx_code when provided', () => {
    const req = buildPreAuthorizedTokenRequest(OFFER, '1234')
    expect(req.tx_code).toBe('1234')
  })

  it('throws if offer has no pre-auth grant', () => {
    const offer = { credential_issuer: 'x', credential_configuration_ids: ['Y'] }
    expect(() => buildPreAuthorizedTokenRequest(offer)).toThrow('pre-authorized_code grant')
  })

  it('builds authorization code token request', () => {
    const req = buildAuthorizationCodeTokenRequest('code123', 'https://app.com/cb', 'verifier456')
    expect(req.grant_type).toBe('authorization_code')
    expect(req.code).toBe('code123')
    expect(req.redirect_uri).toBe('https://app.com/cb')
    expect(req.code_verifier).toBe('verifier456')
  })

  it('encodes token request as form-urlencoded', () => {
    const req = buildPreAuthorizedTokenRequest(OFFER, '9999')
    const encoded = encodeTokenRequest(req)
    expect(encoded).toContain('grant_type=')
    expect(encoded).toContain('pre-authorized_code=SplxlOBeZQQYbYS6WxSbIA')
    expect(encoded).toContain('tx_code=9999')
  })
})

describe('OID4VCI Token: Response Parser', () => {
  it('parses a valid token response', () => {
    const res = parseTokenResponse({
      access_token: 'eyJhbGci.eyJzdWIi.SflKxw',
      token_type: 'Bearer',
      expires_in: 86400,
      c_nonce: 'tZignsnFbp',
      c_nonce_expires_in: 300,
    })
    expect(res.access_token).toBe('eyJhbGci.eyJzdWIi.SflKxw')
    expect(res.token_type).toBe('Bearer')
    expect(res.c_nonce).toBe('tZignsnFbp')
  })

  it('defaults token_type to Bearer', () => {
    const res = parseTokenResponse({ access_token: 'tok' })
    expect(res.token_type).toBe('Bearer')
  })

  it('throws on error response', () => {
    expect(() =>
      parseTokenResponse({ error: 'invalid_grant', error_description: 'Code expired' }),
    ).toThrow('invalid_grant')
  })

  it('throws on missing access_token', () => {
    expect(() => parseTokenResponse({})).toThrow('access_token')
  })
})

describe('OID4VCI Token: Proof of Possession JWT', () => {
  it('builds a valid JWT structure', () => {
    const keys = generateKeyPair('Ed25519')
    const jwt = buildProofJwt({
      holderDid: 'did:web:holder.attestto.id',
      issuerUrl: 'https://issuer.attestto.com',
      nonce: 'tZignsnFbp',
      privateKey: keys.privateKey,
    })

    const parts = jwt.split('.')
    expect(parts).toHaveLength(3)

    const header = JSON.parse(new TextDecoder().decode(fromBase64url(parts[0])))
    expect(header.alg).toBe('EdDSA')
    expect(header.typ).toBe('openid4vci-proof+jwt')
    expect(header.kid).toBe('did:web:holder.attestto.id#key-1')

    const payload = JSON.parse(new TextDecoder().decode(fromBase64url(parts[1])))
    expect(payload.iss).toBe('did:web:holder.attestto.id')
    expect(payload.aud).toBe('https://issuer.attestto.com')
    expect(payload.nonce).toBe('tZignsnFbp')
    expect(payload.iat).toBeTypeOf('number')
  })

  it('uses ES256 when specified', () => {
    const keys = generateKeyPair('ES256')
    const jwt = buildProofJwt({
      holderDid: 'did:web:holder.attestto.id',
      issuerUrl: 'https://issuer.attestto.com',
      nonce: 'abc',
      privateKey: keys.privateKey,
      algorithm: 'ES256',
    })

    const header = JSON.parse(new TextDecoder().decode(fromBase64url(jwt.split('.')[0])))
    expect(header.alg).toBe('ES256')
  })

  it('uses custom keyId', () => {
    const keys = generateKeyPair('Ed25519')
    const jwt = buildProofJwt({
      holderDid: 'did:web:h.com',
      issuerUrl: 'https://i.com',
      nonce: 'n',
      privateKey: keys.privateKey,
      keyId: '#signing-key-2',
    })
    const header = JSON.parse(new TextDecoder().decode(fromBase64url(jwt.split('.')[0])))
    expect(header.kid).toBe('did:web:h.com#signing-key-2')
  })
})

describe('OID4VCI Token: Credential Request', () => {
  it('builds a request without proof', () => {
    const req = buildCredentialRequest('CedulaIdentidadCR')
    expect(req.credential_configuration_id).toBe('CedulaIdentidadCR')
    expect(req.proof).toBeUndefined()
  })

  it('builds a request with proof JWT', () => {
    const req = buildCredentialRequest('CedulaIdentidadCR', 'header.payload.sig')
    expect(req.proof).toEqual({ proof_type: 'jwt', jwt: 'header.payload.sig' })
  })
})

describe('OID4VCI Token: Credential Response', () => {
  it('parses a single credential response', () => {
    const res = parseCredentialResponse({
      credential: { type: ['VerifiableCredential', 'CedulaIdentidadCR'] },
      c_nonce: 'new-nonce',
    })
    expect(res.credential).toBeDefined()
    expect(res.c_nonce).toBe('new-nonce')
  })

  it('parses a batch credential response', () => {
    const res = parseCredentialResponse({
      credentials: [
        { credential: 'jwt1' },
        { credential: 'jwt2' },
      ],
    })
    expect(res.credentials).toHaveLength(2)
  })

  it('parses a deferred response', () => {
    const res = parseCredentialResponse({ transaction_id: 'tx-123' })
    expect(res.transaction_id).toBe('tx-123')
  })

  it('throws on error response', () => {
    expect(() =>
      parseCredentialResponse({ error: 'invalid_proof', error_description: 'Bad nonce' }),
    ).toThrow('invalid_proof')
  })
})
