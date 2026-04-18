import { describe, it, expect } from 'vitest'
import { VCIssuer, VCVerifier, generateKeyPair } from '../src/index.js'
import type { SchemaPlugin } from '../src/index.js'

describe('Generic VC SDK', () => {
  const keys = generateKeyPair()

  describe('Issue any credential type', () => {
    it('issues a custom credential without plugins', async () => {
      const issuer = new VCIssuer({
        did: 'did:web:university.example.com',
        privateKey: keys.privateKey,
      })

      const vc = await issuer.issue({
        type: 'UniversityDegree',
        context: 'https://schemas.example.org/education/v1',
        subjectDid: 'did:web:student.attestto.id',
        claims: {
          degree: {
            name: 'Computer Science',
            level: 'Bachelor',
            graduationDate: '2026-06-15',
          },
        },
      })

      expect(vc.type).toEqual(['VerifiableCredential', 'UniversityDegree'])
      expect(vc['@context']).toContain('https://schemas.example.org/education/v1')
      expect(vc.credentialSubject.degree).toBeDefined()
      expect(vc.proof).toBeDefined()
    })

    it('issues with multiple types', async () => {
      const issuer = new VCIssuer({
        did: 'did:web:bank.attestto.id',
        privateKey: keys.privateKey,
      })

      const vc = await issuer.issue({
        type: ['BankKYC', 'IdentityVerification'],
        context: 'https://schemas.attestto.org/banking/v1',
        subjectDid: 'did:web:customer.attestto.id',
        claims: {
          kycLevel: 'enhanced',
          verificationDate: '2026-04-01',
          verifiedBy: 'did:web:bank.attestto.id',
        },
      })

      expect(vc.type).toContain('BankKYC')
      expect(vc.type).toContain('IdentityVerification')
    })

    it('issues with no custom context', async () => {
      const issuer = new VCIssuer({
        did: 'did:key:z6Mktest',
        privateKey: keys.privateKey,
      })

      const vc = await issuer.issue({
        type: 'SimpleAttestation',
        subjectDid: 'did:web:someone.attestto.id',
        claims: { message: 'This person is verified' },
      })

      expect(vc['@context']).toEqual(['https://www.w3.org/2018/credentials/v1'])
      expect(vc.credentialSubject.message).toBe('This person is verified')
    })
  })

  describe('Schema plugins', () => {
    it('auto-adds context and wraps claims when plugin matches', async () => {
      const educationPlugin: SchemaPlugin = {
        context: 'https://schemas.example.org/education/v1',
        types: ['UniversityDegree', 'HighSchoolDiploma'],
        propertyMap: {
          UniversityDegree: 'degree',
          HighSchoolDiploma: 'diploma',
        },
      }

      const issuer = new VCIssuer({
        did: 'did:web:ucr.ac.cr',
        privateKey: keys.privateKey,
      })
      issuer.use(educationPlugin)

      const vc = await issuer.issue({
        type: 'UniversityDegree',
        subjectDid: 'did:web:student.attestto.id',
        claims: {
          name: 'Computer Science',
          level: 'Bachelor',
        },
      })

      // Context auto-added from plugin
      expect(vc['@context']).toContain('https://schemas.example.org/education/v1')
      // Claims wrapped in 'degree' property from propertyMap
      expect(vc.credentialSubject.degree).toBeDefined()
      const degree = vc.credentialSubject.degree as Record<string, unknown>
      expect(degree.name).toBe('Computer Science')
    })

    it('does not wrap claims if they already have the property', async () => {
      const plugin: SchemaPlugin = {
        context: 'https://schemas.example.org/health/v1',
        types: ['MedicalCertificate'],
        propertyMap: { MedicalCertificate: 'certificate' },
      }

      const issuer = new VCIssuer({
        did: 'did:web:hospital.example.com',
        privateKey: keys.privateKey,
      })
      issuer.use(plugin)

      const vc = await issuer.issue({
        type: 'MedicalCertificate',
        subjectDid: 'did:web:patient.attestto.id',
        claims: {
          certificate: { status: 'fit', validUntil: '2027-01-01' },
        },
      })

      // Claims already wrapped — should not double-wrap
      expect(vc.credentialSubject.certificate).toBeDefined()
      const cert = vc.credentialSubject.certificate as Record<string, unknown>
      expect(cert.status).toBe('fit')
    })

    it('supports multiple plugins', async () => {
      const issuer = new VCIssuer({
        did: 'did:web:multi-issuer.attestto.id',
        privateKey: keys.privateKey,
      })

      issuer
        .use({
          context: 'https://schemas.example.org/education/v1',
          types: ['UniversityDegree'],
        })
        .use({
          context: 'https://schemas.example.org/employment/v1',
          types: ['EmploymentCredential'],
        })

      const vc1 = await issuer.issue({
        type: 'UniversityDegree',
        subjectDid: 'did:web:person.attestto.id',
        claims: { name: 'Engineering' },
      })

      const vc2 = await issuer.issue({
        type: 'EmploymentCredential',
        subjectDid: 'did:web:person.attestto.id',
        claims: { employer: 'Attestto', role: 'Engineer' },
      })

      expect(vc1['@context']).toContain('https://schemas.example.org/education/v1')
      expect(vc1['@context']).not.toContain('https://schemas.example.org/employment/v1')

      expect(vc2['@context']).toContain('https://schemas.example.org/employment/v1')
      expect(vc2['@context']).not.toContain('https://schemas.example.org/education/v1')
    })
  })

  describe('Verification', () => {
    it('verifies a generic credential', async () => {
      const issuer = new VCIssuer({
        did: 'did:web:issuer.attestto.id',
        privateKey: keys.privateKey,
      })

      const vc = await issuer.issue({
        type: 'GenericAttestation',
        subjectDid: 'did:web:holder.attestto.id',
        expirationDate: '2030-01-01T00:00:00Z',
        claims: { verified: true },
      })

      const verifier = new VCVerifier()
      const result = await verifier.verifyWithKey(vc, keys.publicKey, 'Ed25519', {
        expectedType: 'GenericAttestation',
        expectedIssuer: 'did:web:issuer.attestto.id',
      })

      expect(result.valid).toBe(true)
    })

    it('verifies with expected context', async () => {
      const issuer = new VCIssuer({
        did: 'did:web:issuer.attestto.id',
        privateKey: keys.privateKey,
      })

      const vc = await issuer.issue({
        type: 'CustomVC',
        context: 'https://schemas.custom.org/v1',
        subjectDid: 'did:web:holder.attestto.id',
        claims: { data: 'test' },
      })

      const verifier = new VCVerifier()
      const result = await verifier.verifyWithKey(vc, keys.publicKey, 'Ed25519', {
        expectedContext: 'https://schemas.custom.org/v1',
      })

      expect(result.valid).toBe(true)
    })

    it('fails with wrong context', async () => {
      const issuer = new VCIssuer({
        did: 'did:web:issuer.attestto.id',
        privateKey: keys.privateKey,
      })

      const vc = await issuer.issue({
        type: 'CustomVC',
        context: 'https://schemas.custom.org/v1',
        subjectDid: 'did:web:holder.attestto.id',
        claims: { data: 'test' },
      })

      const verifier = new VCVerifier()
      const result = await verifier.verifyWithKey(vc, keys.publicKey, 'Ed25519', {
        expectedContext: 'https://schemas.wrong.org/v1',
      })

      expect(result.valid).toBe(false)
    })

    it('detects tampered generic credential', async () => {
      const issuer = new VCIssuer({
        did: 'did:web:issuer.attestto.id',
        privateKey: keys.privateKey,
      })

      const vc = await issuer.issue({
        type: 'GenericAttestation',
        subjectDid: 'did:web:holder.attestto.id',
        claims: { score: 95 },
      })

      // Tamper
      const claims = vc.credentialSubject as Record<string, unknown>
      claims.score = 100

      const verifier = new VCVerifier()
      const result = await verifier.verifyWithKey(vc, keys.publicKey, 'Ed25519')

      expect(result.valid).toBe(false)
      expect(result.errors).toContain('Invalid signature on proof')
    })
  })

  describe('Key management', () => {
    it('works with ES256', async () => {
      const es256Keys = generateKeyPair('ES256')
      const issuer = new VCIssuer({
        did: 'did:web:p256-issuer.attestto.id',
        privateKey: es256Keys.privateKey,
        algorithm: 'ES256',
      })

      const vc = await issuer.issue({
        type: 'P256Credential',
        subjectDid: 'did:web:holder.attestto.id',
        claims: { test: true },
      })

      expect(vc.proof!.type).toBe('EcdsaSecp256r1Signature2019')

      const verifier = new VCVerifier()
      const result = await verifier.verifyWithKey(vc, es256Keys.publicKey, 'ES256')

      expect(result.valid).toBe(true)
    })
  })
})
