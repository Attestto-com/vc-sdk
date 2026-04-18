import { describe, it, expect } from 'vitest'
import {
  VCIssuer,
  VCVerifier,
  generateKeyPair,
  agreementSchema,
  presenceSchema,
  chatSchemas,
} from '../src/index.js'
import type { AgreementSubject, PresenceSubject, PublicKeyResolver } from '../src/index.js'

describe('Chat Credential Schemas', () => {
  const keysA = generateKeyPair('Ed25519')
  const keysB = generateKeyPair('Ed25519')

  const issuerA = new VCIssuer({
    did: 'did:sns:alice.attestto.sol',
    privateKey: keysA.privateKey,
  })

  const issuerB = new VCIssuer({
    did: 'did:sns:bob.attestto.sol',
    privateKey: keysB.privateKey,
  })

  const resolver: PublicKeyResolver = async (did) => {
    const map: Record<string, Uint8Array> = {
      'did:sns:alice.attestto.sol': keysA.publicKey,
      'did:sns:bob.attestto.sol': keysB.publicKey,
    }
    const pk = map[did]
    return pk ? { publicKey: pk, algorithm: 'Ed25519' } : null
  }

  describe('PresenceCredential', () => {
    it('issues a short-lived presence credential', async () => {
      const issuer = new VCIssuer({
        did: 'did:sns:alice.attestto.sol',
        privateKey: keysA.privateKey,
      })
      issuer.use(presenceSchema)

      const fiveMinutes = new Date(Date.now() + 5 * 60 * 1000).toISOString()

      const vc = await issuer.issue({
        type: 'PresenceCredential',
        subjectDid: 'did:sns:alice.attestto.sol',
        claims: {
          did: 'did:sns:alice.attestto.sol',
          method: 'device-biometric',
          timestamp: new Date().toISOString(),
        } satisfies PresenceSubject,
        expirationDate: fiveMinutes,
      })

      expect(vc.type).toContain('PresenceCredential')
      expect(vc['@context']).toContain('https://schemas.attestto.org/chat/v1')
      expect(vc.expirationDate).toBe(fiveMinutes)
      expect(vc.credentialSubject.presence).toBeDefined()
      expect((vc.credentialSubject.presence as PresenceSubject).method).toBe('device-biometric')
    })

    it('verifies a presence credential', async () => {
      const issuer = new VCIssuer({
        did: 'did:sns:alice.attestto.sol',
        privateKey: keysA.privateKey,
      })
      issuer.use(presenceSchema)

      const vc = await issuer.issue({
        type: 'PresenceCredential',
        subjectDid: 'did:sns:alice.attestto.sol',
        claims: {
          did: 'did:sns:alice.attestto.sol',
          method: 'device-biometric',
          timestamp: new Date().toISOString(),
        } satisfies PresenceSubject,
        expirationDate: new Date(Date.now() + 300_000).toISOString(),
      })

      const verifier = new VCVerifier({ resolvePublicKey: resolver })
      const result = await verifier.verify(vc)
      expect(result.valid).toBe(true)
    })
  })

  describe('AgreementCredential', () => {
    it('issues an agreement credential with multi-party signing', async () => {
      const issuerWithSchema = new VCIssuer({
        did: 'did:sns:alice.attestto.sol',
        privateKey: keysA.privateKey,
      })
      issuerWithSchema.use(agreementSchema)

      const claims: AgreementSubject = {
        parties: [
          { did: 'did:sns:alice.attestto.sol', role: 'buyer' },
          { did: 'did:sns:bob.attestto.sol', role: 'seller' },
        ],
        terms: [
          {
            obligation: 'Pay $500 for consulting services',
            responsibleParty: 'did:sns:alice.attestto.sol',
            deadline: '2026-05-01T00:00:00Z',
            amount: { value: 500, currency: 'USD' },
          },
          {
            obligation: 'Deliver final report',
            responsibleParty: 'did:sns:bob.attestto.sol',
            deadline: '2026-04-28T00:00:00Z',
          },
        ],
        conversationRef: {
          channelId: 'channel-abc-123',
          messageRange: ['msg-001', 'msg-042'],
          messageCount: 42,
          hash: 'sha256-conversation-hash',
        },
        presenceProofs: [
          {
            signer: 'did:sns:alice.attestto.sol',
            presenceCredentialHash: 'sha256-presence-alice',
            method: 'device-biometric',
            timestamp: new Date().toISOString(),
          },
          {
            signer: 'did:sns:bob.attestto.sol',
            presenceCredentialHash: 'sha256-presence-bob',
            method: 'device-biometric',
            timestamp: new Date().toISOString(),
          },
        ],
        extractedBy: 'ai',
        reviewedBy: ['did:sns:alice.attestto.sol', 'did:sns:bob.attestto.sol'],
      }

      const vc = await issuerWithSchema.issue({
        type: 'AgreementCredential',
        subjectDid: 'did:sns:alice.attestto.sol',
        claims,
      })

      expect(vc.type).toContain('AgreementCredential')
      expect(vc['@context']).toContain('https://schemas.attestto.org/chat/v1')

      // Add second party signature
      const coSigned = VCIssuer.addProof(vc, issuerB)
      const proofs = coSigned.proof as Array<{ verificationMethod: string }>
      expect(proofs).toHaveLength(2)

      // Verify both signatures
      const verifier = new VCVerifier({ resolvePublicKey: resolver })
      const result = await verifier.verify(coSigned)
      expect(result.valid).toBe(true)
    })

    it('includes referenced attachments', async () => {
      const issuer = new VCIssuer({
        did: 'did:sns:alice.attestto.sol',
        privateKey: keysA.privateKey,
      })
      issuer.use(agreementSchema)

      const claims: AgreementSubject = {
        parties: [{ did: 'did:sns:alice.attestto.sol', role: 'tenant' }],
        terms: [{ obligation: 'Pay rent', responsibleParty: 'did:sns:alice.attestto.sol' }],
        conversationRef: {
          channelId: 'ch-1',
          messageRange: ['a', 'b'],
          messageCount: 5,
          hash: 'h',
        },
        referencedAttachments: [
          {
            type: 'vault-reference',
            hash: 'sha256-property-vc',
            summary: 'Property inspection report — folio X-12345',
          },
        ],
        presenceProofs: [{
          signer: 'did:sns:alice.attestto.sol',
          presenceCredentialHash: 'h',
          method: 'device-biometric',
          timestamp: new Date().toISOString(),
        }],
        extractedBy: 'ai',
        reviewedBy: ['did:sns:alice.attestto.sol'],
      }

      const vc = await issuer.issue({
        type: 'AgreementCredential',
        subjectDid: 'did:sns:alice.attestto.sol',
        claims,
      })

      const agreement = vc.credentialSubject.agreement as AgreementSubject
      expect(agreement.referencedAttachments).toHaveLength(1)
      expect(agreement.referencedAttachments![0].summary).toContain('folio X-12345')
    })
  })

  describe('chatSchemas combined plugin', () => {
    it('handles both credential types', async () => {
      const issuer = new VCIssuer({
        did: 'did:sns:alice.attestto.sol',
        privateKey: keysA.privateKey,
      })
      issuer.use(chatSchemas)

      const presence = await issuer.issue({
        type: 'PresenceCredential',
        subjectDid: 'did:sns:alice.attestto.sol',
        claims: {
          did: 'did:sns:alice.attestto.sol',
          method: 'device-biometric',
          timestamp: new Date().toISOString(),
        } satisfies PresenceSubject,
        expirationDate: new Date(Date.now() + 300_000).toISOString(),
      })

      const agreement = await issuer.issue({
        type: 'AgreementCredential',
        subjectDid: 'did:sns:alice.attestto.sol',
        claims: {
          parties: [{ did: 'did:sns:alice.attestto.sol', role: 'party' }],
          terms: [],
          conversationRef: { channelId: 'x', messageRange: ['a', 'b'], messageCount: 1, hash: 'h' },
          presenceProofs: [],
          extractedBy: 'manual',
          reviewedBy: [],
        } satisfies AgreementSubject,
      })

      // Both should have the chat context
      expect(presence['@context']).toContain('https://schemas.attestto.org/chat/v1')
      expect(agreement['@context']).toContain('https://schemas.attestto.org/chat/v1')

      // Each should wrap claims in its own property
      expect(presence.credentialSubject.presence).toBeDefined()
      expect(agreement.credentialSubject.agreement).toBeDefined()
    })
  })
})
