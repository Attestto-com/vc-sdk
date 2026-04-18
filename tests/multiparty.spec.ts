import { describe, it, expect } from 'vitest'
import { VCIssuer, VCVerifier, generateKeyPair } from '../src/index.js'
import type { PublicKeyResolver } from '../src/index.js'

describe('Multi-party VC signing', () => {
  const keysA = generateKeyPair('Ed25519')
  const keysB = generateKeyPair('Ed25519')
  const keysC = generateKeyPair('Ed25519')

  const issuerA = new VCIssuer({
    did: 'did:sns:alice.attestto.sol',
    privateKey: keysA.privateKey,
    keyId: '#key-1',
  })

  const issuerB = new VCIssuer({
    did: 'did:sns:bob.attestto.sol',
    privateKey: keysB.privateKey,
    keyId: '#key-1',
  })

  const issuerC = new VCIssuer({
    did: 'did:sns:charlie.attestto.sol',
    privateKey: keysC.privateKey,
    keyId: '#key-1',
  })

  const resolver: PublicKeyResolver = async (did, keyId) => {
    const map: Record<string, Uint8Array> = {
      'did:sns:alice.attestto.sol': keysA.publicKey,
      'did:sns:bob.attestto.sol': keysB.publicKey,
      'did:sns:charlie.attestto.sol': keysC.publicKey,
    }
    const pk = map[did]
    return pk ? { publicKey: pk, algorithm: 'Ed25519' } : null
  }

  it('single-signer credentials still work (backward compatibility)', async () => {
    const vc = await issuerA.issue({
      type: 'SimpleAttestation',
      subjectDid: 'did:sns:holder.attestto.sol',
      claims: { message: 'test' },
    })

    // proof is a single object, not array
    expect(vc.proof).toBeDefined()
    expect(Array.isArray(vc.proof)).toBe(false)

    const verifier = new VCVerifier({ resolvePublicKey: resolver })
    const result = await verifier.verify(vc)
    expect(result.valid).toBe(true)
  })

  it('two-party signing produces proof array', async () => {
    const vc = await issuerA.issue({
      type: 'AgreementCredential',
      subjectDid: 'did:sns:alice.attestto.sol',
      claims: {
        parties: [
          { did: 'did:sns:alice.attestto.sol', role: 'buyer' },
          { did: 'did:sns:bob.attestto.sol', role: 'seller' },
        ],
        terms: [{ obligation: 'Pay $500', responsibleParty: 'did:sns:alice.attestto.sol' }],
      },
    })

    // Add Party B's signature
    const coSigned = VCIssuer.addProof(vc, issuerB)

    expect(Array.isArray(coSigned.proof)).toBe(true)
    const proofs = coSigned.proof as Array<{ verificationMethod: string }>
    expect(proofs).toHaveLength(2)
    expect(proofs[0].verificationMethod).toBe('did:sns:alice.attestto.sol#key-1')
    expect(proofs[1].verificationMethod).toBe('did:sns:bob.attestto.sol#key-1')
  })

  it('verifier validates all proofs in array', async () => {
    const vc = await issuerA.issue({
      type: 'AgreementCredential',
      subjectDid: 'did:sns:alice.attestto.sol',
      claims: { terms: ['test'] },
    })
    const coSigned = VCIssuer.addProof(vc, issuerB)

    const verifier = new VCVerifier({ resolvePublicKey: resolver })
    const result = await verifier.verify(coSigned)

    expect(result.valid).toBe(true)
    // Should have key resolution + signature checks for both proofs
    const sigChecks = result.checks.filter((c) => c.check.includes('signature'))
    expect(sigChecks).toHaveLength(2)
    expect(sigChecks.every((c) => c.passed)).toBe(true)
  })

  it('three-party signing works', async () => {
    const vc = await issuerA.issue({
      type: 'AgreementCredential',
      subjectDid: 'did:sns:alice.attestto.sol',
      claims: { terms: ['multi-party test'] },
    })
    const twoSigned = VCIssuer.addProof(vc, issuerB)
    const threeSigned = VCIssuer.addProof(twoSigned, issuerC)

    const proofs = threeSigned.proof as Array<{ verificationMethod: string }>
    expect(proofs).toHaveLength(3)

    const verifier = new VCVerifier({ resolvePublicKey: resolver })
    const result = await verifier.verify(threeSigned)
    expect(result.valid).toBe(true)

    const sigChecks = result.checks.filter((c) => c.check.includes('signature'))
    expect(sigChecks).toHaveLength(3)
  })

  it('detects invalid proof in multi-party credential', async () => {
    const vc = await issuerA.issue({
      type: 'AgreementCredential',
      subjectDid: 'did:sns:alice.attestto.sol',
      claims: { terms: ['tamper test'] },
    })
    const coSigned = VCIssuer.addProof(vc, issuerB)

    // Tamper with second proof
    const proofs = coSigned.proof as Array<{ proofValue: string }>
    proofs[1].proofValue = 'AAAA_tampered_value'

    const verifier = new VCVerifier({ resolvePublicKey: resolver })
    const result = await verifier.verify(coSigned)

    expect(result.valid).toBe(false)
    expect(result.errors.some((e) => e.includes('proof[1]'))).toBe(true)
  })

  it('verifyWithKey still works for single-proof credentials', async () => {
    const vc = await issuerA.issue({
      type: 'SimpleAttestation',
      subjectDid: 'did:sns:holder.attestto.sol',
      claims: { msg: 'compat test' },
    })

    const verifier = new VCVerifier()
    const result = await verifier.verifyWithKey(vc, keysA.publicKey, 'Ed25519')
    expect(result.valid).toBe(true)
  })
})
