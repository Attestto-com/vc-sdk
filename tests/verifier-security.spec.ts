/**
 * Security regression tests for VCVerifier.
 *
 * SOC-32: signatures must be bound to the credential issuer.
 * SOC-35: verification is fail-closed — unsigned / unverifiable credentials
 *         are NOT valid.
 */

import { describe, it, expect } from 'vitest'
import { VCIssuer, VCVerifier, generateKeyPair, sign, toBase64url } from '../src/index.js'
import type { PublicKeyResolver } from '../src/verifier.js'

const issuerKeys = generateKeyPair()

/** Resolver that returns a specific key for a specific DID, null otherwise. */
function resolverFor(did: string, publicKey: Uint8Array): PublicKeyResolver {
  return async (d: string) => (d === did ? { publicKey, algorithm: 'Ed25519' } : null)
}

async function issueLegit() {
  const issuer = new VCIssuer({
    did: 'did:web:bank.attestto.id',
    privateKey: issuerKeys.privateKey,
  })
  return issuer.issue({
    type: 'BankKYC',
    subjectDid: 'did:web:customer.attestto.id',
    claims: { kycLevel: 'enhanced' },
  })
}

describe('SOC-35: fail-closed verification', () => {
  it('a legitimately signed, issuer-bound credential is valid and signatureVerified', async () => {
    const vc = await issueLegit()
    const verifier = new VCVerifier({ resolvePublicKey: resolverFor('did:web:bank.attestto.id', issuerKeys.publicKey) })
    const result = await verifier.verify(vc)
    expect(result.valid).toBe(true)
    expect(result.signatureVerified).toBe(true)
  })

  it('an unsigned credential is NOT valid by default', async () => {
    const vc = await issueLegit()
    const { proof: _p, ...unsigned } = vc
    const verifier = new VCVerifier({ resolvePublicKey: resolverFor('did:web:bank.attestto.id', issuerKeys.publicKey) })
    const result = await verifier.verify(unsigned as typeof vc)
    expect(result.valid).toBe(false)
    expect(result.signatureVerified).toBe(false)
    expect(result.errors.some((e) => e.includes('unsigned'))).toBe(true)
  })

  it('a signed credential with no resolver configured is NOT valid by default', async () => {
    const vc = await issueLegit()
    const verifier = new VCVerifier() // no resolver
    const result = await verifier.verify(vc)
    expect(result.valid).toBe(false)
    expect(result.signatureVerified).toBe(false)
    expect(result.errors.some((e) => e.includes('no public key resolver'))).toBe(true)
  })

  it('requireSignature:false allows structural-only validation of an unsigned credential', async () => {
    const vc = await issueLegit()
    const { proof: _p, ...unsigned } = vc
    const verifier = new VCVerifier()
    const result = await verifier.verify(unsigned as typeof vc, { requireSignature: false })
    expect(result.valid).toBe(true) // structurally valid…
    expect(result.signatureVerified).toBe(false) // …but the signature was not verified
  })
})

describe('SOC-32: signature must be bound to the issuer', () => {
  it('rejects a forged credential: valid signature by an attacker key claiming a trusted issuer', async () => {
    // Attacker controls did:web:attacker with a resolvable key. They craft a
    // credential that CLAIMS issuer = did:web:bank, sign it with their own key,
    // and point verificationMethod at their own DID. The signature is valid for
    // the attacker key, but it is not bound to the claimed issuer.
    const attacker = generateKeyPair()
    const base = await issueLegit()
    const { proof: _p, ...unsigned } = base
    const forgedUnsigned = { ...unsigned, issuer: 'did:web:bank.attestto.id' }

    // Sign the forged doc with the attacker key.
    const message = new TextEncoder().encode(JSON.stringify(forgedUnsigned))
    const signature = sign(message, attacker.privateKey, 'Ed25519')
    const forged = {
      ...forgedUnsigned,
      proof: {
        type: 'Ed25519Signature2020',
        created: new Date().toISOString(),
        verificationMethod: 'did:web:attacker.example#key-1',
        proofPurpose: 'assertionMethod',
        proofValue: toBase64url(signature),
      },
    } as typeof base

    // Resolver resolves the attacker's real key (so the signature itself checks out).
    const verifier = new VCVerifier({ resolvePublicKey: resolverFor('did:web:attacker.example', attacker.publicKey) })
    const result = await verifier.verify(forged)

    expect(result.signatureVerified).toBe(false)
    expect(result.valid).toBe(false)
    expect(result.errors.some((e) => e.includes('not bound to the credential issuer'))).toBe(true)
  })

  it('accepts a delegated key when verifyIssuerBinding authorizes it', async () => {
    // Issuer did:web:bank delegates signing to did:web:signer. The signature is
    // by the delegate; a verifyIssuerBinding hook confirms the delegation.
    const delegate = generateKeyPair()
    const base = await issueLegit()
    const { proof: _p, ...unsigned } = base
    const message = new TextEncoder().encode(JSON.stringify(unsigned))
    const signature = sign(message, delegate.privateKey, 'Ed25519')
    const delegated = {
      ...unsigned,
      proof: {
        type: 'Ed25519Signature2020',
        created: new Date().toISOString(),
        verificationMethod: 'did:web:signer.attestto.id#key-1',
        proofPurpose: 'assertionMethod',
        proofValue: toBase64url(signature),
      },
    } as typeof base

    const verifier = new VCVerifier({
      resolvePublicKey: resolverFor('did:web:signer.attestto.id', delegate.publicKey),
      verifyIssuerBinding: async (issuer, vm) =>
        issuer === 'did:web:bank.attestto.id' && vm === 'did:web:signer.attestto.id#key-1',
    })
    const result = await verifier.verify(delegated)
    expect(result.valid).toBe(true)
    expect(result.signatureVerified).toBe(true)
  })

  it('multi-party: co-signer proof from another DID is allowed as long as the issuer also signed', async () => {
    const issuerA = new VCIssuer({ did: 'did:web:bank.attestto.id', privateKey: issuerKeys.privateKey })
    const coKeys = generateKeyPair()
    const issuerB = new VCIssuer({ did: 'did:web:auditor.attestto.id', privateKey: coKeys.privateKey })

    const vc = await issuerA.issue({
      type: 'BankKYC',
      subjectDid: 'did:web:customer.attestto.id',
      claims: { kycLevel: 'enhanced' },
    })
    const coSigned = VCIssuer.addProof(vc, issuerB)

    const verifier = new VCVerifier({
      resolvePublicKey: async (did) => {
        if (did === 'did:web:bank.attestto.id') return { publicKey: issuerKeys.publicKey, algorithm: 'Ed25519' }
        if (did === 'did:web:auditor.attestto.id') return { publicKey: coKeys.publicKey, algorithm: 'Ed25519' }
        return null
      },
    })
    const result = await verifier.verify(coSigned)
    expect(result.valid).toBe(true)
    expect(result.signatureVerified).toBe(true)
  })
})
