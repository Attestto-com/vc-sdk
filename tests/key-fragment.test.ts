/**
 * SOC-174 Class B — `#key-1` is one DID method's convention, not a default.
 *
 * Every entry point here takes a DID of UNSPECIFIED method and assumed a
 * fragment name instead of reading one. `did:sns` §8.5 names its owner key
 * `#solana-key` (the resolver emits exactly that as of SOC-174 Class A);
 * `did:jwk` and `did:key` use `#0`; `did:web` documents name whatever they
 * name. There is no method for which `#key-1` is universally right.
 *
 * The two halves are not the same defect and do not deserve the same fix.
 *
 * **Signing** (`Issuer`, `buildPresentation`, `buildProofJwt`) — the caller
 * holds the key and knows its id. Guessing here produces a well-formed
 * credential naming a method the signer's own document does not contain, which
 * a verifier can only report as "signature invalid". The caller must say which
 * key it used, so the parameter is required.
 *
 * **Verifying** (`checkProofs`) — far worse. When a proof's
 * `verificationMethod` carried no fragment, the verifier substituted `#key-1`
 * and resolved THAT key. A proof that named no key at all was verified against
 * a key the VERIFIER chose. Which key signed a credential is the proof's
 * statement to make, never the verifier's to fill in; a verifier that supplies
 * the missing half of an assertion is no longer checking it.
 */
import { describe, it, expect } from 'vitest'
import { VCIssuer } from '../src/issuer'
import { buildPresentation } from '../src/oid4vp-present'
import { buildProofJwt } from '../src/oid4vci-token'
import { VCVerifier } from '../src/verifier'
import type { VerifiableCredential } from '../src/types'

const KEY = new Uint8Array(32).fill(7)
const SNS_DID = 'did:sns:alice.crbank'
const SNS_VM = `${SNS_DID}#solana-key`

const CREDENTIAL: VerifiableCredential = {
  '@context': ['https://www.w3.org/2018/credentials/v1'],
  'type': ['VerifiableCredential'],
  'id': 'urn:uuid:5f0d1c9e-2b7a-4a1e-9a7e-2f1b3c4d5e6f',
  'issuer': SNS_DID,
  'issuanceDate': '2026-01-01T00:00:00Z',
  'credentialSubject': { id: 'did:key:zSubject' },
}

function header(jwt: string): Record<string, unknown> {
  // `atob` rather than `Buffer`: this package targets the browser as well as
  // node, and pulling @types/node in for a test helper would let node-only
  // globals leak into specs for a library that must not use them.
  const b64 = jwt.split('.')[0].replace(/-/g, '+').replace(/_/g, '/')
  return JSON.parse(atob(b64))
}

describe('signing — the key id is stated, never assumed', () => {
  it('VCIssuer refuses to construct without a key id', () => {
    // Previously defaulted to `#key-1`, so an issuer with a did:sns DID signed
    // every credential naming a method its own document does not contain.
    expect(
      // @ts-expect-error — omitting keyId is the whole point: the type now
      // forbids it and the constructor must refuse it at runtime too, for
      // callers compiled from JavaScript or from a looser tsconfig.
      () => new VCIssuer({ did: SNS_DID, privateKey: KEY }),
    ).toThrow(/keyId/i)
  })

  it('VCIssuer keeps the key id it was given', () => {
    const issuer = new VCIssuer({ did: SNS_DID, privateKey: KEY, keyId: '#solana-key' })
    expect(issuer.keyId).toBe('#solana-key')
  })

  it('buildPresentation refuses without a key id', () => {
    expect(() =>
      buildPresentation([CREDENTIAL], {
        holderDid: SNS_DID,
        privateKey: KEY,
        nonce: 'n',
        domain: 'https://verifier.example',
      } as never),
    ).toThrow(/keyId/i)
  })

  it('buildPresentation names the supplied key in the proof', () => {
    const vp = buildPresentation([CREDENTIAL], {
      holderDid: SNS_DID,
      privateKey: KEY,
      keyId: '#solana-key',
      nonce: 'n',
      domain: 'https://verifier.example',
    })
    const proof = vp.proof as { verificationMethod: string }
    expect(proof.verificationMethod).toBe(SNS_VM)
  })

  it('buildProofJwt refuses without a key id', () => {
    expect(() =>
      buildProofJwt({
        holderDid: SNS_DID,
        issuerUrl: 'https://issuer.example',
        nonce: 'n',
        privateKey: KEY,
      } as never),
    ).toThrow(/keyId/i)
  })

  it('buildProofJwt puts the supplied key in the JWT header', () => {
    const jwt = buildProofJwt({
      holderDid: SNS_DID,
      issuerUrl: 'https://issuer.example',
      nonce: 'n',
      privateKey: KEY,
      keyId: '#solana-key',
    })
    expect(header(jwt).kid).toBe(SNS_VM)
  })
})

describe('verifying — the proof names its key, or it does not verify', () => {
  /** Records which (did, keyId) pair the verifier asked for. */
  function spyVerifier() {
    const asked: Array<{ did: string; keyId: string }> = []
    const verifier = new VCVerifier({
      resolvePublicKey: async (did: string, keyId: string) => {
        asked.push({ did, keyId })
        return null // resolution failure is enough; we assert on the ASK
      },
    })
    return { verifier, asked }
  }

  const signed = (verificationMethod: string): VerifiableCredential => ({
    ...CREDENTIAL,
    proof: {
      type: 'Ed25519Signature2020',
      created: '2026-01-01T00:00:00Z',
      proofPurpose: 'assertionMethod',
      verificationMethod,
      proofValue: 'z'.repeat(80),
    },
  })

  it('asks for the exact fragment the proof names', async () => {
    const { verifier, asked } = spyVerifier()
    await verifier.verify(signed(SNS_VM))
    expect(asked).toContainEqual({ did: SNS_DID, keyId: '#solana-key' })
  })

  it('does NOT substitute #key-1 for a proof that names no key', async () => {
    // The defect: `hashIdx > 0 ? … : '#key-1'` meant a bare DID resolved
    // against a key the verifier picked. If the subject's document happens to
    // contain a `#key-1`, an unbound proof verifies against it.
    const { verifier, asked } = spyVerifier()
    const result = await verifier.verify(signed(SNS_DID))

    expect(asked.some(a => a.keyId === '#key-1')).toBe(false)
    expect(result.valid).toBe(false)
    expect(result.errors.join(' ')).toMatch(/fragment/i)
  })

  it('never even asks for a key when the proof names none', async () => {
    // Asserting only `valid === false` here would be vacuous: the fixture's
    // proofValue is nonsense, so the signature check fails either way and the
    // test would pass with the defect fully present. The behavioural claim is
    // that resolution is not ATTEMPTED — the verifier does not get as far as
    // choosing a key, because choosing is the defect.
    let calls = 0
    const verifier = new VCVerifier({
      resolvePublicKey: async () => {
        calls++
        return { publicKey: KEY, algorithm: 'Ed25519' as const }
      },
    })

    await verifier.verify(signed(SNS_DID))
    expect(calls).toBe(0)
  })
})
