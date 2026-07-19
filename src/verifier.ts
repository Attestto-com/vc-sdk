/**
 * VCVerifier — Universal Verifiable Credential verification
 */

import { verify as verifySignature, fromBase64url } from './keys.js'
import type { VerifiableCredential, VerificationResult, VerificationCheck, VerifyOptions } from './types.js'

const W3C_VC_CONTEXT = 'https://www.w3.org/2018/credentials/v1'

export type PublicKeyResolver = (did: string, keyId: string) => Promise<{
  publicKey: Uint8Array
  algorithm: 'Ed25519' | 'ES256'
} | null>

export interface VerifierConfig {
  resolvePublicKey?: PublicKeyResolver
  /**
   * Optional issuer-binding check for delegated signing. Given the credential
   * issuer and a proof's `verificationMethod`, resolve the issuer's DID document
   * and return true iff that key is an authorized `assertionMethod` of the
   * issuer. When omitted, the verifier requires the verificationMethod's DID to
   * equal the credential issuer (direct binding). A throwing hook is treated as
   * "not authorized" (fail-closed).
   */
  verifyIssuerBinding?: (issuer: string, verificationMethod: string) => Promise<boolean>
}

export class VCVerifier {
  private resolvePublicKey?: PublicKeyResolver
  private verifyIssuerBinding?: (issuer: string, verificationMethod: string) => Promise<boolean>

  constructor(config?: VerifierConfig) {
    this.resolvePublicKey = config?.resolvePublicKey
    this.verifyIssuerBinding = config?.verifyIssuerBinding
  }

  async verify(
    credential: VerifiableCredential,
    options: VerifyOptions = {}
  ): Promise<VerificationResult> {
    const checks: VerificationCheck[] = []
    const errors: string[] = []
    const warnings: string[] = []

    this.checkStructure(credential, checks, errors)
    this.checkW3CContext(credential, checks, errors)

    if (options.expectedContext) {
      const has = credential['@context'].includes(options.expectedContext)
      checks.push({ check: 'context.expected', passed: has, message: options.expectedContext })
      if (!has) errors.push(`Missing expected context: ${options.expectedContext}`)
    }

    if (options.expectedType) {
      const has = credential.type.includes(options.expectedType)
      checks.push({ check: 'type.expected', passed: has, message: options.expectedType })
      if (!has) errors.push(`Expected type "${options.expectedType}" not found`)
    }

    if (options.expectedIssuer) {
      const matches = credential.issuer === options.expectedIssuer
      checks.push({ check: 'issuer.expected', passed: matches })
      if (!matches) errors.push(`Expected issuer "${options.expectedIssuer}", got "${credential.issuer}"`)
    }

    if (options.checkExpiration !== false) {
      this.checkExpiration(credential, checks, errors, warnings)
    }

    this.checkIssuanceDate(credential, checks, errors)

    // Cryptographic verification. Fail-closed by default (SOC-35): an unsigned
    // credential, or one that cannot be verified, is an ERROR — not a warning —
    // so `valid` never conflates structural validity with signature validity.
    const requireSignature = options.requireSignature !== false
    let signatureVerified = false
    if (credential.proof) {
      if (this.resolvePublicKey) {
        signatureVerified = await this.checkProofs(credential, checks, errors)
      } else {
        const msg = 'Proof present but no public key resolver — signature not verified'
        if (requireSignature) errors.push(msg)
        else warnings.push(msg)
      }
    } else {
      const msg = 'No proof — credential is unsigned'
      if (requireSignature) errors.push(msg)
      else warnings.push(msg)
    }

    if (options.checkStatus && credential.credentialStatus) {
      warnings.push('Status check requested but StatusList2021 not yet implemented')
    }

    return { valid: errors.length === 0, signatureVerified, checks, errors, warnings }
  }

  async verifyWithKey(
    credential: VerifiableCredential,
    publicKey: Uint8Array,
    algorithm: 'Ed25519' | 'ES256' = 'Ed25519',
    options: VerifyOptions = {}
  ): Promise<VerificationResult> {
    const resolver: PublicKeyResolver = async () => ({ publicKey, algorithm })
    const v = new VCVerifier({ resolvePublicKey: resolver })
    return v.verify(credential, options)
  }

  private checkStructure(vc: VerifiableCredential, checks: VerificationCheck[], errors: string[]): void {
    const hasCtx = Array.isArray(vc['@context']) && vc['@context'].length > 0
    checks.push({ check: 'structure.context', passed: hasCtx })
    if (!hasCtx) errors.push('Missing @context')

    const hasType = Array.isArray(vc.type) && vc.type.includes('VerifiableCredential')
    checks.push({ check: 'structure.type', passed: hasType })
    if (!hasType) errors.push('Missing VerifiableCredential in type')

    const hasIssuer = typeof vc.issuer === 'string' && vc.issuer.startsWith('did:')
    checks.push({ check: 'structure.issuer', passed: hasIssuer })
    if (!hasIssuer) errors.push('Missing or invalid issuer DID')

    const hasSub = vc.credentialSubject?.id != null
    checks.push({ check: 'structure.subject', passed: hasSub })
    if (!hasSub) errors.push('Missing credentialSubject.id')

    const hasDate = typeof vc.issuanceDate === 'string'
    checks.push({ check: 'structure.issuanceDate', passed: hasDate })
    if (!hasDate) errors.push('Missing issuanceDate')
  }

  private checkW3CContext(vc: VerifiableCredential, checks: VerificationCheck[], errors: string[]): void {
    const has = vc['@context'].includes(W3C_VC_CONTEXT)
    checks.push({ check: 'context.w3c', passed: has })
    if (!has) errors.push(`Missing W3C VC context: ${W3C_VC_CONTEXT}`)
  }

  private checkExpiration(vc: VerifiableCredential, checks: VerificationCheck[], errors: string[], warnings: string[]): void {
    if (!vc.expirationDate) {
      checks.push({ check: 'expiration', passed: true, message: 'No expiration' })
      return
    }
    const expiry = new Date(vc.expirationDate)
    const now = new Date()
    const valid = expiry > now
    checks.push({ check: 'expiration', passed: valid, message: vc.expirationDate })
    if (!valid) errors.push(`Expired on ${vc.expirationDate}`)
    const thirtyDays = 30 * 24 * 60 * 60 * 1000
    if (valid && (expiry.getTime() - now.getTime()) < thirtyDays) {
      warnings.push(`Expires soon: ${vc.expirationDate}`)
    }
  }

  private checkIssuanceDate(vc: VerifiableCredential, checks: VerificationCheck[], errors: string[]): void {
    if (!vc.issuanceDate) return
    const issued = new Date(vc.issuanceDate)
    const fiveMin = 5 * 60 * 1000
    const valid = issued.getTime() <= (Date.now() + fiveMin)
    checks.push({ check: 'issuanceDate.notFuture', passed: valid })
    if (!valid) errors.push(`Issuance date in future: ${vc.issuanceDate}`)
  }

  /**
   * Verify all proofs on a credential (supports single proof or proof array).
   *
   * Returns true only if EVERY proof is a cryptographically valid signature AND
   * at least one valid proof is bound to the credential issuer (SOC-32) — i.e.
   * signed by the issuer's own DID, or a key the `verifyIssuerBinding` hook
   * authorizes for the issuer. This blocks the forgery where an attacker claims
   * a trusted `issuer` but signs with their own unrelated key. Additional proofs
   * from other DIDs (multi-party co-signers) are allowed but must also verify.
   */
  private async checkProofs(vc: VerifiableCredential, checks: VerificationCheck[], errors: string[]): Promise<boolean> {
    if (!vc.proof || !this.resolvePublicKey) return false

    const proofs = Array.isArray(vc.proof) ? vc.proof : [vc.proof]
    const { proof: _, ...unsigned } = vc
    const message = new TextEncoder().encode(JSON.stringify(unsigned))
    const issuerId =
      typeof vc.issuer === 'string' ? vc.issuer : (vc.issuer as { id?: string } | undefined)?.id

    let allValid = proofs.length > 0
    let issuerBoundValid = false

    for (let i = 0; i < proofs.length; i++) {
      const proof = proofs[i]
      const label = proofs.length > 1 ? `proof[${i}]` : 'proof'

      const vm = proof.verificationMethod
      const hashIdx = vm.lastIndexOf('#')
      const did = hashIdx > 0 ? vm.substring(0, hashIdx) : vm
      const keyId = hashIdx > 0 ? vm.substring(hashIdx) : '#key-1'

      // Issuer binding (SOC-32): is this proof's key the issuer's own, or one
      // the issuer explicitly authorizes?
      const isIssuerKey = this.verifyIssuerBinding
        ? await this.verifyIssuerBinding(issuerId ?? '', vm).catch(() => false)
        : did === issuerId
      checks.push({ check: `${label}.issuerBinding`, passed: isIssuerKey })

      const resolved = await this.resolvePublicKey!(did, keyId)
      if (!resolved) {
        checks.push({ check: `${label}.keyResolution`, passed: false })
        errors.push(`Could not resolve key for ${vm}`)
        allValid = false
        continue
      }
      checks.push({ check: `${label}.keyResolution`, passed: true })

      const signature = fromBase64url(proof.proofValue ?? '')
      const sigValid = verifySignature(message, signature, resolved.publicKey, resolved.algorithm)
      checks.push({ check: `${label}.signature`, passed: sigValid })
      if (!sigValid) {
        errors.push(`Invalid signature on ${label}`)
        allValid = false
      }

      if (isIssuerKey && sigValid) issuerBoundValid = true
    }

    checks.push({ check: 'proof.issuerBound', passed: issuerBoundValid })
    if (!issuerBoundValid) {
      errors.push(
        `Signature not bound to the credential issuer${issuerId ? ` "${issuerId}"` : ''} — no valid proof from the issuer's key`
      )
    }

    return allValid && issuerBoundValid
  }
}
