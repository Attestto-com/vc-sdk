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
}

export class VCVerifier {
  private resolvePublicKey?: PublicKeyResolver

  constructor(config?: VerifierConfig) {
    this.resolvePublicKey = config?.resolvePublicKey
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

    if (credential.proof && this.resolvePublicKey) {
      await this.checkProof(credential, checks, errors)
    } else if (credential.proof && !this.resolvePublicKey) {
      warnings.push('Proof present but no public key resolver — signature not verified')
    } else if (!credential.proof) {
      warnings.push('No proof — credential is unsigned')
    }

    if (options.checkStatus && credential.credentialStatus) {
      warnings.push('Status check requested but StatusList2021 not yet implemented')
    }

    return { valid: errors.length === 0, checks, errors, warnings }
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

  private async checkProof(vc: VerifiableCredential, checks: VerificationCheck[], errors: string[]): Promise<void> {
    if (!vc.proof || !this.resolvePublicKey) return

    const vm = vc.proof.verificationMethod
    const hashIdx = vm.lastIndexOf('#')
    const did = hashIdx > 0 ? vm.substring(0, hashIdx) : vm
    const keyId = hashIdx > 0 ? vm.substring(hashIdx) : '#key-1'

    const resolved = await this.resolvePublicKey(did, keyId)
    if (!resolved) {
      checks.push({ check: 'proof.keyResolution', passed: false })
      errors.push(`Could not resolve key for ${vm}`)
      return
    }
    checks.push({ check: 'proof.keyResolution', passed: true })

    const { proof: _, ...unsigned } = vc
    const message = new TextEncoder().encode(JSON.stringify(unsigned))
    const signature = fromBase64url(vc.proof.proofValue ?? '')
    const valid = verifySignature(message, signature, resolved.publicKey, resolved.algorithm)

    checks.push({ check: 'proof.signature', passed: valid })
    if (!valid) errors.push('Invalid signature')
  }
}
