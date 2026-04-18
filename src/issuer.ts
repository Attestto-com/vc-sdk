/**
 * VCIssuer — Universal Verifiable Credential issuance
 *
 * Works with any credential type and any JSON-LD context.
 * Domain-specific types come from schema plugins (cr-vc-schemas, etc.)
 *
 * Usage:
 * ```ts
 * import { VCIssuer, generateKeyPair } from '@attestto/vc-sdk'
 *
 * const keys = generateKeyPair()
 * const issuer = new VCIssuer({
 *   did: 'did:web:my-org.attestto.id',
 *   privateKey: keys.privateKey,
 * })
 *
 * // Issue any credential — no type constraints
 * const vc = await issuer.issue({
 *   type: 'UniversityDegree',
 *   context: 'https://schemas.example.org/education/v1',
 *   subjectDid: 'did:web:student.attestto.id',
 *   claims: {
 *     degree: {
 *       name: 'Computer Science',
 *       level: 'Bachelor',
 *       university: 'Universidad de Costa Rica',
 *       graduationDate: '2026-06-15',
 *     }
 *   },
 * })
 * ```
 */

import { sign, toBase64url } from './keys.js'
import type { IssuerConfig, IssueOptions, VerifiableCredential, Proof, SchemaPlugin } from './types.js'

const W3C_VC_CONTEXT = 'https://www.w3.org/2018/credentials/v1'

export class VCIssuer {
  private config: Required<IssuerConfig>
  private plugins: SchemaPlugin[] = []

  constructor(config: IssuerConfig) {
    this.config = {
      did: config.did,
      privateKey: typeof config.privateKey === 'string'
        ? new TextEncoder().encode(config.privateKey)
        : config.privateKey,
      algorithm: config.algorithm ?? 'Ed25519',
      keyId: config.keyId ?? '#key-1',
    }
  }

  /**
   * Register a schema plugin for domain-specific credential types
   *
   * ```ts
   * issuer.use({
   *   context: 'https://schemas.attestto.org/cr/driving/v1',
   *   types: ['DrivingLicense', 'TheoreticalTestResult', ...],
   *   propertyMap: { DrivingLicense: 'license', TheoreticalTestResult: 'theoreticalTest' },
   * })
   * ```
   */
  use(plugin: SchemaPlugin): this {
    this.plugins.push(plugin)
    return this
  }

  /**
   * Issue a signed Verifiable Credential
   */
  async issue(options: IssueOptions): Promise<VerifiableCredential> {
    const now = new Date().toISOString()
    const credentialId = options.id ?? `urn:uuid:${crypto.randomUUID()}`

    // Resolve types
    const types = Array.isArray(options.type) ? options.type : [options.type]
    const credentialTypes = ['VerifiableCredential', ...types]

    // Resolve contexts
    const contexts = this.resolveContexts(options.context, types)

    // Build credential subject
    const credentialSubject = this.buildSubject(options.subjectDid, types, options.claims)

    // Build the unsigned credential
    const credential: VerifiableCredential = {
      '@context': contexts,
      id: credentialId,
      type: credentialTypes,
      issuer: this.config.did,
      issuanceDate: now,
      credentialSubject,
    }

    if (options.expirationDate) {
      credential.expirationDate = options.expirationDate
    }

    if (options.credentialStatus) {
      credential.credentialStatus = options.credentialStatus
    }

    // Sign
    credential.proof = this.createProof(credential)

    return credential
  }

  /**
   * Resolve JSON-LD contexts — always includes W3C VC, adds plugin contexts and custom ones
   */
  private resolveContexts(custom: string | string[] | undefined, types: string[]): string[] {
    const contexts = [W3C_VC_CONTEXT]

    // Add plugin contexts for matched types
    for (const plugin of this.plugins) {
      if (types.some((t) => plugin.types.includes(t))) {
        if (!contexts.includes(plugin.context)) {
          contexts.push(plugin.context)
        }
      }
    }

    // Add custom contexts
    if (custom) {
      const customs = Array.isArray(custom) ? custom : [custom]
      for (const ctx of customs) {
        if (!contexts.includes(ctx)) {
          contexts.push(ctx)
        }
      }
    }

    return contexts
  }

  /**
   * Build credentialSubject — wraps claims in property name if plugin defines it
   */
  private buildSubject(
    subjectDid: string,
    types: string[],
    claims: Record<string, unknown>
  ): VerifiableCredential['credentialSubject'] {
    const subject: Record<string, unknown> = { id: subjectDid }

    // Check if any plugin defines a property wrapper for this type
    for (const plugin of this.plugins) {
      if (!plugin.propertyMap) continue
      for (const type of types) {
        const propertyName = plugin.propertyMap[type]
        if (propertyName && !claims[propertyName]) {
          // Wrap claims in the expected property
          subject[propertyName] = claims
          return subject as VerifiableCredential['credentialSubject']
        }
      }
    }

    // No plugin match — merge claims directly into subject
    Object.assign(subject, claims)
    return subject as VerifiableCredential['credentialSubject']
  }

  /**
   * Create a linked data proof
   */
  private createProof(credential: VerifiableCredential): Proof {
    const now = new Date().toISOString()
    const { proof: _, ...unsigned } = credential
    const message = new TextEncoder().encode(JSON.stringify(unsigned))

    const privateKey = this.config.privateKey instanceof Uint8Array
      ? this.config.privateKey
      : new TextEncoder().encode(this.config.privateKey)

    const signature = sign(message, privateKey, this.config.algorithm)

    return {
      type: this.config.algorithm === 'Ed25519' ? 'Ed25519Signature2020' : 'EcdsaSecp256r1Signature2019',
      created: now,
      verificationMethod: `${this.config.did}${this.config.keyId}`,
      proofPurpose: 'assertionMethod',
      proofValue: toBase64url(signature),
    }
  }

  /**
   * Add a proof to an existing credential (multi-party signing).
   *
   * The credential may already have one or more proofs. This method
   * appends a new proof signed by this issuer's key, converting the
   * proof field to an array if needed.
   *
   * ```ts
   * // Party A issues
   * const vc = await issuerA.issue({ ... })
   * // Party B co-signs
   * const coSigned = VCIssuer.addProof(vc, issuerB)
   * // vc.proof is now [proofA, proofB]
   * ```
   */
  static addProof(
    credential: VerifiableCredential,
    issuer: VCIssuer
  ): VerifiableCredential {
    const existing = credential.proof
    const { proof: _, ...unsigned } = credential
    const message = new TextEncoder().encode(JSON.stringify(unsigned))

    const privateKey = issuer.config.privateKey instanceof Uint8Array
      ? issuer.config.privateKey
      : new TextEncoder().encode(issuer.config.privateKey)

    const signature = sign(message, privateKey, issuer.config.algorithm)

    const newProof: Proof = {
      type: issuer.config.algorithm === 'Ed25519' ? 'Ed25519Signature2020' : 'EcdsaSecp256r1Signature2019',
      created: new Date().toISOString(),
      verificationMethod: `${issuer.config.did}${issuer.config.keyId}`,
      proofPurpose: 'assertionMethod',
      proofValue: toBase64url(signature),
    }

    // Convert to array
    const proofs: Proof[] = existing
      ? (Array.isArray(existing) ? [...existing, newProof] : [existing, newProof])
      : [newProof]

    return { ...credential, proof: proofs }
  }

  get did(): string {
    return this.config.did
  }
}
