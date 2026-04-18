/**
 * Chat credential schemas — AgreementCredential + PresenceCredential.
 *
 * These are schema plugins for the VCIssuer that auto-inject the correct
 * JSON-LD context when issuing chat-related credentials.
 *
 * TypeScript interfaces define the credential subject shapes.
 */

import type { SchemaPlugin } from './types.js'

// ── JSON-LD Context ──────────────────────────────────────────────────

const CHAT_CONTEXT = 'https://schemas.attestto.org/chat/v1'

// ── Schema Plugins ───────────────────────────────────────────────────

/**
 * Schema plugin for AgreementCredential — the crystallized negotiation result.
 *
 * Usage:
 * ```ts
 * const issuer = new VCIssuer({ did, privateKey })
 * issuer.use(agreementSchema)
 * ```
 */
export const agreementSchema: SchemaPlugin = {
  context: CHAT_CONTEXT,
  types: ['AgreementCredential'],
  propertyMap: { AgreementCredential: 'agreement' },
}

/**
 * Schema plugin for PresenceCredential — short-lived biometric liveness proof.
 *
 * Usage:
 * ```ts
 * issuer.use(presenceSchema)
 * ```
 */
export const presenceSchema: SchemaPlugin = {
  context: CHAT_CONTEXT,
  types: ['PresenceCredential'],
  propertyMap: { PresenceCredential: 'presence' },
}

/**
 * Combined plugin for both credential types.
 */
export const chatSchemas: SchemaPlugin = {
  context: CHAT_CONTEXT,
  types: ['AgreementCredential', 'PresenceCredential'],
  propertyMap: {
    AgreementCredential: 'agreement',
    PresenceCredential: 'presence',
  },
}

// ── TypeScript Interfaces ────────────────────────────────────────────

/** Party in an agreement */
export interface AgreementParty {
  did: string
  role: string
}

/** Individual obligation/term */
export interface AgreementTerm {
  obligation: string
  responsibleParty: string
  deadline?: string
  amount?: {
    value: number
    currency: string
  }
  conditions?: string[]
}

/** Reference to the conversation that produced the agreement */
export interface ConversationRef {
  channelId: string
  messageRange: [string, string]
  messageCount: number
  hash: string
}

/** Reference to an attachment included in the agreement */
export interface ReferencedAttachment {
  type: 'vault-reference' | 'structured-card'
  hash: string
  summary: string
}

/** Liveness proof for a signer */
export interface PresenceProof {
  signer: string
  presenceCredentialHash: string
  method: 'device-biometric' | 'face-match'
  timestamp: string
}

/** AgreementCredential subject shape */
export interface AgreementSubject {
  parties: AgreementParty[]
  terms: AgreementTerm[]
  conversationRef: ConversationRef
  referencedAttachments?: ReferencedAttachment[]
  presenceProofs: PresenceProof[]
  extractedBy: 'ai' | 'manual'
  reviewedBy: string[]
}

/** PresenceCredential subject shape */
export interface PresenceSubject {
  did: string
  method: 'device-biometric' | 'face-match'
  timestamp: string
  deviceAttestation?: string
}
