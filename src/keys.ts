/**
 * Key management — Ed25519 + P-256 (ES256)
 * Zero native dependencies via @noble/curves
 */

import { ed25519 } from '@noble/curves/ed25519'
import { p256 } from '@noble/curves/p256'
import { randomBytes } from '@noble/hashes/utils'

export interface KeyPair {
  algorithm: 'Ed25519' | 'ES256'
  publicKey: Uint8Array
  privateKey: Uint8Array
}

export function generateKeyPair(algorithm: 'Ed25519' | 'ES256' = 'Ed25519'): KeyPair {
  if (algorithm === 'Ed25519') {
    const privateKey = randomBytes(32)
    const publicKey = ed25519.getPublicKey(privateKey)
    return { algorithm, publicKey, privateKey }
  }
  const privateKey = p256.utils.randomPrivateKey()
  const publicKey = p256.getPublicKey(privateKey, false)
  return { algorithm, publicKey, privateKey }
}

export function sign(message: Uint8Array, privateKey: Uint8Array, algorithm: 'Ed25519' | 'ES256' = 'Ed25519'): Uint8Array {
  if (algorithm === 'Ed25519') {
    return ed25519.sign(message, privateKey)
  }
  return p256.sign(message, privateKey).toCompactRawBytes()
}

export function verify(
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array,
  algorithm: 'Ed25519' | 'ES256' = 'Ed25519'
): boolean {
  try {
    if (algorithm === 'Ed25519') {
      return ed25519.verify(signature, message, publicKey)
    }
    return p256.verify(signature, message, publicKey)
  } catch {
    return false
  }
}

export function toBase64url(bytes: Uint8Array): string {
  const base64 = btoa(String.fromCharCode(...bytes))
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export function fromBase64url(str: string): Uint8Array {
  const base64 = str.replace(/-/g, '+').replace(/_/g, '/')
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4)
  const binary = atob(padded)
  return Uint8Array.from(binary, (c) => c.charCodeAt(0))
}

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('')
}
