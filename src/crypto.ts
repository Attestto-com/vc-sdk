/**
 * E2E encryption primitives for Attestto Chat
 *
 * X25519 key agreement + XChaCha20-Poly1305 symmetric encryption.
 * Used for channel-level message encryption where each message is
 * DID-signed (Ed25519) and content-encrypted (X25519 + XChaCha20).
 */

import { edwardsToMontgomeryPub, edwardsToMontgomeryPriv } from '@noble/curves/ed25519'
import { x25519 } from '@noble/curves/ed25519'
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js'
import { hkdf } from '@noble/hashes/hkdf'
import { sha256 } from '@noble/hashes/sha256'
import { randomBytes } from '@noble/hashes/utils'

/** Result of X25519 key generation */
export interface X25519KeyPair {
  publicKey: Uint8Array // 32 bytes
  privateKey: Uint8Array // 32 bytes
}

/**
 * Convert an Ed25519 public key to an X25519 public key.
 * Enables DID key reuse for both signing and key agreement.
 */
export function edToX25519Public(ed25519PublicKey: Uint8Array): Uint8Array {
  return edwardsToMontgomeryPub(ed25519PublicKey)
}

/**
 * Convert an Ed25519 private key to an X25519 private key.
 * The conversion is deterministic — same Ed25519 key always yields the same X25519 key.
 */
export function edToX25519Private(ed25519PrivateKey: Uint8Array): Uint8Array {
  return edwardsToMontgomeryPriv(ed25519PrivateKey)
}

/**
 * Generate an ephemeral X25519 key pair (not derived from Ed25519).
 * Use for channel-specific ephemeral keys where DID key reuse is not needed.
 */
export function generateX25519KeyPair(): X25519KeyPair {
  const privateKey = randomBytes(32)
  const publicKey = x25519.getPublicKey(privateKey)
  return { publicKey, privateKey }
}

/**
 * Compute the X25519 shared secret between two parties.
 * Each party uses their private key and the other's public key.
 */
export function x25519SharedSecret(
  privateKey: Uint8Array,
  publicKey: Uint8Array
): Uint8Array {
  return x25519.getSharedSecret(privateKey, publicKey)
}

/**
 * Derive a symmetric channel key from a shared secret and channel ID.
 * Uses HKDF-SHA256 to produce a 32-byte key suitable for XChaCha20-Poly1305.
 */
export function deriveChannelKey(
  sharedSecret: Uint8Array,
  channelId: string
): Uint8Array {
  const info = new TextEncoder().encode(`attestto-chat:${channelId}`)
  return hkdf(sha256, sharedSecret, /* salt */ undefined, info, 32)
}

/**
 * Build a nonce from a message sequence number.
 * XChaCha20-Poly1305 uses a 24-byte nonce.
 * First 8 bytes: sequence number (big-endian). Last 16 bytes: random.
 */
export function buildNonce(sequence: number): Uint8Array {
  const nonce = new Uint8Array(24)
  // First 8 bytes: sequence as big-endian uint64
  const view = new DataView(nonce.buffer)
  // JavaScript numbers are safe up to 2^53, sufficient for message sequences
  view.setUint32(0, Math.floor(sequence / 0x100000000))
  view.setUint32(4, sequence >>> 0)
  // Last 16 bytes: random
  const rand = randomBytes(16)
  nonce.set(rand, 8)
  return nonce
}

/**
 * Encrypt a plaintext message using XChaCha20-Poly1305.
 *
 * @param channelKey - 32-byte symmetric key from deriveChannelKey
 * @param nonce - 24-byte nonce from buildNonce
 * @param plaintext - UTF-8 plaintext message
 * @returns ciphertext with appended 16-byte Poly1305 auth tag
 */
export function encrypt(
  channelKey: Uint8Array,
  nonce: Uint8Array,
  plaintext: string
): Uint8Array {
  const data = new TextEncoder().encode(plaintext)
  const cipher = xchacha20poly1305(channelKey, nonce)
  return cipher.encrypt(data)
}

/**
 * Decrypt a ciphertext message using XChaCha20-Poly1305.
 *
 * @param channelKey - 32-byte symmetric key from deriveChannelKey
 * @param nonce - 24-byte nonce (must match the one used for encryption)
 * @param ciphertext - encrypted data with auth tag
 * @returns UTF-8 plaintext message
 * @throws if authentication fails (tampered or wrong key)
 */
export function decrypt(
  channelKey: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array
): string {
  const cipher = xchacha20poly1305(channelKey, nonce)
  const data = cipher.decrypt(ciphertext)
  return new TextDecoder().decode(data)
}

/**
 * Full channel encryption setup between two parties.
 *
 * Usage:
 * ```ts
 * // Party A
 * const a = generateX25519KeyPair()
 * // Party B
 * const b = generateX25519KeyPair()
 *
 * // Both derive the same channel key
 * const secretA = x25519SharedSecret(a.privateKey, b.publicKey)
 * const secretB = x25519SharedSecret(b.privateKey, a.publicKey)
 * // secretA === secretB
 *
 * const channelKey = deriveChannelKey(secretA, 'channel-123')
 *
 * // Encrypt
 * const nonce = buildNonce(1)
 * const ct = encrypt(channelKey, nonce, 'I agree to pay $500')
 *
 * // Decrypt (other party, same channelKey)
 * const pt = decrypt(channelKey, nonce, ct) // 'I agree to pay $500'
 * ```
 */
