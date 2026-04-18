import { describe, it, expect } from 'vitest'
import {
  edToX25519Public,
  edToX25519Private,
  generateX25519KeyPair,
  x25519SharedSecret,
  deriveChannelKey,
  buildNonce,
  encrypt,
  decrypt,
  generateKeyPair,
} from '../src/index.js'

describe('E2E Encryption Primitives', () => {
  describe('X25519 key conversion', () => {
    it('converts Ed25519 keys to X25519', () => {
      const ed = generateKeyPair('Ed25519')
      const xPub = edToX25519Public(ed.publicKey)
      const xPriv = edToX25519Private(ed.privateKey)

      expect(xPub).toBeInstanceOf(Uint8Array)
      expect(xPriv).toBeInstanceOf(Uint8Array)
      expect(xPub.length).toBe(32)
      expect(xPriv.length).toBe(32)
    })

    it('same Ed25519 key always produces same X25519 key', () => {
      const ed = generateKeyPair('Ed25519')
      const x1 = edToX25519Public(ed.publicKey)
      const x2 = edToX25519Public(ed.publicKey)
      expect(x1).toEqual(x2)
    })
  })

  describe('X25519 key pair generation', () => {
    it('generates valid ephemeral key pairs', () => {
      const kp = generateX25519KeyPair()
      expect(kp.publicKey.length).toBe(32)
      expect(kp.privateKey.length).toBe(32)
    })

    it('generates unique key pairs', () => {
      const a = generateX25519KeyPair()
      const b = generateX25519KeyPair()
      expect(a.privateKey).not.toEqual(b.privateKey)
    })
  })

  describe('X25519 shared secret', () => {
    it('both parties derive the same shared secret', () => {
      const a = generateX25519KeyPair()
      const b = generateX25519KeyPair()

      const secretA = x25519SharedSecret(a.privateKey, b.publicKey)
      const secretB = x25519SharedSecret(b.privateKey, a.publicKey)

      expect(secretA).toEqual(secretB)
    })

    it('works with Ed25519-derived X25519 keys', () => {
      const edA = generateKeyPair('Ed25519')
      const edB = generateKeyPair('Ed25519')

      const xPrivA = edToX25519Private(edA.privateKey)
      const xPubA = edToX25519Public(edA.publicKey)
      const xPrivB = edToX25519Private(edB.privateKey)
      const xPubB = edToX25519Public(edB.publicKey)

      const secretA = x25519SharedSecret(xPrivA, xPubB)
      const secretB = x25519SharedSecret(xPrivB, xPubA)

      expect(secretA).toEqual(secretB)
    })
  })

  describe('deriveChannelKey', () => {
    it('produces a 32-byte key', () => {
      const secret = x25519SharedSecret(
        generateX25519KeyPair().privateKey,
        generateX25519KeyPair().publicKey
      )
      // Note: different keys won't produce matching secrets, but deriveChannelKey doesn't care
      const key = deriveChannelKey(new Uint8Array(32), 'channel-1')
      expect(key.length).toBe(32)
    })

    it('different channel IDs produce different keys', () => {
      const secret = new Uint8Array(32).fill(42)
      const k1 = deriveChannelKey(secret, 'channel-1')
      const k2 = deriveChannelKey(secret, 'channel-2')
      expect(k1).not.toEqual(k2)
    })

    it('same inputs produce same key', () => {
      const secret = new Uint8Array(32).fill(42)
      const k1 = deriveChannelKey(secret, 'channel-1')
      const k2 = deriveChannelKey(secret, 'channel-1')
      expect(k1).toEqual(k2)
    })
  })

  describe('buildNonce', () => {
    it('produces a 24-byte nonce', () => {
      const nonce = buildNonce(1)
      expect(nonce.length).toBe(24)
    })

    it('different sequences produce different nonces', () => {
      const n1 = buildNonce(1)
      const n2 = buildNonce(2)
      // First 8 bytes differ (sequence), last 16 are random
      expect(n1.slice(0, 8)).not.toEqual(n2.slice(0, 8))
    })
  })

  describe('encrypt / decrypt round-trip', () => {
    it('encrypts and decrypts a message', () => {
      const a = generateX25519KeyPair()
      const b = generateX25519KeyPair()

      const secret = x25519SharedSecret(a.privateKey, b.publicKey)
      const channelKey = deriveChannelKey(secret, 'test-channel')
      const nonce = buildNonce(1)

      const plaintext = 'I agree to pay $500 for the service'
      const ciphertext = encrypt(channelKey, nonce, plaintext)
      const decrypted = decrypt(channelKey, nonce, ciphertext)

      expect(decrypted).toBe(plaintext)
    })

    it('encrypts and decrypts with Ed25519-derived keys', () => {
      const edA = generateKeyPair('Ed25519')
      const edB = generateKeyPair('Ed25519')

      const xPrivA = edToX25519Private(edA.privateKey)
      const xPubB = edToX25519Public(edB.publicKey)

      const secret = x25519SharedSecret(xPrivA, xPubB)
      const channelKey = deriveChannelKey(secret, 'negotiation-42')
      const nonce = buildNonce(1)

      const plaintext = 'Acepto las condiciones del contrato'
      const ciphertext = encrypt(channelKey, nonce, plaintext)

      // Other party decrypts
      const xPrivB = edToX25519Private(edB.privateKey)
      const xPubA = edToX25519Public(edA.publicKey)
      const otherSecret = x25519SharedSecret(xPrivB, xPubA)
      const otherKey = deriveChannelKey(otherSecret, 'negotiation-42')
      const decrypted = decrypt(otherKey, nonce, ciphertext)

      expect(decrypted).toBe(plaintext)
    })

    it('fails to decrypt with wrong key', () => {
      const channelKey = deriveChannelKey(new Uint8Array(32).fill(1), 'ch-1')
      const wrongKey = deriveChannelKey(new Uint8Array(32).fill(2), 'ch-1')
      const nonce = buildNonce(1)

      const ciphertext = encrypt(channelKey, nonce, 'secret')
      expect(() => decrypt(wrongKey, nonce, ciphertext)).toThrow()
    })

    it('fails to decrypt with wrong nonce', () => {
      const channelKey = deriveChannelKey(new Uint8Array(32).fill(1), 'ch-1')
      const nonce1 = buildNonce(1)
      const nonce2 = buildNonce(2)

      const ciphertext = encrypt(channelKey, nonce1, 'secret')
      expect(() => decrypt(channelKey, nonce2, ciphertext)).toThrow()
    })

    it('handles empty string', () => {
      const channelKey = deriveChannelKey(new Uint8Array(32).fill(1), 'ch-1')
      const nonce = buildNonce(0)

      const ciphertext = encrypt(channelKey, nonce, '')
      expect(decrypt(channelKey, nonce, ciphertext)).toBe('')
    })

    it('handles unicode / emoji', () => {
      const channelKey = deriveChannelKey(new Uint8Array(32).fill(1), 'ch-1')
      const nonce = buildNonce(1)
      const text = 'Contrato de arrendamiento — precio: ₡500.000'
      const ct = encrypt(channelKey, nonce, text)
      expect(decrypt(channelKey, nonce, ct)).toBe(text)
    })

    it('ciphertext is different from plaintext', () => {
      const channelKey = deriveChannelKey(new Uint8Array(32).fill(1), 'ch-1')
      const nonce = buildNonce(1)
      const plaintext = 'Hello'
      const ciphertext = encrypt(channelKey, nonce, plaintext)
      const plainBytes = new TextEncoder().encode(plaintext)
      expect(ciphertext).not.toEqual(plainBytes)
      // Ciphertext should be longer (auth tag)
      expect(ciphertext.length).toBeGreaterThan(plainBytes.length)
    })
  })
})
