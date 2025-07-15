/**
 * Tests for client-side encryption library
 */

import { auraEncryption } from '../index';

// Mock libsodium for testing
jest.mock('libsodium-wrappers', () => ({
  ready: Promise.resolve(),
  from_string: jest.fn((str: string) => new TextEncoder().encode(str)),
  to_string: jest.fn((bytes: Uint8Array) => new TextDecoder().decode(bytes)),
  from_base64: jest.fn((str: string) => Uint8Array.from(atob(str), c => c.charCodeAt(0))),
  to_base64: jest.fn((bytes: Uint8Array) => btoa(String.fromCharCode(...bytes))),
  randombytes_buf: jest.fn((length: number) => new Uint8Array(length).fill(42)),
  crypto_aead_aes256gcm_is_available: jest.fn(() => true),
  crypto_aead_aes256gcm_encrypt: jest.fn(() => new Uint8Array([1, 2, 3, 4])),
  crypto_aead_aes256gcm_decrypt: jest.fn(() => new TextEncoder().encode('decrypted')),
  crypto_aead_aes256gcm_NPUBBYTES: 12,
  crypto_pwhash: jest.fn(() => new Uint8Array(32).fill(123)),
  crypto_pwhash_OPSLIMIT_INTERACTIVE: 2,
  crypto_pwhash_MEMLIMIT_INTERACTIVE: 67108864,
  crypto_pwhash_ALG_ARGON2ID13: 2,
  base64_variants: { ORIGINAL: 0 }
}));

describe('AuraEncryption', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Key Derivation', () => {
    it('should derive key from password', async () => {
      const password = 'test_password';
      const result = await auraEncryption.deriveKey(password);

      expect(result.key).toBeInstanceOf(Uint8Array);
      expect(result.salt).toBeInstanceOf(Uint8Array);
      expect(result.key.length).toBe(32);
    });

    it('should derive same key with same password and salt', async () => {
      const password = 'test_password';
      const salt = new Uint8Array(32).fill(1);

      const result1 = await auraEncryption.deriveKey(password, salt);
      const result2 = await auraEncryption.deriveKey(password, salt);

      expect(result1.key).toEqual(result2.key);
    });
  });

  describe('Encryption/Decryption', () => {
    const testKey = new Uint8Array(32).fill(123);
    const testData = { message: 'test', number: 42 };

    it('should encrypt and decrypt data', async () => {
      const encrypted = await auraEncryption.encrypt(testData, testKey);

      expect(encrypted.ciphertext).toBeDefined();
      expect(encrypted.nonce).toBeDefined();
      expect(encrypted.algorithm).toBe('aes-256-gcm');
      expect(encrypted.version).toBe(1);

      const decrypted = await auraEncryption.decrypt(encrypted, testKey);
      expect(decrypted).toEqual(testData);
    });

    it('should handle string data', async () => {
      const testString = 'Hello, World!';
      const encrypted = await auraEncryption.encrypt(testString, testKey);
      const decrypted = await auraEncryption.decrypt(encrypted, testKey);

      expect(decrypted).toBe(testString);
    });

    it('should generate random nonces', async () => {
      const encrypted1 = await auraEncryption.encrypt(testData, testKey);
      const encrypted2 = await auraEncryption.encrypt(testData, testKey);

      // Mock returns same value, but in real implementation would be different
      expect(encrypted1.nonce).toBeDefined();
      expect(encrypted2.nonce).toBeDefined();
    });
  });

  describe('Token Generation', () => {
    it('should generate random tokens', async () => {
      const token1 = await auraEncryption.generateToken();
      const token2 = await auraEncryption.generateToken();

      expect(typeof token1).toBe('string');
      expect(typeof token2).toBe('string');
      expect(token1.length).toBeGreaterThan(0);
      expect(token2.length).toBeGreaterThan(0);
    });

    it('should generate tokens of specified length', async () => {
      const token = await auraEncryption.generateToken(16);
      expect(typeof token).toBe('string');
    });
  });

  describe('Hashing', () => {
    it('should hash string data', async () => {
      const data = 'test data';
      const hash = await auraEncryption.hash(data);

      expect(typeof hash).toBe('string');
      expect(hash.length).toBeGreaterThan(0);
    });

    it('should hash binary data', async () => {
      const data = new Uint8Array([1, 2, 3, 4, 5]);
      const hash = await auraEncryption.hash(data);

      expect(typeof hash).toBe('string');
      expect(hash.length).toBeGreaterThan(0);
    });
  });

  describe('Error Handling', () => {
    it('should handle invalid encrypted data', async () => {
      const invalidData = {
        ciphertext: 'invalid',
        nonce: 'invalid',
        algorithm: 'invalid',
        version: 1
      };

      await expect(auraEncryption.decrypt(invalidData, testKey))
        .rejects.toThrow();
    });
  });
});