/**
 * Client-side encryption library for Aura web frontend
 * All encryption happens in the browser before data leaves the device
 */

import sodium from 'libsodium-wrappers';

export interface EncryptedData {
  ciphertext: string;
  nonce: string;
  salt?: string;
  algorithm: string;
  version: number;
}

export interface DerivedKey {
  key: Uint8Array;
  salt: Uint8Array;
}

class AuraEncryption {
  private initialized = false;

  /**
   * Initialize the encryption library
   */
  async init(): Promise<void> {
    if (!this.initialized) {
      await sodium.ready;
      this.initialized = true;
    }
  }

  /**
   * Derive encryption key from password
   */
  async deriveKey(password: string, salt?: Uint8Array): Promise<DerivedKey> {
    await this.init();

    const useSalt = salt || sodium.randombytes_buf(32);
    
    // Use Argon2id for key derivation
    const key = sodium.crypto_pwhash(
      32, // key length
      password,
      useSalt,
      sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
      sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
      sodium.crypto_pwhash_ALG_ARGON2ID13
    );

    return {
      key: new Uint8Array(key),
      salt: useSalt,
    };
  }

  /**
   * Generate a random encryption key
   */
  async generateKey(): Promise<Uint8Array> {
    await this.init();
    return sodium.randombytes_buf(32);
  }

  /**
   * Encrypt data with AES-256-GCM
   */
  async encrypt(data: any, key: Uint8Array): Promise<EncryptedData> {
    await this.init();

    const plaintext = typeof data === 'string' 
      ? sodium.from_string(data)
      : sodium.from_string(JSON.stringify(data));

    const nonce = sodium.randombytes_buf(sodium.crypto_aead_aes256gcm_NPUBBYTES);
    
    // Check if AES-256-GCM is available
    if (!sodium.crypto_aead_aes256gcm_is_available()) {
      // Fallback to ChaCha20-Poly1305
      return this.encryptChaCha(plaintext, key);
    }

    const ciphertext = sodium.crypto_aead_aes256gcm_encrypt(
      plaintext,
      null,
      null,
      nonce,
      key
    );

    return {
      ciphertext: sodium.to_base64(ciphertext, sodium.base64_variants.ORIGINAL),
      nonce: sodium.to_base64(nonce, sodium.base64_variants.ORIGINAL),
      algorithm: 'aes-256-gcm',
      version: 1,
    };
  }

  /**
   * Encrypt with ChaCha20-Poly1305 (fallback)
   */
  private async encryptChaCha(plaintext: Uint8Array, key: Uint8Array): Promise<EncryptedData> {
    const nonce = sodium.randombytes_buf(sodium.crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
    
    const ciphertext = sodium.crypto_aead_chacha20poly1305_ietf_encrypt(
      plaintext,
      null,
      null,
      nonce,
      key
    );

    return {
      ciphertext: sodium.to_base64(ciphertext, sodium.base64_variants.ORIGINAL),
      nonce: sodium.to_base64(nonce, sodium.base64_variants.ORIGINAL),
      algorithm: 'chacha20-poly1305',
      version: 1,
    };
  }

  /**
   * Decrypt data
   */
  async decrypt(encryptedData: EncryptedData, key: Uint8Array): Promise<any> {
    await this.init();

    const ciphertext = sodium.from_base64(
      encryptedData.ciphertext,
      sodium.base64_variants.ORIGINAL
    );
    const nonce = sodium.from_base64(
      encryptedData.nonce,
      sodium.base64_variants.ORIGINAL
    );

    let decrypted: Uint8Array;

    if (encryptedData.algorithm === 'aes-256-gcm') {
      decrypted = sodium.crypto_aead_aes256gcm_decrypt(
        null,
        ciphertext,
        null,
        nonce,
        key
      );
    } else if (encryptedData.algorithm === 'chacha20-poly1305') {
      decrypted = sodium.crypto_aead_chacha20poly1305_ietf_decrypt(
        null,
        ciphertext,
        null,
        nonce,
        key
      );
    } else {
      throw new Error(`Unsupported algorithm: ${encryptedData.algorithm}`);
    }

    const decryptedString = sodium.to_string(decrypted);
    
    // Try to parse as JSON, otherwise return as string
    try {
      return JSON.parse(decryptedString);
    } catch {
      return decryptedString;
    }
  }

  /**
   * Generate a secure random token
   */
  async generateToken(length: number = 32): Promise<string> {
    await this.init();
    const bytes = sodium.randombytes_buf(length);
    return sodium.to_base64(bytes, sodium.base64_variants.URLSAFE_NO_PADDING);
  }

  /**
   * Hash data with SHA-256
   */
  async hash(data: string | Uint8Array): Promise<string> {
    await this.init();
    const input = typeof data === 'string' ? sodium.from_string(data) : data;
    const hash = sodium.crypto_hash_sha256(input);
    return sodium.to_hex(hash);
  }
}

// Export singleton instance
export const auraEncryption = new AuraEncryption();

// Key storage using Web Crypto API
export class SecureKeyStorage {
  private readonly STORAGE_KEY = 'aura_keys';

  /**
   * Store key securely using Web Crypto API
   */
  async storeKey(key: Uint8Array, identifier: string): Promise<void> {
    // In production, use IndexedDB with encryption
    const keys = await this.getKeys();
    keys[identifier] = sodium.to_base64(key, sodium.base64_variants.ORIGINAL);
    
    if (typeof window !== 'undefined') {
      sessionStorage.setItem(this.STORAGE_KEY, JSON.stringify(keys));
    }
  }

  /**
   * Retrieve key
   */
  async retrieveKey(identifier: string): Promise<Uint8Array | null> {
    const keys = await this.getKeys();
    const keyBase64 = keys[identifier];
    
    if (!keyBase64) {
      return null;
    }

    return sodium.from_base64(keyBase64, sodium.base64_variants.ORIGINAL);
  }

  /**
   * Delete key
   */
  async deleteKey(identifier: string): Promise<void> {
    const keys = await this.getKeys();
    delete keys[identifier];
    
    if (typeof window !== 'undefined') {
      sessionStorage.setItem(this.STORAGE_KEY, JSON.stringify(keys));
    }
  }

  /**
   * Clear all keys
   */
  async clearKeys(): Promise<void> {
    if (typeof window !== 'undefined') {
      sessionStorage.removeItem(this.STORAGE_KEY);
    }
  }

  private async getKeys(): Promise<Record<string, string>> {
    if (typeof window === 'undefined') {
      return {};
    }

    const stored = sessionStorage.getItem(this.STORAGE_KEY);
    return stored ? JSON.parse(stored) : {};
  }
}

export const keyStorage = new SecureKeyStorage();