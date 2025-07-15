/**
 * API client with automatic encryption/decryption
 */

import axios, { AxiosInstance, AxiosRequestConfig } from 'axios';
import { auraEncryption, keyStorage } from '../crypto';
import { srpClient } from '../auth/srp-client';

export interface AuthTokens {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

export class AuraAPIClient {
  private client: AxiosInstance;
  private encryptionKey: Uint8Array | null = null;
  private tokens: AuthTokens | null = null;

  constructor(baseURL: string = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001') {
    this.client = axios.create({
      baseURL,
      headers: {
        'Content-Type': 'application/json',
      },
    });

    // Add auth interceptor
    this.client.interceptors.request.use(
      (config) => {
        if (this.tokens?.accessToken) {
          config.headers.Authorization = `Bearer ${this.tokens.accessToken}`;
        }
        return config;
      },
      (error) => Promise.reject(error)
    );

    // Add response interceptor for token refresh
    this.client.interceptors.response.use(
      (response) => response,
      async (error) => {
        if (error.response?.status === 401 && this.tokens?.refreshToken) {
          try {
            await this.refreshTokens();
            return this.client.request(error.config);
          } catch {
            // Refresh failed, redirect to login
            this.logout();
          }
        }
        return Promise.reject(error);
      }
    );
  }

  /**
   * Register a new user
   */
  async register(email: string, password: string): Promise<{ userId: string }> {
    // Generate SRP parameters
    const { salt, verifier } = await srpClient.register(email, password);

    // Send to server
    const response = await this.client.post('/api/auth/register', {
      email,
      srpSalt: salt,
      srpVerifier: verifier,
    });

    // Derive and store encryption key
    const { key } = await auraEncryption.deriveKey(password, Buffer.from(salt, 'hex'));
    this.encryptionKey = key;
    await keyStorage.storeKey(key, 'master');

    return response.data;
  }

  /**
   * Login with zero-knowledge proof
   */
  async login(email: string, password: string): Promise<AuthTokens> {
    // Phase 1: Start authentication
    const { clientPublicEphemeral, clientEphemeral } = await srpClient.startLogin(email, password);
    
    const phase1Response = await this.client.post('/api/auth/login/start', {
      email,
      clientPublicEphemeral,
    });

    const { salt, serverPublicEphemeral, sessionId } = phase1Response.data;

    // Phase 2: Complete authentication
    const { clientProof, clientSession } = await srpClient.completeLogin(
      email,
      password,
      salt,
      serverPublicEphemeral,
      clientEphemeral
    );

    const phase2Response = await this.client.post('/api/auth/login/complete', {
      sessionId,
      clientPublicEphemeral,
      clientProof,
    });

    const { serverProof, accessToken, refreshToken, expiresIn } = phase2Response.data;

    // Verify server proof
    if (!srpClient.verifyServerProof(serverProof, clientSession)) {
      throw new Error('Server authentication failed');
    }

    // Store tokens
    this.tokens = { accessToken, refreshToken, expiresIn };

    // Derive and store encryption key
    const { key } = await auraEncryption.deriveKey(password, Buffer.from(salt, 'hex'));
    this.encryptionKey = key;
    await keyStorage.storeKey(key, 'master');

    return this.tokens;
  }

  /**
   * Refresh access token
   */
  async refreshTokens(): Promise<void> {
    if (!this.tokens?.refreshToken) {
      throw new Error('No refresh token available');
    }

    const response = await this.client.post('/api/auth/refresh', {
      refreshToken: this.tokens.refreshToken,
    });

    this.tokens = response.data;
  }

  /**
   * Logout and clear keys
   */
  async logout(): Promise<void> {
    try {
      await this.client.post('/api/auth/logout');
    } catch {
      // Ignore logout errors
    }

    this.tokens = null;
    this.encryptionKey = null;
    await keyStorage.clearKeys();
  }

  /**
   * Make encrypted API request
   */
  async encryptedRequest<T>(
    method: string,
    url: string,
    data?: any,
    config?: AxiosRequestConfig
  ): Promise<T> {
    if (!this.encryptionKey) {
      throw new Error('No encryption key available');
    }

    // Encrypt request data
    let encryptedData;
    if (data) {
      encryptedData = await auraEncryption.encrypt(data, this.encryptionKey);
    }

    // Make request
    const response = await this.client.request({
      method,
      url,
      data: encryptedData,
      ...config,
    });

    // Decrypt response
    if (response.data && typeof response.data === 'object' && 'ciphertext' in response.data) {
      return await auraEncryption.decrypt(response.data, this.encryptionKey);
    }

    return response.data;
  }

  /**
   * Convenience methods
   */
  async get<T>(url: string, config?: AxiosRequestConfig): Promise<T> {
    return this.encryptedRequest<T>('GET', url, undefined, config);
  }

  async post<T>(url: string, data?: any, config?: AxiosRequestConfig): Promise<T> {
    return this.encryptedRequest<T>('POST', url, data, config);
  }

  async put<T>(url: string, data?: any, config?: AxiosRequestConfig): Promise<T> {
    return this.encryptedRequest<T>('PUT', url, data, config);
  }

  async delete<T>(url: string, config?: AxiosRequestConfig): Promise<T> {
    return this.encryptedRequest<T>('DELETE', url, undefined, config);
  }
}

// Export singleton instance
export const auraAPI = new AuraAPIClient();