/**
 * Tests for API client with encryption
 */

import { AuraAPIClient } from '../client';
import axios from 'axios';

// Mock axios
jest.mock('axios');
const mockedAxios = axios as jest.Mocked<typeof axios>;

// Mock crypto and auth modules
jest.mock('../crypto', () => ({
  auraEncryption: {
    encrypt: jest.fn().mockResolvedValue({
      ciphertext: 'encrypted_data',
      nonce: 'test_nonce',
      algorithm: 'aes-256-gcm',
      version: 1
    }),
    decrypt: jest.fn().mockResolvedValue('decrypted_data'),
    deriveKey: jest.fn().mockResolvedValue({
      key: new Uint8Array(32),
      salt: new Uint8Array(32)
    })
  },
  keyStorage: {
    storeKey: jest.fn(),
    retrieveKey: jest.fn(),
    deleteKey: jest.fn(),
    clearKeys: jest.fn()
  }
}));

jest.mock('../auth/srp-client', () => ({
  srpClient: {
    register: jest.fn().mockResolvedValue({
      salt: 'test_salt',
      verifier: 'test_verifier'
    }),
    startLogin: jest.fn().mockResolvedValue({
      clientPublicEphemeral: 'test_ephemeral',
      clientEphemeral: { public: 'pub', secret: 'sec' }
    }),
    completeLogin: jest.fn().mockResolvedValue({
      clientProof: 'test_proof',
      clientSession: { proof: 'proof', key: 'key' }
    }),
    verifyServerProof: jest.fn().mockReturnValue(true)
  }
}));

describe('AuraAPIClient', () => {
  let client: AuraAPIClient;
  let mockAxiosInstance: any;

  beforeEach(() => {
    mockAxiosInstance = {
      create: jest.fn().mockReturnThis(),
      request: jest.fn(),
      post: jest.fn(),
      get: jest.fn(),
      put: jest.fn(),
      delete: jest.fn(),
      interceptors: {
        request: { use: jest.fn() },
        response: { use: jest.fn() }
      }
    };

    mockedAxios.create.mockReturnValue(mockAxiosInstance);
    client = new AuraAPIClient('http://localhost:3001');

    jest.clearAllMocks();
  });

  describe('Registration', () => {
    it('should register user with SRP', async () => {
      const mockResponse = {
        data: { success: true, userId: 'test_user_id' }
      };
      mockAxiosInstance.post.mockResolvedValue(mockResponse);

      const result = await client.register('test@example.com', 'password123');

      expect(result.userId).toBe('test_user_id');
      expect(mockAxiosInstance.post).toHaveBeenCalledWith(
        '/api/auth/register',
        expect.objectContaining({
          email: 'test@example.com',
          srpSalt: 'test_salt',
          srpVerifier: 'test_verifier'
        })
      );
    });

    it('should store encryption key after registration', async () => {
      const mockResponse = {
        data: { success: true, userId: 'test_user_id' }
      };
      mockAxiosInstance.post.mockResolvedValue(mockResponse);

      const { keyStorage } = require('../crypto');
      await client.register('test@example.com', 'password123');

      expect(keyStorage.storeKey).toHaveBeenCalled();
    });
  });

  describe('Login', () => {
    it('should complete SRP login flow', async () => {
      // Mock phase 1 response
      const phase1Response = {
        data: {
          salt: 'server_salt',
          serverPublicEphemeral: 'server_ephemeral',
          sessionId: 'session_123'
        }
      };

      // Mock phase 2 response
      const phase2Response = {
        data: {
          serverProof: 'server_proof',
          accessToken: 'access_token_123',
          refreshToken: 'refresh_token_123',
          expiresIn: 900
        }
      };

      mockAxiosInstance.post
        .mockResolvedValueOnce(phase1Response)
        .mockResolvedValueOnce(phase2Response);

      const tokens = await client.login('test@example.com', 'password123');

      expect(tokens.accessToken).toBe('access_token_123');
      expect(tokens.refreshToken).toBe('refresh_token_123');
      expect(mockAxiosInstance.post).toHaveBeenCalledTimes(2);
    });

    it('should reject invalid server proof', async () => {
      const { srpClient } = require('../auth/srp-client');
      srpClient.verifyServerProof.mockReturnValue(false);

      const phase1Response = {
        data: {
          salt: 'server_salt',
          serverPublicEphemeral: 'server_ephemeral',
          sessionId: 'session_123'
        }
      };

      const phase2Response = {
        data: {
          serverProof: 'invalid_proof',
          accessToken: 'access_token_123',
          refreshToken: 'refresh_token_123',
          expiresIn: 900
        }
      };

      mockAxiosInstance.post
        .mockResolvedValueOnce(phase1Response)
        .mockResolvedValueOnce(phase2Response);

      await expect(client.login('test@example.com', 'password123'))
        .rejects.toThrow('Server authentication failed');
    });
  });

  describe('Encrypted Requests', () => {
    beforeEach(() => {
      // Set up client with tokens
      (client as any).tokens = {
        accessToken: 'test_token',
        refreshToken: 'refresh_token',
        expiresIn: 900
      };
      (client as any).encryptionKey = new Uint8Array(32);
    });

    it('should encrypt request data', async () => {
      const testData = { message: 'test' };
      const mockResponse = { data: 'response' };
      
      mockAxiosInstance.request.mockResolvedValue(mockResponse);

      await client.post('/test', testData);

      const { auraEncryption } = require('../crypto');
      expect(auraEncryption.encrypt).toHaveBeenCalledWith(
        testData,
        expect.any(Uint8Array)
      );
    });

    it('should decrypt response data', async () => {
      const encryptedResponse = {
        data: {
          ciphertext: 'encrypted_response',
          nonce: 'response_nonce',
          algorithm: 'aes-256-gcm',
          version: 1
        }
      };

      mockAxiosInstance.request.mockResolvedValue(encryptedResponse);

      const result = await client.get('/test');

      const { auraEncryption } = require('../crypto');
      expect(auraEncryption.decrypt).toHaveBeenCalledWith(
        encryptedResponse.data,
        expect.any(Uint8Array)
      );
    });

    it('should handle unencrypted responses', async () => {
      const plainResponse = { data: { message: 'plain response' } };
      mockAxiosInstance.request.mockResolvedValue(plainResponse);

      const result = await client.get('/test');

      expect(result).toEqual({ message: 'plain response' });
    });

    it('should throw error when no encryption key available', async () => {
      (client as any).encryptionKey = null;

      await expect(client.post('/test', { data: 'test' }))
        .rejects.toThrow('No encryption key available');
    });
  });

  describe('Token Management', () => {
    it('should refresh tokens automatically', async () => {
      const mockRefreshResponse = {
        data: {
          accessToken: 'new_access_token',
          refreshToken: 'new_refresh_token',
          expiresIn: 900
        }
      };

      mockAxiosInstance.post.mockResolvedValue(mockRefreshResponse);

      (client as any).tokens = {
        refreshToken: 'old_refresh_token'
      };

      await client.refreshTokens();

      expect(mockAxiosInstance.post).toHaveBeenCalledWith(
        '/api/auth/refresh',
        { refreshToken: 'old_refresh_token' }
      );
    });

    it('should logout and clear keys', async () => {
      mockAxiosInstance.post.mockResolvedValue({ data: { success: true } });

      await client.logout();

      const { keyStorage } = require('../crypto');
      expect(keyStorage.clearKeys).toHaveBeenCalled();
      expect((client as any).tokens).toBeNull();
      expect((client as any).encryptionKey).toBeNull();
    });
  });

  describe('Error Handling', () => {
    it('should handle network errors', async () => {
      mockAxiosInstance.post.mockRejectedValue(new Error('Network error'));

      await expect(client.register('test@example.com', 'password'))
        .rejects.toThrow('Network error');
    });

    it('should handle authentication errors', async () => {
      mockAxiosInstance.post.mockRejectedValue({
        response: { status: 401, data: { error: 'Unauthorized' } }
      });

      await expect(client.login('test@example.com', 'wrong_password'))
        .rejects.toMatchObject({
          response: { status: 401 }
        });
    });
  });
});