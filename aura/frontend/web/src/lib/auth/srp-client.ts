/**
 * SRP-6a client implementation for zero-knowledge authentication
 */

import * as srp from 'secure-remote-password/client';
import { auraEncryption } from '../crypto';

export interface SRPRegistration {
  email: string;
  salt: string;
  verifier: string;
}

export interface SRPLoginPhase1 {
  email: string;
  clientPublicEphemeral: string;
  clientEphemeral: srp.Ephemeral;
}

export class SRPClient {
  /**
   * Generate SRP registration parameters
   * Password never leaves the client
   */
  async register(email: string, password: string): Promise<SRPRegistration> {
    // Generate random salt
    const salt = await auraEncryption.generateToken(32);
    
    // Derive private key from credentials
    const privateKey = srp.derivePrivateKey(salt, email, password);
    
    // Generate verifier
    const verifier = srp.deriveVerifier(privateKey);

    return {
      email,
      salt,
      verifier,
    };
  }

  /**
   * Start SRP login - Phase 1
   */
  async startLogin(email: string, password: string): Promise<SRPLoginPhase1> {
    // Generate client ephemeral
    const clientEphemeral = srp.generateEphemeral();

    return {
      email,
      clientPublicEphemeral: clientEphemeral.public,
      clientEphemeral,
    };
  }

  /**
   * Complete SRP login - Phase 2
   */
  async completeLogin(
    email: string,
    password: string,
    salt: string,
    serverPublicEphemeral: string,
    clientEphemeral: srp.Ephemeral
  ): Promise<{ clientProof: string; clientSession: srp.Session }> {
    // Derive private key
    const privateKey = srp.derivePrivateKey(salt, email, password);
    
    // Derive session
    const clientSession = srp.deriveSession(
      clientEphemeral.secret,
      serverPublicEphemeral,
      salt,
      email,
      privateKey
    );

    return {
      clientProof: clientSession.proof,
      clientSession,
    };
  }

  /**
   * Verify server proof
   */
  verifyServerProof(
    serverProof: string,
    clientSession: srp.Session
  ): boolean {
    try {
      srp.verifySession(clientEphemeral.public, clientSession, serverProof);
      return true;
    } catch {
      return false;
    }
  }
}

export const srpClient = new SRPClient();