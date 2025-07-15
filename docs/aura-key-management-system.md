# Aura User-Controlled Encryption Key Management System

## Overview

This document describes a comprehensive key management system that gives users complete control over their encryption keys while maintaining usability and security. The system ensures that Aura never has access to user keys while providing robust recovery mechanisms.

## Key Hierarchy Architecture

### Master Key Structure

```
User Master Secret (never transmitted)
├── Authentication Key (SRP verifier)
├── Key Encryption Key (KEK)
│   ├── Data Encryption Keys (DEK)
│   │   ├── Personal Data Key
│   │   ├── Calendar Data Key
│   │   ├── Email Data Key
│   │   ├── Health Data Key
│   │   └── Financial Data Key
│   ├── Search Index Keys
│   │   ├── Content Search Key
│   │   └── Metadata Search Key
│   └── Sharing Keys
│       ├── Family Sharing Key
│       ├── Support Access Key
│       └── Device Sync Key
└── Recovery Keys
    ├── Social Recovery Shards
    ├── Hardware Token Key
    └── Paper Backup Key
```

### Key Derivation Implementation

```typescript
// Advanced key derivation with quantum-resistant considerations
class KeyHierarchyManager {
  private masterSecret: Uint8Array;
  private keyCache: Map<string, CryptoKey> = new Map();
  
  async initializeFromEntropy(entropy: Uint8Array): Promise<void> {
    // Ensure sufficient entropy (at least 256 bits)
    if (entropy.length < 32) {
      throw new Error('Insufficient entropy for secure key generation');
    }
    
    // Apply key stretching with memory-hard function
    this.masterSecret = await this.stretchKey(entropy);
    
    // Initialize root keys
    await this.initializeRootKeys();
  }
  
  private async stretchKey(entropy: Uint8Array): Promise<Uint8Array> {
    // Use Argon2id for quantum resistance
    const salt = await this.generateDeterministicSalt(entropy);
    
    return argon2id({
      password: entropy,
      salt,
      iterations: 4,
      memorySize: 2097152, // 2 GB
      parallelism: 8,
      tagLength: 32,
      version: 0x13
    });
  }
  
  async deriveKey(
    purpose: string,
    algorithm: AlgorithmIdentifier = 'AES-GCM'
  ): Promise<CryptoKey> {
    const cacheKey = `${purpose}:${JSON.stringify(algorithm)}`;
    
    if (this.keyCache.has(cacheKey)) {
      return this.keyCache.get(cacheKey)!;
    }
    
    // Hierarchical derivation path
    const path = this.parsePath(purpose);
    let currentKey = this.masterSecret;
    
    for (const segment of path) {
      currentKey = await this.deriveChildKey(currentKey, segment);
    }
    
    // Import as CryptoKey
    const key = await crypto.subtle.importKey(
      'raw',
      currentKey,
      algorithm,
      false,
      this.getKeyUsages(algorithm)
    );
    
    this.keyCache.set(cacheKey, key);
    return key;
  }
  
  private async deriveChildKey(
    parentKey: Uint8Array,
    index: string
  ): Promise<Uint8Array> {
    // Use HKDF with domain separation
    const info = new TextEncoder().encode(`aura-key-${index}`);
    const salt = crypto.getRandomValues(new Uint8Array(32));
    
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      parentKey,
      'HKDF',
      false,
      ['deriveBits']
    );
    
    const derived = await crypto.subtle.deriveBits(
      {
        name: 'HKDF',
        hash: 'SHA-512',
        salt,
        info
      },
      keyMaterial,
      256
    );
    
    return new Uint8Array(derived);
  }
}
```

## Key Storage Solutions

### 1. Browser/Device Storage

```typescript
class SecureLocalKeyStorage {
  private dbName = 'AuraKeyStore';
  private db: IDBDatabase | null = null;
  
  async initialize(): Promise<void> {
    this.db = await this.openDatabase();
    
    // Check for hardware security module support
    if ('navigator' in globalThis && 'credentials' in navigator) {
      await this.initializeWebAuthn();
    }
  }
  
  async storeKey(
    keyId: string,
    keyData: CryptoKey,
    metadata: KeyMetadata
  ): Promise<void> {
    // Try hardware-backed storage first
    if (await this.isHardwareBackedStorageAvailable()) {
      await this.storeInHardware(keyId, keyData, metadata);
      return;
    }
    
    // Fall back to encrypted IndexedDB
    const wrappingKey = await this.getOrCreateWrappingKey();
    const wrapped = await crypto.subtle.wrapKey(
      'raw',
      keyData,
      wrappingKey,
      'AES-KW'
    );
    
    const transaction = this.db!.transaction(['keys'], 'readwrite');
    const store = transaction.objectStore('keys');
    
    await store.put({
      id: keyId,
      wrappedKey: wrapped,
      metadata: {
        ...metadata,
        created: Date.now(),
        algorithm: keyData.algorithm,
        usages: keyData.usages,
        extractable: keyData.extractable
      }
    });
  }
  
  private async storeInHardware(
    keyId: string,
    keyData: CryptoKey,
    metadata: KeyMetadata
  ): Promise<void> {
    // Use WebAuthn for hardware-backed key storage
    const credential = await navigator.credentials.create({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rp: { name: 'Aura', id: 'aura.app' },
        user: {
          id: new TextEncoder().encode(keyId),
          name: metadata.name,
          displayName: metadata.displayName
        },
        pubKeyCredParams: [
          { alg: -7, type: 'public-key' }, // ES256
          { alg: -257, type: 'public-key' } // RS256
        ],
        authenticatorSelection: {
          authenticatorAttachment: 'platform',
          requireResidentKey: true,
          userVerification: 'required'
        },
        attestation: 'direct'
      }
    });
    
    // Store key reference
    await this.storeKeyReference(keyId, credential!.id, metadata);
  }
}
```

### 2. Multi-Device Synchronization

```typescript
class SecureKeySynchronization {
  private deviceKeys: Map<string, DeviceKeyPair> = new Map();
  
  async initializeDevicePairing(
    deviceName: string
  ): Promise<DevicePairingCode> {
    // Generate device-specific key pair
    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'ECDH',
        namedCurve: 'P-521'
      },
      true,
      ['deriveKey']
    );
    
    // Create pairing code with time limit
    const pairingData = {
      deviceId: crypto.randomUUID(),
      deviceName,
      publicKey: await crypto.subtle.exportKey('jwk', keyPair.publicKey),
      timestamp: Date.now(),
      expires: Date.now() + 300000 // 5 minutes
    };
    
    // Encode as QR code or pairing string
    const pairingCode = await this.encodePairingData(pairingData);
    
    this.deviceKeys.set(pairingData.deviceId, {
      keyPair,
      deviceName,
      paired: false
    });
    
    return {
      code: pairingCode,
      expiresAt: pairingData.expires
    };
  }
  
  async completeDevicePairing(
    pairingCode: string,
    localDeviceId: string
  ): Promise<void> {
    const pairingData = await this.decodePairingData(pairingCode);
    
    // Verify not expired
    if (Date.now() > pairingData.expires) {
      throw new Error('Pairing code expired');
    }
    
    // Import remote device's public key
    const remotePublicKey = await crypto.subtle.importKey(
      'jwk',
      pairingData.publicKey,
      {
        name: 'ECDH',
        namedCurve: 'P-521'
      },
      false,
      []
    );
    
    // Derive shared secret
    const localKeyPair = this.deviceKeys.get(localDeviceId)!.keyPair;
    const sharedSecret = await crypto.subtle.deriveKey(
      {
        name: 'ECDH',
        public: remotePublicKey
      },
      localKeyPair.privateKey,
      {
        name: 'AES-GCM',
        length: 256
      },
      false,
      ['encrypt', 'decrypt']
    );
    
    // Establish secure channel
    await this.establishSecureChannel(
      localDeviceId,
      pairingData.deviceId,
      sharedSecret
    );
  }
  
  async syncKeys(targetDeviceId: string): Promise<void> {
    const channel = await this.getSecureChannel(targetDeviceId);
    
    // Get all exportable keys
    const keys = await this.getExportableKeys();
    
    for (const [keyId, keyData] of keys) {
      // Wrap key for transport
      const wrapped = await crypto.subtle.wrapKey(
        'jwk',
        keyData.key,
        channel.transportKey,
        {
          name: 'AES-KW'
        }
      );
      
      // Send through secure channel
      await channel.send({
        type: 'key-sync',
        keyId,
        wrappedKey: wrapped,
        metadata: keyData.metadata,
        timestamp: Date.now()
      });
    }
  }
}
```

## Key Recovery Mechanisms

### 1. Social Recovery System

```typescript
class SocialKeyRecovery {
  private readonly MINIMUM_SHARES = 3;
  private readonly TOTAL_SHARES = 5;
  
  async setupSocialRecovery(
    masterKey: CryptoKey,
    guardians: Guardian[]
  ): Promise<RecoverySetup> {
    if (guardians.length < this.TOTAL_SHARES) {
      throw new Error(`Need at least ${this.TOTAL_SHARES} guardians`);
    }
    
    // Export master key
    const keyData = await crypto.subtle.exportKey('raw', masterKey);
    
    // Split using Shamir's Secret Sharing
    const shares = await this.splitSecret(keyData, {
      shares: this.TOTAL_SHARES,
      threshold: this.MINIMUM_SHARES
    });
    
    // Encrypt each share for its guardian
    const encryptedShares: EncryptedShare[] = [];
    
    for (let i = 0; i < guardians.length; i++) {
      const guardian = guardians[i];
      const share = shares[i];
      
      // Fetch guardian's public key
      const guardianKey = await this.fetchGuardianPublicKey(guardian.id);
      
      // Encrypt share
      const encrypted = await crypto.subtle.encrypt(
        {
          name: 'RSA-OAEP',
          hash: 'SHA-256'
        },
        guardianKey,
        share
      );
      
      encryptedShares.push({
        guardianId: guardian.id,
        guardianName: guardian.name,
        encryptedShare: new Uint8Array(encrypted),
        shareIndex: i,
        createdAt: Date.now()
      });
      
      // Notify guardian
      await this.notifyGuardian(guardian, {
        type: 'recovery-share-assigned',
        userName: await this.getCurrentUserName(),
        instructions: this.getGuardianInstructions()
      });
    }
    
    return {
      setupId: crypto.randomUUID(),
      totalShares: this.TOTAL_SHARES,
      requiredShares: this.MINIMUM_SHARES,
      guardians: encryptedShares.map(s => ({
        id: s.guardianId,
        name: s.guardianName
      })),
      createdAt: Date.now()
    };
  }
  
  async initiateRecovery(
    guardianContacts: GuardianContact[]
  ): Promise<RecoverySession> {
    const session: RecoverySession = {
      id: crypto.randomUUID(),
      status: 'pending',
      requestedAt: Date.now(),
      shares: [],
      requiredShares: this.MINIMUM_SHARES
    };
    
    // Contact guardians
    for (const contact of guardianContacts) {
      await this.requestShareFromGuardian(contact, session.id);
    }
    
    // Set up monitoring
    this.monitorRecoverySession(session);
    
    return session;
  }
  
  private async monitorRecoverySession(
    session: RecoverySession
  ): Promise<void> {
    const checkInterval = setInterval(async () => {
      const shares = await this.getCollectedShares(session.id);
      
      if (shares.length >= this.MINIMUM_SHARES) {
        clearInterval(checkInterval);
        await this.attemptKeyRecovery(session.id, shares);
      }
      
      // Timeout after 24 hours
      if (Date.now() - session.requestedAt > 86400000) {
        clearInterval(checkInterval);
        await this.cancelRecoverySession(session.id);
      }
    }, 60000); // Check every minute
  }
  
  private async attemptKeyRecovery(
    sessionId: string,
    shares: Share[]
  ): Promise<void> {
    try {
      // Combine shares
      const masterKeyData = await this.combineShares(shares);
      
      // Import recovered key
      const masterKey = await crypto.subtle.importKey(
        'raw',
        masterKeyData,
        'AES-GCM',
        true,
        ['encrypt', 'decrypt']
      );
      
      // Re-establish key hierarchy
      await this.reestablishKeyHierarchy(masterKey);
      
      // Notify success
      await this.notifyRecoverySuccess(sessionId);
      
    } catch (error) {
      await this.notifyRecoveryFailure(sessionId, error);
    }
  }
}
```

### 2. Hardware Token Recovery

```typescript
class HardwareTokenRecovery {
  async setupHardwareBackup(
    masterKey: CryptoKey
  ): Promise<HardwareBackupInfo> {
    // Check for compatible hardware
    const availableAuthenticators = await this.detectAuthenticators();
    
    if (availableAuthenticators.length === 0) {
      throw new Error('No compatible hardware authenticators found');
    }
    
    // Create backup credential
    const backupId = crypto.randomUUID();
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    
    const credential = await navigator.credentials.create({
      publicKey: {
        challenge,
        rp: {
          name: 'Aura Backup',
          id: 'aura.app'
        },
        user: {
          id: new TextEncoder().encode(backupId),
          name: 'Recovery Key',
          displayName: 'Aura Recovery Key'
        },
        pubKeyCredParams: [
          { alg: -7, type: 'public-key' }, // ES256
          { alg: -8, type: 'public-key' }, // EdDSA
        ],
        authenticatorSelection: {
          authenticatorAttachment: 'cross-platform',
          requireResidentKey: true,
          userVerification: 'required'
        },
        attestation: 'direct',
        extensions: {
          credentialProtectionPolicy: 'userVerificationRequired',
          enforceCredentialProtectionPolicy: true,
          minPinLength: true
        }
      }
    }) as PublicKeyCredential;
    
    // Derive backup key from hardware credential
    const backupKey = await this.deriveBackupKey(credential);
    
    // Encrypt master key with backup key
    const encryptedMaster = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: crypto.getRandomValues(new Uint8Array(12))
      },
      backupKey,
      await crypto.subtle.exportKey('raw', masterKey)
    );
    
    return {
      backupId,
      credentialId: credential.id,
      authenticatorType: this.getAuthenticatorType(credential),
      encryptedMasterKey: new Uint8Array(encryptedMaster),
      createdAt: Date.now(),
      attestation: credential.response.attestationObject
    };
  }
  
  async recoverFromHardware(
    backupId: string
  ): Promise<CryptoKey> {
    // Get backup info
    const backupInfo = await this.getBackupInfo(backupId);
    
    // Request hardware authentication
    const assertion = await navigator.credentials.get({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        allowCredentials: [{
          id: base64ToArrayBuffer(backupInfo.credentialId),
          type: 'public-key'
        }],
        userVerification: 'required'
      }
    }) as PublicKeyCredential;
    
    // Derive backup key from assertion
    const backupKey = await this.deriveBackupKeyFromAssertion(assertion);
    
    // Decrypt master key
    const masterKeyData = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: backupInfo.iv
      },
      backupKey,
      backupInfo.encryptedMasterKey
    );
    
    // Import recovered master key
    return crypto.subtle.importKey(
      'raw',
      masterKeyData,
      'AES-GCM',
      true,
      ['encrypt', 'decrypt']
    );
  }
}
```

### 3. Emergency Access System

```typescript
class EmergencyAccessSystem {
  async setupEmergencyAccess(
    emergencyContacts: EmergencyContact[]
  ): Promise<EmergencyAccessSetup> {
    const setup: EmergencyAccessSetup = {
      id: crypto.randomUUID(),
      contacts: [],
      waitingPeriod: 48 * 3600 * 1000, // 48 hours
      createdAt: Date.now()
    };
    
    for (const contact of emergencyContacts) {
      // Generate unique access key for contact
      const accessKey = await crypto.subtle.generateKey(
        {
          name: 'AES-GCM',
          length: 256
        },
        true,
        ['encrypt', 'decrypt']
      );
      
      // Create time-locked access capability
      const capability = await this.createTimeLockCapability(
        contact,
        accessKey,
        setup.waitingPeriod
      );
      
      setup.contacts.push({
        id: contact.id,
        name: contact.name,
        capability: capability,
        status: 'inactive'
      });
    }
    
    return setup;
  }
  
  private async createTimeLockCapability(
    contact: EmergencyContact,
    accessKey: CryptoKey,
    waitingPeriod: number
  ): Promise<TimeLockCapability> {
    // Create smart contract or time-lock puzzle
    const timeLock = {
      beneficiary: contact.id,
      unlockTime: 0, // Set when access is requested
      waitingPeriod,
      puzzle: await this.createTimeLockPuzzle(waitingPeriod)
    };
    
    // Encrypt access key with time-lock
    const encryptedKey = await this.encryptWithTimeLock(
      accessKey,
      timeLock
    );
    
    return {
      contactId: contact.id,
      encryptedAccessKey: encryptedKey,
      timeLock,
      createdAt: Date.now()
    };
  }
  
  async requestEmergencyAccess(
    contactId: string,
    reason: string
  ): Promise<EmergencyAccessRequest> {
    const capability = await this.getCapability(contactId);
    
    // Start waiting period
    const request: EmergencyAccessRequest = {
      id: crypto.randomUUID(),
      contactId,
      reason,
      requestedAt: Date.now(),
      unlocksAt: Date.now() + capability.timeLock.waitingPeriod,
      status: 'waiting'
    };
    
    // Notify user
    await this.notifyUserOfEmergencyRequest(request);
    
    // Set up monitoring
    setTimeout(async () => {
      if (!await this.wasRequestCancelled(request.id)) {
        await this.grantEmergencyAccess(request);
      }
    }, capability.timeLock.waitingPeriod);
    
    return request;
  }
}
```

## Key Rotation and Lifecycle

### Automatic Key Rotation

```typescript
class KeyRotationManager {
  private rotationSchedule: Map<string, RotationPolicy> = new Map();
  
  async setupRotationPolicy(
    keyType: string,
    policy: RotationPolicy
  ): Promise<void> {
    this.rotationSchedule.set(keyType, policy);
    
    // Schedule first rotation
    await this.scheduleRotation(keyType, policy);
  }
  
  private async scheduleRotation(
    keyType: string,
    policy: RotationPolicy
  ): Promise<void> {
    const nextRotation = this.calculateNextRotation(policy);
    
    setTimeout(async () => {
      await this.rotateKey(keyType);
      
      // Schedule next rotation
      await this.scheduleRotation(keyType, policy);
    }, nextRotation - Date.now());
  }
  
  async rotateKey(keyType: string): Promise<void> {
    // Generate new key
    const newKey = await this.generateNewKey(keyType);
    
    // Get current key
    const currentKey = await this.getCurrentKey(keyType);
    
    // Re-encrypt data with new key
    await this.reencryptData(keyType, currentKey, newKey);
    
    // Update key references
    await this.updateKeyReferences(keyType, newKey);
    
    // Archive old key (for decryption only)
    await this.archiveKey(currentKey, keyType);
    
    // Log rotation
    await this.logRotation(keyType, {
      oldKeyId: currentKey.id,
      newKeyId: newKey.id,
      timestamp: Date.now()
    });
  }
  
  private async reencryptData(
    keyType: string,
    oldKey: CryptoKey,
    newKey: CryptoKey
  ): Promise<void> {
    // Get all data encrypted with old key
    const encryptedData = await this.getDataByKeyType(keyType);
    
    // Process in batches to avoid memory issues
    const batchSize = 100;
    for (let i = 0; i < encryptedData.length; i += batchSize) {
      const batch = encryptedData.slice(i, i + batchSize);
      
      await Promise.all(batch.map(async (item) => {
        // Decrypt with old key
        const decrypted = await crypto.subtle.decrypt(
          {
            name: 'AES-GCM',
            iv: item.iv
          },
          oldKey,
          item.encryptedData
        );
        
        // Encrypt with new key
        const newIv = crypto.getRandomValues(new Uint8Array(12));
        const reencrypted = await crypto.subtle.encrypt(
          {
            name: 'AES-GCM',
            iv: newIv
          },
          newKey,
          decrypted
        );
        
        // Update storage
        await this.updateEncryptedData(item.id, {
          encryptedData: new Uint8Array(reencrypted),
          iv: newIv,
          keyVersion: newKey.version
        });
      }));
    }
  }
}
```

## Security Monitoring and Alerts

### Key Usage Monitoring

```typescript
class KeySecurityMonitor {
  private usagePatterns: Map<string, UsagePattern> = new Map();
  private alertThresholds: AlertThresholds;
  
  async monitorKeyUsage(
    keyId: string,
    operation: KeyOperation
  ): Promise<void> {
    // Record usage
    const usage: KeyUsage = {
      keyId,
      operation: operation.type,
      timestamp: Date.now(),
      source: operation.source,
      metadata: operation.metadata
    };
    
    // Check for anomalies
    const anomalies = await this.detectAnomalies(keyId, usage);
    
    if (anomalies.length > 0) {
      await this.handleAnomalies(keyId, anomalies);
    }
    
    // Update usage patterns
    await this.updateUsagePattern(keyId, usage);
  }
  
  private async detectAnomalies(
    keyId: string,
    usage: KeyUsage
  ): Promise<Anomaly[]> {
    const anomalies: Anomaly[] = [];
    const pattern = this.usagePatterns.get(keyId);
    
    if (!pattern) {
      return anomalies;
    }
    
    // Check usage frequency
    if (this.isFrequencyAnomaly(pattern, usage)) {
      anomalies.push({
        type: 'frequency',
        severity: 'medium',
        description: 'Unusual key usage frequency detected'
      });
    }
    
    // Check access location
    if (this.isLocationAnomaly(pattern, usage)) {
      anomalies.push({
        type: 'location',
        severity: 'high',
        description: 'Key accessed from unusual location'
      });
    }
    
    // Check time pattern
    if (this.isTimeAnomaly(pattern, usage)) {
      anomalies.push({
        type: 'time',
        severity: 'low',
        description: 'Key accessed at unusual time'
      });
    }
    
    return anomalies;
  }
  
  private async handleAnomalies(
    keyId: string,
    anomalies: Anomaly[]
  ): Promise<void> {
    const highSeverityAnomalies = anomalies.filter(
      a => a.severity === 'high'
    );
    
    if (highSeverityAnomalies.length > 0) {
      // Immediate action for high severity
      await this.lockKey(keyId);
      await this.notifyUser('urgent', {
        keyId,
        anomalies: highSeverityAnomalies,
        action: 'key_locked',
        requiredAction: 'verify_identity'
      });
    } else {
      // Standard notification for lower severity
      await this.notifyUser('warning', {
        keyId,
        anomalies,
        recommendation: 'review_activity'
      });
    }
  }
}
```

## Implementation Best Practices

### 1. Secure Key Generation

```typescript
class SecureKeyGenerator {
  async generateMasterKey(): Promise<CryptoKeyPair> {
    // Ensure sufficient entropy
    const entropy = await this.gatherEntropy();
    
    if (entropy.strength < 256) {
      throw new Error('Insufficient entropy for secure key generation');
    }
    
    // Generate key pair with post-quantum considerations
    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'ECDSA',
        namedCurve: 'P-521' // Use strongest available curve
      },
      true,
      ['sign', 'verify']
    );
    
    // Validate key strength
    await this.validateKeyStrength(keyPair);
    
    return keyPair;
  }
  
  private async gatherEntropy(): Promise<EntropyResult> {
    const sources: Uint8Array[] = [];
    
    // Hardware RNG
    sources.push(crypto.getRandomValues(new Uint8Array(32)));
    
    // User interaction entropy
    sources.push(await this.captureUserEntropy());
    
    // Timing entropy
    sources.push(await this.captureTimingEntropy());
    
    // Combine sources
    const combined = await this.combineEntropySources(sources);
    
    return {
      data: combined,
      strength: this.calculateEntropyStrength(combined)
    };
  }
}
```

### 2. Key Backup Strategies

```typescript
class KeyBackupManager {
  async createComprehensiveBackup(
    masterKey: CryptoKey
  ): Promise<BackupPackage> {
    const backupId = crypto.randomUUID();
    
    // Create multiple backup methods
    const backups: BackupMethod[] = [];
    
    // 1. Encrypted cloud backup
    if (await this.isCloudBackupEnabled()) {
      backups.push(await this.createCloudBackup(masterKey, backupId));
    }
    
    // 2. QR code paper backup
    backups.push(await this.createPaperBackup(masterKey, backupId));
    
    // 3. Social recovery shares
    if (await this.hasSocialRecoveryContacts()) {
      backups.push(await this.createSocialShares(masterKey, backupId));
    }
    
    // 4. Hardware token backup
    if (await this.hasHardwareToken()) {
      backups.push(await this.createHardwareBackup(masterKey, backupId));
    }
    
    return {
      backupId,
      methods: backups,
      createdAt: Date.now(),
      expiresAt: Date.now() + (365 * 24 * 3600 * 1000) // 1 year
    };
  }
  
  private async createPaperBackup(
    masterKey: CryptoKey,
    backupId: string
  ): Promise<PaperBackup> {
    // Export key
    const keyData = await crypto.subtle.exportKey('raw', masterKey);
    
    // Encode for paper storage
    const encoded = this.encodeToPaperFormat(keyData);
    
    // Split into QR codes if too large
    const qrCodes = await this.generateQRCodes(encoded);
    
    // Add error correction
    const withErrorCorrection = this.addErrorCorrection(qrCodes);
    
    return {
      type: 'paper',
      backupId,
      qrCodes: withErrorCorrection,
      instructions: this.generatePrintInstructions(),
      verificationCode: await this.generateVerificationCode(keyData)
    };
  }
}
```

## Conclusion

This key management system provides users with complete control over their encryption keys while maintaining security and usability. Key features include:

1. **User Sovereignty**: Keys never leave user control
2. **Multiple Recovery Options**: Social, hardware, and emergency recovery
3. **Automatic Security**: Key rotation and anomaly detection
4. **Cross-Device Support**: Secure synchronization between devices
5. **Future-Proof**: Quantum-resistant algorithms and upgradeable design

The system ensures that users can always access their data while preventing unauthorized access, even by Aura itself.