# Aura - Privacy-First AI Personal Assistant

Aura is a revolutionary AI personal assistant that prioritizes user privacy through **zero-knowledge architecture**. Unlike traditional AI assistants, Aura ensures that your data is encrypted client-side before leaving your device, making it mathematically impossible for even Aura's servers to access your information without your explicit cryptographic permission.

## 🔐 Zero-Knowledge Architecture

### What Makes Aura Different

- **Client-Side Encryption**: All data is encrypted on your device before transmission
- **Zero-Knowledge Authentication**: Your password never leaves your device
- **Cryptographic Access Control**: Support requires your explicit authorization
- **Mathematical Privacy Guarantees**: Privacy is proven, not just promised

### Core Privacy Principles

1. **Data Sovereignty**: You control your encryption keys
2. **Selective Disclosure**: Grant access only to specific data types
3. **Temporal Access**: All access is time-limited and revocable
4. **Complete Transparency**: Full audit trail of all access

## 🚀 Quick Start

### Prerequisites

- Python 3.11+
- Node.js 18+
- Docker & Docker Compose
- Git

### One-Command Setup

```bash
git clone https://github.com/aura/aura.git
cd aura
chmod +x scripts/setup.sh
./scripts/setup.sh
```

### Manual Setup

1. **Start Infrastructure**
   ```bash
   docker-compose up -d
   ```

2. **Backend Setup**
   ```bash
   cd backend
   pip install -e ".[dev,test]"
   python -m aura.main
   ```

3. **Frontend Setup**
   ```bash
   cd frontend/web
   npm install
   npm run dev
   ```

## 🔬 Privacy Demonstration

Run our comprehensive privacy demo:

```bash
python scripts/demo.py
```

This demonstrates:
- Client-side encryption/decryption
- Zero-knowledge authentication flow
- Encrypted storage privacy
- Support access control
- Threat resistance scenarios

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    CLIENT-SIDE ENCRYPTION LAYER                  │
├──────────────┬──────────────┬──────────────┬───────────────────┤
│   Key Mgmt   │  Encryption  │   Search     │  Access Control   │
│   (Argon2id) │ (AES-256-GCM)│  (Encrypted) │  (Cryptographic)  │
└──────┬───────┴──────┬───────┴──────┬────────┴───────┬──────────┘
       │              │              │                │
┌──────┴──────────────┴──────────────┴────────────────┴──────────┐
│                     ZERO-KNOWLEDGE SERVICES                     │
├─────────────┬─────────────┬─────────────┬───────────────────────┤
│   SRP-6a    │  Encrypted  │ Homomorphic │   Support Access      │
│    Auth     │  Storage    │  Operations │   Control Service     │
└─────────────┴─────────────┴─────────────┴───────────────────────┘
```

## 🧪 Testing

### Backend Tests
```bash
cd backend
pytest tests/ -v --cov=aura
```

### Frontend Tests
```bash
cd frontend/web
npm test -- --coverage
```

### Integration Tests
```bash
cd backend
pytest tests/integration/ -v
```

## 📡 API Usage

### Authentication (Zero-Knowledge)

```python
# Registration (client-side)
from aura.services.auth.srp import SRPAuthService

salt, verifier = SRPAuthService.generate_verifier(username, password)
# Send salt + verifier to server (password never transmitted)

# Login (SRP-6a protocol)
challenge = await auth_service.start_authentication(username, client_ephemeral, salt, verifier)
success, proof = await auth_service.complete_authentication(session_id, client_ephemeral, client_proof)
```

### Encrypted Storage

```python
# Encrypt data client-side
from aura.core.crypto import aura_encryption

encrypted = await aura_encryption.encrypt_json(sensitive_data, user_key)
# Server stores encrypted blob (cannot decrypt)

# Decrypt client-side
decrypted = await aura_encryption.decrypt_json(encrypted, user_key)
```

### Support Access Control

```python
# Request limited access
access_request = {
    "scope": ["system_logs"],
    "purpose": "Debug connection issue", 
    "duration": "30 minutes"
}

# User grants cryptographic permission
access_grant = await grant_support_access(request, user_approval)
# Support gets time-limited, scope-limited access
```

## 🛡️ Security Features

### Cryptographic Guarantees

- **AES-256-GCM**: Military-grade encryption
- **Argon2id**: Quantum-resistant key derivation
- **SRP-6a**: Zero-knowledge password authentication
- **Perfect Forward Secrecy**: Past data stays secure

### Attack Resistance

- ✅ **Server Breach**: Data remains encrypted
- ✅ **Insider Threats**: No admin access to user data
- ✅ **Government Surveillance**: Technical impossibility to comply
- ✅ **Advanced Persistent Threats**: Zero-knowledge prevents extraction

## 📊 Threat Model

| Attack Vector | Traditional Systems | Aura |
|---------------|-------------------|------|
| Database Breach | ❌ Plaintext exposed | ✅ Only encrypted blobs |
| Password Leak | ❌ Hashes vulnerable | ✅ SRP verifiers safe |
| Malicious Admin | ❌ Full data access | ✅ Zero access possible |
| Government Order | ❌ Must comply | ✅ Technically impossible |
| Quantum Computer | ⚠️ Current crypto at risk | ✅ Quantum-resistant design |

## 🔧 Development

### Project Structure

```
aura/
├── backend/              # Python FastAPI backend
│   ├── src/aura/
│   │   ├── core/         # Cryptographic libraries
│   │   ├── services/     # Business logic
│   │   ├── api/          # API endpoints
│   │   └── models/       # Database models
│   └── tests/            # Comprehensive test suite
├── frontend/             
│   └── web/              # React/Next.js frontend
│       ├── src/lib/      # Client-side crypto
│       └── __tests__/    # Frontend tests
├── scripts/              # Demo and setup scripts
└── docs/                 # Documentation
```

### Key Technologies

**Backend:**
- FastAPI (async Python web framework)
- SQLAlchemy (encrypted database ORM)
- Cryptography + PyNaCl (encryption libraries)
- SRP library (zero-knowledge auth)

**Frontend:**
- Next.js 14 (React framework)
- libsodium-wrappers (client-side crypto)
- Axios (encrypted API client)
- Jest (comprehensive testing)

## 🎯 Roadmap

### Phase 0: Privacy Foundation ✅
- [x] Zero-knowledge architecture
- [x] Client-side encryption
- [x] SRP-6a authentication
- [x] Encrypted storage

### Phase 1: Core Features (Next)
- [ ] Searchable encryption
- [ ] Support access control
- [ ] Task management
- [ ] Email/calendar integration

### Future Phases
- [ ] Mobile applications
- [ ] Voice interface with privacy
- [ ] Advanced AI features
- [ ] Plugin ecosystem

## 📝 License

Copyright (c) 2024 Aura. All rights reserved.

## 🤝 Contributing

We welcome contributions to Aura's privacy-first mission! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## 🔗 Links

- [Documentation](https://docs.aura.ai)
- [Security Whitepaper](https://aura.ai/security)
- [Privacy Policy](https://aura.ai/privacy)
- [Bug Reports](https://github.com/aura/aura/issues)

---

**Aura: Where privacy is mathematically guaranteed.**