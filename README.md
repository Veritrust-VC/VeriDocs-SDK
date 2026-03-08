# VeriDocs SDK

Docker sidecar for integrating document lifecycle DID/VC capabilities into any Document Management System.

Run it alongside your DMS (Namejs, Lietvaris, DocLogix, or any DMS). Every document lifecycle action — created, sent, received, assigned, decided, archived — is signed as a W3C Verifiable Credential and submitted to the central [VeriDocs Register](https://github.com/Veritrust-VC/VeriDocs-Register).

**Forked from [VeriTrust](https://veritrust.vc) production codebase.** Uses the same Veramo 6.x agent, JsonWebSignature2020 proof type, ES256K signatures, and StatusList2021 revocation. Credentials issued by VeriDocs SDK are interoperable with VeriTrust production.

---

## How It Works

```
Your DMS (Namejs, DocLogix, etc.)
    │
    │  POST /api/documents/create
    │  POST /api/documents/{did}/send
    │  POST /api/documents/{did}/receive
    │  ...
    ▼
┌─────────────────────────┐         ┌─────────────────────────┐
│  VeriDocs SDK Sidecar    │────────▶│  VeriDocs Register      │
│  :3100                   │  VCs    │  :8001                  │
│                          │────────▶│                         │
│  - Org DID management    │         │  - VC storage           │
│  - Document DID creation │         │  - Signature verify     │
│  - VC signing (ES256K)   │         │  - State machine        │
│  - Lifecycle hooks       │         │  - Document tracking    │
│  - StatusList2021        │         │  - Admin dashboard      │
└─────────────────────────┘         └─────────────────────────┘
```

Your DMS calls the SDK via simple HTTP. The SDK handles all DID/VC complexity — key management, credential signing, Registry communication. The DMS never touches cryptography directly.

## Quick Start

### 1. Start the SDK

```bash
git clone https://github.com/Veritrust-VC/VeriDocs-SDK.git
cd VeriDocs-SDK
cp .env.example .env
docker compose up --build
```

SDK starts at **http://localhost:3100**.

### 2. Create your organization DID

```bash
curl -X POST http://localhost:3100/api/setup/org \
  -H "Content-Type: application/json" \
  -d '{"orgCode": "MYORG-001", "orgName": "My Organization"}'
```

Copy the returned DID into your `.env`:
```
ORG_DID=did:web:localhost%3A8001:org:MYORG-001
```

Restart: `docker compose restart sdk`

### 3. Use from your DMS

```bash
# Create a document
curl -X POST http://localhost:3100/api/documents/create \
  -H "Content-Type: application/json" \
  -d '{"title": "Application for building permit", "classification": "construction/permits"}'

# Send to another organization
curl -X POST http://localhost:3100/api/documents/{docDid}/send \
  -H "Content-Type: application/json" \
  -d '{"recipientDid": "did:web:...:org:OTHER-001", "deliveryMethod": "eAdrese"}'

# Track document
curl http://localhost:3100/api/documents/{docDid}/track
```

## API Reference

### Setup (one-time)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/setup/org` | Create organization DID and register with Registry |
| `GET` | `/api/setup/status` | Check setup status, Registry connection, signing mode |

### Document Lifecycle

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/documents/create` | Create document DID + register + DocumentCreated VC |
| `POST` | `/api/documents/{did}/send` | Sign and submit DocumentSent VC |
| `POST` | `/api/documents/{did}/receive` | Sign and submit DocumentReceived VC |
| `POST` | `/api/documents/{did}/assign` | Sign and submit DocumentAssigned VC |
| `POST` | `/api/documents/{did}/decide` | Sign and submit DocumentDecided VC |
| `POST` | `/api/documents/{did}/archive` | Sign and submit DocumentArchived VC |
| `GET` | `/api/documents/{did}/track` | Track document via Registry |

### DID/VC Utilities

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/did/resolve` | Resolve any DID |
| `POST` | `/api/vc/verify` | Verify a Verifiable Credential |
| `GET` | `/api/identifiers` | List managed DIDs |

### System

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/health` | Health check |
| `GET` | `/.well-known/did.json` | This agent's DID Document |
| `GET` | `/contexts/*.jsonld` | JSON-LD context files |

## Signing Modes

The SDK supports two signing modes, configurable via `SIGNING_MODE` env var:

**Local (default):** The SDK runs its own Veramo agent with locally managed keys. The organization holds its own private keys — no external dependency for signing. This is the decentralized model per the VDVC architecture.

**Delegate:** The SDK sends unsigned credentials to the Registry's Veramo agent for signing. Useful for small organizations that don't want to manage keys. Requires `DELEGATE_URL` and `DELEGATE_API_KEY`.

```bash
# Local signing (default)
SIGNING_MODE=local

# Delegated signing
SIGNING_MODE=delegate
DELEGATE_URL=http://registry-veramo:3000
DELEGATE_API_KEY=your-registry-api-key
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | (required) | 32-byte hex for encrypted key storage |
| `ORG_DID` | | Organization DID (set after setup) |
| `REGISTRY_URL` | `http://localhost:8001` | VeriDocs Register API URL |
| `REGISTRY_API_KEY` | | API key for Registry |
| `REGISTRY_DOMAIN` | `localhost%3A8001` | Domain used in `did:web` identifiers |
| `SIGNING_MODE` | `local` | `local` or `delegate` |
| `DELEGATE_URL` | | Registry Veramo URL (for delegate mode) |
| `DELEGATE_API_KEY` | | API key for delegate signing |
| `VERAMO_API_KEY` | | API key for SDK endpoints |
| `SDK_PORT` | `3100` | SDK server port |

## Project Structure

```
VeriDocs-SDK/
├── server.js                    # Express REST API (DVS-facing)
├── agent-setup.js               # Veramo 6.x agent (VeriTrust fork)
├── custom-data-store.js         # SQLite key/DID stores
├── custom-private-key-store.js  # Encrypted private key storage
├── auth.js                      # API key authentication
├── src/
│   ├── did-manager.js           # Organization + document DID creation
│   ├── vc-builder.js            # Lifecycle VC creation + signing
│   ├── hooks/
│   │   └── lifecycle.js         # DVS integration hooks
│   ├── registry-client/
│   │   └── index.js             # HTTP client for VeriDocs Register
│   └── ld-suites/               # JsonWebSignature2020 (ES256K)
├── public/contexts/             # JSON-LD contexts
│   └── document-lifecycle-v1.jsonld
├── status/                      # StatusList2021 management
├── patches/                     # Veramo credential-ld patch
├── test/
├── Dockerfile
├── docker-compose.yml
└── .env.example
```

## Integration Patterns

### Pattern 1: Direct HTTP calls (any language)

Your DMS makes REST calls to the SDK. Works with Java, .NET, Python, PHP — anything with HTTP client.

```python
# Python example
import requests
SDK = "http://localhost:3100"
doc = requests.post(f"{SDK}/api/documents/create", json={"title": "Permit Application"}).json()
requests.post(f"{SDK}/api/documents/{doc['docDid']}/send", json={"recipientDid": "did:web:...:org:OTHER"})
```

### Pattern 2: Webhook-style (DMS event hooks)

Configure your DMS to call SDK endpoints on state transitions:
- Document registered → `POST /api/documents/create`
- Document sent → `POST /api/documents/{did}/send`
- Document received → `POST /api/documents/{did}/receive`

### Pattern 3: SDK inside docker-compose (with your DMS)

```yaml
services:
  my-dms:
    image: my-dms:latest
    environment:
      VERIDOCS_SDK_URL: http://veridocs-sdk:3100
    depends_on:
      - veridocs-sdk

  veridocs-sdk:
    image: ghcr.io/veritrust-vc/veridocs-sdk:latest
    environment:
      SECRET_KEY: ${SECRET_KEY}
      ORG_DID: ${ORG_DID}
      REGISTRY_URL: https://registry.example.com
```

## Related Repositories

| Repository | Description |
|------------|-------------|
| [VeriDocs-Register](https://github.com/Veritrust-VC/VeriDocs-Register) | Central DID/VC registry. Receives and verifies lifecycle VCs submitted by SDK instances. |
| [OpenDMS](https://github.com/Veritrust-VC/OpenDMS) | Reference DMS with VeriDocs SDK pre-integrated. Every document action fires VCs automatically. |

## License

MIT
