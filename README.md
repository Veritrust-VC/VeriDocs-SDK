# VeriDocs SDK

Docker sidecar for integrating document lifecycle DID/VC capabilities into any Document Management System.

Run it alongside your DMS. Every document lifecycle action — created, sent, received, assigned, decided, archived — is signed as a W3C Verifiable Credential and submitted to the central [VeriDocs Register](https://github.com/Veritrust-VC/VeriDocs-Register).

Uses the same Veramo 6.x agent, JsonWebSignature2020 proof type, ES256K signatures, and StatusList2021 revocation. Credentials issued by VeriDocs SDK are interoperable with VeriTrust production.

---

## How It Works

```
Your DMS 
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

Your DMS calls the SDK via simple HTTP. The SDK handles all DID/VC complexity — key management, credential signing, Registry communication, and Register authentication. Register endpoints are protected, so the SDK authenticates with service credentials before protected calls. OpenDMS (or any DMS) never talks directly to Register.

## Quick Start

### 1. Start the SDK

```bash
git clone https://github.com/Veritrust-VC/VeriDocs-SDK.git
cd VeriDocs-SDK
cp .env.example .env
docker compose up --build
```

SDK starts at **http://localhost:3100**.

### 2. Configure Register access and create your organization DID

```bash
curl -X POST http://localhost:3100/api/setup/org \
  -H "Content-Type: application/json" \
  -d '{"orgCode": "MYORG-001", "orgName": "My Organization"}'
```

The SDK automatically persists this DID as the active organization DID for lifecycle hooks, authenticates to Register using `REGISTRY_EMAIL` and `REGISTRY_PASSWORD`, and registers the organization centrally.

Check readiness:

```bash
curl http://localhost:3100/api/setup/status
curl http://localhost:3100/api/setup/verify
```

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
| `GET` | `/api/setup/status` | Current SDK state, active org DID, registry connectivity/authentication, readiness, and last setup metadata |
| `GET` | `/api/setup/verify` | Readiness check for lifecycle usage (org DID + registry + managed identifier) |

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
| `GET` | `/api/health` | Health check including registry connectivity/authentication summary |
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
| `ORG_DID` | | Optional fallback/legacy bootstrap DID. Preferred mode is SDK-managed persisted active org DID. |
| `REGISTRY_URL` | `http://localhost:8001` | VeriDocs Register API URL |
| `REGISTRY_EMAIL` | | Register service account email (required for protected registry operations) |
| `REGISTRY_PASSWORD` | | Register service account password (required for protected registry operations) |
| `REGISTRY_API_KEY` | | Optional API key header for Registry if deployment uses it |
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
      # ORG_DID optional fallback; SDK persists active DID after /api/setup/org
      ORG_DID: ${ORG_DID}
      REGISTRY_URL: https://registry.example.com
      REGISTRY_EMAIL: sdk-service@example.com
      REGISTRY_PASSWORD: change-me
```

## Related Repositories

| Repository | Description |
|------------|-------------|
| [VeriDocs-Register](https://github.com/Veritrust-VC/VeriDocs-Register) | Central DID/VC registry. Receives and verifies lifecycle VCs submitted by SDK instances. |
| [OpenDMS](https://github.com/Veritrust-VC/OpenDMS) | Reference DMS with VeriDocs SDK pre-integrated. Every document action fires VCs automatically. |

## License

MIT

## Persistence

The SDK persists the active organization DID and last setup metadata in a local state file (`data/sdk-state.json` by default, configurable via `SDK_STATE_FILE`). In Docker deployments, mount a persistent volume for `/app/data` to avoid losing active configuration when containers are recreated.

## Lifecycle Readiness

A DID returned by setup does not always mean lifecycle submission is ready. Full lifecycle readiness requires:
- active organization DID configured in SDK state (or fallback env),
- Registry reachable,
- managed identifier present in the SDK agent.

Use `GET /api/setup/verify` for machine-usable readiness flags.

## Register Authentication and Health Semantics

Protected Register routes such as `POST /api/v1/orgs`, `POST /api/v1/docs`, and `POST /api/v1/events` require bearer authentication. The SDK first calls `POST /api/v1/auth/login`, caches the access token in memory, and sends `Authorization: Bearer <token>` on protected requests.

The Register health endpoint used by SDK is the public `GET /api/v1/health` route (not `/health`).

Setup flow for central registration:
1. Configure `REGISTRY_URL`, `REGISTRY_EMAIL`, and `REGISTRY_PASSWORD`.
2. Call `POST /api/setup/org`.
3. SDK creates and persists the active organization DID.
4. SDK authenticates to Register and registers organization metadata centrally.
5. Verify state via `GET /api/setup/status`.

`/api/health` and `/api/setup/status` include:
- `registry_connected`
- `registry_auth_configured`
- `registry_authenticated`
- `registry_auth_error`

Readiness (`lifecycle_ready`/`ready_for_lifecycle`) requires an org DID plus registry connectivity and successful auth.

## Central Sync Verification and Audit Logging

### Register authentication

The SDK authenticates against Register using:

- `REGISTRY_URL`
- `REGISTRY_EMAIL`
- `REGISTRY_PASSWORD`

Login is performed via `POST /api/v1/auth/login`. The SDK accepts either `access_token` or `token` in login responses.

### Connected vs authenticated vs registered vs verified

- **connected**: SDK can reach `GET /api/v1/health` on Register.
- **authenticated**: SDK can login and cache bearer token.
- **registered**: organization registration (`POST /api/v1/orgs`) completed.
- **verified**: SDK can read organization back via `GET /api/v1/orgs/{org_did}`.

`POST /api/setup/org` now creates/imports local DID, attempts remote registration, then verifies remote presence immediately.

### Audit log database

Sync and auth logs are persisted in SQLite:

- default DB file: `/app/status-data/sdk_audit.db`
- override with: `SDK_AUDIT_DB_FILE`

Persistent Docker volume mapping should include:

- `sdk-data:/app/status-data`

### Trace ID propagation

SDK accepts incoming `X-Trace-Id` headers. If absent, SDK generates a new trace ID and returns it in response headers/body.

Trace IDs are written to all central sync audit rows and auth log rows.

### Audit log API endpoints

- `GET /api/audit/logs?limit=&offset=&action=&success=&trace_id=`
- `GET /api/audit/logs/:id`
- `GET /api/audit/summary`

### Setup/Health truth fields

`GET /api/setup/status` and `GET /api/health` include high-level sync truth fields:

- `registry_connected`
- `registry_auth_configured`
- `registry_authenticated`
- `org_registered_in_registry`
- `org_verified_in_registry`
- `last_sync_error`
- `last_trace_id`

### Additional environment variables

- `SDK_STATE_FILE` — persisted local setup state JSON file.
- `SDK_AUDIT_DB_FILE` *(optional)* — path to SQLite audit database.
