/**
 * VC Builder — creates and signs document lifecycle Verifiable Credentials.
 * 
 * Uses ES256K (secp256k1) JWT signing via Veramo's keyManagerSign.
 * This bypasses Veramo's high-level createVerifiableCredential* methods
 * which internally resolve the issuer DID over the network — causing
 * timeouts in Docker environments where the domain isn't reachable.
 * 
 * Supports two signing modes:
 *   - LOCAL:    signs with the org's own Veramo-managed keys (direct JWT)
 *   - DELEGATE: sends to Registry's Veramo agent for signing
 */

const crypto = require('crypto');
const { createAgentInstance } = require('../agent-setup');

let agentPromise;
async function getAgent() {
  if (!agentPromise) agentPromise = createAgentInstance();
  return agentPromise;
}

const SIGNING_MODE = process.env.SIGNING_MODE || 'local'; // 'local' or 'delegate'
const DELEGATE_URL = process.env.DELEGATE_URL || '';       // Registry Veramo URL for delegate mode
const DELEGATE_API_KEY = process.env.DELEGATE_API_KEY || '';
const VC_HOST_BASE = (process.env.VC_HOST_BASE || 'http://localhost:3100').replace(/\/+$/, '');

const EVENT_TYPES = [
  'DocumentCreated', 'DocumentSent', 'DocumentReceived',
  'DocumentAssigned', 'DocumentDecided', 'DocumentArchived',
];

/**
 * Build and sign a lifecycle VC.
 * 
 * @param {string} eventType - One of the 6 lifecycle event types
 * @param {string} documentDid - DID of the document
 * @param {string} issuerDid - DID of the issuing organization
 * @param {object} claims - Additional claims (recipient, assignee, decision, etc.)
 * @param {object} [statusEntry] - Optional StatusList2021 entry { listId, index }
 * @returns {object} Signed Verifiable Credential
 */
async function createLifecycleVC(eventType, documentDid, issuerDid, claims, statusEntry) {
  if (!EVENT_TYPES.includes(eventType)) {
    throw new Error(`Invalid event type: ${eventType}. Must be one of: ${EVENT_TYPES.join(', ')}`);
  }

  const now = new Date();
  const expiry = new Date(now);
  expiry.setFullYear(expiry.getFullYear() + 2);

  // Build credential subject
  const credentialSubject = {
    id: documentDid,
    eventType,
    timestamp: now.toISOString(),
    issuerOrganization: issuerDid,
    ...claims,
  };

  if (eventType === 'DocumentCreated') {
    credentialSubject.metadata = claims && claims.metadata ? claims.metadata : {};
    credentialSubject.semanticSummary = claims && claims.semanticSummary ? claims.semanticSummary : null;
    credentialSubject.sensitivityControl = claims && claims.sensitivityControl ? claims.sensitivityControl : null;
  }

  // Build the credential
  const credential = {
    '@context': [
      'https://www.w3.org/2018/credentials/v1',
      'https://w3id.org/security/suites/jws-2020/v1',
      `${VC_HOST_BASE}/contexts/document-lifecycle-v1.jsonld`,
    ],
    id: `urn:uuid:${crypto.randomUUID()}`,
    type: ['VerifiableCredential', `${eventType}Credential`],
    issuer: issuerDid,
    issuanceDate: now.toISOString(),
    expirationDate: expiry.toISOString(),
    credentialSubject,
  };

  // Add StatusList entry if provided
  if (statusEntry) {
    credential.credentialStatus = {
      id: `${VC_HOST_BASE}/status/${statusEntry.listId}/status_vc.json#list`,
      type: 'BitstringStatusListEntry',
      statusPurpose: 'revocation',
      statusListIndex: String(statusEntry.index),
      statusListCredential: `${VC_HOST_BASE}/status/${statusEntry.listId}/status_vc.json`,
    };
  }

  // Sign
  if (SIGNING_MODE === 'delegate' && DELEGATE_URL) {
    return await _signDelegated(credential);
  } else {
    return await _signLocal(credential, issuerDid);
  }
}

/**
 * Resolve the Veramo managed identifier for an org DID.
 *
 * The SDK creates DIDs via didManagerImport with did:web provider.
 * This function looks up the managed identifier by DID or alias.
 */
async function _resolveIdentifier(agent, issuerDid) {
  // 1. Try direct lookup by DID
  try {
    return await agent.didManagerGet({ did: issuerDid });
  } catch (_e) {
    // Not found by DID
  }

  // 2. Extract org code from did:web:domain:org:{code} and try alias lookup
  const parts = issuerDid.split(':');
  const orgIdx = parts.indexOf('org');
  const orgCode = orgIdx >= 0 && parts[orgIdx + 1] ? parts[orgIdx + 1] : null;

  if (orgCode) {
    const keyAlias = `orgkey-${orgCode}`;
    try {
      return await agent.didManagerGet({ alias: keyAlias });
    } catch (_e) {
      // Not found by alias
    }
  }

  // 3. Scan all managed identifiers
  const allIdentifiers = await agent.didManagerFind();

  if (orgCode) {
    const keyAlias = `orgkey-${orgCode}`;
    const byAlias = allIdentifiers.find(
      i => i.alias === keyAlias || i.alias === orgCode
    );
    if (byAlias) return byAlias;
  }

  // 4. Last resort — if only one identifier exists, use it
  if (allIdentifiers.length === 1) {
    console.warn(
      `[VC Builder] Single managed DID fallback: using ${allIdentifiers[0].did} for ${issuerDid}`
    );
    return allIdentifiers[0];
  }

  throw new Error(
    `Issuer DID not managed by this agent: ${issuerDid}. ` +
    `Managed DIDs: ${allIdentifiers.map(i => `${i.did} (alias: ${i.alias})`).join(', ') || 'none'}`
  );
}

// ─── Base64url helpers ───────────────────────────────────────────────────────

function base64url(buf) {
  return Buffer.from(buf)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function base64urlJSON(obj) {
  return base64url(Buffer.from(JSON.stringify(obj), 'utf8'));
}

/**
 * Sign locally using direct JWT construction + keyManagerSign.
 * 
 * This NEVER resolves DIDs over the network — it reads the key from
 * Veramo's local store and signs the JWT directly. This avoids the
 * Docker hairpin NAT timeout that kills createVerifiableCredential*.
 */
async function _signLocal(credential, issuerDid) {
  const agent = await getAgent();

  // Resolve the managed identifier
  const ident = await _resolveIdentifier(agent, issuerDid);

  const key = ident.keys && ident.keys[0];
  if (!key) throw new Error(`No signing key found for ${issuerDid} (resolved via ${ident.did})`);

  // Build JWT header
  const header = {
    alg: 'ES256K',
    typ: 'JWT',
    kid: `${issuerDid}#key-1`,
  };

  // Build JWT payload (W3C VC-JWT profile)
  const nowSec = Math.floor(Date.now() / 1000);
  const expSec = credential.expirationDate
    ? Math.floor(new Date(credential.expirationDate).getTime() / 1000)
    : nowSec + (2 * 365 * 24 * 3600);

  const payload = {
    iss: issuerDid,
    sub: credential.credentialSubject.id || '',
    nbf: Math.floor(new Date(credential.issuanceDate).getTime() / 1000),
    exp: expSec,
    jti: credential.id || `urn:uuid:${crypto.randomUUID()}`,
    vc: {
      '@context': credential['@context'],
      type: credential.type,
      credentialSubject: credential.credentialSubject,
    },
  };

  // Add credentialStatus if present
  if (credential.credentialStatus) {
    payload.vc.credentialStatus = credential.credentialStatus;
  }

  // Sign: header.payload → ES256K signature via Veramo KMS
  const signingInput = `${base64urlJSON(header)}.${base64urlJSON(payload)}`;

  const signature = await agent.keyManagerSign({
    keyRef: key.kid,
    algorithm: 'ES256K',
    data: signingInput,
  });

  const jwt = `${signingInput}.${signature}`;

  // Return as a W3C VC with JWT proof (same shape Veramo returns)
  return {
    ...credential,
    proof: {
      type: 'JwtProof2020',
      jwt,
    },
  };
}

/**
 * Delegate signing to the Registry's Veramo agent.
 */
async function _signDelegated(credential) {
  const http = require('http');
  const https = require('https');
  const { URL } = require('url');

  const url = new URL('/credentials/issueLD', DELEGATE_URL);
  const lib = url.protocol === 'https:' ? https : http;

  const body = JSON.stringify({ credential });
  const headers = {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(body),
  };
  if (DELEGATE_API_KEY) headers['x-api-key'] = DELEGATE_API_KEY;

  return new Promise((resolve, reject) => {
    const req = lib.request(url, { method: 'POST', headers }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          if (res.statusCode >= 400) {
            reject(new Error(parsed.error || parsed.message || `Delegate signing failed: HTTP ${res.statusCode}`));
          } else {
            resolve(parsed.vc || parsed);
          }
        } catch (e) {
          reject(new Error(`Delegate signing response parse error: ${data}`));
        }
      });
    });
    req.on('error', reject);
    req.setTimeout(30000, () => { req.destroy(); reject(new Error('Delegate signing timeout')); });
    req.write(body);
    req.end();
  });
}

/**
 * Verify a VC using this agent.
 */
async function verifyVC(credential) {
  const agent = await getAgent();
  try {
    // For JWT VCs, verify the JWT directly
    if (credential.proof && credential.proof.jwt) {
      try {
        const result = await agent.verifyCredential({
          credential: credential.proof.jwt,
        });
        return { verified: result.verified !== false, error: result.error?.message || null };
      } catch (e) {
        return { verified: false, error: e.message };
      }
    }
    if (credential.proof && credential.proof.type === 'JsonWebSignature2020') {
      try {
        const result = await agent.verifyCredentialLD({ credential });
        return { verified: result.verified !== false, error: null };
      } catch (e) {
        // fallback
      }
    }
    const result = await agent.verifyCredential({ credential });
    return { verified: result.verified !== false, error: result.error?.message || null };
  } catch (err) {
    return { verified: false, error: err.message };
  }
}

module.exports = {
  createLifecycleVC,
  verifyVC,
  EVENT_TYPES,
};
