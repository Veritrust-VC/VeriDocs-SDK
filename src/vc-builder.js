/**
 * VC Builder — creates and signs document lifecycle Verifiable Credentials.
 * 
 * Uses JsonWebSignature2020 with ES256K (secp256k1) — same as VeriTrust production.
 * Supports two signing modes:
 *   - LOCAL:    signs with the org's own Veramo-managed keys
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
 * Sign locally using this agent's Veramo instance.
 */
async function _signLocal(credential, issuerDid) {
  const agent = await getAgent();

  // Get the issuer's managed identifier
  let ident;
  try {
    ident = await agent.didManagerGet({ did: issuerDid });
  } catch (e) {
    throw new Error(`Issuer DID not managed by this agent: ${issuerDid}`);
  }

  const key = ident.keys && ident.keys[0];
  if (!key) throw new Error(`No signing key found for ${issuerDid}`);

  const verificationMethod = key.kid;

  // Try JSON-LD signing first (JsonWebSignature2020)
  try {
    const vc = await agent.createVerifiableCredentialLD({
      credential,
      verificationMethod,
      keyRef: verificationMethod,
      proofType: 'JsonWebSignature2020',
      purpose: 'assertionMethod',
    }, { agent });
    return vc;
  } catch (ldErr) {
    // Fallback to JWT
    console.warn('[SDK] LD signing failed, falling back to JWT:', ldErr.message);
    const vc = await agent.createVerifiableCredential({
      credential,
      proofFormat: 'jwt',
    });
    return vc;
  }
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
