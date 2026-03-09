/**
 * DID Manager — creates and manages organization and document DIDs.
 * 
 * Organization DID: did:web:{domain}:org:{code}
 * Document DID:     did:web:{domain}:doc:{uuid}
 * 
 * Uses the same Veramo agent and key management as VeriTrust.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { createAgentInstance } = require('../agent-setup');

let agentPromise;
async function getAgent() {
  if (!agentPromise) agentPromise = createAgentInstance();
  return agentPromise;
}

const REGISTRY_DOMAIN = (process.env.REGISTRY_DOMAIN || 'localhost%3A8001');

function normalizeOrgCode(code) {
  return String(code || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '');
}

/**
 * Create an organization DID and register it with the Veramo agent.
 * @param {string} orgCode - Organization code (e.g., 'ACME-001')
 * @param {string} [alias] - Human-readable alias
 * @returns {{ did, didDocument, keys, controllerKeyId }}
 */
async function createOrganizationDID(orgCode, alias) {
  const agent = await getAgent();
  const normalizedOrgCode = normalizeOrgCode(orgCode);
  if (!normalizedOrgCode) throw new Error('Invalid orgCode. Provide a non-empty slug-safe organization code.');
  const did = `did:web:${REGISTRY_DOMAIN}:org:${normalizedOrgCode}`;

  // Check if already exists
  try {
    const existing = await agent.didManagerGet({ did });
    return {
      did: existing.did,
      alias: existing.alias,
      controllerKeyId: existing.controllerKeyId,
      keys: existing.keys || [],
      alreadyExisted: true,
    };
  } catch (e) {
    // Not found — create new
  }

  const identifier = await agent.didManagerCreate({
    provider: 'did:web',
    alias: normalizedOrgCode,
    kms: 'local',
    options: {
      keyType: 'Secp256k1',
    },
  });

  // Export DID Document to .well-known
  const wellKnownDir = path.join(__dirname, '..', '.well-known');
  fs.mkdirSync(wellKnownDir, { recursive: true });
  try {
    const resolution = await agent.resolveDid({ didUrl: identifier.did });
    if (resolution.didDocument) {
      fs.writeFileSync(
        path.join(wellKnownDir, 'did.json'),
        JSON.stringify(resolution.didDocument, null, 2),
      );
    }
  } catch (e) {
    console.warn('[SDK] Could not export DID document:', e.message);
  }

  return {
    did: identifier.did,
    alias: identifier.alias,
    controllerKeyId: identifier.controllerKeyId,
    keys: (identifier.keys || []).map(k => ({
      kid: k.kid,
      type: k.type,
      publicKeyHex: k.publicKeyHex,
    })),
    alreadyExisted: false,
  };
}

/**
 * Create a document DID (not managed by Veramo — just a deterministic identifier).
 * @param {string} orgDid - The organization's DID
 * @param {object} [metadata] - Optional document metadata
 * @returns {{ did, uuid, issuer, metadata }}
 */
function createDocumentDID(orgDid, metadata) {
  const docUuid = crypto.randomUUID();
  const did = `did:web:${REGISTRY_DOMAIN}:doc:${docUuid}`;
  return {
    did,
    uuid: docUuid,
    issuer: orgDid,
    created: new Date().toISOString(),
    metadata: metadata || {},
  };
}

/**
 * Get the managed identifier for a DID.
 */
async function getIdentifier(did) {
  const agent = await getAgent();
  return agent.didManagerGet({ did });
}

/**
 * List all managed identifiers.
 */
async function listIdentifiers() {
  const agent = await getAgent();
  return agent.didManagerFind();
}

/**
 * Get the public key (hex) for the controller key of a managed DID.
 */
async function getPublicKeyHex(did) {
  const agent = await getAgent();
  const ident = await agent.didManagerGet({ did });
  const key = ident.keys && ident.keys[0];
  return key ? key.publicKeyHex : null;
}

module.exports = {
  normalizeOrgCode,
  createOrganizationDID,
  createDocumentDID,
  getIdentifier,
  listIdentifiers,
  getPublicKeyHex,
};
