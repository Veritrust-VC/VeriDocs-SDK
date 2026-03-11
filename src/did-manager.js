/**
 * DID Manager — creates and manages organization and document DIDs.
 * 
 * Organization DID: did:web:{domain}:org:{code}
 * Document DID:     did:web:{domain}:doc:{uuid}
 * 
 * Uses the same Veramo agent and key management as VeriTrust.
 */

const crypto = require('crypto');
const { secp256k1 } = require('@noble/curves/secp256k1');
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

function toBase64Url(bytes) {
  return Buffer.from(bytes)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function publicKeyHexToSecp256k1Jwk(publicKeyHex) {
  if (!publicKeyHex) throw new Error('Missing publicKeyHex for DID document generation');

  const normalizedHex = String(publicKeyHex).toLowerCase().replace(/^0x/, '');
  let uncompressedHex = normalizedHex;

  if (normalizedHex.length === 66 && (normalizedHex.startsWith('02') || normalizedHex.startsWith('03'))) {
    uncompressedHex = Buffer.from(secp256k1.ProjectivePoint.fromHex(normalizedHex).toRawBytes(false)).toString('hex');
  }

  if (!(uncompressedHex.length === 130 && uncompressedHex.startsWith('04'))) {
    throw new Error(`Unsupported secp256k1 public key format: expected compressed or uncompressed hex, got length ${normalizedHex.length}`);
  }

  const xHex = uncompressedHex.slice(2, 66);
  const yHex = uncompressedHex.slice(66, 130);

  return {
    kty: 'EC',
    crv: 'secp256k1',
    x: toBase64Url(Buffer.from(xHex, 'hex')),
    y: toBase64Url(Buffer.from(yHex, 'hex')),
  };
}

function buildCanonicalDidDocument(did, key) {
  return {
    '@context': [
      'https://www.w3.org/ns/did/v1',
      'https://w3id.org/security/suites/jws-2020/v1',
    ],
    id: did,
    verificationMethod: [
      {
        id: `${did}#key-1`,
        type: 'JsonWebKey2020',
        controller: did,
        publicKeyJwk: publicKeyHexToSecp256k1Jwk(key.publicKeyHex),
      },
    ],
    authentication: [`${did}#key-1`],
    assertionMethod: [`${did}#key-1`],
  };
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
  const keyAlias = `orgkey-${normalizedOrgCode}`;
  const identifiers = await agent.didManagerFind();

  const existingCanonical = identifiers.find((i) => i.did === did);
  const staleAlias = identifiers.find((i) => (i.alias === normalizedOrgCode || i.alias === keyAlias) && i.did !== did);

  if (!existingCanonical && staleAlias) {
    throw new Error(`local alias conflict: ${normalizedOrgCode} exists with non-canonical DID ${staleAlias.did}`);
  }

  const identifier = existingCanonical
    ? await agent.didManagerGet({ did })
    : await agent.didManagerCreate({
      provider: 'did:key',
      alias: keyAlias,
      kms: 'local',
      options: {
        keyType: 'Secp256k1',
      },
    });

  const primaryKey = identifier.keys && identifier.keys[0];
  if (!primaryKey) throw new Error(`No key material found for organization DID ${did}`);
  const didDocument = buildCanonicalDidDocument(did, primaryKey);


  return {
    did,
    didDocument,
    alias: alias || normalizedOrgCode,
    controllerKeyId: identifier.controllerKeyId,
    keys: (identifier.keys || []).map(k => ({
      kid: k.kid,
      type: k.type,
      publicKeyHex: k.publicKeyHex,
    })),
    alreadyExisted: !!existingCanonical,
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
