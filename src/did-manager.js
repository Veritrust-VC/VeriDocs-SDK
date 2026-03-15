/**
 * DID Manager — creates and manages organization and document DIDs.
 * 
 * Organization DID: did:web:{domain}:org:{code}
 * Document DID:     did:web:{domain}:doc:{uuid}
 * 
 * Key design: We generate Secp256k1 key pairs ourselves using @noble/curves,
 * then import the did:web DID directly into Veramo with full key material
 * (including privateKeyHex). This means Veramo manages did:web natively —
 * no did:key intermediary, no import issues.
 */

const crypto = require('crypto');
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

  const { secp256k1 } = require('@noble/curves/secp256k1');
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

function buildCanonicalDidDocument(did, publicKeyHex) {
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
        publicKeyJwk: publicKeyHexToSecp256k1Jwk(publicKeyHex),
      },
    ],
    authentication: [`${did}#key-1`],
    assertionMethod: [`${did}#key-1`],
  };
}

/**
 * Create an organization DID and register it with the Veramo agent.
 * 
 * Generates a Secp256k1 key pair directly, then imports a did:web DID
 * with full key material. No did:key intermediary.
 * 
 * @param {string} orgCode - Organization code (e.g., 'ACME-001')
 * @param {string} [alias] - Human-readable alias
 * @returns {{ did, didDocument, keys, controllerKeyId }}
 */
async function createOrganizationDID(orgCode, alias) {
  const agent = await getAgent();
  const normalizedOrgCode = normalizeOrgCode(orgCode);
  if (!normalizedOrgCode) throw new Error('Invalid orgCode. Provide a non-empty slug-safe organization code.');

  const didWeb = `did:web:${REGISTRY_DOMAIN}:org:${normalizedOrgCode}`;
  const keyAlias = `orgkey-${normalizedOrgCode}`;
  const keyKid = `${keyAlias}-key`;

  // Check if did:web already exists as a managed DID
  const identifiers = await agent.didManagerFind();
  const existingWeb = identifiers.find((i) => i.did === didWeb);
  if (existingWeb) {
    const primaryKey = existingWeb.keys && existingWeb.keys[0];
    if (!primaryKey) throw new Error(`No key material found for ${didWeb}`);
    const didDocument = buildCanonicalDidDocument(didWeb, primaryKey.publicKeyHex);
    return {
      did: didWeb,
      didDocument,
      alias: alias || normalizedOrgCode,
      controllerKeyId: existingWeb.controllerKeyId || (primaryKey && primaryKey.kid),
      keys: (existingWeb.keys || []).map(k => ({
        kid: k.kid, type: k.type, publicKeyHex: k.publicKeyHex,
      })),
      alreadyExisted: true,
    };
  }

  // Clean up any old did:key entries with the same alias
  for (const id of identifiers) {
    if (id.alias === keyAlias && id.did.startsWith('did:key:')) {
      console.log(`[DID Manager] Cleaning up old did:key ${id.did} (alias: ${keyAlias})`);
      try {
        await agent.didManagerDelete({ did: id.did });
      } catch (delErr) {
        console.warn(`[DID Manager] Could not delete old did:key: ${delErr.message}`);
      }
    }
  }

  // Generate Secp256k1 key pair directly
  const { secp256k1 } = require('@noble/curves/secp256k1');
  const privBytes = crypto.randomBytes(32);
  const privateKeyHex = Buffer.from(privBytes).toString('hex');
  const pubBytesCompressed = secp256k1.getPublicKey(privBytes, true);
  const publicKeyHex = Buffer.from(pubBytesCompressed).toString('hex');

  console.log(`[DID Manager] Generated Secp256k1 key pair for ${didWeb}`);

  // Import did:web directly with full key material
  const imported = await agent.didManagerImport({
    did: didWeb,
    provider: 'did:web',
    alias: keyAlias,
    keys: [{
      kid: keyKid,
      type: 'Secp256k1',
      publicKeyHex,
      privateKeyHex,
      kms: 'local',
    }],
    services: [],
  });

  console.log(`[DID Manager] Imported did:web ${didWeb} with key ${keyKid}`);

  // The imported identifier may have uncompressed publicKeyHex (Veramo expands it)
  const finalKey = imported.keys && imported.keys[0];
  const finalPublicKeyHex = finalKey ? finalKey.publicKeyHex : publicKeyHex;
  const didDocument = buildCanonicalDidDocument(didWeb, finalPublicKeyHex);

  return {
    did: didWeb,
    didDocument,
    alias: alias || normalizedOrgCode,
    controllerKeyId: imported.controllerKeyId || keyKid,
    keys: (imported.keys || []).map(k => ({
      kid: k.kid, type: k.type, publicKeyHex: k.publicKeyHex,
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
