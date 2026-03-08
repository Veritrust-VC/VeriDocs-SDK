require('dotenv').config();

const fs = require('fs');
const path = require('path');

let prompt;
try {
  prompt = require('prompt-sync')({ sigint: true });
} catch (error) {
  console.warn('[WARN] prompt-sync not available; interactive root DID ceremony disabled:', error?.message);
  prompt = () => {
    throw new Error('prompt-sync is required for interactive root DID creation. Reinstall dependencies to enable prompts.');
  };
}
const { Wallet } = require('ethers');
const { createAgentInstance } = require('./agent-setup');

const ROOT_DID = 'did:web:veritrust.vc';
const ROOT_KEY_ID = `${ROOT_DID}#keys-1`;
const ROOT_KEY_ALGORITHMS = [
  'ES256K',
  'ES256K-R',
  'eth_signTransaction',
  'eth_signTypedData',
  'eth_signMessage',
  'eth_rawSign',
];
const WELL_KNOWN_DIR = path.join(__dirname, '.well-known');
const WINDOWS_WELL_KNOWN_DIR =
  process.env.WINDOWS_WELL_KNOWN_DIR || '/mnt/c/WebServers/Home/veritrust/www/.well-known';
const DEFAULT_DID_CONTEXT = [
  'https://www.w3.org/ns/did/v1',
  'https://w3id.org/security/suites/jws-2020/v1',
];
const DEFAULT_SERVICES = [
  {
    id: '#issuer',
    type: 'OpenIDCredentialIssuer',
    serviceEndpoint: 'https://veritrust.vc/.well-known/openid-credential-issuer',
  },
  {
    id: '#status',
    type: 'StatusList2021',
    serviceEndpoint: 'https://veritrust.vc/status',
  },
  {
    id: '#jwks',
    type: 'JSONWebKeySet',
    serviceEndpoint: 'https://veritrust.vc/.well-known/jwks.json',
  },
];

function getSecretKeyFromEnv() {
  const rawValue = process.env.SECRET_KEY;
  if (!rawValue) {
    throw new Error('SECRET_KEY environment variable is not set');
  }
  const normalized = rawValue.startsWith('0x') ? rawValue : `0x${rawValue}`;
  if (!/^0x[0-9a-fA-F]{64}$/.test(normalized)) {
    throw new Error(
      `Invalid SECRET_KEY: expected 32-byte hex (optionally prefixed with 0x). Got: ${rawValue}`
    );
  }
  return normalized.toLowerCase();
}

function hexToBase64Url(hex) {
  return Buffer.from(hex, 'hex').toString('base64url');
}

function deriveRootKeyMaterial(secretKey) {
  let wallet;
  try {
    wallet = new Wallet(secretKey);
  } catch (err) {
    throw new Error(`Failed to derive wallet from SECRET_KEY: ${err.message}`);
  }

  const publicKeyHex = wallet.signingKey.publicKey.slice(2);
  const compressedPublicKeyHex = wallet.signingKey.compressedPublicKey.slice(2);
  const privateKeyHex = wallet.privateKey.slice(2);
  const xComponent = publicKeyHex.slice(2, 66);
  const yComponent = publicKeyHex.slice(66);

  const jwk = {
    kty: 'EC',
    crv: 'secp256k1',
    x: hexToBase64Url(xComponent),
    y: hexToBase64Url(yComponent),
    d: hexToBase64Url(privateKeyHex),
    alg: 'ES256K',
    use: 'sig',
    kid: ROOT_KEY_ID,
  };

  return {
    wallet,
    privateKeyHex,
    publicKeyHex,
    compressedPublicKeyHex,
    jwk,
    kid: ROOT_KEY_ID,
    ethereumAddress: wallet.address.toLowerCase(),
  };
}

function buildRootKeyMeta(keyMaterial) {
  const { jwk, kid, publicKeyHex, compressedPublicKeyHex, ethereumAddress } = keyMaterial;
  const { d: _ignoredPrivate, ...publicJwk } = jwk;
  const meta = {
    algorithms: ROOT_KEY_ALGORITHMS,
    identifierDid: ROOT_DID,
    verificationMethod: kid,
    publicKeyJwk: publicJwk,
  };

  if (publicKeyHex) {
    meta.uncompressedPublicKeyHex = publicKeyHex;
  }

  if (compressedPublicKeyHex) {
    meta.compressedPublicKeyHex = compressedPublicKeyHex;
  }

  if (ethereumAddress) {
    meta.ethereumAddress = ethereumAddress;
  }

  return meta;
}

function ensureDirectoryExists(directoryPath) {
  if (!directoryPath) {
    return false;
  }
  try {
    fs.mkdirSync(directoryPath, { recursive: true });
    return true;
  } catch (error) {
    console.warn(`[WARN] Failed to create directory ${directoryPath}:`, error?.message || error);
    return false;
  }
}

function readJsonIfExists(filePath) {
  try {
    if (!fs.existsSync(filePath)) {
      return null;
    }
    const contents = fs.readFileSync(filePath, 'utf8');
    return JSON.parse(contents);
  } catch (error) {
    console.warn(`[WARN] Failed to read JSON from ${filePath}:`, error?.message || error);
    return null;
  }
}

function mergeDidContexts(existingContext) {
  const contexts = Array.isArray(existingContext)
    ? existingContext
    : existingContext
      ? [existingContext]
      : [];
  const result = [...DEFAULT_DID_CONTEXT];
  for (const ctx of contexts) {
    if (ctx && !result.includes(ctx)) {
      result.push(ctx);
    }
  }
  return result;
}

function getPublicJwk(keyMaterial) {
  const { jwk } = keyMaterial;
  if (!jwk) return {};
  const { d: _removed, ...publicJwk } = jwk;
  return publicJwk;
}

function findPublicJwkInDidDoc(didDocument, kid) {
  if (!didDocument) return null;
  const methods = Array.isArray(didDocument.verificationMethod)
    ? didDocument.verificationMethod
    : [];
  const entry = methods.find(method => method && method.id === kid && method.publicKeyJwk);
  return entry ? entry.publicKeyJwk : null;
}

function buildDidDocument(keyMaterial, options = {}) {
  const existingDoc = options.existingDidDoc || null;
  const publicJwk = getPublicJwk(keyMaterial);

  const remainingMethods = Array.isArray(existingDoc?.verificationMethod)
    ? existingDoc.verificationMethod.filter(method => method?.id && method.id !== keyMaterial.kid)
    : [];

  const verificationMethod = {
    id: keyMaterial.kid,
    type: 'JsonWebKey2020',
    controller: ROOT_DID,
    publicKeyJwk: publicJwk,
  };

  const authenticationEntries = Array.isArray(existingDoc?.authentication)
    ? existingDoc.authentication.filter(entry => entry && entry !== keyMaterial.kid)
    : [];
  const assertionEntries = Array.isArray(existingDoc?.assertionMethod)
    ? existingDoc.assertionMethod.filter(entry => entry && entry !== keyMaterial.kid)
    : [];

  const doc = {
    '@context': mergeDidContexts(existingDoc?.['@context']),
    id: ROOT_DID,
    controller: ROOT_DID,
    verificationMethod: [verificationMethod, ...remainingMethods],
    authentication: [keyMaterial.kid, ...authenticationEntries],
    assertionMethod: [keyMaterial.kid, ...assertionEntries],
  };

  const services =
    Array.isArray(existingDoc?.service) && existingDoc.service.length > 0
      ? existingDoc.service
      : DEFAULT_SERVICES;
  if (services && services.length > 0) {
    doc.service = services;
  }

  return doc;
}

function buildJwks(keyMaterial) {
  return { keys: [getPublicJwk(keyMaterial)] };
}

function writeJsonFile(filePath, data) {
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
}

function writeDidArtifacts(keyMaterial, options = {}) {
  const existingDidDoc =
    options.existingDidDoc !== undefined
      ? options.existingDidDoc
      : readJsonIfExists(path.join(WELL_KNOWN_DIR, 'did.json'));
  const existingJwk = findPublicJwkInDidDoc(existingDidDoc, keyMaterial.kid);
  const derivedJwk = getPublicJwk(keyMaterial);

  if (
    existingJwk &&
    (existingJwk.x !== derivedJwk.x || existingJwk.y !== derivedJwk.y || existingJwk.crv !== derivedJwk.crv)
  ) {
    console.warn(
      `[WARN] Existing DID document public key for ${keyMaterial.kid} differs from derived key. Overwriting with the new key material.`,
    );
  }

  ensureDirectoryExists(WELL_KNOWN_DIR);

  const didDocument = buildDidDocument(keyMaterial, { existingDidDoc });
  const jwks = buildJwks(keyMaterial);

  const didPath = path.join(WELL_KNOWN_DIR, 'did.json');
  writeJsonFile(didPath, didDocument);
  console.log(`✅ DID document written to ${didPath}`);

  const jwksPath = path.join(WELL_KNOWN_DIR, 'jwks.json');
  writeJsonFile(jwksPath, jwks);
  console.log(`✅ JWKS written to ${jwksPath}`);

  const outputs = [
    { type: 'did', path: didPath },
    { type: 'jwks', path: jwksPath },
  ];

  if (options.copyToWindows !== false && WINDOWS_WELL_KNOWN_DIR) {
    try {
      if (ensureDirectoryExists(WINDOWS_WELL_KNOWN_DIR)) {
        for (const output of outputs) {
          const targetPath = path.join(WINDOWS_WELL_KNOWN_DIR, path.basename(output.path));
          fs.copyFileSync(output.path, targetPath);
          console.log(`✅ ${output.type.toUpperCase()} copied to ${targetPath}`);
        }
      }
    } catch (error) {
      console.warn(
        `⚠️ Failed to copy DID artifacts to ${WINDOWS_WELL_KNOWN_DIR}:`,
        error?.message || error,
      );
    }
  }

  return { didDocument, jwks, outputs };
}

async function ensureRootKey(agent, keyMaterial) {
  const keyMeta = buildRootKeyMeta(keyMaterial);
  console.debug('[DEBUG] Importing root key material with meta:', keyMeta);

  await agent.keyManagerImport({
    kid: keyMaterial.kid,
    kms: 'local',
    type: 'Secp256k1',
    privateKeyHex: keyMaterial.privateKeyHex,
    publicKeyHex: keyMaterial.publicKeyHex,
    meta: keyMeta,
  });

  return keyMeta;
}

async function ensureRootDid(options = {}) {
  const providedAgent = options.agent || (await createAgentInstance());
  const keyMaterial = options.keyMaterial || deriveRootKeyMaterial(getSecretKeyFromEnv());
  const keyMeta = await ensureRootKey(providedAgent, keyMaterial);

  console.debug('[DEBUG] Ensuring DID exists:', ROOT_DID);
  const existing = await providedAgent
    .didManagerGet({ did: ROOT_DID })
    .catch(() => null);
  let identifier = existing;

  if (existing) {
    console.debug('[DEBUG] DID already present:', existing);
  } else {
    console.debug('[DEBUG] Importing DID using derived key material');
    try {
      await providedAgent.didManagerImport({
        did: ROOT_DID,
        provider: 'did:web',
        alias: 'veritrust.vc',
        controllerKeyId: keyMaterial.kid,
        keys: [
          {
            kid: keyMaterial.kid,
            kms: 'local',
            type: 'Secp256k1',
            privateKeyHex: keyMaterial.privateKeyHex,
            publicKeyHex: keyMaterial.publicKeyHex,
            meta: keyMeta,
            publicKeyJwk: keyMeta.publicKeyJwk,
          },
        ],
        services: [],
      });
    } catch (error) {
      if (/UNIQUE constraint failed: key\.kid/.test(error?.message || '')) {
        throw new Error(
          `Key ${keyMaterial.kid} already exists in the key store. Remove the stale key or choose a different SECRET_KEY before retrying.`
        );
      }
      throw error;
    }

    identifier = await providedAgent.didManagerGet({ did: ROOT_DID });
    console.debug('[DEBUG] DID imported:', identifier);
  }

  let artifacts = null;
  if (options.writeArtifacts !== false) {
    artifacts = writeDidArtifacts(keyMaterial, options.artifactOptions || {});
  }

  return { identifier, keyMaterial, keyMeta, artifacts };
}

async function main() {
  try {
    console.debug('[DEBUG] Raw SECRET_KEY:', process.env.SECRET_KEY);
    const secretKey = getSecretKeyFromEnv();
    console.debug('[DEBUG] Normalized SECRET_KEY:', secretKey);

    if (process.env.ROOT_DID_CEREMONY !== 'YES') {
      throw new Error('ROOT_DID_CEREMONY=YES is required to proceed with root DID creation.');
    }

    console.log('Type exactly to proceed:');
    console.log('I ACKNOWLEDGE ROOT DID CREATION');
    const input = prompt();
    if (input !== 'I ACKNOWLEDGE ROOT DID CREATION') {
      throw new Error('Aborted: Incorrect confirmation input');
    }

    console.debug('[DEBUG] Starting DID creation');
    const keyMaterial = deriveRootKeyMaterial(secretKey);
    const agent = await createAgentInstance();
    const { identifier } = await ensureRootDid({ agent, keyMaterial });

    console.log('✅ DID ensured:', identifier.did);
    const { d: _removed, ...publicJwk } = keyMaterial.jwk;
    console.log('🔑 Public JWK:', JSON.stringify(publicJwk, null, 2));
  } catch (error) {
    console.error('❌ Error creating DID:', error);
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}

module.exports = {
  ensureRootDid,
  deriveRootKeyMaterial,
  ROOT_DID,
  ROOT_KEY_ID,
  buildRootKeyMeta,
  buildDidDocument,
  buildJwks,
  writeDidArtifacts,
};
