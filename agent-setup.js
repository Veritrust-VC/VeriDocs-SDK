require('dotenv').config();
require('reflect-metadata');
require('./patch-credential-ld');

const fs = require('fs');
const path = require('path');
const { createAgent } = require('@veramo/core');
const { DIDManager } = require('@veramo/did-manager');
const { KeyManager } = require('@veramo/key-manager');
const { KeyManagementSystem } = require('@veramo/kms-local');
const { WebDIDProvider } = require('@veramo/did-provider-web');
const { KeyDIDProvider, getDidKeyResolver } = require('@veramo/did-provider-key');
const { DIDResolverPlugin } = require('@veramo/did-resolver');
const { Resolver } = require('did-resolver');
const { getResolver: webDidResolver } = require('web-did-resolver');
const { CredentialPlugin } = require('@veramo/credential-w3c');
const {
  CredentialIssuerLD,
  LdDefaultContexts,
  defaultDocumentLoader,
} = require('@veramo/credential-ld');
const Database = require('better-sqlite3');
const { Entities, DataStore, DataStoreORM, migrations } = require('@veramo/data-store');
const { DataSource } = require('typeorm');
const { CustomKeyStore, CustomDIDStore } = require('./custom-data-store');
const { CustomPrivateKeyStore } = require('./custom-private-key-store');
const { JsonWebSignature2020_ES256K } = require('./src/ld-suites/jws2020-es256k');

const DATABASE_PATH = 'database.sqlite';

let dbConnection;
let agentPromise;
let sqliteDb;

function buildContextMap() {
  const defaultMap = new Map(LdDefaultContexts);
  const contextsDir = path.join(__dirname, 'public', 'contexts');

  let files;
  try {
    files = fs.readdirSync(contextsDir, { withFileTypes: true });
  } catch (err) {
    console.warn(
      `[WARN] Unable to preload VC contexts from ${contextsDir}: ${err?.message || err}`
    );
    return defaultMap;
  }

  const canonicalOrigin = (process.env.CONTEXT_ORIGIN || 'https://localhost:3100').replace(
    /\/+$/,
    ''
  );
  const additionalOrigins = new Set([canonicalOrigin]);

  if (canonicalOrigin.startsWith('https://')) {
    additionalOrigins.add(`http://${canonicalOrigin.slice('https://'.length)}`);
  }

  const baseUrl = process.env.VERAMO_BASE_URL;
  if (baseUrl) {
    try {
      const baseOrigin = new URL(baseUrl).origin;
      additionalOrigins.add(baseOrigin.replace(/\/+$/, ''));
    } catch (err) {
      console.warn(
        `[WARN] Ignoring invalid VERAMO_BASE_URL for context preloading: ${
          err?.message || err
        }`
      );
    }
  }

  additionalOrigins.add('http://localhost:3000');
  additionalOrigins.add('https://localhost:3000');

  for (const entry of files) {
    if (!entry.isFile() || !entry.name.endsWith('.jsonld')) continue;

    const filePath = path.join(contextsDir, entry.name);
    let parsed;
    try {
      const raw = fs.readFileSync(filePath, 'utf8');
      parsed = JSON.parse(raw);
    } catch (err) {
      console.warn(
        `[WARN] Failed to preload context ${entry.name}: ${err?.message || err}`
      );
      continue;
    }

    for (const origin of additionalOrigins) {
      const trimmedOrigin = origin.replace(/\/+$/, '');
      const url = `${trimmedOrigin}/contexts/${entry.name}`;
      defaultMap.set(url, parsed);
    }
  }

  return defaultMap;
}

function normalizeSecretKey(rawValue) {
  if (typeof rawValue !== 'string' || rawValue.length === 0) {
    throw new Error('SECRET_KEY environment variable is not set');
  }
  const trimmed = rawValue.startsWith('0x') ? rawValue.slice(2) : rawValue;
  if (!/^[0-9a-fA-F]{64}$/.test(trimmed)) {
    throw new Error(
      'SECRET_KEY must be a 32-byte hex string (optionally prefixed with 0x)'
    );
  }
  return trimmed.toLowerCase();
}

async function initializeDatabase() {
  if (!dbConnection) {
    dbConnection = new DataSource({
      type: 'sqlite',
      database: DATABASE_PATH,
      entities: Entities,
      migrations,
      migrationsRun: false,
      synchronize: false,
      logging: false,
    });
  }

  if (!dbConnection.isInitialized) {
    await dbConnection.initialize();
    await dbConnection.runMigrations();
  }

  return dbConnection;
}

function getSqliteDb() {
  if (!sqliteDb) {
    sqliteDb = new Database(DATABASE_PATH);
    sqliteDb.pragma('foreign_keys = ON');
  }
  return sqliteDb;
}

process.once('exit', () => {
  if (sqliteDb) {
    try {
      sqliteDb.close();
    } catch (err) {
      console.warn('[WARN] Failed to close sqlite connection cleanly:', err);
    }
    sqliteDb = undefined;
  }
});

function getSecretBoxAwareKeyStore(secretKey) {
  const sqlite = getSqliteDb();
  return new KeyManagementSystem(new CustomPrivateKeyStore(sqlite, secretKey));
}

async function buildAgent() {
  const normalizedSecret = normalizeSecretKey(process.env.SECRET_KEY);
  console.debug('[DEBUG] Agent setup secretKey:', normalizedSecret);

  const connection = await initializeDatabase();
  const sqlite = getSqliteDb();

  const ldSuite = new JsonWebSignature2020_ES256K();
  const contextMap = buildContextMap();
  const credentialLd = new CredentialIssuerLD({
    suites: [ldSuite],
    contextMaps: [contextMap],
    documentLoader: defaultDocumentLoader,
  });

  return createAgent({
    plugins: [
      new KeyManager({
        store: new CustomKeyStore(sqlite),
        kms: {
          local: getSecretBoxAwareKeyStore(normalizedSecret),
        },
      }),
      new DIDManager({
        store: new CustomDIDStore(sqlite),
        defaultProvider: 'did:web',
        providers: {
          'did:web': new WebDIDProvider({ defaultKms: 'local' }),
          'did:key': new KeyDIDProvider({ defaultKms: 'local' }),
        },
      }),
      new DIDResolverPlugin({
        resolver: new Resolver({
          ...webDidResolver(),
          ...getDidKeyResolver(),
        }),
      }),
      new CredentialPlugin(),
      credentialLd,
      new DataStore(connection),
      new DataStoreORM(connection),
    ],
  });
}

async function createAgentInstance() {
  if (!agentPromise) {
    agentPromise = buildAgent().catch(err => {
      agentPromise = undefined;
      throw err;
    });
  }
  return agentPromise;
}

module.exports = { createAgentInstance };
module.exports.default = module.exports;
