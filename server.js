/**
 * VeriDocs SDK — REST API sidecar for Document Management Systems.
 * 
 * Run alongside your DVS (Namejs, Lietvaris, DocLogix, or any DMS).
 * Every document lifecycle event triggers a signed Verifiable Credential
 * that is submitted to the central VeriDocs Register.
 * 
 * Endpoints (DVS-facing):
 * 
 * Setup:
 *   POST /api/setup/org           — Create organization DID and register with Registry
 *   GET  /api/setup/status        — Check setup status (org DID, Registry connection)
 * 
 * Document lifecycle:
 *   POST /api/documents/create    — Create document DID + register + DocumentCreated VC
 *   POST /api/documents/:did/send      — DocumentSent VC
 *   POST /api/documents/:did/receive   — DocumentReceived VC
 *   POST /api/documents/:did/assign    — DocumentAssigned VC
 *   POST /api/documents/:did/decide    — DocumentDecided VC
 *   POST /api/documents/:did/archive   — DocumentArchived VC
 *   GET  /api/documents/:did/track     — Track via Registry
 * 
 * DID/VC utilities:
 *   POST /api/did/resolve         — Resolve any DID
 *   POST /api/vc/verify           — Verify a VC
 *   GET  /api/identifiers         — List managed DIDs
 * 
 * System:
 *   GET  /api/health              — Health check
 *   GET  /.well-known/did.json    — This agent's DID Document
 */

require('./patch-credential-ld');

const express = require('express');
const fs = require('fs');
const path = require('path');
const { createAgentInstance } = require('./agent-setup');
const { requireApiKey } = require('./auth');
const { createOrganizationDID, listIdentifiers } = require('./src/did-manager');
const { verifyVC } = require('./src/vc-builder');
const hooks = require('./src/hooks/lifecycle');
const { RegistryClient } = require('./src/registry-client');
const {
  setActiveOrgDid,
  getActiveOrgDid,
  setLastSetup,
  getLastSetup,
} = require('./src/state-store');

const PORT = parseInt(process.env.PORT || process.env.SDK_PORT || '3100', 10);
const HOST = process.env.HOST || '0.0.0.0';
const REGISTRY_URL = process.env.REGISTRY_URL || 'http://localhost:8001';
const REGISTRY_API_KEY = process.env.REGISTRY_API_KEY || '';

function isRegistryAuthConfigured() {
  return !!(process.env.REGISTRY_EMAIL && process.env.REGISTRY_PASSWORD);
}

async function getRegistryStatus(client) {
  let registryConnected = false;
  try {
    const health = await client.health();
    registryConnected = health && health.status === 'ok';
  } catch (error) {
    registryConnected = false;
  }

  const authResult = await client.testAuth();

  return {
    registry_connected: registryConnected,
    registry_auth_configured: authResult.auth_configured,
    registry_authenticated: authResult.authenticated,
    registry_auth_error: authResult.error,
  };
}

// Pre-initialize agent
const agentReady = createAgentInstance().catch(err => {
  console.error('Failed to initialize Veramo agent:', err);
  process.exit(1);
});

const app = express();
app.use(express.json({ limit: '5mb' }));

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, x-api-key, Authorization');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// Serve DID Document
app.get('/.well-known/did.json', (req, res) => {
  const p = path.join(__dirname, '.well-known', 'did.json');
  if (fs.existsSync(p)) res.type('application/did+json').send(fs.readFileSync(p, 'utf8'));
  else res.status(404).json({ error: 'DID not initialized. POST /api/setup/org first.' });
});

// Serve LD contexts
app.use('/contexts', express.static(path.join(__dirname, 'public', 'contexts')));

// ═══════════════════════════════════════════
// Setup — one-time organization onboarding
// ═══════════════════════════════════════════

app.post('/api/setup/org', requireApiKey, async (req, res) => {
  const { orgCode, orgName, orgDescription } = req.body || {};
  if (!orgCode) return res.status(400).json({ error: 'Required: orgCode' });

  try {
    const orgResult = await createOrganizationDID(orgCode, orgName);
    console.log(`[SDK] Organization DID: ${orgResult.did} (existed: ${orgResult.alreadyExisted})`);

    const publicKeyHex = orgResult.keys && orgResult.keys[0] && orgResult.keys[0].publicKeyHex;

    const agent = await agentReady;
    let didDocument;
    try {
      const resolution = await agent.resolveDid({ didUrl: orgResult.did });
      didDocument = resolution.didDocument;
    } catch (e) {
      didDocument = {
        '@context': ['https://www.w3.org/ns/did/v1'],
        id: orgResult.did,
        verificationMethod: [{
          id: `${orgResult.did}#keys-1`,
          type: 'EcdsaSecp256k1VerificationKey2019',
          controller: orgResult.did,
          publicKeyHex: publicKeyHex,
        }],
        authentication: [`${orgResult.did}#keys-1`],
        assertionMethod: [`${orgResult.did}#keys-1`],
      };
    }

    setActiveOrgDid(orgResult.did);

    const client = new RegistryClient(REGISTRY_URL, REGISTRY_API_KEY);
    const registryStatus = await getRegistryStatus(client);

    let registryResult = {
      attempted: true,
      connected: registryStatus.registry_connected,
      auth_configured: registryStatus.registry_auth_configured,
      authenticated: registryStatus.registry_authenticated,
      registered: false,
      error: null,
    };

    if (!REGISTRY_URL) {
      registryResult = {
        ...registryResult,
        connected: false,
        attempted: false,
        error: 'Registry URL is not configured',
      };
    } else if (!isRegistryAuthConfigured()) {
      registryResult.error = 'Registry credentials are not configured';
    } else if (!registryStatus.registry_connected) {
      registryResult.error = 'Registry health check failed';
    } else if (!registryStatus.registry_authenticated) {
      registryResult.error = registryStatus.registry_auth_error;
    } else {
      try {
        const rawRegistryResult = await client.registerOrganization(
          didDocument,
          publicKeyHex || '',
          orgName,
          orgDescription,
        );
        registryResult.registered = true;
        registryResult.result = rawRegistryResult;
      } catch (regErr) {
        registryResult.error = regErr.message;
      }
    }

    const lifecycleReady = !!orgResult.did
      && registryResult.connected
      && registryResult.auth_configured
      && registryResult.authenticated
      && registryResult.registered;

    const lastSetup = {
      orgCode,
      orgName,
      orgDescription: orgDescription || '',
      did: orgResult.did,
      alreadyExisted: !!orgResult.alreadyExisted,
      registry: registryResult,
      lifecycle_ready: lifecycleReady,
      timestamp: new Date().toISOString(),
    };
    setLastSetup(lastSetup);

    const message = lifecycleReady
      ? 'Organization DID created and registered in central registry.'
      : `Organization DID created locally, but central registry registration is unavailable: ${registryResult.error || 'unknown error'}.`;

    res.status(201).json({
      did: orgResult.did,
      alreadyExisted: orgResult.alreadyExisted,
      keys: orgResult.keys,
      active_org_did_persisted: true,
      registry: registryResult,
      lifecycle_ready: lifecycleReady,
      message,
    });
  } catch (err) {
    console.error('[SDK] Org setup failed:', err);
    res.status(500).json({ error: 'Organization setup failed', detail: err.message });
  }
});

app.get('/api/setup/status', async (req, res) => {
  const orgDid = getActiveOrgDid() || process.env.ORG_DID || '';
  const lastSetup = getLastSetup();
  const client = new RegistryClient(REGISTRY_URL, REGISTRY_API_KEY);
  const registryStatus = await getRegistryStatus(client);

  let managedDids = [];
  try {
    const ids = await listIdentifiers();
    managedDids = ids.map(i => ({ did: i.did, alias: i.alias }));
  } catch (e) { /* */ }

  const lifecycleReady = !!orgDid
    && registryStatus.registry_connected
    && registryStatus.registry_auth_configured
    && registryStatus.registry_authenticated;

  res.json({
    org_did: orgDid || null,
    org_did_configured: !!orgDid,
    signing_mode: process.env.SIGNING_MODE || 'local',
    registry_url: REGISTRY_URL,
    registry_connected: registryStatus.registry_connected,
    registry_auth_configured: registryStatus.registry_auth_configured,
    registry_authenticated: registryStatus.registry_authenticated,
    registry_auth_error: registryStatus.registry_auth_error,
    lifecycle_ready: lifecycleReady,
    managed_dids: managedDids,
    last_setup: lastSetup,
  });
});

app.get('/api/setup/verify', async (req, res) => {
  const orgDid = getActiveOrgDid() || process.env.ORG_DID || '';
  let managedIdentifierExists = false;

  const client = new RegistryClient(REGISTRY_URL, REGISTRY_API_KEY);
  const registryStatus = await getRegistryStatus(client);

  try {
    const ids = await listIdentifiers();
    managedIdentifierExists = !!orgDid && ids.some(i => i.did === orgDid);
  } catch (e) { /* */ }

  const orgDidConfigured = !!orgDid;
  const readyForLifecycle = orgDidConfigured
    && registryStatus.registry_connected
    && registryStatus.registry_auth_configured
    && registryStatus.registry_authenticated
    && managedIdentifierExists;

  res.json({
    org_did: orgDid || null,
    org_did_configured: orgDidConfigured,
    registry_connected: registryStatus.registry_connected,
    registry_auth_configured: registryStatus.registry_auth_configured,
    registry_authenticated: registryStatus.registry_authenticated,
    registry_auth_error: registryStatus.registry_auth_error,
    managed_identifier_exists: managedIdentifierExists,
    ready_for_lifecycle: readyForLifecycle,
  });
});

// ═══════════════════════════════════════════
// Document lifecycle (DVS integration points)
// ═══════════════════════════════════════════

app.post('/api/documents/create', requireApiKey, async (req, res) => {
  const { title, type, classification, registrationNumber, metadata } = req.body || {};
  try {
    const result = await hooks.createDocument({
      title, type, classification, registrationNumber, ...(metadata || {}),
    });
    res.status(201).json(result);
  } catch (err) {
    console.error('[SDK] Document create failed:', err);
    res.status(500).json({ error: 'Document creation failed', detail: err.message });
  }
});

app.post('/api/documents/:did/send', requireApiKey, async (req, res) => {
  const documentDid = decodeURIComponent(req.params.did);
  const { recipientDid, deliveryMethod } = req.body || {};
  if (!recipientDid) return res.status(400).json({ error: 'Required: recipientDid' });
  try {
    const result = await hooks.onDocumentSent(documentDid, recipientDid, { deliveryMethod });
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'Send failed', detail: err.message });
  }
});

app.post('/api/documents/:did/receive', requireApiKey, async (req, res) => {
  const documentDid = decodeURIComponent(req.params.did);
  const { senderDid, localRegistrationNumber } = req.body || {};
  if (!senderDid) return res.status(400).json({ error: 'Required: senderDid' });
  try {
    const result = await hooks.onDocumentReceived(documentDid, senderDid, { localRegistrationNumber });
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'Receive failed', detail: err.message });
  }
});

app.post('/api/documents/:did/assign', requireApiKey, async (req, res) => {
  const documentDid = decodeURIComponent(req.params.did);
  const { assignee, department } = req.body || {};
  try {
    const result = await hooks.onDocumentAssigned(documentDid, { assignee, department });
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'Assign failed', detail: err.message });
  }
});

app.post('/api/documents/:did/decide', requireApiKey, async (req, res) => {
  const documentDid = decodeURIComponent(req.params.did);
  const { decision, resolution } = req.body || {};
  try {
    const result = await hooks.onDocumentDecided(documentDid, { decision, resolution });
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'Decide failed', detail: err.message });
  }
});

app.post('/api/documents/:did/archive', requireApiKey, async (req, res) => {
  const documentDid = decodeURIComponent(req.params.did);
  const { archiveReference } = req.body || {};
  try {
    const result = await hooks.onDocumentArchived(documentDid, { archiveReference });
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'Archive failed', detail: err.message });
  }
});

app.get('/api/documents/:did/track', async (req, res) => {
  const documentDid = decodeURIComponent(req.params.did);
  try {
    const result = await hooks.trackDocument(documentDid);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'Tracking failed', detail: err.message });
  }
});

// ═══════════════════════════════════════════
// AI Intelligence Layer
// ═══════════════════════════════════════════

const { recommendRouting } = require('./src/ai/routing');
const { harmonizeStatuses, mapStatus } = require('./src/ai/harmonization');
const { isConfigured: aiConfigured, getConfig: aiConfig } = require('./src/ai/llm-client');

app.get('/api/ai/health', (req, res) => {
  res.json({
    ai_available: aiConfigured(),
    provider: aiConfig().provider,
    model: aiConfig().model,
    capabilities: ['intelligent_routing', 'status_harmonization'],
  });
});

app.post('/api/ai/routing', requireApiKey, async (req, res) => {
  const { document, sender, lifecycleEvents, orgStructure } = req.body || {};
  if (!document) return res.status(400).json({ error: 'Required: document' });
  try {
    const result = await recommendRouting(document, sender || {}, lifecycleEvents || [], orgStructure || []);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'Routing failed', detail: err.message });
  }
});

app.post('/api/ai/harmonize', requireApiKey, async (req, res) => {
  const { statuses, context } = req.body || {};
  if (!statuses || !Array.isArray(statuses)) return res.status(400).json({ error: 'Required: statuses (array)' });
  try {
    const result = await harmonizeStatuses(statuses, context);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'Harmonization failed', detail: err.message });
  }
});

app.post('/api/ai/map-status', requireApiKey, async (req, res) => {
  const { status, context } = req.body || {};
  if (!status) return res.status(400).json({ error: 'Required: status' });
  try {
    const result = await mapStatus(status, context);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'Mapping failed', detail: err.message });
  }
});

// ═══════════════════════════════════════════
// DID/VC utilities
// ═══════════════════════════════════════════

app.post('/api/did/resolve', async (req, res) => {
  const { did } = req.body || {};
  if (!did) return res.status(400).json({ error: 'Missing "did"' });
  try {
    const agent = await agentReady;
    const result = await agent.resolveDid({ didUrl: did });
    res.json({ didDocument: result.didDocument });
  } catch (err) {
    res.status(422).json({ error: 'DID resolution failed', detail: err.message });
  }
});

app.post('/api/vc/verify', async (req, res) => {
  const { credential } = req.body || {};
  if (!credential) return res.status(400).json({ error: 'Missing "credential"' });
  const result = await verifyVC(credential);
  res.json(result);
});

app.get('/api/identifiers', requireApiKey, async (req, res) => {
  try {
    const ids = await listIdentifiers();
    res.json(ids.map(i => ({
      did: i.did, alias: i.alias, provider: i.provider,
      controllerKeyId: i.controllerKeyId,
      keys: (i.keys || []).map(k => ({ kid: k.kid, type: k.type, publicKeyHex: k.publicKeyHex })),
    })));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════
// Health
// ═══════════════════════════════════════════

app.get('/api/health', async (req, res) => {
  const stateOrgDid = getActiveOrgDid();
  const envOrgDid = process.env.ORG_DID || '';
  const orgDid = stateOrgDid || envOrgDid || '';
  const orgDidSource = stateOrgDid ? 'state' : (envOrgDid ? 'env' : 'none');
  let agentOk = false, managedDids = 0;
  try {
    const ids = await listIdentifiers();
    agentOk = true;
    managedDids = ids.length;
  } catch (e) { /* */ }

  const client = new RegistryClient(REGISTRY_URL, REGISTRY_API_KEY);
  const registryStatus = await getRegistryStatus(client);

  res.json({
    status: agentOk ? 'ok' : 'degraded',
    service: 'veridocs-sdk',
    org_did: orgDid || null,
    org_did_source: orgDidSource,
    signing_mode: process.env.SIGNING_MODE || 'local',
    managed_dids: managedDids,
    registry_url: REGISTRY_URL,
    registry_connected: registryStatus.registry_connected,
    registry_auth_configured: registryStatus.registry_auth_configured,
    registry_authenticated: registryStatus.registry_authenticated,
    registry_auth_error: registryStatus.registry_auth_error,
    capabilities: [
      'did:web', 'did:key',
      'JsonWebSignature2020', 'ES256K',
      'lifecycle-hooks',
      'statusList2021',
    ],
    veritrust_compatible: true,
  });
});

app.get('/', (req, res) => {
  const stateOrgDid = getActiveOrgDid();
  const envOrgDid = process.env.ORG_DID || '';
  const orgDid = stateOrgDid || envOrgDid || '';
  const orgDidSource = stateOrgDid ? 'state' : (envOrgDid ? 'env' : 'none');

  res.json({
    name: 'VeriDocs SDK',
    description: 'Document lifecycle DID/VC sidecar for DMS integration',
    org_did: orgDid || '(not configured)',
    org_did_source: orgDidSource,
    registry: REGISTRY_URL,
    signing_mode: process.env.SIGNING_MODE || 'local',
  });
});

app.use((err, req, res, _next) => {
  console.error(`[SDK ERROR] ${req.method} ${req.url}:`, err);
  res.status(500).json({ error: 'Internal server error', detail: err.message });
});

app.listen(PORT, HOST, async () => {
  console.log(`VeriDocs SDK sidecar: http://${HOST}:${PORT}`);
  console.log(`Registry: ${REGISTRY_URL}`);
  console.log(`Signing mode: ${process.env.SIGNING_MODE || 'local'}`);
  const stateOrgDid = getActiveOrgDid();
  const envOrgDid = process.env.ORG_DID || '';
  console.log(`Org DID: ${stateOrgDid || envOrgDid || '(not set — POST /api/setup/org)'}`);
  try {
    const ids = await listIdentifiers();
    console.log(`Managed DIDs: ${ids.length}`);
    ids.forEach(id => console.log(`  - ${id.did}`));
  } catch (e) { console.warn('Agent:', e.message); }
});
