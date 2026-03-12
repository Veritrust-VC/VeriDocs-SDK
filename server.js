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
const {
  initAuditDb,
  writeSyncLog,
  listSyncLogs,
  getSyncLog,
  setSyncState,
  getSyncState,
  setOrgSyncState,
  getOrgSyncState,
} = require('./src/audit-db');
const { newTraceId, nowIso } = require('./src/trace');
const multer = require('multer');
const os = require('os');
const { extractAndSummarize, anonymizeText, getAiStatus } = require('./src/ai/agent');

const PORT = parseInt(process.env.PORT || process.env.SDK_PORT || '3100', 10);
const HOST = process.env.HOST || '0.0.0.0';
const REGISTRY_URL = process.env.REGISTRY_URL || 'http://localhost:8001';
const REGISTRY_API_KEY = process.env.REGISTRY_API_KEY || '';
const ORG_VC_PATH = path.join(__dirname, 'data', 'org_vcs.json');

initAuditDb();

function ensureOrgVcStore() {
  const dir = path.dirname(ORG_VC_PATH);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

function loadOrgVcDb() {
  ensureOrgVcStore();
  if (!fs.existsSync(ORG_VC_PATH)) return {};

  try {
    const raw = fs.readFileSync(ORG_VC_PATH, 'utf8');
    if (!raw.trim()) return {};
    return JSON.parse(raw);
  } catch (_err) {
    return {};
  }
}

function saveOrgVC(orgDid, vc) {
  if (!orgDid || !vc) return;
  const db = loadOrgVcDb();
  db[orgDid] = vc;
  fs.writeFileSync(ORG_VC_PATH, JSON.stringify(db, null, 2));
}

function loadOrgVC(orgDid) {
  if (!orgDid) return null;
  const db = loadOrgVcDb();
  return db[orgDid] || null;
}

function isRegistryAuthConfigured() {
  return !!(process.env.REGISTRY_EMAIL && process.env.REGISTRY_PASSWORD);
}

async function getRegistryStatus(client, traceId) {
  let registryConnected = false;
  let lastSyncError = getSyncState('last_sync_error')?.value || null;

  try {
    const health = await client.health({ traceId, action: 'sdk.registry.health' });
    registryConnected = health && (health.status === 'ok' || health.ok === true);
  } catch (error) {
    registryConnected = false;
    lastSyncError = error.message;
  }

  const authResult = await client.testAuth(traceId);
  const orgRegistered = getSyncState('org_registered_in_registry')?.value === 'true';
  const orgVerified = getSyncState('org_verified_in_registry')?.value === 'true';

  return {
    registry_connected: registryConnected,
    registry_auth_configured: authResult.auth_configured,
    registry_authenticated: authResult.authenticated,
    registry_auth_error: authResult.error,
    org_registered_in_registry: orgRegistered,
    org_verified_in_registry: orgVerified,
    last_trace_id: getSyncState('last_trace_id')?.value || traceId || null,
    last_sync_error: lastSyncError,
  };
}

const agentReady = createAgentInstance().catch(err => {
  console.error('Failed to initialize Veramo agent:', err);
  process.exit(1);
});

const app = express();
const upload = multer({ dest: path.join(os.tmpdir(), 'veridocs-sdk-uploads') });
app.use(express.json({ limit: '5mb' }));

app.use((req, res, next) => {
  const incoming = req.header('X-Trace-Id');
  const traceId = incoming || newTraceId();
  req.traceId = traceId;
  res.setHeader('X-Trace-Id', traceId);
  setSyncState('last_trace_id', traceId);
  next();
});

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, x-api-key, Authorization, X-Trace-Id');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

app.get('/.well-known/did.json', (req, res) => {
  const p = path.join(__dirname, '.well-known', 'did.json');
  if (fs.existsSync(p)) res.type('application/did+json').send(fs.readFileSync(p, 'utf8'));
  else res.status(404).json({ error: 'DID not initialized. POST /api/setup/org first.' });
});

app.use('/contexts', express.static(path.join(__dirname, 'public', 'contexts')));

app.post('/api/setup/org', requireApiKey, async (req, res) => {
  const { orgCode, orgName, orgDescription } = req.body || {};
  const traceId = req.traceId;
  if (!orgCode) return res.status(400).json({ error: 'Required: orgCode', trace_id: traceId });

  try {
    const orgResult = await createOrganizationDID(orgCode, orgName);

    writeSyncLog({
      trace_id: traceId,
      action: 'sdk.org.local_create',
      source_system: 'veridocs-sdk',
      target_system: 'sdk-local',
      success: true,
      request_payload_json: { orgCode, orgName, orgDescription },
      response_body_json: orgResult,
      local_entity_type: 'organization',
      local_entity_did: orgResult.did,
      source_org_code: orgCode,
      source_org_did: orgResult.did,
    });

    const didDocument = orgResult.didDocument;

    if (!didDocument) throw new Error('Organization DID document generation failed');

    const publicKeyHex = orgResult.keys && orgResult.keys[0] && orgResult.keys[0].publicKeyHex;

    setActiveOrgDid(orgResult.did);

    const client = new RegistryClient(REGISTRY_URL, REGISTRY_API_KEY);
    const registryStatus = await getRegistryStatus(client, traceId);

    const registryResult = {
      attempted: true,
      connected: registryStatus.registry_connected,
      auth_configured: registryStatus.registry_auth_configured,
      authenticated: registryStatus.registry_authenticated,
      registered: false,
      verified: false,
      error: null,
      last_response_body: null,
    };

    if (!REGISTRY_URL) {
      registryResult.attempted = false;
      registryResult.connected = false;
      registryResult.error = 'Registry URL is not configured';
    } else if (!isRegistryAuthConfigured()) {
      registryResult.error = 'Registry credentials are not configured';
    } else if (!registryStatus.registry_connected) {
      registryResult.error = 'Registry health check failed';
    } else if (!registryStatus.registry_authenticated) {
      registryResult.error = registryStatus.registry_auth_error;
    } else {
      try {
        const registerResp = await client.registerOrganization(
          didDocument,
          publicKeyHex || '',
          orgName,
          orgDescription,
          {
            traceId,
            sourceOrgCode: orgCode,
            sourceOrgDid: orgResult.did,
            actorType: 'sdk',
            localEntityType: 'organization',
            localEntityDid: orgResult.did,
            remoteEntityDid: orgResult.did,
            action: 'sdk.org.register_remote',
          },
        );
        registryResult.registered = true;
        registryResult.last_response_body = registerResp;

        if (registerResp?.registration_vc) {
          registryResult.registration_vc = registerResp.registration_vc;
          registryResult.verified = true;
          saveOrgVC(orgResult.did, registerResp.registration_vc);
        }
      } catch (regErr) {
        const msg = regErr?.message || '';
        registryResult.last_response_body = msg;

        if (msg.includes('HTTP 409') && msg.includes('already registered')) {
          registryResult.registered = true;
          registryResult.error = null;
        } else {
          registryResult.error = msg;
        }
      }

      if (registryResult.registered && !registryResult.verified) {
        try {
          const verifyResp = await client.resolveOrganization(orgResult.did, {
            traceId,
            sourceOrgCode: orgCode,
            sourceOrgDid: orgResult.did,
            actorType: 'sdk',
            localEntityType: 'organization',
            localEntityDid: orgResult.did,
            remoteEntityDid: orgResult.did,
            action: 'sdk.org.verify_remote',
          });
          registryResult.verified = !!verifyResp;
        } catch (verifyErr) {
          registryResult.verified = false;
          registryResult.error = verifyErr.message;
          registryResult.last_response_body = verifyErr.message;
        }
      }
    }

    const lifecycleReady = !!orgResult.did
      && registryResult.connected
      && registryResult.auth_configured
      && registryResult.authenticated
      && registryResult.registered
      && registryResult.verified;

    setSyncState('org_registered_in_registry', String(!!registryResult.registered));
    setSyncState('org_verified_in_registry', String(!!registryResult.verified));
    setSyncState('last_sync_error', registryResult.error || '');

    setOrgSyncState('org_registered_in_registry', orgResult.did, String(!!registryResult.registered));
    setOrgSyncState('org_verified_in_registry', orgResult.did, String(!!registryResult.verified));
    setOrgSyncState('last_sync_error', orgResult.did, registryResult.error || '');
    setOrgSyncState('last_setup_trace_id', orgResult.did, traceId);

    const lastSetup = {
      orgCode,
      orgName,
      orgDescription: orgDescription || '',
      did: orgResult.did,
      alreadyExisted: !!orgResult.alreadyExisted,
      registry: registryResult,
      lifecycle_ready: lifecycleReady,
      timestamp: nowIso(),
      trace_id: traceId,
    };
    setLastSetup(lastSetup);

    const message = lifecycleReady
      ? 'Organization DID created locally and verified in central registry.'
      : 'Organization DID created locally, but central registration failed.';

    res.status(201).json({
      did: orgResult.did,
      active_org_did_persisted: true,
      registry: registryResult,
      trace_id: traceId,
      lifecycle_ready: lifecycleReady,
      message,
    });
  } catch (err) {
    setSyncState('last_sync_error', err.message);
    writeSyncLog({
      trace_id: traceId,
      action: 'sdk.org.local_create',
      source_system: 'veridocs-sdk',
      target_system: 'sdk-local',
      success: false,
      error_message: err.message,
      request_payload_json: req.body || null,
    });
    res.status(500).json({ error: 'Organization setup failed', detail: err.message, trace_id: traceId });
  }
});

app.get('/api/setup/status', async (req, res) => {
  const traceId = req.traceId;
  const requestedOrgDid = req.query.orgDid || '';
  const orgDid = requestedOrgDid || getActiveOrgDid() || process.env.ORG_DID || '';
  const lastSetup = getLastSetup();
  const client = new RegistryClient(REGISTRY_URL, REGISTRY_API_KEY);
  const registryStatus = await getRegistryStatus(client, traceId);

  let managedDids = [];
  try {
    const ids = await listIdentifiers();
    managedDids = ids.map(i => ({ did: i.did, alias: i.alias }));
  } catch (_e) { }

  const orgRegisteredState = getOrgSyncState('org_registered_in_registry', orgDid);
  const orgVerifiedState = getOrgSyncState('org_verified_in_registry', orgDid);
  const orgLastErrorState = getOrgSyncState('last_sync_error', orgDid);
  const orgLastTraceState = getOrgSyncState('last_setup_trace_id', orgDid);

  const orgRegistered = orgRegisteredState ? orgRegisteredState.value === 'true' : registryStatus.org_registered_in_registry;
  const orgVerified = orgVerifiedState ? orgVerifiedState.value === 'true' : registryStatus.org_verified_in_registry;
  const orgLastError = orgLastErrorState ? orgLastErrorState.value : registryStatus.last_sync_error;
  const orgLastTrace = orgLastTraceState ? orgLastTraceState.value : registryStatus.last_trace_id;

  const lifecycleReady = !!orgDid
    && registryStatus.registry_connected
    && registryStatus.registry_auth_configured
    && registryStatus.registry_authenticated
    && orgRegistered
    && orgVerified;

  res.json({
    org_did: orgDid || null,
    selected_org_did: orgDid || null,
    default_org_did: orgDid || null,
    org_did_configured: !!orgDid,
    signing_mode: process.env.SIGNING_MODE || 'local',
    registry_url: REGISTRY_URL,
    registry_connected: registryStatus.registry_connected,
    registry_auth_configured: registryStatus.registry_auth_configured,
    registry_authenticated: registryStatus.registry_authenticated,
    last_sync_error: orgLastError || null,
    active_org_did: orgDid || null,
    org_registered_in_registry: orgRegistered,
    org_verified_in_registry: orgVerified,
    registration_vc_present: !!loadOrgVC(orgDid),
    last_trace_id: orgLastTrace || traceId,
    lifecycle_ready: lifecycleReady,
    managed_dids: managedDids,
    last_setup: lastSetup,
  });
});

app.post('/api/setup/select-org', requireApiKey, async (req, res) => {
  const { orgDid } = req.body || {};
  const traceId = req.traceId;

  try {
    if (!orgDid) {
      setActiveOrgDid(null);
      return res.json({
        status: 'ok',
        active_org_did: null,
        trace_id: traceId,
        message: 'Active organization cleared',
      });
    }

    const ids = await listIdentifiers();
    const match = ids.find(i => i.did === orgDid);
    if (!match) {
      return res.status(404).json({
        error: 'Managed DID not found in SDK',
        detail: `No local managed identifier for ${orgDid}`,
        trace_id: traceId,
      });
    }

    setActiveOrgDid(orgDid);

    const state = getLastSetup() || null;
    return res.json({
      status: 'ok',
      active_org_did: orgDid,
      trace_id: traceId,
      last_setup: state,
      message: 'Active organization switched',
    });
  } catch (err) {
    return res.status(500).json({
      error: 'Failed to switch active organization',
      detail: err.message,
      trace_id: traceId,
    });
  }
});


app.get('/api/setup/verify', async (req, res) => {
  const orgDid = getActiveOrgDid() || process.env.ORG_DID || '';
  let managedIdentifierExists = false;
  const client = new RegistryClient(REGISTRY_URL, REGISTRY_API_KEY);
  const registryStatus = await getRegistryStatus(client, req.traceId);

  try {
    const ids = await listIdentifiers();
    managedIdentifierExists = !!orgDid && ids.some(i => i.did === orgDid);
  } catch (_e) { }

  const readyForLifecycle = !!orgDid
    && registryStatus.registry_connected
    && registryStatus.registry_auth_configured
    && registryStatus.registry_authenticated
    && registryStatus.org_registered_in_registry
    && registryStatus.org_verified_in_registry
    && managedIdentifierExists;

  res.json({
    org_did: orgDid || null,
    registry_connected: registryStatus.registry_connected,
    registry_auth_configured: registryStatus.registry_auth_configured,
    registry_authenticated: registryStatus.registry_authenticated,
    org_registered_in_registry: registryStatus.org_registered_in_registry,
    org_verified_in_registry: registryStatus.org_verified_in_registry,
    managed_identifier_exists: managedIdentifierExists,
    ready_for_lifecycle: readyForLifecycle,
    last_sync_error: registryStatus.last_sync_error || null,
    last_trace_id: registryStatus.last_trace_id,
  });
});

app.post('/api/documents/create', requireApiKey, async (req, res) => {
  const { title, type, classification, registrationNumber, metadata, semanticSummary, sensitivityControl } = req.body || {};
  try {
    const mergedMetadata = {
      title,
      type,
      classification,
      registrationNumber,
      ...(metadata || {}),
    };

    if (semanticSummary) mergedMetadata.semanticSummary = semanticSummary;
    if (sensitivityControl) mergedMetadata.sensitivityControl = sensitivityControl;

    const result = await hooks.createDocument(mergedMetadata, { traceId: req.traceId });
    res.status(201).json(result);
  } catch (err) {
    res.status(500).json({ error: 'Document creation failed', detail: err.message, trace_id: req.traceId });
  }
});

app.post('/api/documents/:did/send', requireApiKey, async (req, res) => {
  const documentDid = decodeURIComponent(req.params.did);
  const { recipientDid, deliveryMethod } = req.body || {};
  if (!recipientDid) return res.status(400).json({ error: 'Required: recipientDid', trace_id: req.traceId });
  try {
    const result = await hooks.onDocumentSent(documentDid, recipientDid, { deliveryMethod }, { traceId: req.traceId });
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'Send failed', detail: err.message, trace_id: req.traceId });
  }
});

app.post('/api/documents/:did/receive', requireApiKey, async (req, res) => {
  const documentDid = decodeURIComponent(req.params.did);
  const { senderDid, localRegistrationNumber } = req.body || {};
  if (!senderDid) return res.status(400).json({ error: 'Required: senderDid', trace_id: req.traceId });
  try {
    const result = await hooks.onDocumentReceived(documentDid, senderDid, { localRegistrationNumber }, { traceId: req.traceId });
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'Receive failed', detail: err.message, trace_id: req.traceId });
  }
});

app.post('/api/documents/:did/assign', requireApiKey, async (req, res) => {
  const documentDid = decodeURIComponent(req.params.did);
  const { assignee, department } = req.body || {};
  try {
    const result = await hooks.onDocumentAssigned(documentDid, { assignee, department }, { traceId: req.traceId });
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'Assign failed', detail: err.message, trace_id: req.traceId });
  }
});

app.post('/api/documents/:did/decide', requireApiKey, async (req, res) => {
  const documentDid = decodeURIComponent(req.params.did);
  const { decision, resolution } = req.body || {};
  try {
    const result = await hooks.onDocumentDecided(documentDid, { decision, resolution }, { traceId: req.traceId });
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'Decide failed', detail: err.message, trace_id: req.traceId });
  }
});

app.post('/api/documents/:did/archive', requireApiKey, async (req, res) => {
  const documentDid = decodeURIComponent(req.params.did);
  const { archiveReference } = req.body || {};
  try {
    const result = await hooks.onDocumentArchived(documentDid, { archiveReference }, { traceId: req.traceId });
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'Archive failed', detail: err.message, trace_id: req.traceId });
  }
});

app.get('/api/documents/:did/track', async (req, res) => {
  const documentDid = decodeURIComponent(req.params.did);
  try {
    const result = await hooks.trackDocument(documentDid, { traceId: req.traceId });
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'Tracking failed', detail: err.message, trace_id: req.traceId });
  }
});

const { recommendRouting } = require('./src/ai/routing');
const { harmonizeStatuses, mapStatus } = require('./src/ai/harmonization');
const { isConfigured: aiConfigured, getConfig: aiConfig } = require('./src/ai/llm-client');

app.get('/api/ai/health', (req, res) => {
  res.json({ ai_available: aiConfigured(), provider: aiConfig().provider, model: aiConfig().model, capabilities: ['intelligent_routing', 'status_harmonization'] });
});

app.get('/api/ai/status', async (req, res) => {
  const status = getAiStatus();
  res.json(status);
});

app.post('/api/ai/anonymize', requireApiKey, async (req, res) => {
  const { text } = req.body || {};
  if (!text || typeof text !== 'string') return res.status(400).json({ error: 'Required: text' });
  try {
    const result = await anonymizeText(text);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'Anonymization failed', detail: err.message });
  }
});

app.post('/api/ai/extract-summary', requireApiKey, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Required: file' });

  let metadata = {};
  if (req.body && req.body.metadata) {
    try {
      metadata = JSON.parse(req.body.metadata);
    } catch (_e) {
      return res.status(400).json({ error: 'metadata must be valid JSON string' });
    }
  }

  try {
    const client = new RegistryClient(REGISTRY_URL, REGISTRY_API_KEY);
    const result = await extractAndSummarize({ filePath: req.file.path, metadata, registryClient: client });
    const body = {
      semanticSummary: result.semanticSummary,
      sensitivityControl: result.sensitivityControl,
      confidence: result.confidence,
      routeUsed: result.routeUsed,
    };
    if (process.env.AI_DEBUG_RETURN_EXTRACTED_TEXT === 'true') body.extractedText = result.extractedText;
    res.json(body);
  } catch (err) {
    res.status(500).json({ error: 'Extract/summary failed', detail: err.message });
  } finally {
    fs.unlink(req.file.path, () => {});
  }
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
      did: i.did, alias: i.alias, provider: i.provider, controllerKeyId: i.controllerKeyId,
      keys: (i.keys || []).map(k => ({ kid: k.kid, type: k.type, publicKeyHex: k.publicKeyHex })),
    })));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/audit/logs', async (req, res) => {
  const { limit, offset, action, success, trace_id } = req.query;
  const rows = listSyncLogs({ limit, offset, action, success, trace_id });
  res.json({
    items: rows,
    total: rows.length,
    limit: Number(limit) || 50,
    offset: Number(offset) || 0,
  });
});

app.get('/api/audit/logs/:id', async (req, res) => {
  const row = getSyncLog(Number(req.params.id));
  if (!row) return res.status(404).json({ error: 'Log not found' });
  res.json(row);
});

app.get('/api/audit/summary', async (_req, res) => {
  const all = listSyncLogs({ limit: 10000, offset: 0 });
  const failed = all.filter(r => r.success === 0);
  const authFailures = failed.filter(r => r.action && r.action.includes('auth')).length;
  const orgFailures = failed.filter(r => r.action && r.action.startsWith('sdk.org')).length;
  const docFailures = failed.filter(r => r.action && r.action.startsWith('sdk.doc')).length;
  const eventFailures = failed.filter(r => r.action && r.action.startsWith('sdk.event')).length;

  res.json({
    total_calls: all.length,
    failed_calls: failed.length,
    auth_failures: authFailures,
    org_sync_failures: orgFailures,
    doc_sync_failures: docFailures,
    event_sync_failures: eventFailures,
    latest_failed_action: failed.length ? failed[0].action : null,
  });
});

app.get('/api/health', async (req, res) => {
  const stateOrgDid = getActiveOrgDid();
  const envOrgDid = process.env.ORG_DID || '';
  const orgDid = stateOrgDid || envOrgDid || '';
  const orgDidSource = stateOrgDid ? 'state' : (envOrgDid ? 'env' : 'none');
  let agentOk = false;
  let managedDids = 0;
  try {
    const ids = await listIdentifiers();
    agentOk = true;
    managedDids = ids.length;
  } catch (_e) { }

  const client = new RegistryClient(REGISTRY_URL, REGISTRY_API_KEY);
  const registryStatus = await getRegistryStatus(client, req.traceId);

  const aiStatus = getAiStatus();

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
    org_registered_in_registry: registryStatus.org_registered_in_registry,
    org_verified_in_registry: registryStatus.org_verified_in_registry,
    last_sync_error: registryStatus.last_sync_error || null,
    last_trace_id: registryStatus.last_trace_id || req.traceId,
    ai_enabled: aiStatus.ai_enabled,
    extractor_available: aiStatus.extractor_available,
    anonymizer_available: aiStatus.anonymizer_available,
    central_llm_available: aiStatus.central_llm_available,
    local_llm_available: aiStatus.local_llm_available,
    fallback_provider: aiStatus.fallback_provider,
    semantic_summary_supported: true,
  });
});

app.get('/', (req, res) => {
  const stateOrgDid = getActiveOrgDid();
  const envOrgDid = process.env.ORG_DID || '';
  const orgDid = stateOrgDid || envOrgDid || '';
  const orgDidSource = stateOrgDid ? 'state' : (envOrgDid ? 'env' : 'none');

  res.json({ name: 'VeriDocs SDK', description: 'Document lifecycle DID/VC sidecar for DMS integration', org_did: orgDid || '(not configured)', org_did_source: orgDidSource, registry: REGISTRY_URL, signing_mode: process.env.SIGNING_MODE || 'local' });
});

app.use((err, req, res, _next) => {
  console.error(`[SDK ERROR] ${req.method} ${req.url}:`, err);
  res.status(500).json({ error: 'Internal server error', detail: err.message, trace_id: req.traceId || null });
});

app.listen(PORT, HOST, async () => {
  console.log(`VeriDocs SDK sidecar: http://${HOST}:${PORT}`);
  console.log(`Registry: ${REGISTRY_URL}`);
  console.log(`Signing mode: ${process.env.SIGNING_MODE || 'local'}`);
  try {
    const ids = await listIdentifiers();
    console.log(`Managed DIDs: ${ids.length}`);
  } catch (e) {
    console.warn('Agent:', e.message);
  }
});
