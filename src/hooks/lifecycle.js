const { createLifecycleVC } = require('../vc-builder');
const { createDocumentDID } = require('../did-manager');
const { RegistryClient } = require('../registry-client');
const { getActiveOrgDid } = require('../state-store');
const { writeSyncLog } = require('../audit-db');
const { newTraceId } = require('../trace');

const REGISTRY_URL = process.env.REGISTRY_URL || 'http://localhost:8001';
const REGISTRY_API_KEY = process.env.REGISTRY_API_KEY || '';

let _client;
function getRegistryClient() {
  if (!_client) _client = new RegistryClient(REGISTRY_URL, REGISTRY_API_KEY);
  return _client;
}

function getConfiguredOrgDid() {
  return getActiveOrgDid() || process.env.ORG_DID || '';
}

function requireOrgDid() {
  const did = getConfiguredOrgDid();
  if (!did) throw new Error('Organization DID not configured. Run POST /api/setup/org first.');
  return did;
}

function localLog(action, traceId, details = {}) {
  writeSyncLog({
    trace_id: traceId,
    action,
    source_system: 'veridocs-sdk',
    target_system: 'sdk-local',
    success: details.success !== false,
    error_message: details.error_message || null,
    request_payload_summary: details.request_payload_summary || null,
    request_payload_json: details.request_payload_json || null,
    response_body_summary: details.response_body_summary || null,
    response_body_json: details.response_body_json || null,
    local_entity_type: details.local_entity_type || null,
    local_entity_did: details.local_entity_did || null,
    source_org_did: details.source_org_did || null,
  });
}

async function createDocument(metadata, options = {}) {
  const traceId = options.traceId || newTraceId();
  const orgDid = requireOrgDid();
  const client = getRegistryClient();

  const docMeta = createDocumentDID(orgDid, metadata);
  localLog('sdk.doc.local_create', traceId, {
    request_payload_summary: 'local document DID creation',
    request_payload_json: metadata,
    response_body_json: docMeta,
    local_entity_type: 'document',
    local_entity_did: docMeta.did,
    source_org_did: orgDid,
  });

  const regResult = await client.registerDocument(docMeta.did, orgDid, metadata, {
    traceId,
    sourceOrgDid: orgDid,
    actorType: 'sdk',
    localEntityType: 'document',
    localEntityDid: docMeta.did,
  });

  const verifyResult = await client.resolveDocument(docMeta.did, {
    traceId,
    sourceOrgDid: orgDid,
    localEntityType: 'document',
    localEntityDid: docMeta.did,
  });

  const vc = await createLifecycleVC('DocumentCreated', docMeta.did, orgDid, {
    documentTitle: metadata.title || undefined,
    classification: metadata.classification || undefined,
    localRegistrationNumber: metadata.registrationNumber || undefined,
  });

  localLog('sdk.event.vc_built', traceId, {
    request_payload_summary: 'DocumentCreated VC built',
    response_body_summary: vc.type ? vc.type.join(',') : 'vc',
    local_entity_type: 'document',
    local_entity_did: docMeta.did,
    source_org_did: orgDid,
  });

  const eventResult = await client.submitEvent(vc, {
    traceId,
    sourceOrgDid: orgDid,
    localEntityType: 'document',
    localEntityDid: docMeta.did,
  });

  return {
    trace_id: traceId,
    docDid: docMeta.did,
    docUuid: docMeta.uuid,
    docMeta,
    vc,
    registry: { document: regResult, verify: verifyResult, event: eventResult },
  };
}

async function submitLifecycleEvent(eventType, documentDid, claims = {}, options = {}) {
  const traceId = options.traceId || newTraceId();
  const orgDid = requireOrgDid();
  const vc = await createLifecycleVC(eventType, documentDid, orgDid, claims || {});

  localLog('sdk.event.vc_built', traceId, {
    request_payload_summary: `${eventType} VC built`,
    local_entity_type: 'document',
    local_entity_did: documentDid,
    source_org_did: orgDid,
  });

  const eventResult = await getRegistryClient().submitEvent(vc, {
    traceId,
    sourceOrgDid: orgDid,
    localEntityType: 'document',
    localEntityDid: documentDid,
  });

  return { trace_id: traceId, vc, registry: eventResult };
}

async function onDocumentCreated(documentDid, claims, options = {}) {
  return submitLifecycleEvent('DocumentCreated', documentDid, claims || {}, options);
}

async function onDocumentSent(documentDid, recipientDid, claims, options = {}) {
  return submitLifecycleEvent('DocumentSent', documentDid, {
    recipientOrganization: recipientDid,
    ...claims,
  }, options);
}

async function onDocumentReceived(documentDid, senderDid, claims, options = {}) {
  return submitLifecycleEvent('DocumentReceived', documentDid, {
    senderOrganization: senderDid,
    ...claims,
  }, options);
}

async function onDocumentAssigned(documentDid, claims, options = {}) {
  return submitLifecycleEvent('DocumentAssigned', documentDid, claims || {}, options);
}

async function onDocumentDecided(documentDid, claims, options = {}) {
  return submitLifecycleEvent('DocumentDecided', documentDid, claims || {}, options);
}

async function onDocumentArchived(documentDid, claims, options = {}) {
  return submitLifecycleEvent('DocumentArchived', documentDid, claims || {}, options);
}

async function trackDocument(documentDid, options = {}) {
  const traceId = options.traceId || newTraceId();
  const orgDid = getConfiguredOrgDid();
  const result = await getRegistryClient().trackDocument(documentDid, {
    traceId,
    sourceOrgDid: orgDid || null,
    localEntityType: 'document',
    localEntityDid: documentDid,
  });
  return { trace_id: traceId, ...result };
}

module.exports = {
  createDocument,
  onDocumentCreated,
  onDocumentSent,
  onDocumentReceived,
  onDocumentAssigned,
  onDocumentDecided,
  onDocumentArchived,
  trackDocument,
};
