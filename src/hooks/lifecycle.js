/**
 * Lifecycle Hooks — the integration layer between a DVS and VeriDocs.
 * 
 * Each hook:
 *   1. Creates the appropriate lifecycle VC (signed locally or delegated)
 *   2. Submits the VC to the central VeriDocs Register
 *   3. Returns the VC and registry response
 * 
 * Usage from DVS:
 *   const hooks = require('./hooks/lifecycle');
 *   // On document creation:
 *   const result = await hooks.onDocumentCreated(docDid, { documentTitle: 'Application' });
 *   // On sending:
 *   const result = await hooks.onDocumentSent(docDid, recipientDid, { deliveryMethod: 'eAdrese' });
 */

const { createLifecycleVC } = require('../vc-builder');
const { createDocumentDID } = require('../did-manager');
const { RegistryClient } = require('../registry-client');

const REGISTRY_URL = process.env.REGISTRY_URL || 'http://localhost:8001';
const REGISTRY_API_KEY = process.env.REGISTRY_API_KEY || '';
const ORG_DID = process.env.ORG_DID || '';

let _client;
function getRegistryClient() {
  if (!_client) _client = new RegistryClient(REGISTRY_URL, REGISTRY_API_KEY);
  return _client;
}

function requireOrgDid() {
  if (!ORG_DID) throw new Error('ORG_DID environment variable not set. Run the setup first.');
  return ORG_DID;
}

/**
 * Create a new document: generate DID, register with Registry, issue DocumentCreated VC.
 * @param {object} metadata - Document metadata (title, type, classification, etc.)
 * @returns {{ docDid, docMeta, vc, registry }}
 */
async function createDocument(metadata) {
  const orgDid = requireOrgDid();
  const client = getRegistryClient();

  // Generate document DID
  const docMeta = createDocumentDID(orgDid, metadata);

  // Register document with central Registry
  const regResult = await client.registerDocument(docMeta.did, orgDid, metadata);

  // Create and sign DocumentCreated VC
  const vc = await createLifecycleVC('DocumentCreated', docMeta.did, orgDid, {
    documentTitle: metadata.title || undefined,
    classification: metadata.classification || undefined,
    localRegistrationNumber: metadata.registrationNumber || undefined,
  });

  // Submit VC to Registry
  const eventResult = await client.submitEvent(vc);

  return {
    docDid: docMeta.did,
    docUuid: docMeta.uuid,
    docMeta,
    vc,
    registry: { document: regResult, event: eventResult },
  };
}

/**
 * Hook: Document created in DVS (use when document already has a DID).
 */
async function onDocumentCreated(documentDid, claims) {
  const orgDid = requireOrgDid();
  const vc = await createLifecycleVC('DocumentCreated', documentDid, orgDid, claims || {});
  const eventResult = await getRegistryClient().submitEvent(vc);
  return { vc, registry: eventResult };
}

/**
 * Hook: Document sent to another organization.
 */
async function onDocumentSent(documentDid, recipientDid, claims) {
  const orgDid = requireOrgDid();
  const vc = await createLifecycleVC('DocumentSent', documentDid, orgDid, {
    recipientOrganization: recipientDid,
    ...claims,
  });
  const eventResult = await getRegistryClient().submitEvent(vc);
  return { vc, registry: eventResult };
}

/**
 * Hook: Document received from another organization.
 */
async function onDocumentReceived(documentDid, senderDid, claims) {
  const orgDid = requireOrgDid();
  const vc = await createLifecycleVC('DocumentReceived', documentDid, orgDid, {
    senderOrganization: senderDid,
    ...claims,
  });
  const eventResult = await getRegistryClient().submitEvent(vc);
  return { vc, registry: eventResult };
}

/**
 * Hook: Document assigned to person/department.
 */
async function onDocumentAssigned(documentDid, claims) {
  const orgDid = requireOrgDid();
  const vc = await createLifecycleVC('DocumentAssigned', documentDid, orgDid, claims || {});
  const eventResult = await getRegistryClient().submitEvent(vc);
  return { vc, registry: eventResult };
}

/**
 * Hook: Decision made on document.
 */
async function onDocumentDecided(documentDid, claims) {
  const orgDid = requireOrgDid();
  const vc = await createLifecycleVC('DocumentDecided', documentDid, orgDid, claims || {});
  const eventResult = await getRegistryClient().submitEvent(vc);
  return { vc, registry: eventResult };
}

/**
 * Hook: Document archived.
 */
async function onDocumentArchived(documentDid, claims) {
  const orgDid = requireOrgDid();
  const vc = await createLifecycleVC('DocumentArchived', documentDid, orgDid, claims || {});
  const eventResult = await getRegistryClient().submitEvent(vc);
  return { vc, registry: eventResult };
}

/**
 * Track document via Registry.
 */
async function trackDocument(documentDid) {
  return getRegistryClient().trackDocument(documentDid);
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
