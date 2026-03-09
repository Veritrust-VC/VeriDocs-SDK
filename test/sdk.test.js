/**
 * Basic integration tests for VeriDocs SDK.
 * Requires: SDK running on :3100, Registry running on :8001
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const SDK_URL = process.env.SDK_URL || 'http://localhost:3100';

async function api(path, opts = {}) {
  const res = await fetch(`${SDK_URL}${path}`, {
    headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.VERAMO_API_KEY || '' },
    ...opts,
  });
  const body = await res.json();
  return { status: res.status, body };
}

describe('SDK Health', () => {
  it('should return ok', async () => {
    const { status, body } = await api('/api/health');
    assert.equal(status, 200);
    assert.equal(body.status, 'ok');
    assert.equal(body.service, 'veridocs-sdk');
    assert.ok('org_did_source' in body);
    assert.ok(body.capabilities.includes('lifecycle-hooks'));
  });
});

describe('SDK Setup', () => {
  it('should report setup status', async () => {
    const { status, body } = await api('/api/setup/status');
    assert.equal(status, 200);
    assert.ok('org_did' in body);
    assert.ok('registry_connected' in body);
    assert.ok('signing_mode' in body);
    assert.ok('last_setup' in body);
  });


  it('should expose setup verification endpoint', async () => {
    const { status, body } = await api('/api/setup/verify');
    assert.equal(status, 200);
    assert.ok('org_did_configured' in body);
    assert.ok('registry_connected' in body);
    assert.ok('managed_identifier_exists' in body);
    assert.ok('ready_for_lifecycle' in body);
  });

  it('should create organization DID', async () => {
    const { status, body } = await api('/api/setup/org', {
      method: 'POST',
      body: JSON.stringify({ orgCode: 'TEST-SDK-001', orgName: 'SDK Test Organization' }),
    });
    assert.ok([201, 200].includes(status), `Expected 201 or 200, got ${status}: ${JSON.stringify(body)}`);
    assert.ok(body.did);
    assert.ok(body.did.includes('TEST-SDK-001'));
  });
});

describe('DID Resolution', () => {
  it('should resolve a did:key', async () => {
    const { status, body } = await api('/api/did/resolve', {
      method: 'POST',
      body: JSON.stringify({ did: 'did:key:zQ3sheoYG5PVbQSoPQUJvQwtgWNu3zQNAavWQbPFCYZRYHvpt' }),
    });
    assert.equal(status, 200);
    assert.ok(body.didDocument);
  });
});

describe('Managed Identifiers', () => {
  it('should list identifiers', async () => {
    const { status, body } = await api('/api/identifiers');
    assert.equal(status, 200);
    assert.ok(Array.isArray(body));
  });
});
