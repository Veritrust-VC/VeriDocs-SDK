const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const Module = require('module');

const { validateSemanticSummary } = require('../src/ai/validator');
const { extractText, anonymizeText } = require('../src/ai/agent');

describe('AI validator', () => {
  it('clamps summary lengths and keyword count', () => {
    const long = 'a'.repeat(500);
    const result = validateSemanticSummary({
      summary: long,
      requestedAction: 'b'.repeat(140),
      keywords: new Array(20).fill('k'),
      confidence: 9,
      source: 'CENTRAL',
      requiresHuman: false,
    });

    assert.equal(result.valid, true);
    assert.equal(result.semanticSummary.summary.length, 300);
    assert.equal(result.semanticSummary.requestedAction.length, 100);
    assert.equal(result.semanticSummary.keywords.length, 10);
    assert.equal(result.semanticSummary.confidence, 1);
  });
});

describe('Extractor/anonymizer', () => {
  it('extracts txt and pdf fixtures', async () => {
    const txt = await extractText(path.join(__dirname, 'fixtures', 'sample.txt'));
    const pdf = await extractText(path.join(__dirname, 'fixtures', 'sample.pdf'));

    assert.match(txt.text, /jane@example.com/i);
    assert.match(pdf.text, /Hello PDF Summary/);
  });

  it('anonymizes sensitive patterns', async () => {
    const result = await anonymizeText('John Doe john@example.com +37120000000 123456 Main Street');
    assert.match(result.anonymizedText, /\[EMAIL\]/);
    assert.ok(Array.isArray(result.detectedEntities));
    assert.ok(['LOW', 'MEDIUM', 'HIGH', 'NONE'].includes(result.personalDataRisk));
  });
});

describe('Document create compatibility and semantic fields', () => {
  function loadLifecycleWithMocks(calls) {
    const originalLoad = Module._load;
    Module._load = function(request, parent, isMain) {
      if (request === '../vc-builder') {
        return {
          createLifecycleVC: async (_eventType, _docDid, _issuerDid, claims) => ({
            type: ['VerifiableCredential'],
            credentialSubject: claims,
          }),
        };
      }
      if (request === '../did-manager') {
        return {
          createDocumentDID: () => ({ did: 'did:web:test:doc:1', uuid: '1' }),
        };
      }
      if (request === '../registry-client') {
        return {
          RegistryClient: class {
            async registerDocument(did, issuerDid, metadata) {
              calls.registerDocument = { did, issuerDid, metadata };
              return { ok: true };
            }
            async resolveDocument() { return { ok: true }; }
            async submitEvent(vc) { calls.submitEvent = vc; return { ok: true }; }
            async trackDocument() { return { ok: true }; }
          },
        };
      }
      if (request === '../state-store') {
        return { getActiveOrgDid: () => 'did:web:test:org:1' };
      }
      if (request === '../audit-db') {
        return { writeSyncLog: () => {} };
      }
      return originalLoad(request, parent, isMain);
    };

    const modPath = require.resolve('../src/hooks/lifecycle');
    delete require.cache[modPath];
    const lifecycle = require('../src/hooks/lifecycle');
    Module._load = originalLoad;
    return lifecycle;
  }

  it('includes semanticSummary/sensitivityControl in outgoing payload and VC claims', async () => {
    const calls = {};
    const lifecycle = loadLifecycleWithMocks(calls);

    await lifecycle.createDocument({
      title: 'Doc',
      semanticSummary: { summary: 'Hello' },
      sensitivityControl: { personalDataRisk: 'LOW' },
    });

    assert.deepEqual(calls.registerDocument.metadata.semanticSummary, { summary: 'Hello' });
    assert.deepEqual(calls.submitEvent.credentialSubject.semanticSummary, { summary: 'Hello' });
    assert.deepEqual(calls.submitEvent.credentialSubject.sensitivityControl, { personalDataRisk: 'LOW' });
  });

  it('still works without semanticSummary for legacy callers', async () => {
    const calls = {};
    const lifecycle = loadLifecycleWithMocks(calls);
    await lifecycle.createDocument({ title: 'Legacy doc' });
    assert.equal(calls.registerDocument.metadata.title, 'Legacy doc');
  });
});
