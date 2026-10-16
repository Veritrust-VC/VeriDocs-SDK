const test = require('node:test');
const assert = require('node:assert');

function load(env) {
  for (const k of ['ORG_DID', 'REGISTRY_DOMAIN']) delete process.env[k];
  Object.assign(process.env, env);
  delete require.cache[require.resolve('../src/did-manager')];
  return require('../src/did-manager');
}

test('own-domain DID is taken from ORG_DID', () => {
  const m = load({ ORG_DID: 'did:web:ombud.pac.kis.gov.lv', REGISTRY_DOMAIN: 'dokregistrs.pac.kis.gov.lv' });
  assert.strictEqual(m.ownDomainDid(), 'did:web:ombud.pac.kis.gov.lv');
});

test('register-hosted or empty ORG_DID keeps the register form', () => {
  const r = 'dokregistrs.pac.kis.gov.lv';
  assert.strictEqual(load({ REGISTRY_DOMAIN: r }).ownDomainDid(), null);
  assert.strictEqual(load({ ORG_DID: `did:web:${r}:org:x`, REGISTRY_DOMAIN: r }).ownDomainDid(), null);
  assert.strictEqual(load({ ORG_DID: `did:web:${r}`, REGISTRY_DOMAIN: r }).ownDomainDid(), null);
});

test('DID document carries the public key under #key-1', () => {
  const m = load({});
  const doc = m.buildCanonicalDidDocument('did:web:ombud.pac.kis.gov.lv',
    '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');
  assert.strictEqual(doc.id, 'did:web:ombud.pac.kis.gov.lv');
  assert.strictEqual(doc.verificationMethod[0].id, 'did:web:ombud.pac.kis.gov.lv#key-1');
  assert.strictEqual(doc.verificationMethod[0].publicKeyJwk.crv, 'secp256k1');
});
