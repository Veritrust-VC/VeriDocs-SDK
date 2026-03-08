// src/ld-suites/jws2020-es256k.js
// CJS module (require/exports) to match current agent-setup.js usage.

const { JsonWebSignature2020: BaseJsonWebSignature2020 } = require('./jsonWebSignature2020');

/**
 * JsonWebSignature2020 suite locked to ES256K/secp256k1 for Veramo v6.
 * It exposes the metadata the LD plugin uses to match a verificationMethod.
 */
class JsonWebSignature2020_ES256K extends BaseJsonWebSignature2020 {
  constructor(options = {}) {
    const {
      alg = 'ES256K',
      curve = 'secp256k1',
      keyType = 'Secp256k1',
      id = 'JsonWebSignature2020_ES256K',
    } = options;

    super({ alg, curve, keyType });

    // CRITICAL: Veramo selects suites by their `.type` string.
    this.type = 'JsonWebSignature2020';
    this.id = id;
    this.algorithm = alg;

    // <-- These fields are what the @veramo/credential-ld suite picker looks at
    this.verificationMethodTypes = ['JsonWebKey2020'];
    this.keyTypes = [keyType];
    this.alg = alg;
    this.curve = curve;
  }

  /**
   * The LD plugin calls this before trying to use the suite.
   * We only accept JsonWebKey2020 (EC + secp256k1).
   */
  async supportsVerificationMethod(vm) {
    if (!vm || vm.type !== 'JsonWebKey2020') return false;
    const jwk = vm.publicKeyJwk || {};
    const expectedCurve = String(this.curve || 'secp256k1').toLowerCase();
    const crv = String(jwk.crv || '').toLowerCase();
    const kty = String(jwk.kty || '').toUpperCase();
    return kty === 'EC' && crv === expectedCurve;
  }

  /**
   * Return a signer bound to agent.keyManagerSign(kid, ES256K).
   * CredentialIssuerLD will call this after it picks the suite.
   */
  getSigner({ keyRef, alg = 'ES256K', agent }) {
    if (!agent || !keyRef) throw new Error('missing agent/keyRef');
    return async ({ data }) => agent.keyManagerSign({ kid: keyRef, algorithm: alg, data });
  }
}

module.exports = { JsonWebSignature2020_ES256K };
