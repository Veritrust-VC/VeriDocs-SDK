const { VeramoLdSignature } = require('@veramo/credential-ld');
const { JsonWebKey } = require('@transmute/json-web-signature');

let JsonWebSignature;
try {
  ({ JsonWebSignature } = require('@digitalbazaar/json-web-signature'));
} catch (err) {
  ({ JsonWebSignature } = require('@transmute/json-web-signature'));
}
const {
  asArray,
  bytesToBase64,
  bytesToBase64url,
  concat,
  encodeJoseBlob,
  hexToBytes,
  stringToUtf8Bytes,
} = require('@veramo/utils');

class JsonWebSignature2020 extends VeramoLdSignature {
  constructor(options = {}) {
    super();
    this.alg = options.alg || 'ES256K';
    this.curve = options.curve || (this.alg === 'ES256K' ? 'secp256k1' : 'P-256');
    this.keyType = options.keyType || (this.alg === 'ES256K' ? 'Secp256k1' : 'Secp256r1');
  }

  getSupportedVerificationType() {
    return 'JsonWebKey2020';
  }

  getSupportedVeramoKeyType() {
    return this.keyType;
  }

  async getSuiteForSigning(key, issuerDid, verificationMethodId, context) {
    const controller = issuerDid;
    const header = {
      alg: this.alg,
      b64: false,
      crit: ['b64'],
    };

    const signer = {
      sign: async ({ data }) => {
        const headerString = encodeJoseBlob(header);
        const messageBuffer = concat([stringToUtf8Bytes(`${headerString}.`), data]);
        const messageString = bytesToBase64(messageBuffer);
        const signature = await context.agent.keyManagerSign({
          keyRef: key.kid,
          algorithm: this.alg,
          data: messageString,
          encoding: 'base64',
        });
        return `${headerString}..${signature}`;
      },
    };

    const verificationKey = await JsonWebKey.from({
      id: verificationMethodId,
      type: 'JsonWebKey2020',
      controller,
      publicKeyJwk: this._publicKeyToJwk(key),
    });

    verificationKey.signer = () => signer;

    const suite = new JsonWebSignature({ key: verificationKey });
    suite.ensureSuiteContext = ({ document }) => {
      document['@context'] = [
        ...asArray(document['@context'] || []),
        'https://w3id.org/security/suites/jws-2020/v1',
      ];
    };

    return suite;
  }

  getSuiteForVerification() {
    return new JsonWebSignature();
  }

  preSigningCredModification() {}

  async preDidResolutionModification(_didUrl, didDoc) {
    return didDoc;
  }

  _publicKeyToJwk(key) {
    const source = key?.publicKeyJwk || key?.meta?.publicKeyJwk;
    if (source) {
      return this._withDefaults({ ...source }, key?.kid);
    }

    const hex = key?.publicKeyHex || key?.meta?.publicKeyHex;
    if (typeof hex === 'string' && hex.length > 0) {
      const normalized = hex.startsWith('0x') ? hex.slice(2) : hex;
      const bytes = hexToBytes(normalized);
      if (bytes.length !== 65 || bytes[0] !== 0x04) {
        throw new Error('Unsupported EC publicKeyHex format');
      }

      const xBytes = bytes.slice(1, 33);
      const yBytes = bytes.slice(33);
      return this._withDefaults(
        {
          kty: 'EC',
          crv: this.curve,
          x: bytesToBase64url(xBytes),
          y: bytesToBase64url(yBytes),
        },
        key?.kid,
      );
    }

    throw new Error('Missing public key material for JsonWebSignature2020 suite');
  }

  _withDefaults(jwk, kid) {
    const result = { ...jwk };
    if (!result.alg) result.alg = this.alg;
    if (!result.kty) result.kty = 'EC';
    if (!result.crv) result.crv = this.curve;
    if (!result.use) result.use = 'sig';
    if (!result.kid && kid) result.kid = kid;
    return result;
  }
}

module.exports = { JsonWebSignature2020 };
