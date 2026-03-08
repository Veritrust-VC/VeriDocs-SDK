/* eslint-disable no-console */
function patchCredentialLd() {
  const modPath = require.resolve('@veramo/credential-ld');
  const mod = require('@veramo/credential-ld');
  console.log('[PATCH LD] using module at', modPath);

  const Issuer = mod.CredentialIssuerLD;
  if (!Issuer) {
    console.warn('[PATCH LD] CredentialIssuerLD not found; skip patch');
    return;
  }

  let AssertionProofPurposeCtor;
  let AuthenticationProofPurposeCtor;
  let CredentialIssuancePurposeCtor;
  try {
    const { purposes } = require('jsonld-signatures');
    AssertionProofPurposeCtor = purposes?.AssertionProofPurpose;
    AuthenticationProofPurposeCtor = purposes?.AuthenticationProofPurpose;
    CredentialIssuancePurposeCtor = purposes?.CredentialIssuancePurpose;
  } catch (e) {
    console.warn('[PATCH LD] Failed to load jsonld-signatures purposes:', e?.message || e);
  }

  const coercePurpose = purpose => {
    if (purpose && typeof purpose.update === 'function') {
      return purpose;
    }

    const requested = typeof purpose === 'string' && purpose;
    const mapping = {
      assertionMethod: AssertionProofPurposeCtor,
      authentication: AuthenticationProofPurposeCtor,
      credentialIssuance: CredentialIssuancePurposeCtor,
    };

    const PurposeCtor = mapping[requested || 'assertionMethod'];

    if (PurposeCtor) {
      return new PurposeCtor();
    }

    if (typeof purpose === 'string') {
      console.warn(`[PATCH LD] Unknown proof purpose "${purpose}"; passing through as string.`);
      return purpose;
    }

    if (!purpose) {
      console.warn('[PATCH LD] No usable proof purpose available; proceeding without coercion.');
    }

    return purpose;
  };

  const _create = Issuer.prototype.createVerifiableCredentialLD;
  Issuer.prototype.createVerifiableCredentialLD = async function patchedCreate(options, ctx) {
    const opts = options || {};
    if (!opts.suites && Array.isArray(this.suites) && this.suites.length > 0) {
      opts.suites = this.suites;
      console.log('[PATCH LD] mirrored instance suites to options.suites');
    }
    if (!opts.proofType) {
      opts.proofType = 'JsonWebSignature2020';
    }
    opts.purpose = coercePurpose(opts.purpose);
    return _create.call(this, opts, ctx);
  };

  const _findKey = Issuer.prototype.findSigningKeyWithId;
  Issuer.prototype.findSigningKeyWithId = async function patchedFindKey(context, identifier, keyRef, resolutionOptions) {
    if (!this.agent && context?.agent) {
      this.agent = context.agent;
    }

    try {
      return await _findKey.call(this, context, identifier, keyRef, resolutionOptions);
    } catch (err) {
      const message = err?.message || String(err || '');
      if (!message.startsWith('key_not_found') || !identifier?.keys?.length) {
        throw err;
      }

      const supportedTypes =
        this.ldCredentialModule?.ldSuiteLoader?.getAllSignatureSuiteTypes?.() || [];

      const buildVerificationMethod = key => {
        const meta = key?.meta || {};
        const existingVm = typeof meta.verificationMethod === 'object' && meta.verificationMethod;
        const vmIdFromMeta =
          (typeof meta.verificationMethod === 'string' && meta.verificationMethod) || existingVm?.id || key?.kid;

        const candidateTypes = [];
        if (existingVm?.type) candidateTypes.push(existingVm.type);
        if (meta.publicKeyJwk) candidateTypes.push('JsonWebKey2020');
        if (meta.publicKeyHex || meta.uncompressedPublicKeyHex || key?.publicKeyHex) {
          candidateTypes.push('EcdsaSecp256k1RecoveryMethod2020');
        }

        const vmType = candidateTypes.find(type => supportedTypes.includes(type));
        if (!vmType) return null;

        const vm = existingVm && existingVm.type === vmType
          ? existingVm
          : {
              id: vmIdFromMeta,
              type: vmType,
              controller: identifier?.did,
              publicKeyJwk: vmType === 'JsonWebKey2020' ? meta.publicKeyJwk : undefined,
              publicKeyHex:
                vmType === 'JsonWebKey2020'
                  ? undefined
                  : key?.publicKeyHex || meta.uncompressedPublicKeyHex || meta.publicKeyHex,
            };

        if (!vm?.id || !supportedTypes.includes(vm.type)) return null;

        const idMatches = !keyRef || vm.id === keyRef || key?.kid === keyRef;
        if (!idMatches) return null;

        return {
          ...key,
          meta: { ...meta, verificationMethod: vm },
        };
      };

      const signingKey = identifier.keys
        .map(buildVerificationMethod)
        .find(candidate => !!candidate);

      if (!signingKey) {
        throw err;
      }

      const verificationMethodId = signingKey.meta.verificationMethod.id;
      console.warn(
        `[PATCH LD] Falling back to locally managed key ${signingKey.kid} for DID ${identifier?.did} with verification method ${verificationMethodId}`,
      );

      return { signingKey, verificationMethodId };
    }
  };
}

patchCredentialLd();

module.exports = patchCredentialLd;
