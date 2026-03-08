const { createAgentInstance } = require('./agent-setup');
const { ensureRootDid } = require('./create-did');

const ROOT_DID = 'did:web:veritrust.vc';

let agentPromise;

async function getAgent() {
  if (!agentPromise) {
    agentPromise = createAgentInstance();
  }
  return agentPromise;
}

function normalizeOptions(options) {
  if (!options || typeof options === 'string') {
    return { did: typeof options === 'string' ? options : ROOT_DID };
  }
  return { did: options.did || ROOT_DID, agent: options.agent };
}

async function resolveIdentifierWithKey(options) {
  const { did, agent } = normalizeOptions(options);
  const activeAgent = agent || (await getAgent());

  if (did === ROOT_DID) {
    await ensureRootDid({ agent: activeAgent });
  }

  const identifier = await activeAgent.didManagerGet({ did });
  const key = identifier?.keys?.[0];
  if (!key?.kid) {
    throw new Error(`No verification key available for DID ${identifier?.did || did}`);
  }
  const verificationMethod =
    typeof key.kid === 'string' && key.kid.includes('#') ? key.kid : `${identifier.did}#${key.kid}`;
  return { agent: activeAgent, identifier, key, keyId: key.kid, verificationMethod };
}

async function getVerificationMethodForDid(options) {
  const { verificationMethod } = await resolveIdentifierWithKey(options);
  return verificationMethod;
}

async function getKeyIdForDid(options) {
  const { keyId } = await resolveIdentifierWithKey(options);
  return keyId;
}

module.exports = {
  resolveIdentifierWithKey,
  getVerificationMethodForDid,
  getKeyIdForDid,
};
