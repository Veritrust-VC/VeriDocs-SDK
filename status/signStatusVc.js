const { createAgentInstance } = require('../agent-setup');

/** Signs the Status List VC as VC-JWT and returns { ...vc, proof: { type, jwt } } */
async function signStatusListVcAsJwt(unsignedVc, kid) {
  const agent = await createAgentInstance();
  // Depending on your Veramo setup, keyRef might need to be a KMS key ID.
  // Ensure the JOSE header kid matches the DID's verification method and alg ES256K.
  const res = await agent.createVerifiableCredential({
    credential: unsignedVc,
    proofFormat: 'jwt',
    keyRef: kid,
    removeOriginalFields: false,
  });
  const jwt = typeof res === 'string'
    ? res
    : (typeof res.verifiableCredential === 'string' ? res.verifiableCredential : res);
  if (typeof jwt !== 'string') return res; // already an object
  return { ...unsignedVc, proof: { type: 'JwtProof2020', jwt } };
}

module.exports = { signStatusListVcAsJwt };

