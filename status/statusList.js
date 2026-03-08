const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const FILE_BITS = 'bits.bin';
const FILE_META = 'meta.json';
const FILE_VC   = 'status_vc.json';
const FILE_LOCK = '.lock';

function ensureDir(p) { fs.mkdirSync(p, { recursive: true }); }
function lockFile(p) { fs.writeFileSync(path.join(p, FILE_LOCK), String(process.pid)); }
function unlockFile(p) { try { fs.unlinkSync(path.join(p, FILE_LOCK)); } catch {} }

function ensureBits(dir, minBytes) {
  const bitsPath = path.join(dir, FILE_BITS);
  if (!fs.existsSync(bitsPath)) {
    fs.writeFileSync(bitsPath, Buffer.alloc(minBytes, 0));
    return;
  }
  const stat = fs.statSync(bitsPath);
  if (stat.size < minBytes) {
    const bigger = Buffer.alloc(minBytes, 0);
    const existing = fs.readFileSync(bitsPath);
    existing.copy(bigger);
    fs.writeFileSync(bitsPath, bigger);
  }
}

function readBits(dir) { return fs.readFileSync(path.join(dir, FILE_BITS)); }
function writeBits(dir, buf) {
  const tmp = path.join(dir, FILE_BITS + '.tmp');
  fs.writeFileSync(tmp, buf);
  fs.renameSync(tmp, path.join(dir, FILE_BITS));
}

function setBit(buf, index, value) {
  const byte = index >> 3, mask = 1 << (index & 7);
  if (value) buf[byte] |= mask; else buf[byte] &= ~mask;
}
function getBit(buf, index) {
  const byte = index >> 3, mask = 1 << (index & 7);
  return (buf[byte] & mask) !== 0 ? 1 : 0;
}

function b64url(buf) { return Buffer.from(buf).toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''); }
function encodeGzipB64url(buf) { return b64url(zlib.gzipSync(buf)); }

function initStore({ root, url, issuerDid, purpose = 'revocation', initialBytes = 16384 }) {
  ensureDir(root);
  const metaPath = path.join(root, FILE_META);
  if (!fs.existsSync(metaPath)) {
    fs.writeFileSync(metaPath, JSON.stringify({
      statusPurpose: purpose,
      size: initialBytes,
      issuerDid,
      url,
      updatedAt: new Date().toISOString()
    }, null, 2));
  }
  const meta = JSON.parse(fs.readFileSync(metaPath, 'utf-8'));
  ensureBits(root, meta.size);
  return meta;
}

function buildUnsignedStatusVc(encodedList, { url, issuerDid, purpose }) {
  return {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    "type": ["VerifiableCredential","StatusList2021Credential"],
    "issuer": issuerDid,
    "validFrom": new Date().toISOString(),
    "id": url,
    "credentialSubject": {
      "id": url + "#list",
      "type": "StatusList2021",
      "statusPurpose": purpose,
      "encodedList": encodedList
    }
  };
}

function atomicWriteJson(dir, name, obj) {
  const tmp = path.join(dir, name + '.tmp');
  fs.writeFileSync(tmp, JSON.stringify(obj, null, 2));
  fs.renameSync(tmp, path.join(dir, name));
}

function findFreeIndex(buf) {
  for (let i = 0; i < buf.length * 8; i++) {
    if (getBit(buf, i) === 0) return i;
  }
  throw new Error('Status list full; increase bits.bin size.');
}

function allocateIndexAndPersist(cfg) {
  lockFile(cfg.root);
  try {
    const meta = initStore(cfg);
    const bits = readBits(cfg.root);
    const index = findFreeIndex(bits);
    // Keep bit = 0 (GOOD) for new issuance.
    const encoded = encodeGzipB64url(bits);
    const unsigned = buildUnsignedStatusVc(encoded, { url: cfg.url, issuerDid: cfg.issuerDid, purpose: cfg.purpose });
    atomicWriteJson(cfg.root, FILE_VC, unsigned);
    return index;
  } finally {
    unlockFile(cfg.root);
  }
}

function setRevokedAndPersist(cfg, index, revoked) {
  lockFile(cfg.root);
  try {
    initStore(cfg);
    const bits = readBits(cfg.root);
    const needed = Math.floor(index / 8) + 1;
    const buf = bits.length < needed ? Buffer.concat([bits, Buffer.alloc(needed - bits.length)]) : bits;
    setBit(buf, index, revoked ? 1 : 0);
    writeBits(cfg.root, buf);
    const encoded = encodeGzipB64url(buf);
    const unsigned = buildUnsignedStatusVc(encoded, { url: cfg.url, issuerDid: cfg.issuerDid, purpose: cfg.purpose });
    atomicWriteJson(cfg.root, FILE_VC, unsigned);
  } finally {
    unlockFile(cfg.root);
  }
}

module.exports = {
  allocateIndexAndPersist,
  setRevokedAndPersist,
  encodeGzipB64url,
};

