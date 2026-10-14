#!/usr/bin/env node
/**
 * Re-sign existing lifecycle credentials after a DID move (e.g. a domain change).
 *
 *   node scripts/resign-credentials.js <old-domain> <new-domain> [out.json] < in.json   (stdout if no out.json)
 *
 * in.json:  [{ "ref": <any>, "vc": <credential as stored by the register> }, ...]
 * out.json: [{ "ref": <same>, "vc": <re-signed credential>, "issuer": <new issuer DID> }, ...]
 *
 * Every occurrence of the old domain in the credential (DIDs, context and status URLs)
 * is replaced; id, type, dates and all claims are kept. The proof is dropped and a new
 * one is made with the key this SDK holds for the new issuer DID. Nothing is logged
 * except a count on stderr.
 */
// stdout carries only the JSON result: everything the SDK logs goes to stderr.
for (const m of ['log', 'info', 'debug', 'warn']) console[m] = (...a) => process.stderr.write(a.map(String).join(' ') + '\n');
const { signCredential } = require('../src/vc-builder');

function readStdin() {
  return new Promise((resolve, reject) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (c) => { data += c; });
    process.stdin.on('end', () => resolve(data));
    process.stdin.on('error', reject);
  });
}

(async () => {
  const [oldDomain, newDomain, outFile] = process.argv.slice(2);
  if (!oldDomain || !newDomain) throw new Error('usage: resign-credentials.js <old-domain> <new-domain>');
  const items = JSON.parse(await readStdin());
  const out = [];
  for (const { ref, vc } of items) {
    const { proof, ...rest } = vc;
    const moved = JSON.parse(JSON.stringify(rest).split(oldDomain).join(newDomain));
    const issuer = typeof moved.issuer === 'string' ? moved.issuer : moved.issuer && moved.issuer.id;
    if (!issuer) throw new Error(`credential ${ref}: no issuer`);
    const credential = { ...moved, issuer };
    const signed = await signCredential(credential, issuer);
    out.push({ ref, vc: signed, issuer });
  }
  const fs = require('fs');
  const text = JSON.stringify(out);
  if (outFile) fs.writeFileSync(outFile, text);          // pipes through docker exec cut large output
  else { let off = 0; const buf = Buffer.from(text); while (off < buf.length) { try { off += fs.writeSync(1, buf, off); } catch (e) { if (e.code !== 'EAGAIN') throw e; } } }
  process.stderr.write(`re-signed ${out.length} credential(s)\n`);
  process.exit(0);
})().catch((e) => { process.stderr.write(`ERROR ${e.message}\n`); process.exit(1); });
