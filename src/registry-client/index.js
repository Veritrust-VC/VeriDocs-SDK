/**
 * Registry Client — HTTP client for the VeriDocs Register API.
 * Used by the SDK to register orgs/docs and submit lifecycle VCs.
 */

const http = require('http');
const https = require('https');
const { URL } = require('url');

class RegistryClient {
  constructor(baseUrl, apiKey) {
    this.baseUrl = (baseUrl || 'http://localhost:8001').replace(/\/+$/, '');
    this.apiKey = apiKey || '';
  }

  async _request(method, path, body) {
    const url = new URL(path, this.baseUrl);
    const isHttps = url.protocol === 'https:';
    const lib = isHttps ? https : http;

    const headers = { 'Content-Type': 'application/json' };
    if (this.apiKey) headers['x-api-key'] = this.apiKey;

    const payload = body ? JSON.stringify(body) : undefined;
    if (payload) headers['Content-Length'] = Buffer.byteLength(payload);

    return new Promise((resolve, reject) => {
      const req = lib.request(url, { method, headers }, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          try {
            const parsed = JSON.parse(data);
            if (res.statusCode >= 400) {
              const err = new Error(parsed.detail || parsed.error || `HTTP ${res.statusCode}`);
              err.statusCode = res.statusCode;
              err.body = parsed;
              reject(err);
            } else {
              resolve(parsed);
            }
          } catch (e) {
            if (res.statusCode >= 400) reject(new Error(`HTTP ${res.statusCode}: ${data}`));
            else resolve(data);
          }
        });
      });
      req.on('error', reject);
      req.setTimeout(30000, () => { req.destroy(); reject(new Error('Request timeout')); });
      if (payload) req.write(payload);
      req.end();
    });
  }

  // ── Organizations ──

  async registerOrganization(didDocument, publicKey, name, description) {
    return this._request('POST', '/api/v1/orgs', {
      did_document: didDocument,
      public_key: publicKey,
      name, description,
    });
  }

  async resolveOrganization(did) {
    return this._request('GET', `/api/v1/orgs/${encodeURIComponent(did)}`);
  }

  // ── Documents ──

  async registerDocument(did, issuerDid, metadata) {
    return this._request('POST', '/api/v1/docs', {
      did, issuer: issuerDid, metadata: metadata || {},
    });
  }

  async resolveDocument(did) {
    return this._request('GET', `/api/v1/docs/${encodeURIComponent(did)}`);
  }

  async trackDocument(did) {
    return this._request('GET', `/api/v1/docs/${encodeURIComponent(did)}/status`);
  }

  // ── Events ──

  async submitEvent(vc) {
    return this._request('POST', '/api/v1/events', vc);
  }

  // ── Health ──

  async health() {
    return this._request('GET', '/api/v1/health');
  }
}

module.exports = { RegistryClient };
