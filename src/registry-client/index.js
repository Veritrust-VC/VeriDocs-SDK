/**
 * Registry Client — HTTP client for the VeriDocs Register API.
 * Used by the SDK to register orgs/docs and submit lifecycle VCs.
 */

let registryToken = null;
let registryTokenObtainedAt = null;

function getRegistryCredentials() {
  const email = process.env.REGISTRY_EMAIL;
  const password = process.env.REGISTRY_PASSWORD;

  if (!email || !password) {
    throw new Error('Registry credentials are not configured');
  }

  return { email, password };
}

class RegistryClient {
  constructor(baseUrl, apiKey) {
    this.baseUrl = (baseUrl || 'http://localhost:8001').replace(/\/+$/, '');
    this.apiKey = apiKey || '';
  }

  async loginToRegistry() {
    const { email, password } = getRegistryCredentials();
    const url = `${this.baseUrl}/api/v1/auth/login`;

    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });

    const responseText = await response.text();
    if (!response.ok) {
      throw new Error(`Registry login failed: ${response.status} ${responseText}`);
    }

    let payload;
    try {
      payload = responseText ? JSON.parse(responseText) : {};
    } catch (err) {
      throw new Error(`Registry login failed: invalid JSON response (${err.message})`);
    }

    if (!payload.access_token) {
      throw new Error('Registry login failed: access_token missing in response');
    }

    registryToken = payload.access_token;
    registryTokenObtainedAt = new Date().toISOString();

    return registryToken;
  }

  async getRegistryToken(forceRefresh = false) {
    if (!forceRefresh && registryToken) {
      return registryToken;
    }

    return this.loginToRegistry();
  }

  async registryFetch(path, options = {}, retry = true) {
    const token = await this.getRegistryToken();
    const url = `${this.baseUrl}${path}`;

    const headers = {
      ...(options.headers || {}),
      Authorization: `Bearer ${token}`,
    };

    if (this.apiKey) {
      headers['x-api-key'] = this.apiKey;
    }

    const hasBody = options.body !== undefined && options.body !== null;
    if (hasBody && !headers['Content-Type']) {
      headers['Content-Type'] = 'application/json';
    }

    const response = await fetch(url, {
      ...options,
      headers,
    });

    if (response.status === 401 && retry) {
      const freshToken = await this.getRegistryToken(true);
      headers.Authorization = `Bearer ${freshToken}`;
      return fetch(url, {
        ...options,
        headers,
      });
    }

    return response;
  }

  async _publicFetch(path, options = {}) {
    const headers = { ...(options.headers || {}) };
    if (this.apiKey) {
      headers['x-api-key'] = this.apiKey;
    }

    return fetch(`${this.baseUrl}${path}`, {
      ...options,
      headers,
    });
  }

  async _parseResponse(response, operationName) {
    const bodyText = await response.text();
    let parsedBody;

    try {
      parsedBody = bodyText ? JSON.parse(bodyText) : {};
    } catch (err) {
      parsedBody = bodyText;
    }

    if (!response.ok) {
      const bodyForError = typeof parsedBody === 'string' ? parsedBody : JSON.stringify(parsedBody);
      throw new Error(`${operationName} failed: ${response.status} ${bodyForError}`);
    }

    return parsedBody;
  }

  async testAuth() {
    try {
      await this.getRegistryToken(true);
      return {
        auth_configured: true,
        authenticated: true,
        error: null,
      };
    } catch (error) {
      const authConfigured = !!(process.env.REGISTRY_EMAIL && process.env.REGISTRY_PASSWORD);
      return {
        auth_configured: authConfigured,
        authenticated: false,
        error: error.message,
      };
    }
  }

  // ── Organizations ──

  async registerOrganization(didDocument, publicKey, name, description) {
    const response = await this.registryFetch('/api/v1/orgs', {
      method: 'POST',
      body: JSON.stringify({
        did_document: didDocument,
        public_key: publicKey,
        name,
        description,
      }),
    });

    return this._parseResponse(response, 'Registry organization registration');
  }

  async resolveOrganization(did) {
    const response = await this._publicFetch(`/api/v1/orgs/${encodeURIComponent(did)}`);
    return this._parseResponse(response, 'Registry organization resolve');
  }

  // ── Documents ──

  async registerDocument(did, issuerDid, metadata) {
    const response = await this.registryFetch('/api/v1/docs', {
      method: 'POST',
      body: JSON.stringify({
        did,
        issuer: issuerDid,
        metadata: metadata || {},
      }),
    });

    return this._parseResponse(response, 'Registry document registration');
  }

  async resolveDocument(did) {
    const response = await this._publicFetch(`/api/v1/docs/${encodeURIComponent(did)}`);
    return this._parseResponse(response, 'Registry document resolve');
  }

  async trackDocument(did) {
    const response = await this._publicFetch(`/api/v1/docs/${encodeURIComponent(did)}/status`);
    return this._parseResponse(response, 'Registry document tracking');
  }

  // ── Events ──

  async submitEvent(vc) {
    const response = await this.registryFetch('/api/v1/events', {
      method: 'POST',
      body: JSON.stringify(vc),
    });

    return this._parseResponse(response, 'Registry event submission');
  }

  // ── Health ──

  async health() {
    const response = await this._publicFetch('/api/v1/health');
    return this._parseResponse(response, 'Registry health check');
  }

  getCachedTokenMetadata() {
    return {
      registry_token_cached: !!registryToken,
      registry_token_obtained_at: registryTokenObtainedAt,
    };
  }
}

module.exports = { RegistryClient };
