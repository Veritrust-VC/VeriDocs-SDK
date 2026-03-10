/**
 * Registry Client — HTTP client for the VeriDocs Register API.
 */

const { writeSyncLog, writeRegistryAuthLog } = require('../audit-db');

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

function summarizePayload(payload) {
  if (payload == null) return null;
  if (typeof payload === 'string') return payload.slice(0, 300);
  if (Array.isArray(payload)) return `array(${payload.length})`;
  if (typeof payload === 'object') return `keys:${Object.keys(payload).slice(0, 10).join(',')}`;
  return String(payload);
}

function parseMaybeJson(text) {
  if (!text) return {};
  try {
    return JSON.parse(text);
  } catch (_err) {
    return text;
  }
}

class RegistryClient {
  constructor(baseUrl, apiKey) {
    this.baseUrl = (baseUrl || 'http://localhost:8001').replace(/\/+$/, '');
    this.apiKey = apiKey || '';
  }

  async loginToRegistry(traceId) {
    const { email, password } = getRegistryCredentials();
    const url = `${this.baseUrl}/api/v1/auth/login`;

    let responseStatus = null;
    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });

      responseStatus = response.status;
      const responseText = await response.text();
      const data = parseMaybeJson(responseText);

      if (!response.ok) {
        writeRegistryAuthLog({
          trace_id: traceId,
          registry_url: this.baseUrl,
          username: email,
          success: false,
          response_status: response.status,
          error_message: `Registry login failed: ${response.status}`,
        });
        throw new Error(`Registry login failed: ${response.status} ${responseText}`);
      }

      const token = data.access_token || data.token || null;
      if (!token) {
        writeRegistryAuthLog({
          trace_id: traceId,
          registry_url: this.baseUrl,
          username: email,
          success: false,
          response_status: response.status,
          error_message: 'Registry login failed: token missing in response',
        });
        throw new Error('Registry login failed: token missing in response');
      }

      registryToken = token;
      registryTokenObtainedAt = new Date().toISOString();

      writeRegistryAuthLog({
        trace_id: traceId,
        registry_url: this.baseUrl,
        username: email,
        success: true,
        response_status: response.status,
      });

      return { token, user: data.user || null };
    } catch (error) {
      if (responseStatus == null) {
        writeRegistryAuthLog({
          trace_id: traceId,
          registry_url: this.baseUrl,
          username: process.env.REGISTRY_EMAIL || null,
          success: false,
          response_status: null,
          error_message: error.message,
        });
      }
      throw error;
    }
  }

  async getRegistryToken(forceRefresh = false, traceId) {
    if (!forceRefresh && registryToken) {
      return { token: registryToken, user: null };
    }
    return this.loginToRegistry(traceId);
  }

  async registryFetch(path, options = {}, meta = {}) {
    const startedAt = Date.now();
    const traceId = meta.traceId || null;
    const method = options.method || 'GET';
    const url = `${this.baseUrl}${path}`;

    let auth = await this.getRegistryToken(false, traceId);
    const headers = {
      ...(options.headers || {}),
      Authorization: `Bearer ${auth.token || auth}`,
    };

    if (this.apiKey) headers['x-api-key'] = this.apiKey;

    const hasBody = options.body !== undefined && options.body !== null;
    if (hasBody && !headers['Content-Type']) headers['Content-Type'] = 'application/json';

    let response;
    let responseText = '';
    let parsedBody;
    let errorMessage = null;

    try {
      response = await fetch(url, { ...options, headers });
      if (response.status === 401) {
        auth = await this.getRegistryToken(true, traceId);
        headers.Authorization = `Bearer ${auth.token || auth}`;
        response = await fetch(url, { ...options, headers });
      }
      responseText = await response.text();
      parsedBody = parseMaybeJson(responseText);
      if (!response.ok) {
        const bodyForError = typeof parsedBody === 'string' ? parsedBody : JSON.stringify(parsedBody);
        throw new Error(`HTTP ${response.status} ${bodyForError}`);
      }
      return parsedBody;
    } catch (error) {
      errorMessage = error.message;
      throw error;
    } finally {
      writeSyncLog({
        trace_id: traceId,
        source_system: 'veridocs-sdk',
        source_org_code: meta.sourceOrgCode || null,
        source_org_did: meta.sourceOrgDid || null,
        actor_type: meta.actorType || null,
        actor_id: meta.actorId || null,
        action: meta.action || 'sdk.registry.call',
        target_system: 'register',
        target_url: url,
        http_method: method,
        request_path: path,
        request_payload_summary: summarizePayload(options.body ? parseMaybeJson(options.body) : null),
        request_payload_json: options.body ? parseMaybeJson(options.body) : null,
        response_status: response ? response.status : null,
        response_body_summary: summarizePayload(parsedBody),
        response_body_json: parsedBody || null,
        success: !!(response && response.ok && !errorMessage),
        error_message: errorMessage,
        duration_ms: Date.now() - startedAt,
        local_entity_type: meta.localEntityType || null,
        local_entity_id: meta.localEntityId || null,
        local_entity_did: meta.localEntityDid || null,
        remote_entity_type: meta.remoteEntityType || null,
        remote_entity_id: meta.remoteEntityId || null,
        remote_entity_did: meta.remoteEntityDid || null,
      });
    }
  }

  async testAuth(traceId) {
    try {
      await this.getRegistryToken(true, traceId);
      return { auth_configured: true, authenticated: true, error: null };
    } catch (error) {
      const authConfigured = !!(process.env.REGISTRY_EMAIL && process.env.REGISTRY_PASSWORD);
      return { auth_configured: authConfigured, authenticated: false, error: error.message };
    }
  }

  async registerOrganization(didDocument, publicKey, name, description, meta = {}) {
    return this.registryFetch('/api/v1/orgs', {
      method: 'POST',
      body: JSON.stringify({ did_document: didDocument, public_key: publicKey, name, description }),
    }, { ...meta, action: meta.action || 'sdk.org.register_remote', remoteEntityType: 'organization' });
  }

  async resolveOrganization(did, meta = {}) {
    return this.registryFetch(`/api/v1/orgs/${encodeURIComponent(did)}`, { method: 'GET' }, {
      ...meta,
      action: meta.action || 'sdk.org.verify_remote',
      remoteEntityType: 'organization',
      remoteEntityDid: did,
    });
  }

  async registerDocument(did, issuerDid, metadata, meta = {}) {
    return this.registryFetch('/api/v1/docs', {
      method: 'POST',
      body: JSON.stringify({ did, issuer: issuerDid, metadata: metadata || {} }),
    }, {
      ...meta,
      action: meta.action || 'sdk.doc.register_remote',
      localEntityType: 'document',
      localEntityDid: did,
      remoteEntityType: 'document',
      remoteEntityDid: did,
    });
  }

  async resolveDocument(did, meta = {}) {
    return this.registryFetch(`/api/v1/docs/${encodeURIComponent(did)}`, { method: 'GET' }, {
      ...meta,
      action: meta.action || 'sdk.doc.verify_remote',
      remoteEntityType: 'document',
      remoteEntityDid: did,
    });
  }

  async trackDocument(did, meta = {}) {
    return this.registryFetch(`/api/v1/docs/${encodeURIComponent(did)}/status`, { method: 'GET' }, {
      ...meta,
      action: meta.action || 'sdk.doc.track_remote',
      remoteEntityType: 'document',
      remoteEntityDid: did,
    });
  }

  async submitEvent(vc, meta = {}) {
    return this.registryFetch('/api/v1/events', {
      method: 'POST',
      body: JSON.stringify(vc),
    }, {
      ...meta,
      action: meta.action || 'sdk.event.submit_remote',
      remoteEntityType: 'event',
    });
  }

  async health(meta = {}) {
    return this.registryFetch('/api/v1/health', { method: 'GET' }, {
      ...meta,
      action: meta.action || 'sdk.registry.health',
    });
  }

  getCachedTokenMetadata() {
    return {
      registry_token_cached: !!registryToken,
      registry_token_obtained_at: registryTokenObtainedAt,
    };
  }
}

module.exports = { RegistryClient };
