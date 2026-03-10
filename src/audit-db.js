const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');
const { nowIso } = require('./trace');

const DEFAULT_DB_FILE = '/app/status-data/sdk_audit.db';
const AUDIT_DB_FILE = process.env.SDK_AUDIT_DB_FILE || DEFAULT_DB_FILE;

let db;

function getDb() {
  if (!db) {
    fs.mkdirSync(path.dirname(AUDIT_DB_FILE), { recursive: true });
    db = new Database(AUDIT_DB_FILE);
    db.pragma('journal_mode = WAL');
  }

  return db;
}

function initAuditDb() {
  const conn = getDb();
  conn.exec(`
    CREATE TABLE IF NOT EXISTS sync_audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      created_at TEXT NOT NULL,
      trace_id TEXT,
      source_system TEXT NOT NULL,
      source_org_code TEXT,
      source_org_did TEXT,
      actor_type TEXT,
      actor_id TEXT,
      action TEXT NOT NULL,
      target_system TEXT NOT NULL,
      target_url TEXT,
      http_method TEXT,
      request_path TEXT,
      request_payload_summary TEXT,
      request_payload_json TEXT,
      response_status INTEGER,
      response_body_summary TEXT,
      response_body_json TEXT,
      success INTEGER NOT NULL DEFAULT 0,
      error_message TEXT,
      duration_ms INTEGER,
      local_entity_type TEXT,
      local_entity_id TEXT,
      local_entity_did TEXT,
      remote_entity_type TEXT,
      remote_entity_id TEXT,
      remote_entity_did TEXT
    );

    CREATE TABLE IF NOT EXISTS sync_state (
      key TEXT PRIMARY KEY,
      value TEXT,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS registry_auth_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      created_at TEXT NOT NULL,
      trace_id TEXT,
      registry_url TEXT,
      username TEXT,
      success INTEGER NOT NULL DEFAULT 0,
      response_status INTEGER,
      error_message TEXT
    );
  `);
}

function safeStringify(value) {
  if (value === undefined || value === null) return null;
  try {
    return JSON.stringify(value);
  } catch (_err) {
    return JSON.stringify({ note: 'non-serializable payload' });
  }
}

function writeSyncLog(entry = {}) {
  const conn = getDb();
  const stmt = conn.prepare(`
    INSERT INTO sync_audit_log (
      created_at, trace_id, source_system, source_org_code, source_org_did,
      actor_type, actor_id, action, target_system, target_url,
      http_method, request_path, request_payload_summary, request_payload_json,
      response_status, response_body_summary, response_body_json, success,
      error_message, duration_ms, local_entity_type, local_entity_id,
      local_entity_did, remote_entity_type, remote_entity_id, remote_entity_did
    ) VALUES (
      @created_at, @trace_id, @source_system, @source_org_code, @source_org_did,
      @actor_type, @actor_id, @action, @target_system, @target_url,
      @http_method, @request_path, @request_payload_summary, @request_payload_json,
      @response_status, @response_body_summary, @response_body_json, @success,
      @error_message, @duration_ms, @local_entity_type, @local_entity_id,
      @local_entity_did, @remote_entity_type, @remote_entity_id, @remote_entity_did
    )
  `);

  const payload = {
    created_at: entry.created_at || nowIso(),
    trace_id: entry.trace_id || null,
    source_system: entry.source_system || 'veridocs-sdk',
    source_org_code: entry.source_org_code || null,
    source_org_did: entry.source_org_did || null,
    actor_type: entry.actor_type || null,
    actor_id: entry.actor_id || null,
    action: entry.action || 'sdk.unknown',
    target_system: entry.target_system || 'register',
    target_url: entry.target_url || null,
    http_method: entry.http_method || null,
    request_path: entry.request_path || null,
    request_payload_summary: entry.request_payload_summary || null,
    request_payload_json: typeof entry.request_payload_json === 'string' ? entry.request_payload_json : safeStringify(entry.request_payload_json),
    response_status: Number.isInteger(entry.response_status) ? entry.response_status : null,
    response_body_summary: entry.response_body_summary || null,
    response_body_json: typeof entry.response_body_json === 'string' ? entry.response_body_json : safeStringify(entry.response_body_json),
    success: entry.success ? 1 : 0,
    error_message: entry.error_message || null,
    duration_ms: Number.isInteger(entry.duration_ms) ? entry.duration_ms : null,
    local_entity_type: entry.local_entity_type || null,
    local_entity_id: entry.local_entity_id || null,
    local_entity_did: entry.local_entity_did || null,
    remote_entity_type: entry.remote_entity_type || null,
    remote_entity_id: entry.remote_entity_id || null,
    remote_entity_did: entry.remote_entity_did || null,
  };

  const info = stmt.run(payload);
  return info.lastInsertRowid;
}

function writeRegistryAuthLog(entry = {}) {
  const conn = getDb();
  const stmt = conn.prepare(`
    INSERT INTO registry_auth_log (
      created_at, trace_id, registry_url, username, success, response_status, error_message
    ) VALUES (
      @created_at, @trace_id, @registry_url, @username, @success, @response_status, @error_message
    )
  `);

  const info = stmt.run({
    created_at: entry.created_at || nowIso(),
    trace_id: entry.trace_id || null,
    registry_url: entry.registry_url || null,
    username: entry.username || null,
    success: entry.success ? 1 : 0,
    response_status: Number.isInteger(entry.response_status) ? entry.response_status : null,
    error_message: entry.error_message || null,
  });

  return info.lastInsertRowid;
}

function listSyncLogs({ limit = 100, offset = 0, action, success, trace_id } = {}) {
  const conn = getDb();
  const conditions = [];
  const params = {};

  if (action) {
    conditions.push('action = @action');
    params.action = action;
  }

  if (success !== undefined && success !== null && success !== '') {
    conditions.push('success = @success');
    params.success = Number(success) ? 1 : 0;
  }

  if (trace_id) {
    conditions.push('trace_id = @trace_id');
    params.trace_id = trace_id;
  }

  const whereClause = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
  const sql = `
    SELECT * FROM sync_audit_log
    ${whereClause}
    ORDER BY id DESC
    LIMIT @limit OFFSET @offset
  `;

  return conn.prepare(sql).all({
    ...params,
    limit: Number(limit) > 0 ? Number(limit) : 100,
    offset: Number(offset) >= 0 ? Number(offset) : 0,
  });
}

function getSyncLog(id) {
  const conn = getDb();
  return conn.prepare('SELECT * FROM sync_audit_log WHERE id = ?').get(id);
}

function setSyncState(key, value) {
  const conn = getDb();
  conn.prepare(`
    INSERT INTO sync_state (key, value, updated_at)
    VALUES (@key, @value, @updated_at)
    ON CONFLICT(key) DO UPDATE SET
      value = excluded.value,
      updated_at = excluded.updated_at
  `).run({ key, value: value == null ? null : String(value), updated_at: nowIso() });
}

function getSyncState(key) {
  const conn = getDb();
  return conn.prepare('SELECT key, value, updated_at FROM sync_state WHERE key = ?').get(key) || null;
}

module.exports = {
  initAuditDb,
  writeSyncLog,
  writeRegistryAuthLog,
  listSyncLogs,
  getSyncLog,
  setSyncState,
  getSyncState,
};
