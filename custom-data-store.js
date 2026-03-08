const { AbstractKeyStore } = require('@veramo/key-manager');
const { AbstractDIDStore } = require('@veramo/did-manager');

class CustomKeyStore extends AbstractKeyStore {
  constructor(db) {
    super();
    this.db = db;
    this.keyTableHasPrivateKeyColumn = this.detectPrivateKeyColumn();
  }

  detectPrivateKeyColumn() {
    try {
      const columns = this.db.prepare('PRAGMA table_info("key")').all();
      return columns.some(column => column.name === 'privateKeyHex');
    } catch (error) {
      console.warn('[WARN] Failed to inspect key table for privateKeyHex column:', error);
      return false;
    }
  }

  async importKey(args) {
    console.debug('[DEBUG] CustomKeyStore.importKey args:', args);
    const { kid, type, publicKeyHex, meta, kms } = args;
    const identifierDid =
      args.identifierDid || (meta && meta.identifierDid) || null;
    if (!kid) {
      throw new Error('Missing kid for key import');
    }
    let resolvedIdentifierDid = identifierDid;
    if (resolvedIdentifierDid) {
      const identifierExists = this.db
        .prepare('SELECT did FROM identifier WHERE did = ?')
        .get(resolvedIdentifierDid);
      if (!identifierExists) {
        console.debug(
          `[DEBUG] Identifier ${resolvedIdentifierDid} not yet present when importing key ${kid}, deferring association.`
        );
        resolvedIdentifierDid = null;
      }
    }
    const columns = ['kid', 'kms', 'type', 'publicKeyHex', 'meta', 'identifierDid'];
    const values = [
      kid,
      kms || 'local',
      type,
      publicKeyHex,
      JSON.stringify(meta || {}),
      resolvedIdentifierDid,
    ];
    if (this.keyTableHasPrivateKeyColumn) {
      columns.push('privateKeyHex');
      values.push(args.privateKeyHex || null);
    }

    const placeholders = columns.map(() => '?').join(', ');
    this.db
      .prepare(`INSERT OR REPLACE INTO key (${columns.join(', ')}) VALUES (${placeholders})`)
      .run(...values);
    return { ...args, identifierDid: resolvedIdentifierDid };
  }

  async getKey({ kid }) {
    const row = this.db.prepare('SELECT * FROM key WHERE kid = ?').get(kid);
    if (!row) throw new Error('key_not_found');
    return {
      kid: row.kid,
      kms: row.kms,
      type: row.type,
      publicKeyHex: row.publicKeyHex,
      meta: row.meta ? JSON.parse(row.meta) : undefined,
      identifierDid: row.identifierDid,
      privateKeyHex: row.privateKeyHex,
    };
  }

  async deleteKey({ kid }) {
    const { changes } = this.db.prepare('DELETE FROM key WHERE kid = ?').run(kid);
    return changes > 0;
  }

  async listKeys() {
    const rows = this.db.prepare('SELECT * FROM key').all();
    return rows.map(row => ({
      kid: row.kid,
      kms: row.kms,
      type: row.type,
      publicKeyHex: row.publicKeyHex,
      meta: row.meta ? JSON.parse(row.meta) : undefined,
      identifierDid: row.identifierDid,
      privateKeyHex: row.privateKeyHex,
    }));
  }
}

class CustomDIDStore extends AbstractDIDStore {
  constructor(db) {
    super();
    this.db = db;
  }

  mapIdentifierRow(row) {
    const identifier = {
      did: row.did,
      provider: row.provider,
      controllerKeyId: row.controllerKeyId,
      keys: this.db
        .prepare('SELECT * FROM key WHERE identifierDid = ?')
        .all(row.did)
        .map(keyRow => ({
          kid: keyRow.kid,
          kms: keyRow.kms,
          type: keyRow.type,
          publicKeyHex: keyRow.publicKeyHex,
          meta: keyRow.meta ? JSON.parse(keyRow.meta) : undefined,
        })),
      services: this.db
        .prepare('SELECT * FROM service WHERE identifierDid = ?')
        .all(row.did)
        .map(serviceRow => ({
          id: serviceRow.id,
          type: serviceRow.type,
          serviceEndpoint: this.parseServiceEndpoint(serviceRow.serviceEndpoint),
          description: serviceRow.description || undefined,
        })),
    };

    if (row.alias) {
      identifier.alias = row.alias;
    }

    return identifier;
  }

  parseServiceEndpoint(value) {
    if (value == null) return value;
    try {
      return JSON.parse(value);
    } catch (err) {
      return value;
    }
  }

  async getDID({ did, alias }) {
    let row;
    if (did) {
      row = this.db.prepare('SELECT * FROM identifier WHERE did = ?').get(did);
    } else if (alias) {
      row = this.db.prepare('SELECT * FROM identifier WHERE alias = ?').get(alias);
    } else {
      throw new Error('identifier_not_found');
    }

    if (!row) throw new Error('identifier_not_found');
    return this.mapIdentifierRow(row);
  }

  async deleteDID({ did }) {
    const { changes } = this.db.prepare('DELETE FROM identifier WHERE did = ?').run(did);
    this.db.prepare('UPDATE key SET identifierDid = NULL WHERE identifierDid = ?').run(did);
    this.db.prepare('DELETE FROM service WHERE identifierDid = ?').run(did);
    return changes > 0;
  }

  async importDID(args) {
    console.debug('[DEBUG] CustomDIDStore.import args:', args);
    const { did, provider, alias, controllerKeyId } = args;
    this.db.prepare(`
      INSERT OR REPLACE INTO identifier (did, provider, alias, controllerKeyId, saveDate, updateDate)
      VALUES (?, ?, ?, ?, datetime('now'), datetime('now'))
    `).run(did, provider, alias, controllerKeyId);

    if (Array.isArray(args.keys)) {
      for (const key of args.keys) {
        if (!key || !key.kid) continue;
        const targetDid = key.identifierDid || did || key.meta?.identifierDid;
        if (!targetDid) continue;
        this.db
          .prepare('UPDATE key SET identifierDid = ? WHERE kid = ?')
          .run(targetDid, key.kid);
      }
    }
    return true;
  }

  async listDIDs(args = {}) {
    const conditions = [];
    const params = [];
    if (args.provider) {
      conditions.push('provider = ?');
      params.push(args.provider);
    }
    if (args.alias) {
      conditions.push('alias = ?');
      params.push(args.alias);
    }
    let query = 'SELECT * FROM identifier';
    if (conditions.length > 0) {
      query += ` WHERE ${conditions.join(' AND ')}`;
    }
    const rows = this.db.prepare(query).all(...params);
    return rows.map(row => this.mapIdentifierRow(row));
  }
}

module.exports = { CustomKeyStore, CustomDIDStore };
