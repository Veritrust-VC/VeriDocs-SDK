const { SecretBox } = require('@veramo/kms-local');
const { AbstractKeyStore } = require('@veramo/key-manager');

class CustomPrivateKeyStore extends AbstractKeyStore {
  constructor(db, secretKey) {
    super();
    console.debug('[DEBUG] CustomPrivateKeyStore secretKey:', secretKey);
    this.db = db;
    this.secretBox = new SecretBox(secretKey);
    this.hasMetaColumn = this.detectMetaColumn();
  }

  detectMetaColumn() {
    try {
      const columns = this.db.prepare('PRAGMA table_info("private-key")').all();
      return columns.some(column => column.name === 'meta');
    } catch (error) {
      console.warn('[WARN] Failed to inspect private-key table for meta column:', error);
      return false;
    }
  }

  async importKey(args) {
    console.debug('[DEBUG] CustomPrivateKeyStore.importKey args:', args);
    const { alias, type, privateKeyHex } = args;
    const encrypted = await this.secretBox.encrypt(privateKeyHex);
    if (this.hasMetaColumn) {
      this.db
        .prepare(
          'INSERT OR REPLACE INTO "private-key" (alias, type, privateKeyHex, meta) VALUES (?, ?, ?, ?)' 
        )
        .run(alias, type, encrypted, JSON.stringify(args.meta || {}));
    } else {
      this.db
        .prepare('INSERT OR REPLACE INTO "private-key" (alias, type, privateKeyHex) VALUES (?, ?, ?)')
        .run(alias, type, encrypted);
    }
    return args;
  }

  async getKey({ alias }) {
    console.debug('[DEBUG] CustomPrivateKeyStore.getKey alias:', alias);
    const row = this.db.prepare('SELECT * FROM "private-key" WHERE alias = ?').get(alias);
    if (!row) throw new Error('key_not_found');
    const privateKeyHex = await this.secretBox.decrypt(row.privateKeyHex);
    return {
      alias: row.alias,
      type: row.type,
      privateKeyHex,
      meta: row.meta ? JSON.parse(row.meta) : undefined,
    };
  }

  async deleteKey({ alias }) {
    console.debug('[DEBUG] CustomPrivateKeyStore.deleteKey alias:', alias);
    const { changes } = this.db.prepare('DELETE FROM "private-key" WHERE alias = ?').run(alias);
    return changes > 0;
  }

  async listKeys() {
    console.debug('[DEBUG] CustomPrivateKeyStore.listKeys');
    const rows = this.db.prepare('SELECT * FROM "private-key"').all();
    return Promise.all(
      rows.map(async row => ({
        alias: row.alias,
        type: row.type,
        privateKeyHex: await this.secretBox.decrypt(row.privateKeyHex),
        meta: row.meta ? JSON.parse(row.meta) : undefined,
      }))
    );
  }
}

module.exports = { CustomPrivateKeyStore };
