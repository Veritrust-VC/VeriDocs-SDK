const sqlite3 = require('sqlite3');

function getEnvironmentApiKeys() {
  const candidates = [
    process.env.VERAMO_API_KEY,
    process.env.ADMIN_API_KEY,
    process.env.MEDIATOR_ADMIN_API_KEY,
  ];

  const seen = new Set();
  const keys = [];

  for (const candidate of candidates) {
    const normalized = normalizeKey(candidate);
    if (normalized && !seen.has(normalized)) {
      seen.add(normalized);
      keys.push(normalized);
    }
  }

  return keys;
}

async function isApiKeyValid(key) {
  const normalizedKey = normalizeKey(key);
  if (!normalizedKey) return false;

  const envKeys = getEnvironmentApiKeys();
  if (envKeys.includes(normalizedKey)) {
    return true;
  }

  return await new Promise((resolve) => {
    const db = new sqlite3.Database('./database.sqlite');
    db.serialize(() => {
      db.run(`CREATE TABLE IF NOT EXISTS api_keys (
        name TEXT PRIMARY KEY,
        key TEXT NOT NULL,
        created_at INTEGER NOT NULL
      )`);
      db.get('SELECT 1 FROM api_keys WHERE key = ?', [normalizedKey], (err, row) => {
        db.close();
        resolve(!err && !!row);
      });
    });
  });
}

function firstValue(value) {
  if (Array.isArray(value)) {
    return firstValue(value[0]);
  }
  return value;
}

function normalizeKey(value) {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function extractApiKey(req) {
  const headerCandidates = ['x-api-key', 'x-user-api-key'];
  for (const name of headerCandidates) {
    const headerValue = normalizeKey(firstValue(req.header(name)));
    if (headerValue) {
      return headerValue;
    }
  }

  const authHeader = normalizeKey(firstValue(req.header('authorization')));
  if (authHeader) {
    const match = authHeader.match(/^Bearer\s+(.+)$/i);
    if (match) {
      const bearer = normalizeKey(match[1]);
      if (bearer) {
        return bearer;
      }
    }
  }

  const queryCandidates = ['x-api-key', 'x-user-api-key', 'apiKey', 'api_key'];
  for (const name of queryCandidates) {
    const queryValue = normalizeKey(firstValue(req.query?.[name]));
    if (queryValue) {
      return queryValue;
    }
  }

  return undefined;
}

async function requireApiKey(req, res, next) {
  if (process.env.DISABLE_API_KEY_AUTH === 'true') {
    return next();
  }
  const apiKey = extractApiKey(req);
  if (await isApiKeyValid(apiKey)) {
    return next();
  }
  return res.status(401).json({ error: 'unauthorized' });
}

function ensureAdminApiKey() {
  const adminKey = normalizeKey(process.env.ADMIN_API_KEY);
  if (!adminKey) {
    return Promise.resolve({ ensured: false, reason: 'missing' });
  }

  const adminName = normalizeKey(process.env.ADMIN_API_KEY_NAME) || 'admin';

  return new Promise((resolve, reject) => {
    const db = new sqlite3.Database('./database.sqlite');

    const finish = (err, result) => {
      db.close((closeErr) => {
        if (err) {
          return reject(err);
        }
        if (closeErr) {
          return reject(closeErr);
        }
        resolve(result);
      });
    };

    db.serialize(() => {
      db.run(`CREATE TABLE IF NOT EXISTS api_keys (
        name TEXT PRIMARY KEY,
        key TEXT NOT NULL,
        created_at INTEGER NOT NULL
      )`, (createErr) => {
        if (createErr) {
          return finish(createErr);
        }

        db.get('SELECT key FROM api_keys WHERE name = ?', [adminName], (selectErr, row) => {
          if (selectErr) {
            return finish(selectErr);
          }

          const createdAt = Math.floor(Date.now() / 1000);

          if (row) {
            if (normalizeKey(row.key) === adminKey) {
              return finish(null, { ensured: false, reason: 'unchanged', name: adminName });
            }

            db.run(
              'UPDATE api_keys SET key = ?, created_at = ? WHERE name = ?',
              [adminKey, createdAt, adminName],
              (updateErr) => {
                if (updateErr) {
                  return finish(updateErr);
                }
                finish(null, { ensured: true, reason: 'updated', name: adminName });
              }
            );
            return;
          }

          db.run(
            'INSERT INTO api_keys(name, key, created_at) VALUES (?, ?, ?)',
            [adminName, adminKey, createdAt],
            (insertErr) => {
              if (insertErr) {
                return finish(insertErr);
              }
              finish(null, { ensured: true, reason: 'created', name: adminName });
            }
          );
        });
      });
    });
  });
}

module.exports = { isApiKeyValid, requireApiKey, extractApiKey, ensureAdminApiKey, getEnvironmentApiKeys };
