const crypto = require('crypto');

function newTraceId() {
  return crypto.randomUUID();
}

function nowIso() {
  return new Date().toISOString();
}

module.exports = {
  newTraceId,
  nowIso,
};
