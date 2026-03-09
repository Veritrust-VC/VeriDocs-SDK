const fs = require('fs');
const path = require('path');

const STATE_FILE = process.env.SDK_STATE_FILE || path.join(process.cwd(), 'data', 'sdk-state.json');

const DEFAULT_STATE = {
  activeOrgDid: null,
  lastSetup: null,
};

function ensureStateDir() {
  fs.mkdirSync(path.dirname(STATE_FILE), { recursive: true });
}

function loadState() {
  ensureStateDir();
  if (!fs.existsSync(STATE_FILE)) {
    return { ...DEFAULT_STATE };
  }

  try {
    const raw = fs.readFileSync(STATE_FILE, 'utf8');
    const parsed = JSON.parse(raw || '{}');
    return {
      activeOrgDid: parsed.activeOrgDid || null,
      lastSetup: parsed.lastSetup || null,
    };
  } catch (err) {
    return { ...DEFAULT_STATE };
  }
}

function saveState(state) {
  ensureStateDir();
  const merged = {
    ...DEFAULT_STATE,
    ...(state || {}),
  };
  fs.writeFileSync(STATE_FILE, JSON.stringify(merged, null, 2));
  return merged;
}

function getActiveOrgDid() {
  return loadState().activeOrgDid;
}

function setActiveOrgDid(did) {
  const state = loadState();
  return saveState({ ...state, activeOrgDid: did || null });
}

function getLastSetup() {
  return loadState().lastSetup;
}

function setLastSetup(obj) {
  const state = loadState();
  return saveState({ ...state, lastSetup: obj || null });
}

module.exports = {
  loadState,
  saveState,
  getActiveOrgDid,
  setActiveOrgDid,
  getLastSetup,
  setLastSetup,
};
