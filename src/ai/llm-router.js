const { RegistryClient } = require('../registry-client');

const AI_CENTRAL_LLM_URL = process.env.AI_CENTRAL_LLM_URL || '/api/v1/ai/llm/complete';
const AI_LOCAL_OLLAMA_URL = process.env.AI_LOCAL_OLLAMA_URL || '';
const AI_FALLBACK_PROVIDER = (process.env.AI_FALLBACK_PROVIDER || 'none').toLowerCase();

function riskRank(level) {
  const table = { NONE: 0, LOW: 1, MEDIUM: 2, HIGH: 3 };
  return table[(level || '').toUpperCase()] ?? 1;
}

async function isReachable(url) {
  if (!url) return false;
  try {
    const res = await fetch(url, { method: 'GET' });
    return res.status < 500;
  } catch (_e) {
    return false;
  }
}

async function decideRoute({ classifiedInformation, allowCentralization, personalDataRisk }) {
  const risk = (personalDataRisk || 'LOW').toUpperCase();
  const mustStayLocal = !!classifiedInformation || allowCentralization === false;

  const localAvailable = await isReachable(AI_LOCAL_OLLAMA_URL);
  const centralAvailable = await isReachable(process.env.REGISTRY_URL || '');

  if (mustStayLocal) {
    return { routeUsed: localAvailable ? 'LOCAL' : 'NONE', reason: 'policy_local_only', localAvailable, centralAvailable };
  }

  if (riskRank(risk) <= riskRank('MEDIUM') && allowCentralization !== false && centralAvailable) {
    return { routeUsed: 'CENTRAL', reason: 'risk_and_policy_allow_central', localAvailable, centralAvailable };
  }

  if (!centralAvailable && risk === 'NONE' && AI_FALLBACK_PROVIDER === 'azure') {
    return { routeUsed: 'AZURE_FALLBACK', reason: 'central_unavailable_non_sensitive', localAvailable, centralAvailable };
  }

  if (risk === 'HIGH' && !localAvailable) {
    return { routeUsed: 'NONE', reason: 'high_risk_no_local_model', localAvailable, centralAvailable };
  }

  return { routeUsed: localAvailable ? 'LOCAL' : 'NONE', reason: 'default_local_preferred', localAvailable, centralAvailable };
}

async function callLocalLLM(payload) {
  const response = await fetch(AI_LOCAL_OLLAMA_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!response.ok) throw new Error(`Local LLM failed: ${response.status}`);
  return response.json();
}

async function callAzureFallback(payload) {
  const endpoint = process.env.AI_AZURE_ENDPOINT || '';
  const apiKey = process.env.AI_AZURE_API_KEY || '';
  if (!endpoint || !apiKey) throw new Error('Azure fallback not configured');

  const response = await fetch(endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'api-key': apiKey,
    },
    body: JSON.stringify(payload),
  });

  if (!response.ok) throw new Error(`Azure fallback failed: ${response.status}`);
  return response.json();
}

async function requestSummary(routeUsed, payload, registryClient) {
  if (routeUsed === 'CENTRAL') {
    return registryClient.aiComplete(payload);
  }
  if (routeUsed === 'LOCAL') {
    return callLocalLLM(payload);
  }
  if (routeUsed === 'AZURE_FALLBACK') {
    return callAzureFallback(payload);
  }
  return null;
}

function createDefaultClient() {
  return new RegistryClient(process.env.REGISTRY_URL || 'http://localhost:8001', process.env.REGISTRY_API_KEY || '');
}

module.exports = {
  decideRoute,
  requestSummary,
  createDefaultClient,
  AI_CENTRAL_LLM_URL,
  AI_FALLBACK_PROVIDER,
};
