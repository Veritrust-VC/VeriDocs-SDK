/**
 * LLM Client — OpenAI-compatible interface for SDK AI modules.
 *
 * Works with: Anthropic Claude, OpenAI, Ollama, Azure OpenAI.
 *
 * Config via env:
 *   LLM_PROVIDER: anthropic | openai | ollama (default: anthropic)
 *   LLM_API_KEY: API key
 *   LLM_BASE_URL: Custom endpoint
 *   LLM_MODEL: Model name
 */

const http = require('http');
const https = require('https');
const { URL } = require('url');

const PROVIDER = process.env.LLM_PROVIDER || 'anthropic';
const API_KEY = process.env.LLM_API_KEY || '';
const BASE_URL = process.env.LLM_BASE_URL || '';
const MODEL = process.env.LLM_MODEL || '';

const DEFAULTS = {
  anthropic: { base_url: 'https://api.anthropic.com', model: 'claude-sonnet-4-20250514' },
  openai: { base_url: 'https://api.openai.com', model: 'gpt-4o-mini' },
  ollama: { base_url: 'http://localhost:11434', model: 'llama3.1' },
};

function getConfig() {
  const d = DEFAULTS[PROVIDER] || DEFAULTS.anthropic;
  return { provider: PROVIDER, api_key: API_KEY, base_url: BASE_URL || d.base_url, model: MODEL || d.model };
}

function isConfigured() {
  return !!API_KEY || PROVIDER === 'ollama';
}

async function complete(system, userMessage, { temperature = 0.2, maxTokens = 2000 } = {}) {
  const cfg = getConfig();
  if (!cfg.api_key && cfg.provider !== 'ollama') return null;

  try {
    if (cfg.provider === 'anthropic') return await _anthropic(cfg, system, userMessage, temperature, maxTokens);
    return await _openaiCompat(cfg, system, userMessage, temperature, maxTokens);
  } catch (err) {
    console.error('[AI] LLM error:', err.message);
    return null;
  }
}

async function completeJSON(system, userMessage, opts = {}) {
  const raw = await complete(system, userMessage, opts);
  if (!raw) return null;
  let text = raw.trim();
  if (text.startsWith('```')) { text = text.split('\n').slice(1).join('\n'); if (text.endsWith('```')) text = text.slice(0, -3); text = text.trim(); }
  try { return JSON.parse(text); } catch { console.warn('[AI] Non-JSON response:', text.slice(0, 200)); return null; }
}

function _request(url, headers, body) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const lib = u.protocol === 'https:' ? https : http;
    const payload = JSON.stringify(body);
    headers['Content-Length'] = Buffer.byteLength(payload);
    const req = lib.request(u, { method: 'POST', headers }, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); } catch { reject(new Error(`Parse error: ${data.slice(0, 200)}`)); }
      });
    });
    req.on('error', reject);
    req.setTimeout(60000, () => { req.destroy(); reject(new Error('Timeout')); });
    req.write(payload);
    req.end();
  });
}

async function _anthropic(cfg, system, userMessage, temperature, maxTokens) {
  const data = await _request(`${cfg.base_url}/v1/messages`, {
    'x-api-key': cfg.api_key, 'anthropic-version': '2023-06-01', 'content-type': 'application/json',
  }, { model: cfg.model, max_tokens: maxTokens, temperature, system, messages: [{ role: 'user', content: userMessage }] });
  return data.content?.[0]?.text || null;
}

async function _openaiCompat(cfg, system, userMessage, temperature, maxTokens) {
  const url = cfg.provider === 'ollama' ? `${cfg.base_url}/api/chat` : `${cfg.base_url}/v1/chat/completions`;
  const headers = { 'content-type': 'application/json' };
  if (cfg.api_key) headers.authorization = `Bearer ${cfg.api_key}`;
  const data = await _request(url, headers, {
    model: cfg.model, temperature, max_tokens: maxTokens,
    messages: [{ role: 'system', content: system }, { role: 'user', content: userMessage }],
  });
  return data.message?.content || data.choices?.[0]?.message?.content || null;
}

module.exports = { complete, completeJSON, isConfigured, getConfig };
