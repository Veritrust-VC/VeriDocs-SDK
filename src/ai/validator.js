const {
  SUMMARY_SOURCES,
  DATA_RISK_LEVELS,
  DEFAULT_SEMANTIC_SUMMARY,
  DEFAULT_SENSITIVITY_CONTROL,
} = require('./schemas');

function clampText(value, maxLen) {
  if (!value || typeof value !== 'string') return '';
  const trimmed = value.trim();
  return trimmed.length > maxLen ? trimmed.slice(0, maxLen) : trimmed;
}

function normalizeKeywords(value) {
  if (!Array.isArray(value)) return [];
  return value
    .map(item => (typeof item === 'string' ? item.trim() : ''))
    .filter(Boolean)
    .slice(0, 10);
}

function validateSemanticSummary(summary) {
  const input = summary || {};
  const output = {
    ...DEFAULT_SEMANTIC_SUMMARY,
    summary: clampText(input.summary, 300),
    category: typeof input.category === 'string' ? input.category.trim().slice(0, 60) || 'GENERAL' : 'GENERAL',
    requestedAction: clampText(input.requestedAction, 100),
    keywords: normalizeKeywords(input.keywords),
    confidence: Number.isFinite(Number(input.confidence)) ? Math.max(0, Math.min(1, Number(input.confidence))) : 0,
    source: SUMMARY_SOURCES.includes(input.source) ? input.source : DEFAULT_SEMANTIC_SUMMARY.source,
    requiresHuman: input.requiresHuman !== undefined ? !!input.requiresHuman : DEFAULT_SEMANTIC_SUMMARY.requiresHuman,
  };

  const repairable = !!output.summary || !!output.requestedAction || output.keywords.length > 0;
  if (!repairable && !input.summary) {
    return {
      valid: false,
      repaired: true,
      semanticSummary: { ...DEFAULT_SEMANTIC_SUMMARY },
      reason: 'Missing semantic summary content',
    };
  }

  return {
    valid: true,
    repaired: true,
    semanticSummary: output,
    reason: null,
  };
}

function validateSensitivityControl(control) {
  const input = control || {};
  const risk = (typeof input.personalDataRisk === 'string' ? input.personalDataRisk.toUpperCase() : 'LOW');

  return {
    ...DEFAULT_SENSITIVITY_CONTROL,
    personalDataRisk: DATA_RISK_LEVELS.includes(risk) ? risk : DEFAULT_SENSITIVITY_CONTROL.personalDataRisk,
    containsClassifiedInformation: !!(input.containsClassifiedInformation || input.classifiedInformation),
    allowCentralization: input.allowCentralization !== undefined ? !!input.allowCentralization : false,
    detectedEntities: Array.isArray(input.detectedEntities) ? input.detectedEntities.slice(0, 100) : [],
  };
}

module.exports = {
  validateSemanticSummary,
  validateSensitivityControl,
};
