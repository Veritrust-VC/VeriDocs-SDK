const SUMMARY_SOURCES = ['CENTRAL', 'LOCAL', 'AZURE_FALLBACK', 'HUMAN'];
const DATA_RISK_LEVELS = ['NONE', 'LOW', 'MEDIUM', 'HIGH'];
const ROUTE_USED = ['CENTRAL', 'LOCAL', 'AZURE_FALLBACK', 'NONE'];

const DEFAULT_SEMANTIC_SUMMARY = {
  summary: '',
  category: 'GENERAL',
  confidence: 0,
  requestedAction: '',
  keywords: [],
  source: 'HUMAN',
  requiresHuman: true,
};

const DEFAULT_SENSITIVITY_CONTROL = {
  personalDataRisk: 'LOW',
  containsClassifiedInformation: false,
  allowCentralization: false,
  detectedEntities: [],
};

module.exports = {
  SUMMARY_SOURCES,
  DATA_RISK_LEVELS,
  ROUTE_USED,
  DEFAULT_SEMANTIC_SUMMARY,
  DEFAULT_SENSITIVITY_CONTROL,
};
