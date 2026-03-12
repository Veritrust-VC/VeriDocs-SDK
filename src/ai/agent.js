const path = require('path');
const { spawn } = require('child_process');
const { decideRoute, requestSummary, createDefaultClient, AI_FALLBACK_PROVIDER } = require('./llm-router');
const { validateSemanticSummary, validateSensitivityControl } = require('./validator');

const MAX_EXTRACTED_TEXT = parseInt(process.env.AI_MAX_EXTRACTED_CHARS || '8000', 10);

function runPython(scriptPath, args = [], input = null) {
  return new Promise((resolve, reject) => {
    const child = spawn('python3', [scriptPath, ...args]);
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', chunk => { stdout += String(chunk); });
    child.stderr.on('data', chunk => { stderr += String(chunk); });
    child.on('error', reject);
    child.on('close', code => {
      if (code !== 0) return reject(new Error(stderr || `python exited ${code}`));
      try {
        resolve(JSON.parse(stdout || '{}'));
      } catch (_err) {
        reject(new Error(`python output parse error: ${stdout}`));
      }
    });
    if (input) child.stdin.write(JSON.stringify(input));
    child.stdin.end();
  });
}

async function extractText(filePath) {
  const script = path.join(__dirname, 'extractor', 'extract.py');
  const result = await runPython(script, [filePath]);
  const text = (result.text || '').slice(0, MAX_EXTRACTED_TEXT);
  return { ...result, text, truncated: (result.text || '').length > text.length };
}

async function anonymizeText(text) {
  const script = path.join(__dirname, 'anonymizer', 'anonymize.py');
  return runPython(script, [], { text });
}

function parseSummaryResponse(llmResponse) {
  if (!llmResponse) return {};
  if (typeof llmResponse === 'object') return llmResponse;
  return { summary: String(llmResponse).slice(0, 300) };
}

async function extractAndSummarize({ filePath, metadata = {}, registryClient }) {
  const aiEnabled = process.env.AI_ENABLED !== 'false';
  if (!aiEnabled) {
    return {
      semanticSummary: { summary: '', source: 'HUMAN', requiresHuman: true, keywords: [], requestedAction: '', confidence: 0, category: 'GENERAL' },
      sensitivityControl: { personalDataRisk: 'LOW', containsClassifiedInformation: false, allowCentralization: false, detectedEntities: [] },
      confidence: 0,
      routeUsed: 'NONE',
    };
  }

  const extraction = await extractText(filePath);
  const anonymized = await anonymizeText(extraction.text || '');

  const sensitivityControl = validateSensitivityControl({
    personalDataRisk: anonymized.personalDataRisk,
    detectedEntities: anonymized.detectedEntities,
    classifiedInformation: !!metadata.classifiedInformation,
    allowCentralization: metadata.allowCentralization,
  });

  const routeDecision = await decideRoute({
    classifiedInformation: sensitivityControl.containsClassifiedInformation,
    allowCentralization: sensitivityControl.allowCentralization,
    personalDataRisk: sensitivityControl.personalDataRisk,
  });

  let semanticSummaryPayload = null;
  if (routeDecision.routeUsed !== 'NONE') {
    try {
      semanticSummaryPayload = await requestSummary(routeDecision.routeUsed, {
        text: anonymized.anonymizedText,
        metadata,
      }, registryClient || createDefaultClient());
    } catch (_error) {
      semanticSummaryPayload = null;
    }
  }

  const parsed = parseSummaryResponse(semanticSummaryPayload);
  const validation = validateSemanticSummary({
    ...parsed,
    source: routeDecision.routeUsed === 'CENTRAL' ? 'CENTRAL' : routeDecision.routeUsed === 'LOCAL' ? 'LOCAL' : routeDecision.routeUsed === 'AZURE_FALLBACK' ? 'AZURE_FALLBACK' : 'HUMAN',
    requiresHuman: routeDecision.routeUsed === 'NONE',
  });

  const fallback = !validation.valid;
  const semanticSummary = fallback
    ? { summary: '', category: 'GENERAL', confidence: 0, requestedAction: '', keywords: [], source: 'HUMAN', requiresHuman: true }
    : validation.semanticSummary;

  return {
    semanticSummary,
    sensitivityControl,
    confidence: semanticSummary.confidence,
    routeUsed: routeDecision.routeUsed,
    fallbackProvider: AI_FALLBACK_PROVIDER,
    extractedText: extraction.text,
  };
}

function getAiStatus() {
  const extractorPath = path.join(__dirname, 'extractor', 'extract.py');
  const anonymizerPath = path.join(__dirname, 'anonymizer', 'anonymize.py');
  return {
    ai_enabled: process.env.AI_ENABLED !== 'false',
    extractor_available: require('fs').existsSync(extractorPath),
    anonymizer_available: require('fs').existsSync(anonymizerPath),
    central_llm_available: !!process.env.REGISTRY_URL,
    local_llm_available: !!process.env.AI_LOCAL_OLLAMA_URL,
    fallback_provider: (process.env.AI_FALLBACK_PROVIDER || 'none').toLowerCase(),
    semantic_summary_supported: true,
  };
}

module.exports = {
  extractAndSummarize,
  anonymizeText,
  extractText,
  getAiStatus,
};
