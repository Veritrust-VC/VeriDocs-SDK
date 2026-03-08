/**
 * Intelligent Routing — AI-powered document routing recommendations.
 *
 * When a document arrives at an organization, this module analyzes:
 *   - DID metadata (issuer organization, document type)
 *   - VC history (lifecycle events from other institutions)
 *   - Classification schema (organizational structure)
 *   - Document content summary
 *
 * ...and recommends which department/officer should handle it and at what priority.
 *
 * AI system per EU AI Act Article 3(1): infers from document metadata and
 * institutional context to generate routing recommendations and priority assessments.
 */

const { completeJSON, isConfigured } = require('./llm-client');

const SYSTEM_PROMPT = `You are a document routing assistant for a government institution.
When a new document arrives, you analyze its metadata, sender, classification, and lifecycle
history to recommend optimal routing.

You will receive:
- document: DID, title, classification, content summary
- sender: organization DID and name (if known)
- lifecycle: previous events from other institutions
- org_structure: departments and roles available for assignment

Respond ONLY with JSON:
{
  "recommended_department": "department name",
  "recommended_priority": "low|normal|high|urgent",
  "confidence": 0.0 to 1.0,
  "reasoning": "brief explanation of routing logic",
  "alternative_routes": [
    {"department": "...", "reason": "..."}
  ],
  "flags": ["any special handling notes"]
}`;

/**
 * Generate routing recommendation for an incoming document.
 *
 * @param {object} document - { did, title, classification, contentSummary, metadata }
 * @param {object} sender - { did, name }
 * @param {Array} lifecycleEvents - Previous events from VC chain
 * @param {Array} orgStructure - Available departments/roles [{ name, description }]
 * @returns {object|null} Routing recommendation
 */
async function recommendRouting(document, sender, lifecycleEvents = [], orgStructure = []) {
  if (!isConfigured()) {
    return _ruleBasedRouting(document, sender);
  }

  const userMsg = JSON.stringify({
    document: {
      did: document.did,
      title: document.title,
      classification: document.classification || 'unclassified',
      content_summary: document.contentSummary || '',
      metadata: document.metadata || {},
    },
    sender: {
      did: sender.did || 'unknown',
      name: sender.name || 'Unknown Organization',
    },
    lifecycle_events: lifecycleEvents.map(e => ({
      type: e.event_type || e.eventType,
      issuer: e.issuer_did || e.issuerDid,
      timestamp: e.created_at || e.timestamp,
    })),
    org_structure: orgStructure,
  }, null, 2);

  const result = await completeJSON(SYSTEM_PROMPT, userMsg);
  if (result) {
    result.ai_generated = true;
    return result;
  }

  return _ruleBasedRouting(document, sender);
}

function _ruleBasedRouting(document, sender) {
  // Simple keyword-based fallback
  const title = (document.title || '').toLowerCase();
  const cls = (document.classification || '').toLowerCase();

  let dept = 'General Office';
  let priority = 'normal';

  if (title.includes('urgent') || title.includes('steidzam')) {
    priority = 'urgent';
  }

  if (cls.includes('finance') || cls.includes('budget') || title.includes('invoice')) {
    dept = 'Finance';
  } else if (cls.includes('legal') || title.includes('contract') || title.includes('agreement')) {
    dept = 'Legal';
  } else if (cls.includes('hr') || title.includes('employment') || title.includes('personnel')) {
    dept = 'Human Resources';
  } else if (cls.includes('it') || cls.includes('tech') || title.includes('system')) {
    dept = 'IT';
  }

  return {
    recommended_department: dept,
    recommended_priority: priority,
    confidence: 0.4,
    reasoning: 'Rule-based routing (AI not configured)',
    alternative_routes: [],
    flags: [],
    ai_generated: false,
  };
}

module.exports = { recommendRouting };
