/**
 * Status Harmonization — AI-powered cross-institutional status mapping.
 *
 * Different institutions use different terminology for document statuses.
 * One system might say "In Review", another "Under Consideration", another "Izskatīšanā".
 * This module uses AI to infer semantic equivalence and map statuses to a
 * unified lifecycle model.
 *
 * AI system per EU AI Act Article 3(1): infers semantic equivalence from
 * institutional status labels to generate unified status mappings.
 */

const { completeJSON, isConfigured } = require('./llm-client');

const CANONICAL_STATUSES = [
  'draft', 'registered', 'sent', 'in_transit',
  'received', 'assigned', 'in_review', 'decided',
  'approved', 'rejected', 'archived', 'unknown',
];

const SYSTEM_PROMPT = `You are a document status harmonization engine. Different government
institutions use different terminology for document lifecycle statuses. Your job is to map
arbitrary status labels (in any language) to a canonical set of statuses.

Canonical statuses: ${CANONICAL_STATUSES.join(', ')}

When given a list of status labels from various institutions, map each to the closest canonical
status. Consider translations (Latvian: "izskatīšanā" = "in_review", "nosūtīts" = "sent"),
synonyms ("under consideration" = "in_review"), and organizational variations.

Respond ONLY with JSON:
{
  "mappings": [
    {
      "original": "the input status label",
      "canonical": "closest canonical status",
      "confidence": 0.0 to 1.0,
      "reasoning": "brief explanation"
    }
  ],
  "unmapped": ["labels that couldn't be mapped"],
  "language_detected": "detected language(s)"
}`;

/**
 * Map a list of institution-specific statuses to canonical statuses.
 *
 * @param {Array<string>} statusLabels - Status labels from various institutions
 * @param {string} [context] - Optional context about the institution
 * @returns {object} Harmonization result
 */
async function harmonizeStatuses(statusLabels, context) {
  if (!statusLabels || !statusLabels.length) {
    return { mappings: [], unmapped: [] };
  }

  if (!isConfigured()) {
    return _ruleBasedHarmonization(statusLabels);
  }

  const userMsg = JSON.stringify({
    status_labels: statusLabels,
    context: context || 'Government document management systems',
  }, null, 2);

  const result = await completeJSON(SYSTEM_PROMPT, userMsg);
  if (result) {
    result.ai_generated = true;
    return result;
  }

  return _ruleBasedHarmonization(statusLabels);
}

/**
 * Map a single status label to canonical.
 */
async function mapStatus(label, context) {
  const result = await harmonizeStatuses([label], context);
  const mapping = result.mappings?.[0];
  return mapping || { original: label, canonical: 'unknown', confidence: 0, ai_generated: false };
}

// Known mappings for common Latvian/English terms
const KNOWN_MAPPINGS = {
  // English
  'draft': 'draft', 'new': 'draft', 'created': 'registered',
  'registered': 'registered', 'sent': 'sent', 'dispatched': 'sent',
  'delivered': 'sent', 'in transit': 'in_transit', 'pending': 'in_transit',
  'received': 'received', 'accepted': 'received', 'assigned': 'assigned',
  'delegated': 'assigned', 'in review': 'in_review', 'under review': 'in_review',
  'under consideration': 'in_review', 'processing': 'in_review',
  'decided': 'decided', 'resolved': 'decided', 'completed': 'decided',
  'approved': 'approved', 'accepted': 'approved', 'confirmed': 'approved',
  'rejected': 'rejected', 'denied': 'rejected', 'declined': 'rejected',
  'archived': 'archived', 'closed': 'archived', 'filed': 'archived',
  // Latvian
  'jauns': 'draft', 'melnraksts': 'draft', 'reģistrēts': 'registered',
  'nosūtīts': 'sent', 'saņemts': 'received', 'piešķirts': 'assigned',
  'izskatīšanā': 'in_review', 'izlemts': 'decided', 'apstiprināts': 'approved',
  'noraidīts': 'rejected', 'arhivēts': 'archived', 'slēgts': 'archived',
};

function _ruleBasedHarmonization(statusLabels) {
  const mappings = [];
  const unmapped = [];

  for (const label of statusLabels) {
    const normalized = label.toLowerCase().trim();
    const canonical = KNOWN_MAPPINGS[normalized];
    if (canonical) {
      mappings.push({ original: label, canonical, confidence: 0.9, reasoning: 'Dictionary match' });
    } else {
      // Fuzzy: check if any known key is a substring
      let found = false;
      for (const [key, val] of Object.entries(KNOWN_MAPPINGS)) {
        if (normalized.includes(key) || key.includes(normalized)) {
          mappings.push({ original: label, canonical: val, confidence: 0.5, reasoning: `Partial match: "${key}"` });
          found = true;
          break;
        }
      }
      if (!found) {
        mappings.push({ original: label, canonical: 'unknown', confidence: 0.1, reasoning: 'No match found' });
        unmapped.push(label);
      }
    }
  }

  return { mappings, unmapped, ai_generated: false };
}

module.exports = { harmonizeStatuses, mapStatus, CANONICAL_STATUSES };
