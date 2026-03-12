#!/usr/bin/env python3
import json
import re
import sys

PATTERNS = {
    'EMAIL': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',
    'PHONE': r'\b(?:\+?\d{1,3}[\s-]?)?(?:\(?\d{2,4}\)?[\s-]?)\d{3,4}[\s-]?\d{3,4}\b',
    'ID_NUMBER': r'\b\d{6,}\b',
    'PERSON': r'\b[A-Z][a-z]+\s+[A-Z][a-z]+\b',
    'ADDRESS': r'\b\d+\s+[A-Za-z0-9\s]{3,40}(Street|St|Road|Rd|Avenue|Ave|Boulevard|Blvd|Lane|Ln|Way)\b',
}


def classify_risk(entity_count: int, direct_identifiers: int) -> str:
    if direct_identifiers >= 3 or entity_count >= 10:
        return 'HIGH'
    if direct_identifiers >= 1 or entity_count >= 4:
        return 'MEDIUM'
    if entity_count >= 1:
        return 'LOW'
    return 'NONE'


def main():
    payload = json.loads(sys.stdin.read() or '{}')
    text = payload.get('text', '')

    detected = []
    anonymized = text

    for label, pattern in PATTERNS.items():
        matches = re.findall(pattern, anonymized)
        if matches:
            detected.append({'type': label, 'count': len(matches)})
            anonymized = re.sub(pattern, f'[{label}]', anonymized)

    entity_count = sum(item['count'] for item in detected)
    direct_identifiers = sum(item['count'] for item in detected if item['type'] in {'EMAIL', 'PHONE', 'ID_NUMBER', 'ADDRESS'})
    risk = classify_risk(entity_count, direct_identifiers)

    print(json.dumps({
        'anonymizedText': anonymized,
        'detectedEntities': detected,
        'personalDataRisk': risk,
    }))


if __name__ == '__main__':
    main()
