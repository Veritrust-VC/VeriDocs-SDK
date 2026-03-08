const fs = require('fs');
const path = require('path');

const CUSTOM_CONTEXTS = {
  'https://veritrust.vc/contexts/person-identity-v1.jsonld':
    JSON.parse(fs.readFileSync(path.join(__dirname, '../public/contexts/person-identity-v1.jsonld'), 'utf8')),
  'https://veritrust.vc/contexts/person-contact-v1.jsonld':
    JSON.parse(fs.readFileSync(path.join(__dirname, '../public/contexts/person-contact-v1.jsonld'), 'utf8')),
  'https://veritrust.vc/contexts/org-accreditation-v1.jsonld':
    JSON.parse(fs.readFileSync(path.join(__dirname, '../public/contexts/org-accreditation-v1.jsonld'), 'utf8')),
  'https://veritrust.vc/contexts/org-contact-v1.jsonld':
    JSON.parse(fs.readFileSync(path.join(__dirname, '../public/contexts/org-contact-v1.jsonld'), 'utf8')),
};

module.exports = { CUSTOM_CONTEXTS };
