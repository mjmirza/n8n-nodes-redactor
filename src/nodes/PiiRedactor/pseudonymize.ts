/**
 * Pseudonymization Engine
 *
 * Replaces PII with realistic-looking fake data that preserves format.
 * GDPR Article 4(5): "processing personal data so it can no longer be
 * attributed to a specific data subject without additional information."
 *
 * Key properties:
 *   - Format-preserving: emails stay email-shaped, phones stay phone-shaped
 *   - Deterministic: same input + same session = same output (seeded)
 *   - Reversible: mapping stored in vault for restoration
 *   - GDPR-compliant: mapping stored separately from pseudonymized data
 *
 * No external dependencies (no Faker.js). Uses built-in deterministic generation.
 */

import * as crypto from 'crypto';

/** Generate a deterministic seed from session ID + original value */
function getSeed(sessionId: string, original: string): number {
  const hash = crypto.createHash('sha256').update(`${sessionId}:${original}`).digest();
  return hash.readUInt32BE(0);
}

/** Seeded random number generator (Mulberry32) */
function seededRandom(seed: number): () => number {
  let s = seed;
  return () => {
    s |= 0;
    s = (s + 0x6d2b79f5) | 0;
    let t = Math.imul(s ^ (s >>> 15), 1 | s);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// ═══════════════════════════════════════════
// FAKE DATA POOLS
// ═══════════════════════════════════════════

const FIRST_NAMES = [
  'Emma', 'Liam', 'Olivia', 'Noah', 'Ava', 'William', 'Sophia', 'James',
  'Isabella', 'Oliver', 'Mia', 'Benjamin', 'Charlotte', 'Elijah', 'Amelia',
  'Lucas', 'Harper', 'Mason', 'Evelyn', 'Logan', 'Abigail', 'Alexander',
  'Emily', 'Ethan', 'Elizabeth', 'Jacob', 'Sofia', 'Michael', 'Avery',
  'Daniel', 'Ella', 'Henry', 'Scarlett', 'Jackson', 'Grace', 'Sebastian',
  'Victoria', 'Aiden', 'Riley', 'Matthew', 'Aria', 'Samuel', 'Lily',
  'David', 'Layla', 'Joseph', 'Zoe', 'Carter', 'Penelope', 'Owen',
  'Anna', 'Klaus', 'Marie', 'Stefan', 'Laura', 'Marco', 'Giulia',
  'Pierre', 'Camille', 'Pablo', 'Elena', 'Jan', 'Sophie', 'Andrzej',
];

const LAST_NAMES = [
  'Anderson', 'Baker', 'Campbell', 'Davis', 'Edwards', 'Foster', 'Garcia',
  'Harrison', 'Ingram', 'Johnson', 'Kelly', 'Lambert', 'Mitchell', 'Nelson',
  'Owens', 'Parker', 'Quinn', 'Reynolds', 'Stewart', 'Turner', 'Underwood',
  'Vincent', 'Watson', 'Xavier', 'Young', 'Zimmerman', 'Adams', 'Brooks',
  'Cooper', 'Dixon', 'Evans', 'Fisher', 'Grant', 'Hayes', 'Irving',
  'Jordan', 'Klein', 'Lewis', 'Morgan', 'Norton', 'Palmer', 'Ross',
  'Schmidt', 'Weber', 'Mueller', 'Fischer', 'Schneider', 'Hoffmann',
  'Martin', 'Bernard', 'Dubois', 'Rossi', 'Ferrari', 'Kowalski',
];

const EMAIL_DOMAINS = [
  'example.com', 'sample.org', 'demo.net', 'test.io', 'mock.dev',
  'placeholder.com', 'pseudo.org', 'anon.net', 'redacted.io', 'safe.dev',
];

const STREET_NAMES = [
  'Oak', 'Maple', 'Cedar', 'Pine', 'Elm', 'Birch', 'Willow', 'Ash',
  'Cherry', 'Walnut', 'Spruce', 'Cypress', 'Magnolia', 'Jasmine', 'Holly',
];

const STREET_TYPES = ['Street', 'Avenue', 'Road', 'Drive', 'Lane', 'Boulevard', 'Way', 'Place'];

const CITIES = [
  'Springfield', 'Riverside', 'Fairview', 'Greenville', 'Oakland',
  'Brighton', 'Westport', 'Lakewood', 'Northfield', 'Eastwood',
];

const COMPANY_PREFIXES = [
  'Global', 'United', 'Premier', 'Pacific', 'Atlas', 'Apex', 'Nova',
  'Pinnacle', 'Vertex', 'Meridian', 'Horizon', 'Summit', 'Delta',
];

const COMPANY_SUFFIXES = [
  'Solutions', 'Technologies', 'Industries', 'Services', 'Group',
  'Systems', 'Enterprises', 'Partners', 'Holdings', 'Associates',
];

/**
 * Generate a pseudonym for a given PII value based on its type.
 * Deterministic: same sessionId + original = same pseudonym.
 */
export function generatePseudonym(
  sessionId: string,
  original: string,
  label: string,
): string {
  const seed = getSeed(sessionId, original);
  const rng = seededRandom(seed);
  const pick = <T>(arr: T[]): T => arr[Math.floor(rng() * arr.length)];
  const digit = (): string => String(Math.floor(rng() * 10));
  const digits = (n: number): string => Array.from({ length: n }, digit).join('');

  switch (label) {
    case 'EMAIL':
    case 'EDU_EMAIL': {
      const first = pick(FIRST_NAMES).toLowerCase();
      const last = pick(LAST_NAMES).toLowerCase();
      const domain = pick(EMAIL_DOMAINS);
      return `${first}.${last}@${domain}`;
    }

    case 'PERSON_NAME':
    case 'PERSON':
    case 'FULL_NAME': {
      return `${pick(FIRST_NAMES)} ${pick(LAST_NAMES)}`;
    }

    case 'PHONE':
    case 'PHONE_DE':
    case 'PHONE_UK':
    case 'PHONE_FR':
    case 'PHONE_US':
    case 'FAX': {
      // Preserve general phone format
      if (original.startsWith('+49')) return `+49 ${digits(3)} ${digits(4)}-${digits(4)}`;
      if (original.startsWith('+44')) return `+44 ${digits(4)} ${digits(6)}`;
      if (original.startsWith('+33')) return `+33 ${digit()} ${digits(2)} ${digits(2)} ${digits(2)} ${digits(2)}`;
      if (original.startsWith('+1')) return `+1-${digits(3)}-${digits(3)}-${digits(4)}`;
      return `+${digits(2)} ${digits(3)} ${digits(4)}-${digits(4)}`;
    }

    case 'SSN': {
      return `${digits(3)}-${digits(2)}-${digits(4)}`;
    }

    case 'CREDIT_CARD':
    case 'AMEX': {
      return `${digits(4)}-${digits(4)}-${digits(4)}-${digits(4)}`;
    }

    case 'IBAN': {
      const country = original.slice(0, 2) || 'DE';
      return `${country}${digits(20)}`;
    }

    case 'ADDRESS':
    case 'ADDRESS_DE':
    case 'STREET_ADDRESS': {
      return `${digits(3)} ${pick(STREET_NAMES)} ${pick(STREET_TYPES)}, ${pick(CITIES)}`;
    }

    case 'COMPANY':
    case 'ORGANIZATION': {
      return `${pick(COMPANY_PREFIXES)} ${pick(COMPANY_SUFFIXES)}`;
    }

    case 'DOB':
    case 'DATE':
    case 'EMPLOYMENT_DATE':
    case 'HIRE_DATE':
    case 'DATE_OF_DEATH': {
      // Generate a random date preserving format
      const year = 1950 + Math.floor(rng() * 60);
      const month = 1 + Math.floor(rng() * 12);
      const day = 1 + Math.floor(rng() * 28);
      if (original.includes('/')) return `${String(day).padStart(2, '0')}/${String(month).padStart(2, '0')}/${year}`;
      if (original.includes('.')) return `${String(day).padStart(2, '0')}.${String(month).padStart(2, '0')}.${year}`;
      return `${year}-${String(month).padStart(2, '0')}-${String(day).padStart(2, '0')}`;
    }

    case 'IP_ADDRESS':
    case 'PRIVATE_IP': {
      return `${10 + Math.floor(rng() * 240)}.${Math.floor(rng() * 256)}.${Math.floor(rng() * 256)}.${Math.floor(rng() * 256)}`;
    }

    case 'SALARY':
    case 'FINANCIAL_AMOUNT': {
      return String(30000 + Math.floor(rng() * 170000));
    }

    default: {
      // For unknown types, generate a hash-like pseudonym
      const hash = crypto.createHash('sha256').update(`pseudo:${sessionId}:${original}`).digest('hex');
      return `[PSEUDO_${hash.slice(0, 8).toUpperCase()}]`;
    }
  }
}
