import { PiiPattern } from './types';

/**
 * Luhn algorithm — validates credit card numbers, IBANs (partial), etc.
 */
function luhnCheck(num: string): boolean {
  const digits = num.replace(/\D/g, '');
  let sum = 0;
  let alternate = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = parseInt(digits[i], 10);
    if (alternate) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alternate = !alternate;
  }
  return sum % 10 === 0;
}

/**
 * IBAN checksum validation (ISO 13616)
 */
function ibanCheck(iban: string): boolean {
  const cleaned = iban.replace(/\s/g, '').toUpperCase();
  if (cleaned.length < 15 || cleaned.length > 34) return false;
  // Move first 4 chars to end, convert letters to numbers
  const rearranged = cleaned.slice(4) + cleaned.slice(0, 4);
  const numeric = rearranged.replace(/[A-Z]/g, (ch) =>
    (ch.charCodeAt(0) - 55).toString(),
  );
  // Mod 97 check
  let remainder = numeric
    .match(/.{1,7}/g)!
    .reduce((acc, chunk) => (parseInt(acc + chunk, 10) % 97).toString(), '');
  return parseInt(remainder, 10) === 1;
}

/**
 * All built-in PII patterns — 30+ types organized by category.
 */
export const PII_PATTERNS: PiiPattern[] = [
  // ═══════════════════════════════════════════
  // CONTACT
  // ═══════════════════════════════════════════
  {
    name: 'email',
    label: 'EMAIL',
    category: 'contact',
    regex: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g,
    description: 'Email addresses',
  },
  {
    name: 'phone',
    label: 'PHONE',
    category: 'contact',
    regex: /(?:\+\d{1,3}[\s\-.])?(?:\(\d{2,4}\)|\d{2,4})[\s\-.]\d{3,4}[\s\-.]\d{3,8}/g,
    description: 'Phone numbers (international formats)',
  },
  {
    name: 'phoneUK',
    label: 'PHONE_UK',
    category: 'contact',
    regex: /\b(?:0|\+44)\s?\d{2,4}\s?\d{3,4}\s?\d{3,4}\b/g,
    description: 'UK phone numbers',
  },

  // ═══════════════════════════════════════════
  // IDENTITY — Person names (heuristic)
  // ═══════════════════════════════════════════
  {
    name: 'personName',
    label: 'PERSON',
    category: 'identity',
    regex:
      /\b(?:Mr\.?|Mrs\.?|Ms\.?|Miss|Dr\.?|Prof\.?|Sr\.?|Jr\.?|Herr|Frau|Monsieur|Madame|Señor|Señora)\s+[A-Z][a-zA-ZÀ-ÿ]+(?:\s+[A-Z][a-zA-ZÀ-ÿ]+){0,3}\b/g,
    description: 'Person names with title prefixes (Mr., Mrs., Dr., etc.)',
  },

  // ═══════════════════════════════════════════
  // IDENTITY — Government IDs
  // ═══════════════════════════════════════════
  {
    name: 'ssn',
    label: 'SSN',
    category: 'identity',
    regex: /\b\d{3}-\d{2}-\d{4}\b/g,
    description: 'US Social Security Numbers',
  },
  {
    name: 'passportUS',
    label: 'PASSPORT_US',
    category: 'identity',
    regex: /\b[A-Z]\d{8}\b/g,
    description: 'US passport numbers',
  },
  {
    name: 'passportEU',
    label: 'PASSPORT_EU',
    category: 'identity',
    regex: /\b[A-Z]{2}\d{7}\b/g,
    description: 'EU passport numbers (2 letters + 7 digits)',
  },
  {
    name: 'driverLicenseUS',
    label: 'DRIVER_LICENSE_US',
    category: 'identity',
    regex: /\b[A-Z]\d{3}-\d{4}-\d{4}\b/g,
    description: 'US driver license (common format)',
  },
  {
    name: 'nationalIdDE',
    label: 'NATIONAL_ID_DE',
    category: 'identity',
    regex: /\b[CFGHJKLMNPRTVWXYZ0-9]{9}\d\b/g,
    description: 'German ID card number (10 chars)',
  },
  {
    name: 'nhsNumber',
    label: 'NHS_NUMBER',
    category: 'identity',
    regex: /\b\d{3}\s?\d{3}\s?\d{4}\b/g,
    validate: (match: string) => {
      // NHS number checksum: weighted mod 11
      const digits = match.replace(/\s/g, '');
      if (digits.length !== 10) return false;
      const weights = [10, 9, 8, 7, 6, 5, 4, 3, 2];
      let sum = 0;
      for (let i = 0; i < 9; i++) {
        sum += parseInt(digits[i], 10) * weights[i];
      }
      const remainder = sum % 11;
      const check = 11 - remainder;
      if (check === 11) return parseInt(digits[9], 10) === 0;
      if (check === 10) return false; // invalid
      return parseInt(digits[9], 10) === check;
    },
    description: 'UK NHS numbers (with checksum validation)',
  },
  {
    name: 'taxIdUS',
    label: 'EIN',
    category: 'identity',
    regex: /\b\d{2}-\d{7}\b/g,
    description: 'US Employer Identification Number (EIN)',
  },

  // ═══════════════════════════════════════════
  // FINANCIAL
  // ═══════════════════════════════════════════
  {
    name: 'creditCard',
    label: 'CREDIT_CARD',
    category: 'financial',
    regex: /\b(?:\d{4}[\s\-]?){3}\d{4}\b/g,
    validate: (match: string) => luhnCheck(match),
    description: 'Credit/debit card numbers (Luhn validated)',
  },
  {
    name: 'iban',
    label: 'IBAN',
    category: 'financial',
    regex: /\b[A-Z]{2}\d{2}[\s]?[\dA-Z]{4}[\s]?(?:[\dA-Z]{4}[\s]?){2,7}[\dA-Z]{1,4}\b/g,
    validate: (match: string) => ibanCheck(match),
    description: 'International Bank Account Numbers (IBAN checksum validated)',
  },
  {
    name: 'bic',
    label: 'BIC_SWIFT',
    category: 'financial',
    regex: /\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b/g,
    description: 'BIC/SWIFT codes',
  },
  {
    name: 'vatEU',
    label: 'VAT_EU',
    category: 'financial',
    regex:
      /\b(?:ATU\d{8}|BE[01]\d{9}|BG\d{9,10}|CY\d{8}[A-Z]|CZ\d{8,10}|DE\d{9}|DK\d{8}|EE\d{9}|EL\d{9}|ES[A-Z0-9]\d{7}[A-Z0-9]|FI\d{8}|FR[A-Z0-9]{2}\d{9}|HR\d{11}|HU\d{8}|IE\d{7}[A-Z]{1,2}|IT\d{11}|LT\d{9,12}|LU\d{8}|LV\d{11}|MT\d{8}|NL\d{9}B\d{2}|PL\d{10}|PT\d{9}|RO\d{2,10}|SE\d{12}|SI\d{8}|SK\d{10})\b/g,
    description: 'EU VAT identification numbers (all member states)',
  },
  {
    name: 'bankAccountUK',
    label: 'BANK_ACCOUNT_UK',
    category: 'financial',
    regex: /\b\d{6}\s?\d{8}\b/g, // sort code + account
    description: 'UK bank account (sort code + account number)',
  },

  // ═══════════════════════════════════════════
  // NETWORK
  // ═══════════════════════════════════════════
  {
    name: 'ipv4',
    label: 'IP_ADDRESS',
    category: 'network',
    regex: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g,
    description: 'IPv4 addresses',
  },
  {
    name: 'ipv6',
    label: 'IPV6_ADDRESS',
    category: 'network',
    regex:
      /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b/g,
    description: 'IPv6 addresses',
  },
  {
    name: 'macAddress',
    label: 'MAC_ADDRESS',
    category: 'network',
    regex: /\b(?:[0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}\b/g,
    description: 'MAC addresses',
  },
  {
    name: 'url',
    label: 'URL',
    category: 'network',
    regex: /https?:\/\/[^\s<>\"')\]]+/g,
    description: 'URLs (http/https)',
  },

  // ═══════════════════════════════════════════
  // LOCATION
  // ═══════════════════════════════════════════
  {
    name: 'postalCodeUS',
    label: 'ZIP_CODE',
    category: 'location',
    regex: /\b\d{5}(?:-\d{4})?\b/g,
    description: 'US ZIP codes',
  },
  {
    name: 'postalCodeUK',
    label: 'POSTCODE_UK',
    category: 'location',
    regex:
      /\b[A-Z]{1,2}\d[A-Z\d]?\s?\d[A-Z]{2}\b/g,
    description: 'UK postcodes',
  },
  {
    name: 'postalCodeDE',
    label: 'POSTCODE_DE',
    category: 'location',
    regex: /\b\d{5}\b/g, // Same as US ZIP but contextual
    description: 'German postal codes (5 digits)',
  },
  {
    name: 'gpsCoordinates',
    label: 'GPS_COORDS',
    category: 'location',
    regex: /[-+]?\d{1,2}\.\d{4,},\s?[-+]?\d{1,3}\.\d{4,}/g,
    description: 'GPS coordinates (lat,lng with 4+ decimal places)',
  },

  // ═══════════════════════════════════════════
  // TEMPORAL
  // ═══════════════════════════════════════════
  {
    name: 'dateSlash',
    label: 'DATE',
    category: 'temporal',
    regex: /\b\d{1,2}\/\d{1,2}\/\d{2,4}\b/g,
    description: 'Dates (DD/MM/YYYY or MM/DD/YYYY)',
  },
  {
    name: 'dateDash',
    label: 'DATE',
    category: 'temporal',
    regex: /\b\d{4}-\d{2}-\d{2}\b/g,
    description: 'ISO dates (YYYY-MM-DD)',
  },
  {
    name: 'dateDot',
    label: 'DATE',
    category: 'temporal',
    regex: /\b\d{1,2}\.\d{1,2}\.\d{2,4}\b/g,
    description: 'Dates (DD.MM.YYYY — European format)',
  },
  {
    name: 'dateOfBirth',
    label: 'DOB',
    category: 'temporal',
    regex:
      /\b(?:DOB|Date\s+of\s+Birth|Geboren|Né\(e\))[:\s]+\d{1,2}[\/.]\d{1,2}[\/.]\d{2,4}\b/gi,
    description: 'Date of birth with label prefix',
  },

  // ═══════════════════════════════════════════
  // MEDICAL
  // ═══════════════════════════════════════════
  {
    name: 'medicalRecordNumber',
    label: 'MRN',
    category: 'medical',
    regex: /\bMRN[:\s#]*\d{6,10}\b/gi,
    description: 'Medical Record Numbers (MRN prefix)',
  },

  // ═══════════════════════════════════════════
  // CRYPTO
  // ═══════════════════════════════════════════
  {
    name: 'bitcoinAddress',
    label: 'BTC_ADDRESS',
    category: 'crypto',
    regex: /\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b/g,
    description: 'Bitcoin addresses (Legacy + Bech32)',
  },
  {
    name: 'ethereumAddress',
    label: 'ETH_ADDRESS',
    category: 'crypto',
    regex: /\b0x[a-fA-F0-9]{40}\b/g,
    description: 'Ethereum addresses',
  },
];

/**
 * Returns pattern names grouped by category for the UI.
 */
export function getPatternOptions(): Array<{
  name: string;
  value: string;
  description: string;
}> {
  return PII_PATTERNS.map((p) => ({
    name: `${p.description || p.label} (${p.category})`,
    value: p.name,
    description: p.description || p.label,
  }));
}

/**
 * Get patterns by name.
 */
export function getPatternsByNames(names: string[]): PiiPattern[] {
  return PII_PATTERNS.filter((p) => names.includes(p.name));
}
