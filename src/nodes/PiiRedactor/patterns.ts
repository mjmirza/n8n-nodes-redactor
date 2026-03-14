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
  {
    name: 'phoneDE',
    label: 'PHONE_DE',
    category: 'contact',
    regex: /(?:0|\+49)\s?\d{2,4}[\s\/]\d{3,8}(?:[\s\-]\d{1,5})?/g,
    description: 'German phone numbers (089 1234 5678, +49 30 12345678)',
  },
  {
    name: 'phoneAT',
    label: 'PHONE_AT',
    category: 'contact',
    regex: /(?:0|\+43)\s?\d{1,4}[\s\/]\d{3,8}(?:[\s\-]\d{1,5})?/g,
    description: 'Austrian phone numbers',
  },
  {
    name: 'phoneCH',
    label: 'PHONE_CH',
    category: 'contact',
    regex: /(?:0|\+41)\s?\d{2}\s?\d{3}\s?\d{2}\s?\d{2}/g,
    description: 'Swiss phone numbers (079 123 45 67)',
  },
  {
    name: 'phoneFR',
    label: 'PHONE_FR',
    category: 'contact',
    regex: /\b(?:0|\+33)\s?\d[\s.]\d{2}[\s.]\d{2}[\s.]\d{2}[\s.]\d{2}\b/g,
    description: 'French phone numbers (06 12 34 56 78)',
  },
  {
    name: 'phoneNL',
    label: 'PHONE_NL',
    category: 'contact',
    regex: /\b(?:0|\+31)\s?\d{1,3}[\s\-]\d{3,4}[\s\-]\d{2,4}\b/g,
    description: 'Dutch phone numbers',
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
  {
    name: 'taxIdDE',
    label: 'STEUER_ID_DE',
    category: 'identity',
    regex: /\b(?:Steuer[\-\s]?(?:ID|Id|Identifikationsnummer|Nr)[.:\s]*)\d{11}\b/gi,
    description: 'German tax ID (Steuerliche Identifikationsnummer, 11 digits)',
  },
  {
    name: 'taxIdDEPlain',
    label: 'STEUER_ID_DE',
    category: 'identity',
    regex: /\b\d{2}\s?\d{3}\s?\d{3}\s?\d{3}\b/g,
    validate: (match: string) => {
      // German tax ID is exactly 11 digits, first digit != 0
      const digits = match.replace(/\s/g, '');
      return digits.length === 11 && digits[0] !== '0';
    },
    description: 'German tax ID (11 digits, standalone)',
  },
  {
    name: 'sozialversicherungDE',
    label: 'SOZIALVERS_DE',
    category: 'identity',
    regex: /\b\d{2}\s?\d{6}\s?[A-Z]\s?\d{3}\b/g,
    description: 'German social insurance number (Sozialversicherungsnummer)',
  },
  {
    name: 'sozialversicherungAT',
    label: 'SOZIALVERS_AT',
    category: 'identity',
    regex: /\b\d{4}\s?\d{6}\b/g,
    validate: (match: string) => {
      // Austrian SV number: 4-digit serial + 6-digit DOB (DDMMYY)
      const digits = match.replace(/\s/g, '');
      if (digits.length !== 10) return false;
      const day = parseInt(digits.slice(4, 6), 10);
      const month = parseInt(digits.slice(6, 8), 10);
      return day >= 1 && day <= 31 && month >= 1 && month <= 12;
    },
    description: 'Austrian social insurance number (Sozialversicherungsnummer)',
  },
  {
    name: 'ahvCH',
    label: 'AHV_CH',
    category: 'identity',
    regex: /\b756\.\d{4}\.\d{4}\.\d{2}\b/g,
    description: 'Swiss social insurance number (AHV/AVS: 756.XXXX.XXXX.XX)',
  },
  {
    name: 'nationalIdFR',
    label: 'NIR_FR',
    category: 'identity',
    regex: /\b[12]\s?\d{2}\s?\d{2}\s?\d{2}\s?\d{3}\s?\d{3}\s?\d{2}\b/g,
    description: 'French national ID / social security (NIR: 13 digits + 2 check)',
  },
  {
    name: 'codiceFiscaleIT',
    label: 'CODICE_FISCALE_IT',
    category: 'identity',
    regex: /\b[A-Z]{6}\d{2}[A-EHLMPRST]\d{2}[A-Z]\d{3}[A-Z]\b/g,
    description: 'Italian fiscal code (Codice Fiscale)',
  },
  {
    name: 'dniES',
    label: 'DNI_ES',
    category: 'identity',
    regex: /\b\d{8}[A-Z]\b/g,
    description: 'Spanish national ID (DNI: 8 digits + letter)',
  },
  {
    name: 'nieES',
    label: 'NIE_ES',
    category: 'identity',
    regex: /\b[XYZ]\d{7}[A-Z]\b/g,
    description: 'Spanish foreigner ID (NIE: X/Y/Z + 7 digits + letter)',
  },
  {
    name: 'peselPL',
    label: 'PESEL_PL',
    category: 'identity',
    regex: /\b\d{11}\b/g,
    validate: (match: string) => {
      // PESEL checksum: weighted mod 10
      const w = [1, 3, 7, 9, 1, 3, 7, 9, 1, 3];
      let sum = 0;
      for (let i = 0; i < 10; i++) {
        sum += parseInt(match[i], 10) * w[i];
      }
      const check = (10 - (sum % 10)) % 10;
      return parseInt(match[10], 10) === check;
    },
    description: 'Polish national ID (PESEL: 11 digits, checksum validated)',
  },
  {
    name: 'bsnNL',
    label: 'BSN_NL',
    category: 'identity',
    regex: /\b\d{9}\b/g,
    validate: (match: string) => {
      // BSN 11-check: 9*d1 + 8*d2 + ... + 2*d8 - 1*d9 must be divisible by 11
      const w = [9, 8, 7, 6, 5, 4, 3, 2, -1];
      let sum = 0;
      for (let i = 0; i < 9; i++) {
        sum += parseInt(match[i], 10) * w[i];
      }
      return sum % 11 === 0 && sum !== 0;
    },
    description: 'Dutch citizen service number (BSN: 9 digits, 11-check validated)',
  },
  {
    name: 'handelsregisterDE',
    label: 'HRB_DE',
    category: 'identity',
    regex: /\b(?:HRA|HRB|GnR|PR|VR)\s?\d{3,6}\s?[A-Z]?\b/g,
    description: 'German commercial register number (Handelsregisternummer)',
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
    regex: /\b[A-Z]{4}(?:AD|AE|AF|AG|AI|AL|AM|AO|AQ|AR|AS|AT|AU|AW|AX|AZ|BA|BB|BD|BE|BF|BG|BH|BI|BJ|BL|BM|BN|BO|BQ|BR|BS|BT|BV|BW|BY|BZ|CA|CC|CD|CF|CG|CH|CI|CK|CL|CM|CN|CO|CR|CU|CV|CW|CX|CY|CZ|DE|DJ|DK|DM|DO|DZ|EC|EE|EG|EH|ER|ES|ET|FI|FJ|FK|FM|FO|FR|GA|GB|GD|GE|GF|GG|GH|GI|GL|GM|GN|GP|GQ|GR|GS|GT|GU|GW|GY|HK|HM|HN|HR|HT|HU|ID|IE|IL|IM|IN|IO|IQ|IR|IS|IT|JE|JM|JO|JP|KE|KG|KH|KI|KM|KN|KP|KR|KW|KY|KZ|LA|LB|LC|LI|LK|LR|LS|LT|LU|LV|LY|MA|MC|MD|ME|MF|MG|MH|MK|ML|MM|MN|MO|MP|MQ|MR|MS|MT|MU|MV|MW|MX|MY|MZ|NA|NC|NE|NF|NG|NI|NL|NO|NP|NR|NU|NZ|OM|PA|PE|PF|PG|PH|PK|PL|PM|PN|PR|PS|PT|PW|PY|QA|RE|RO|RS|RU|RW|SA|SB|SC|SD|SE|SG|SH|SI|SJ|SK|SL|SM|SN|SO|SR|SS|ST|SV|SX|SY|SZ|TC|TD|TF|TG|TH|TJ|TK|TL|TM|TN|TO|TR|TT|TV|TW|TZ|UA|UG|UM|US|UY|UZ|VA|VC|VE|VG|VI|VN|VU|WF|WS|XK|YE|YT|ZA|ZM|ZW)[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b/g,
    description: 'BIC/SWIFT codes (with country code validation)',
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
    name: 'ipv4Port',
    label: 'IP_PORT',
    category: 'network',
    regex: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?):\d{1,5}\b/g,
    description: 'IPv4 addresses with port (192.168.1.1:8080)',
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
    regex: /\b\d{5}\b/g,
    description: 'German postal codes (5 digits)',
  },
  {
    name: 'postalCodeAT',
    label: 'POSTCODE_AT',
    category: 'location',
    regex: /\b[1-9]\d{3}\b/g,
    description: 'Austrian postal codes (4 digits)',
  },
  {
    name: 'postalCodeCH',
    label: 'POSTCODE_CH',
    category: 'location',
    regex: /\b[1-9]\d{3}\b/g,
    description: 'Swiss postal codes (4 digits)',
  },
  {
    name: 'postalCodeFR',
    label: 'POSTCODE_FR',
    category: 'location',
    regex: /\b(?:0[1-9]|[1-8]\d|9[0-5]|97[1-6])\d{3}\b/g,
    description: 'French postal codes (5 digits, department prefix validated)',
  },
  {
    name: 'postalCodeNL',
    label: 'POSTCODE_NL',
    category: 'location',
    regex: /\b[1-9]\d{3}\s?[A-Z]{2}\b/g,
    description: 'Dutch postal codes (1234 AB)',
  },
  {
    name: 'postalCodeIT',
    label: 'POSTCODE_IT',
    category: 'location',
    regex: /\b\d{5}\b/g,
    description: 'Italian postal codes (5 digits)',
  },
  {
    name: 'postalCodeES',
    label: 'POSTCODE_ES',
    category: 'location',
    regex: /\b(?:0[1-9]|[1-4]\d|5[0-2])\d{3}\b/g,
    description: 'Spanish postal codes (5 digits, province prefix validated)',
  },
  {
    name: 'postalCodePL',
    label: 'POSTCODE_PL',
    category: 'location',
    regex: /\b\d{2}-\d{3}\b/g,
    description: 'Polish postal codes (XX-XXX)',
  },
  {
    name: 'gpsCoordinates',
    label: 'GPS_COORDS',
    category: 'location',
    regex: /[-+]?\d{1,2}\.\d{4,},\s?[-+]?\d{1,3}\.\d{4,}/g,
    description: 'GPS coordinates (lat,lng with 4+ decimal places)',
  },
  // ═══════════════════════════════════════════
  // LOCATION — Street addresses (labeled, multiformat)
  // ═══════════════════════════════════════════
  {
    name: 'addressDE',
    label: 'ADDRESS_DE',
    category: 'location',
    regex: /(?:[A-ZÀ-ÿa-zà-ÿ]+(?:straße|strasse|str\.|weg|gasse|platz|allee|ring|damm|ufer|chaussee))\s+\d{1,5}[a-z]?(?:\s*[,\/]\s*\d{5}\s+[A-ZÀ-ÿ][a-zà-ÿ]+(?:\s+[a-zà-ÿ]+\.?\s+[A-ZÀ-ÿ][a-zà-ÿ]+)?)?/gi,
    description: 'German street addresses (Musterstraße 12, 80331 München)',
  },
  {
    name: 'addressLabeledDE',
    label: 'ADDRESS',
    category: 'location',
    regex: /(?:Adresse|Anschrift|Wohnort|Straße|Wohnadresse)[:\s]+[^\n,]{5,60}(?:,\s*\d{4,5}\s+[A-ZÀ-ÿ][a-zà-ÿ]+)?/gi,
    description: 'Labeled German addresses (Adresse: ..., Anschrift: ...)',
  },
  {
    name: 'addressLabeledEN',
    label: 'ADDRESS',
    category: 'location',
    regex: /(?:Address|Home Address|Street Address|Mailing Address|Shipping Address|Billing Address)[:\s]+[^\n]{5,80}/gi,
    description: 'Labeled English addresses (Address: ...)',
  },
  {
    name: 'addressLabeledFR',
    label: 'ADDRESS',
    category: 'location',
    regex: /(?:Adresse|Domicile|Résidence)[:\s]+[^\n]{5,80}/gi,
    description: 'Labeled French addresses (Adresse: ...)',
  },
  {
    name: 'addressEUStreetNumber',
    label: 'STREET_ADDRESS',
    category: 'location',
    regex: /\b[A-ZÀ-ÿ][a-zà-ÿ]+(?:straat|laan|weg|plein|avenue|boulevard|rue|via|calle|plaza)\s+\d{1,5}[a-z]?\b/gi,
    description: 'EU street addresses (Dutch/French/Italian/Spanish street types)',
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
      /\b(?:DOB|Date\s+of\s+Birth|Geboren\s+am|Geburtsdatum|Né\(e\)\s+le|Fecha\s+de\s+nacimiento|Data\s+di\s+nascita|Geboortedatum)[:\s]+\d{1,2}[\/.]\d{1,2}[\/.]\d{2,4}\b/gi,
    description: 'Date of birth with label prefix (EN/DE/FR/ES/IT/NL)',
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

  // ═══════════════════════════════════════════
  // IDENTITY — Global National IDs (extended)
  // ═══════════════════════════════════════════
  {
    name: 'itinUS',
    label: 'ITIN_US',
    category: 'identity',
    regex: /\b9\d{2}-[7-9]\d-\d{4}\b/g,
    description: 'US Individual Taxpayer Identification Number (ITIN)',
  },
  {
    name: 'sinCA',
    label: 'SIN_CA',
    category: 'identity',
    regex: /\b\d{3}[\s\-]\d{3}[\s\-]\d{3}\b/g,
    validate: (match: string) => luhnCheck(match),
    description: 'Canadian Social Insurance Number (SIN, Luhn validated)',
  },
  {
    name: 'ninoUK',
    label: 'NINO_UK',
    category: 'identity',
    regex: /\b[A-CEGHJ-PR-TW-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b/g,
    description: 'UK National Insurance Number (NINO)',
  },
  {
    name: 'passportDE',
    label: 'PASSPORT_DE',
    category: 'identity',
    regex: /\b[CFGHJK][0-9A-Z]{8}\b/g,
    description: 'German passport number (Reisepassnummer)',
  },
  {
    name: 'rrnBE',
    label: 'RRN_BE',
    category: 'identity',
    regex: /\b\d{2}[.\-]?\d{2}[.\-]?\d{2}[.\-]?\d{3}[.\-]?\d{2}\b/g,
    description: 'Belgian national register number (Rijksregisternummer)',
  },
  {
    name: 'personnummerSE',
    label: 'PERSONNUMMER_SE',
    category: 'identity',
    regex: /\b\d{6}[\-+]?\d{4}\b|\b\d{8}[\-+]?\d{4}\b/g,
    description: 'Swedish personal identity number (Personnummer)',
  },
  {
    name: 'fodselsnummerNO',
    label: 'FODSELSNR_NO',
    category: 'identity',
    regex: /\b\d{6}\s?\d{5}\b/g,
    description: 'Norwegian national ID (Fødselsnummer, 11 digits)',
  },
  {
    name: 'cprDK',
    label: 'CPR_DK',
    category: 'identity',
    regex: /\b\d{6}-?\d{4}\b/g,
    description: 'Danish personal ID (CPR-nummer)',
  },
  {
    name: 'hetuFI',
    label: 'HETU_FI',
    category: 'identity',
    regex: /\b\d{6}[\-+A-Y]\d{3}[0-9A-Y]\b/g,
    description: 'Finnish personal ID (Henkilötunnus / HETU)',
  },
  {
    name: 'nifPT',
    label: 'NIF_PT',
    category: 'identity',
    regex: /\b[1-9]\d{8}\b/g,
    validate: (match: string) => {
      const w = [9, 8, 7, 6, 5, 4, 3, 2];
      let sum = 0;
      for (let i = 0; i < 8; i++) {
        sum += parseInt(match[i], 10) * w[i];
      }
      let check = 11 - (sum % 11);
      if (check >= 10) check = 0;
      return parseInt(match[8], 10) === check;
    },
    description: 'Portuguese tax number (NIF, checksum validated)',
  },
  {
    name: 'ppsIE',
    label: 'PPS_IE',
    category: 'identity',
    regex: /\b\d{7}[A-W][A-IW]?\b/g,
    description: 'Irish Personal Public Service number (PPS)',
  },
  {
    name: 'tfnAU',
    label: 'TFN_AU',
    category: 'identity',
    regex: /\b\d{3}\s?\d{3}\s?\d{3}\b/g,
    validate: (match: string) => {
      const digits = match.replace(/\s/g, '');
      if (digits.length !== 9) return false;
      const w = [1, 4, 3, 7, 5, 8, 6, 9, 10];
      let sum = 0;
      for (let i = 0; i < 9; i++) {
        sum += parseInt(digits[i], 10) * w[i];
      }
      return sum % 11 === 0;
    },
    description: 'Australian Tax File Number (TFN, checksum validated)',
  },
  {
    name: 'medicareAU',
    label: 'MEDICARE_AU',
    category: 'identity',
    regex: /\b\d{4}\s?\d{5}\s?\d\b/g,
    description: 'Australian Medicare number',
  },
  {
    name: 'irdNZ',
    label: 'IRD_NZ',
    category: 'identity',
    regex: /\b\d{2,3}-?\d{3}-?\d{3}\b/g,
    description: 'New Zealand IRD number',
  },
  {
    name: 'myNumberJP',
    label: 'MY_NUMBER_JP',
    category: 'identity',
    regex: /\b\d{4}\s?\d{4}\s?\d{4}\b/g,
    description: 'Japanese My Number (Individual Number, 12 digits)',
  },
  {
    name: 'rrnKR',
    label: 'RRN_KR',
    category: 'identity',
    regex: /\b\d{6}[\s\-]?\d{7}\b/g,
    description: 'South Korean Resident Registration Number (RRN)',
  },
  {
    name: 'nricSG',
    label: 'NRIC_SG',
    category: 'identity',
    regex: /\b[STFGM]\d{7}[A-Z]\b/g,
    description: 'Singapore National Registration Identity Card (NRIC/FIN)',
  },
  {
    name: 'aadhaarIN',
    label: 'AADHAAR_IN',
    category: 'identity',
    regex: /\b\d{4}\s?\d{4}\s?\d{4}\b/g,
    description: 'Indian Aadhaar number (12 digits)',
  },
  {
    name: 'panIN',
    label: 'PAN_IN',
    category: 'identity',
    regex: /\b[A-Z]{3}[ABCFGHLJPTK][A-Z]\d{4}[A-Z]\b/g,
    description: 'Indian PAN card (Permanent Account Number)',
  },
  {
    name: 'cpfBR',
    label: 'CPF_BR',
    category: 'identity',
    regex: /\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b/g,
    description: 'Brazilian individual taxpayer ID (CPF)',
  },
  {
    name: 'nifES',
    label: 'NIF_ES',
    category: 'identity',
    regex: /\b[A-HJ-NP-SUVW]\d{7}[0-9A-J]\b/g,
    description: 'Spanish company tax ID (NIF)',
  },
  {
    name: 'cartaIdIT',
    label: 'CARTA_ID_IT',
    category: 'identity',
    regex: /\b[A-Z]{2}\d{5}[A-Z]{2}\b/g,
    description: 'Italian electronic identity card (Carta d\'Identità)',
  },
  {
    name: 'driverLicenseCtx',
    label: 'DRIVER_LICENSE',
    category: 'identity',
    regex: /(?:driver'?s?\s*(?:license|licence|lic)|DL)[#:\s]*[A-Z]{0,2}\d{4,13}/gi,
    description: 'Driver license numbers (contextual, with label prefix)',
  },

  // ═══════════════════════════════════════════
  // FINANCIAL — Extended
  // ═══════════════════════════════════════════
  {
    name: 'abaRouting',
    label: 'ABA_ROUTING',
    category: 'financial',
    regex: /\b(?:0[1-9]|[12]\d|3[0-2]|6[1-9]|7[0-2]|80)\d{7}\b/g,
    validate: (match: string) => {
      const d = match.split('').map(Number);
      return (3 * (d[0] + d[3] + d[6]) + 7 * (d[1] + d[4] + d[7]) + (d[2] + d[5] + d[8])) % 10 === 0;
    },
    description: 'US ABA routing number (checksum validated)',
  },
  {
    name: 'sortCodeUK',
    label: 'SORT_CODE_UK',
    category: 'financial',
    regex: /\b\d{2}-\d{2}-\d{2}\b/g,
    description: 'UK bank sort code',
  },
  {
    name: 'amex',
    label: 'AMEX',
    category: 'financial',
    regex: /\b3[47]\d{2}[\s\-]?\d{6}[\s\-]?\d{5}\b/g,
    validate: (match: string) => luhnCheck(match),
    description: 'American Express card numbers (Luhn validated)',
  },

  // ═══════════════════════════════════════════
  // ENTERPRISE — Infrastructure & Secrets
  // ═══════════════════════════════════════════
  {
    name: 'internalHostname',
    label: 'INTERNAL_HOST',
    category: 'enterprise',
    regex: /\b[a-z][a-z0-9\-]+\.(?:internal|local|corp|intranet|lan|private|home\.arpa)(?:\.[a-z]+)*\b/gi,
    description: 'Internal/intranet hostnames (.internal, .local, .corp, .lan)',
  },
  {
    name: 'uncPath',
    label: 'UNC_PATH',
    category: 'enterprise',
    regex: /\\\\[a-zA-Z0-9._\-]+\\[a-zA-Z0-9$._\- \\]+/g,
    description: 'Windows UNC network paths (\\\\server\\share)',
  },
  {
    name: 'ldapDN',
    label: 'LDAP_DN',
    category: 'enterprise',
    regex: /(?:CN|OU|DC|O|C|L|ST)=[^,]+(?:,\s*(?:CN|OU|DC|O|C|L|ST)=[^,]+){1,}/gi,
    description: 'LDAP Distinguished Names (CN=...,OU=...,DC=...)',
  },
  {
    name: 'adUsername',
    label: 'AD_USERNAME',
    category: 'enterprise',
    regex: /\b[A-Z][A-Z0-9]{1,15}\\[a-zA-Z][a-zA-Z0-9._\-]{1,20}\b/g,
    description: 'Active Directory usernames (DOMAIN\\user)',
  },
  {
    name: 'privateIp',
    label: 'PRIVATE_IP',
    category: 'enterprise',
    regex: /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/g,
    description: 'Private/internal IP addresses (RFC 1918: 10.x, 172.16-31.x, 192.168.x)',
  },
  {
    name: 'dbConnectionString',
    label: 'DB_CONN_STRING',
    category: 'enterprise',
    regex: /(?:jdbc|mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis(?:s)?|mssql|mariadb):\/\/[^\s"']+/gi,
    description: 'Database connection strings (JDBC, MongoDB, PostgreSQL, MySQL, Redis)',
  },
  {
    name: 'connStringKV',
    label: 'CONN_STRING',
    category: 'enterprise',
    regex: /(?:Server|Data Source|Host)=[^;]+;[^;]*(?:;[^;]*){0,10}(?:Password|Pwd)=[^;]+/gi,
    description: 'Connection strings with credentials (ADO.NET / key=value style)',
  },
  {
    name: 'awsAccessKey',
    label: 'AWS_KEY',
    category: 'enterprise',
    regex: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g,
    description: 'AWS Access Key IDs',
  },
  {
    name: 'gcpApiKey',
    label: 'GCP_KEY',
    category: 'enterprise',
    regex: /\bAIza[0-9A-Za-z_\-]{35}\b/g,
    description: 'Google Cloud API keys',
  },
  {
    name: 'stripeKey',
    label: 'STRIPE_KEY',
    category: 'enterprise',
    regex: /\b[sr]k_(?:live|test)_[A-Za-z0-9]{24,}\b/g,
    description: 'Stripe API keys (secret and publishable)',
  },
  {
    name: 'openaiKey',
    label: 'OPENAI_KEY',
    category: 'enterprise',
    regex: /\bsk-[A-Za-z0-9]{20,}\b/g,
    description: 'OpenAI API keys',
  },
  {
    name: 'githubToken',
    label: 'GITHUB_TOKEN',
    category: 'enterprise',
    regex: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}\b/g,
    description: 'GitHub personal access tokens',
  },
  {
    name: 'slackToken',
    label: 'SLACK_TOKEN',
    category: 'enterprise',
    regex: /\bxox[boaprs]-[A-Za-z0-9\-]+/g,
    description: 'Slack API tokens',
  },
  {
    name: 'bearerToken',
    label: 'BEARER_TOKEN',
    category: 'enterprise',
    regex: /Bearer\s+[A-Za-z0-9\-._~+\/]+=*/g,
    description: 'Bearer authentication tokens',
  },
  {
    name: 'jwtToken',
    label: 'JWT',
    category: 'enterprise',
    regex: /\beyJ[A-Za-z0-9_\-]*\.eyJ[A-Za-z0-9_\-]*\.[A-Za-z0-9_\-]+/g,
    description: 'JSON Web Tokens (JWT)',
  },
  {
    name: 'pemPrivateKey',
    label: 'PRIVATE_KEY',
    category: 'enterprise',
    regex: /-----BEGIN (?:RSA |DSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/g,
    description: 'PEM private key headers',
  },
  {
    name: 'sshPublicKey',
    label: 'SSH_KEY',
    category: 'enterprise',
    regex: /ssh-(?:rsa|dss|ed25519|ecdsa)\s+[A-Za-z0-9+\/=]{40,}/g,
    description: 'SSH public keys',
  },
  {
    name: 'genericSecret',
    label: 'SECRET',
    category: 'enterprise',
    regex: /(?:password|passwd|pwd|secret|token|credential|auth_key|api_key|apikey|api_secret|api_token|access_token|secret_key|private_key|encryption_key)\s*[=:]\s*['"]?[^\s'"]{8,}['"]?/gi,
    description: 'Secrets in config (password=, api_key=, secret=, token=, etc.)',
  },
  {
    name: 'azureKey',
    label: 'AZURE_KEY',
    category: 'enterprise',
    regex: /(?:AccountKey|SharedAccessSignature)\s*=\s*[A-Za-z0-9+\/=]{44,88}/gi,
    description: 'Azure storage keys and SAS tokens',
  },
  {
    name: 'slackWebhook',
    label: 'SLACK_WEBHOOK',
    category: 'enterprise',
    regex: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/g,
    description: 'Slack webhook URLs',
  },

  // ═══════════════════════════════════════════
  // MEDICAL — Extended (HIPAA)
  // ═══════════════════════════════════════════
  {
    name: 'deaNumber',
    label: 'DEA_NUMBER',
    category: 'medical',
    regex: /\b[ABCDEFGHJKLMNPRSTUXabcdefghjklmnprstux][A-Za-z9]\d{7}\b/g,
    description: 'US DEA registration numbers',
  },
  {
    name: 'npiNumber',
    label: 'NPI',
    category: 'medical',
    regex: /(?:NPI)[#:\s]*\d{10}\b/gi,
    description: 'US National Provider Identifier (NPI, contextual)',
  },
  {
    name: 'rxNumber',
    label: 'RX_NUMBER',
    category: 'medical',
    regex: /(?:Rx|RX|Prescription)\s*#?\s*:?\s*\d{6,12}\b/gi,
    description: 'Prescription / Rx numbers',
  },

  // ═══════════════════════════════════════════
  // VEHICLE
  // ═══════════════════════════════════════════
  {
    name: 'vin',
    label: 'VIN',
    category: 'vehicle',
    regex: /\b[A-HJ-NPR-Z0-9]{17}\b/g,
    description: 'Vehicle Identification Number (VIN, 17 chars)',
  },
  {
    name: 'licensePlateDE',
    label: 'LICENSE_PLATE_DE',
    category: 'vehicle',
    regex: /\b[A-ZÄÖÜ]{1,3}\s[A-Z]{1,2}\s\d{1,4}[EH]?\b/g,
    description: 'German license plates (M AB 1234, requires spaces)',
  },
  {
    name: 'licensePlateUK',
    label: 'LICENSE_PLATE_UK',
    category: 'vehicle',
    regex: /\b[A-Z]{2}\d{2}\s?[A-Z]{3}\b/g,
    description: 'UK license plates (AB12 CDE)',
  },
  {
    name: 'licensePlateFR',
    label: 'LICENSE_PLATE_FR',
    category: 'vehicle',
    regex: /\b[A-Z]{2}-\d{3}-[A-Z]{2}\b/g,
    description: 'French license plates (AB-123-CD)',
  },

  // ═══════════════════════════════════════════
  // BIOMETRIC / DIGITAL IDENTITY
  // ═══════════════════════════════════════════
  {
    name: 'uuid',
    label: 'UUID',
    category: 'biometric',
    regex: /\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/g,
    description: 'UUIDs / GUIDs',
  },
  {
    name: 'socialHandle',
    label: 'SOCIAL_HANDLE',
    category: 'biometric',
    regex: /(?<=^|\s)@[a-zA-Z_][a-zA-Z0-9_.]{1,30}\b/g,
    description: 'Social media handles (@username)',
  },
  {
    name: 'imei',
    label: 'IMEI',
    category: 'biometric',
    regex: /\b\d{2}-\d{6}-\d{6}-\d\b/g,
    description: 'IMEI device identifiers (formatted)',
  },
  {
    name: 'iccid',
    label: 'ICCID',
    category: 'biometric',
    regex: /\b89\d{17,19}\b/g,
    description: 'SIM card ICCID numbers',
  },

  // ═══════════════════════════════════════════
  // CONTACT — Extended global phone numbers
  // ═══════════════════════════════════════════
  {
    name: 'phoneIT',
    label: 'PHONE_IT',
    category: 'contact',
    regex: /(?:\+?39[\s\-.])\d{2,4}[\s\-.]\d{4,8}/g,
    description: 'Italian phone numbers (requires +39 prefix)',
  },
  {
    name: 'phoneES',
    label: 'PHONE_ES',
    category: 'contact',
    regex: /\b(?:\+?34[\s\-.]?)?\d{3}[\s\-.]\d{3}[\s\-.]\d{3}\b/g,
    description: 'Spanish phone numbers',
  },
  {
    name: 'phoneAU',
    label: 'PHONE_AU',
    category: 'contact',
    regex: /\b(?:\+?61[\s\-.]?)?0?\d[\s\-.]\d{4}[\s\-.]\d{4}\b/g,
    description: 'Australian phone numbers',
  },
  {
    name: 'phoneIN',
    label: 'PHONE_IN',
    category: 'contact',
    regex: /\b(?:\+?91[\s\-.]?)?[6-9]\d{4}[\s\-.]\d{5}\b/g,
    description: 'Indian phone numbers',
  },
  {
    name: 'phoneJP',
    label: 'PHONE_JP',
    category: 'contact',
    regex: /\b(?:\+?81[\s\-.]?)?0?\d{1,4}[\s\-.]\d{1,4}[\s\-.]\d{4}\b/g,
    description: 'Japanese phone numbers',
  },
  {
    name: 'phoneBR',
    label: 'PHONE_BR',
    category: 'contact',
    regex: /\b(?:\+?55[\s\-.]?)?\(?\d{2}\)?[\s\-.]?\d{4,5}[\s\-.]\d{4}\b/g,
    description: 'Brazilian phone numbers',
  },
  {
    name: 'faxCtx',
    label: 'FAX',
    category: 'contact',
    regex: /(?:fax|facsimile|telefax)[:\s#]*(?:\+?\d[\d\s\-().]{7,20})/gi,
    description: 'Fax numbers (contextual, with label prefix)',
  },
  {
    name: 'phoneCN',
    label: 'PHONE_CN',
    category: 'contact',
    regex: /\b(?:\+?86[\s\-.]?)?1[3-9]\d{9}\b/g,
    description: 'Chinese mobile phone numbers',
  },
  {
    name: 'phoneKR',
    label: 'PHONE_KR',
    category: 'contact',
    regex: /\b(?:\+?82[\s\-.]?)?0?\d{1,2}[\s\-.]\d{3,4}[\s\-.]\d{4}\b/g,
    description: 'South Korean phone numbers',
  },
  {
    name: 'phoneRU',
    label: 'PHONE_RU',
    category: 'contact',
    regex: /\b(?:\+?7[\s\-.]?)?\d{3}[\s\-.]\d{3}[\s\-.]\d{2}[\s\-.]\d{2}\b/g,
    description: 'Russian phone numbers',
  },
  {
    name: 'phoneMX',
    label: 'PHONE_MX',
    category: 'contact',
    regex: /\b(?:\+?52[\s\-.]?)?\d{2,3}[\s\-.]\d{3,4}[\s\-.]\d{4}\b/g,
    description: 'Mexican phone numbers',
  },
  {
    name: 'phoneZA',
    label: 'PHONE_ZA',
    category: 'contact',
    regex: /\b(?:\+?27[\s\-.]?)?0?\d{2}[\s\-.]\d{3}[\s\-.]\d{4}\b/g,
    description: 'South African phone numbers',
  },

  // ═══════════════════════════════════════════
  // IDENTITY — Extended global (Asia, LATAM, MENA, Africa)
  // ═══════════════════════════════════════════
  {
    name: 'nationalIdCN',
    label: 'NATIONAL_ID_CN',
    category: 'identity',
    regex: /\b\d{6}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b/g,
    description: 'Chinese Resident Identity Card number (18 digits)',
  },
  {
    name: 'nationalIdZA',
    label: 'NATIONAL_ID_ZA',
    category: 'identity',
    regex: /\b\d{6}\s?\d{4}\s?\d{3}\b/g,
    description: 'South African ID number (13 digits)',
  },
  {
    name: 'nationalIdTH',
    label: 'NATIONAL_ID_TH',
    category: 'identity',
    regex: /\b\d-\d{4}-\d{5}-\d{2}-\d\b/g,
    description: 'Thai National ID (13 digits with dashes)',
  },
  {
    name: 'nationalIdMY',
    label: 'NRIC_MY',
    category: 'identity',
    regex: /\b\d{6}-?\d{2}-?\d{4}\b/g,
    description: 'Malaysian NRIC (12 digits)',
  },
  {
    name: 'nationalIdTR',
    label: 'TC_KIMLIK_TR',
    category: 'identity',
    regex: /\b[1-9]\d{10}\b/g,
    description: 'Turkish national ID (TC Kimlik No, 11 digits)',
  },
  {
    name: 'curpMX',
    label: 'CURP_MX',
    category: 'identity',
    regex: /\b[A-Z]{4}\d{6}[HM][A-Z]{5}[A-Z0-9]\d\b/g,
    description: 'Mexican CURP (population registry code)',
  },
  {
    name: 'rfcMX',
    label: 'RFC_MX',
    category: 'identity',
    regex: /\b[A-Z&]{3,4}\d{6}[A-Z0-9]{3}\b/g,
    description: 'Mexican RFC (tax ID)',
  },
  {
    name: 'nationalIdHK',
    label: 'HKID',
    category: 'identity',
    regex: /\b[A-Z]{1,2}\d{6}\(?\d\)?\b/g,
    description: 'Hong Kong ID card number',
  },
  {
    name: 'nationalIdTW',
    label: 'NATIONAL_ID_TW',
    category: 'identity',
    regex: /\b[A-Z][12]\d{8}\b/g,
    description: 'Taiwan National ID number',
  },
  {
    name: 'emiratesIdUAE',
    label: 'EMIRATES_ID',
    category: 'identity',
    regex: /\b784-\d{4}-\d{7}-\d\b/g,
    description: 'UAE Emirates ID number',
  },
  {
    name: 'rgBR',
    label: 'RG_BR',
    category: 'identity',
    regex: /\b\d{2}\.?\d{3}\.?\d{3}-?\d\b/g,
    description: 'Brazilian RG (Registro Geral)',
  },
  {
    name: 'cnpjBR',
    label: 'CNPJ_BR',
    category: 'identity',
    regex: /\b\d{2}\.?\d{3}\.?\d{3}\/?\d{4}-?\d{2}\b/g,
    description: 'Brazilian CNPJ (company registration)',
  },
  {
    name: 'driverLicenseUK',
    label: 'DRIVER_LICENSE_UK',
    category: 'identity',
    regex: /\b[A-Z]{5}\d{6}[A-Z]{2}\d[A-Z]{2}\b/g,
    description: 'UK driving licence number (16 characters)',
  },
  {
    name: 'krankenversichertDE',
    label: 'HEALTH_INS_DE',
    category: 'identity',
    regex: /\b[A-Z]\d{9}\b/g,
    description: 'German health insurance number (Krankenversichertennummer)',
  },
  {
    name: 'romanianCNP',
    label: 'CNP_RO',
    category: 'identity',
    regex: /\b[1-9]\d{12}\b/g,
    description: 'Romanian personal numeric code (CNP, 13 digits)',
  },
  {
    name: 'croatianOIB',
    label: 'OIB_HR',
    category: 'identity',
    regex: /\b\d{11}\b/g,
    description: 'Croatian personal identification number (OIB, 11 digits)',
  },
  {
    name: 'mothersMaidenName',
    label: 'MAIDEN_NAME',
    category: 'identity',
    regex: /(?:mother'?s?\s*maiden\s*name|Geburtsname|nom\s+de\s+jeune\s+fille)[:\s]+[A-ZÀ-ÿ][a-zà-ÿ]+/gi,
    description: 'Mother\'s maiden name (security question, labeled)',
  },
  {
    name: 'passportCtx',
    label: 'PASSPORT',
    category: 'identity',
    regex: /(?:passport\s*(?:no|number|#|num))[:\s]*[A-Z0-9]{6,12}/gi,
    description: 'Passport numbers (generic contextual with label)',
  },
  {
    name: 'voterRegCtx',
    label: 'VOTER_REG',
    category: 'identity',
    regex: /(?:voter\s*(?:reg(?:istration)?|ID)\s*#?)[:\s]*[A-Z0-9]{5,15}/gi,
    description: 'Voter registration numbers (contextual)',
  },
  {
    name: 'militaryIdCtx',
    label: 'MILITARY_ID',
    category: 'identity',
    regex: /(?:military\s*ID|DOD\s*ID|CAC)[:\s#]*\d{10}/gi,
    description: 'Military / DOD ID numbers (contextual)',
  },
  {
    name: 'immigrationCtx',
    label: 'IMMIGRATION_ID',
    category: 'identity',
    regex: /(?:visa|immigration|I-94|A-number|alien\s*(?:reg(?:istration)?)?\s*#?)[:\s#]*[A-Z]?\d{7,13}/gi,
    description: 'Immigration / visa / alien registration numbers (contextual)',
  },
  {
    name: 'professionalLicenseCtx',
    label: 'PROF_LICENSE',
    category: 'identity',
    regex: /(?:bar\s*(?:number|#)|CPA\s*(?:license|#)|medical\s*license|nursing\s*license|license\s*#)[:\s]*[A-Z0-9\-]{4,15}/gi,
    description: 'Professional license numbers (bar, CPA, medical, nursing)',
  },
  {
    name: 'employeeIdCtx',
    label: 'EMPLOYEE_ID',
    category: 'identity',
    regex: /(?:employee\s*(?:ID|number|#|no)|Personalnummer|Mitarbeiternummer)[:\s]*[A-Z0-9\-]{3,15}/gi,
    description: 'Employee ID numbers (contextual, EN/DE)',
  },
  {
    name: 'fullNameCtx',
    label: 'FULL_NAME',
    category: 'identity',
    regex: /(?:full\s*name|first\s*name|last\s*name|surname|family\s*name|given\s*name|Vorname|Nachname|Familienname|nom\s*de\s*famille|prenom|nombre|apellido)[:\s]+[A-ZÀ-ÿ][a-zà-ÿ]+(?:\s+[A-ZÀ-ÿ][a-zà-ÿ]+){0,3}/gi,
    description: 'Full name, first name, last name (labeled, multi-language)',
  },
  {
    name: 'departmentCtx',
    label: 'DEPARTMENT',
    category: 'identity',
    regex: /(?:department|Abteilung|departement|service)[:\s]+[A-ZÀ-ÿa-zà-ÿ\s&\-]{2,40}/gi,
    description: 'Department name (contextual, EN/DE/FR)',
  },
  {
    name: 'jobTitleCtx',
    label: 'JOB_TITLE',
    category: 'identity',
    regex: /(?:position|job\s*title|role|Berufsbezeichnung|Stelle|titulo|poste)[:\s]+[A-ZÀ-ÿa-zà-ÿ\s\-\/]{2,50}/gi,
    description: 'Job title / position (contextual, EN/DE/FR/ES)',
  },
  {
    name: 'hiringDateCtx',
    label: 'HIRING_DATE',
    category: 'temporal',
    regex: /(?:hiring\s*date|start\s*date|date\s*of\s*hire|Eintrittsdatum|Einstellungsdatum|date\s*d'?embauche)[:\s]*\d{1,2}[\/.\-]\d{1,2}[\/.\-]\d{2,4}/gi,
    description: 'Hiring / start date (contextual, EN/DE/FR)',
  },
  {
    name: 'payrollCtx',
    label: 'PAYROLL',
    category: 'financial',
    regex: /(?:payroll\s*(?:#|number|no)|Lohnsteuernummer)[:\s]*[A-Z0-9\-]{4,15}/gi,
    description: 'Payroll numbers (contextual, EN/DE)',
  },
  {
    name: 'workersCompCtx',
    label: 'WORKERS_COMP',
    category: 'financial',
    regex: /(?:workers?\s*comp|WC)\s*(?:claim|#)[:\s]*[A-Z0-9\-]{5,15}/gi,
    description: 'Workers compensation claim numbers (contextual)',
  },

  // ═══════════════════════════════════════════
  // FINANCIAL — Extended (PCI-DSS, GLBA, SOX)
  // ═══════════════════════════════════════════
  {
    name: 'cardExpiry',
    label: 'CARD_EXPIRY',
    category: 'financial',
    regex: /\b(?:0[1-9]|1[0-2])\s*[\/\-]\s*(?:\d{2}|\d{4})\b/g,
    description: 'Credit/debit card expiry dates (MM/YY or MM/YYYY)',
  },
  {
    name: 'cvvCtx',
    label: 'CVV',
    category: 'financial',
    regex: /(?:CVV|CVC|CVV2|CVC2|CID|security\s*code)[:\s#]*\d{3,4}/gi,
    description: 'Card verification codes (CVV/CVC, contextual)',
  },
  {
    name: 'bankAccountCtx',
    label: 'BANK_ACCOUNT',
    category: 'financial',
    regex: /(?:account\s*(?:no|number|#|num)|acct)[:\s#]*\d{8,17}/gi,
    description: 'Bank account numbers (contextual with label)',
  },
  {
    name: 'insurancePolicyCtx',
    label: 'INSURANCE_POLICY',
    category: 'financial',
    regex: /(?:policy|insurance)\s*(?:#|number|no)[:\s]*[A-Z0-9\-]{5,20}/gi,
    description: 'Insurance policy numbers (contextual)',
  },
  {
    name: 'insuranceClaimCtx',
    label: 'INSURANCE_CLAIM',
    category: 'financial',
    regex: /(?:claim)\s*(?:#|number|no|ref)[:\s]*[A-Z0-9\-]{5,20}/gi,
    description: 'Insurance claim reference numbers (contextual)',
  },
  {
    name: 'wireTransferCtx',
    label: 'WIRE_TRANSFER',
    category: 'financial',
    regex: /(?:wire|transfer|remittance)\s*(?:#|ref|reference)[:\s]*[A-Z0-9]{6,20}/gi,
    description: 'Wire transfer reference numbers (contextual)',
  },
  {
    name: 'loanNumberCtx',
    label: 'LOAN_NUMBER',
    category: 'financial',
    regex: /(?:mortgage|loan)\s*(?:#|number|no|acct)[:\s]*[A-Z0-9\-]{6,20}/gi,
    description: 'Mortgage / loan account numbers (contextual)',
  },
  {
    name: 'salaryCtx',
    label: 'SALARY',
    category: 'financial',
    regex: /(?:salary|compensation|Gehalt|salaire|annual\s*pay|hourly\s*rate|income)[:\s]*[$€£¥]?\s?[\d,]+(?:\.\d{2})?/gi,
    description: 'Salary / compensation amounts (contextual, multi-currency)',
  },
  {
    name: 'taxReturnCtx',
    label: 'TAX_RETURN',
    category: 'financial',
    regex: /(?:W-?2|1099|W-?4|1040|AGI|adjusted\s*gross\s*income)[:\s]*[$]?[\d,.]+/gi,
    description: 'US tax form references and amounts (W-2, 1099, AGI)',
  },

  // ═══════════════════════════════════════════
  // MEDICAL — Extended (HIPAA 18 identifiers + codes)
  // ═══════════════════════════════════════════
  {
    name: 'ndcDrugCode',
    label: 'NDC_CODE',
    category: 'medical',
    regex: /\b\d{4,5}-\d{3,4}-\d{1,2}\b/g,
    description: 'National Drug Code (NDC)',
  },
  {
    name: 'healthPlanCtx',
    label: 'HEALTH_PLAN_ID',
    category: 'medical',
    regex: /(?:member\s*ID|beneficiary|subscriber|health\s*plan)[:\s#]*[A-Z0-9]{6,20}/gi,
    description: 'Health plan beneficiary / member ID (contextual)',
  },
  {
    name: 'bloodTypeCtx',
    label: 'BLOOD_TYPE',
    category: 'medical',
    regex: /(?:blood\s*type|blood\s*group)[:\s]*(?:A|B|AB|O)[+-]?/gi,
    description: 'Blood type (contextual)',
  },
  {
    name: 'deviceSerialCtx',
    label: 'DEVICE_SERIAL',
    category: 'medical',
    regex: /(?:serial\s*(?:#|number|no)|S\/N|UDI)[:\s]*[A-Z0-9\-]{6,20}/gi,
    description: 'Medical device serial numbers / UDI (contextual)',
  },

  // ═══════════════════════════════════════════
  // LOCATION — Extended postal codes (global)
  // ═══════════════════════════════════════════
  {
    name: 'postalCodeCA',
    label: 'POSTCODE_CA',
    category: 'location',
    regex: /\b[A-Z]\d[A-Z]\s?\d[A-Z]\d\b/g,
    description: 'Canadian postal codes (A1A 1A1)',
  },
  {
    name: 'postalCodeJP',
    label: 'POSTCODE_JP',
    category: 'location',
    regex: /\b\d{3}-\d{4}\b/g,
    description: 'Japanese postal codes (XXX-XXXX)',
  },
  {
    name: 'postalCodeBR',
    label: 'CEP_BR',
    category: 'location',
    regex: /\b\d{5}-?\d{3}\b/g,
    description: 'Brazilian postal codes / CEP',
  },
  {
    name: 'postalCodeIN',
    label: 'PIN_IN',
    category: 'location',
    regex: /\b[1-9]\d{5}\b/g,
    description: 'Indian PIN codes (6 digits)',
  },

  // ═══════════════════════════════════════════
  // ENTERPRISE — Extended API keys & secrets
  // ═══════════════════════════════════════════
  {
    name: 'sendgridKey',
    label: 'SENDGRID_KEY',
    category: 'enterprise',
    regex: /\bSG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}\b/g,
    description: 'SendGrid API keys',
  },
  {
    name: 'twilioKey',
    label: 'TWILIO_KEY',
    category: 'enterprise',
    regex: /\bSK[a-f0-9]{32}\b/g,
    description: 'Twilio API keys',
  },
  {
    name: 'mailgunKey',
    label: 'MAILGUN_KEY',
    category: 'enterprise',
    regex: /\bkey-[A-Za-z0-9]{32}\b/g,
    description: 'Mailgun API keys',
  },
  {
    name: 'gitlabToken',
    label: 'GITLAB_TOKEN',
    category: 'enterprise',
    regex: /\bglpat-[A-Za-z0-9\-]{20}\b/g,
    description: 'GitLab personal access tokens',
  },
  {
    name: 'anthropicKey',
    label: 'ANTHROPIC_KEY',
    category: 'enterprise',
    regex: /\bsk-ant-[A-Za-z0-9\-]{90,}\b/g,
    description: 'Anthropic / Claude API keys',
  },
  {
    name: 'npmToken',
    label: 'NPM_TOKEN',
    category: 'enterprise',
    regex: /\bnpm_[A-Za-z0-9]{36}\b/g,
    description: 'npm authentication tokens',
  },
  {
    name: 'shopifyKey',
    label: 'SHOPIFY_KEY',
    category: 'enterprise',
    regex: /\bshp(?:at|ss|pa)_[a-fA-F0-9]{32}\b/g,
    description: 'Shopify API keys',
  },
  {
    name: 'telegramBotToken',
    label: 'TELEGRAM_TOKEN',
    category: 'enterprise',
    regex: /\b\d{8,10}:[A-Za-z0-9_-]{35}\b/g,
    description: 'Telegram bot tokens',
  },
  {
    name: 'discordBotToken',
    label: 'DISCORD_TOKEN',
    category: 'enterprise',
    regex: /\b[A-Za-z0-9]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}\b/g,
    description: 'Discord bot tokens',
  },
  {
    name: 'huggingfaceToken',
    label: 'HF_TOKEN',
    category: 'enterprise',
    regex: /\bhf_[A-Za-z0-9]{34,}\b/g,
    description: 'Hugging Face API tokens',
  },
  {
    name: 'digitaloceanToken',
    label: 'DO_TOKEN',
    category: 'enterprise',
    regex: /\bdop_v1_[a-f0-9]{64}\b/g,
    description: 'DigitalOcean personal access tokens',
  },
  {
    name: 'hashicorpVaultToken',
    label: 'VAULT_TOKEN',
    category: 'enterprise',
    regex: /\bhvs\.[A-Za-z0-9]{24,}\b/g,
    description: 'HashiCorp Vault tokens',
  },
  {
    name: 'httpBasicAuth',
    label: 'HTTP_BASIC_AUTH',
    category: 'enterprise',
    regex: /Authorization:\s*Basic\s+[A-Za-z0-9+\/=]+/g,
    description: 'HTTP Basic Authentication headers',
  },
  {
    name: 'apiKeyInUrl',
    label: 'API_KEY_URL',
    category: 'enterprise',
    regex: /[?&](?:api_?key|token|access_token|auth)=[A-Za-z0-9\-._~+\/]{8,}/gi,
    description: 'API keys exposed in URLs',
  },
  {
    name: 'x509Certificate',
    label: 'X509_CERT',
    category: 'enterprise',
    regex: /-----BEGIN CERTIFICATE-----/g,
    description: 'X.509 certificate headers',
  },
  {
    name: 'pgpPrivateKey',
    label: 'PGP_KEY',
    category: 'enterprise',
    regex: /-----BEGIN PGP PRIVATE KEY BLOCK-----/g,
    description: 'PGP private key block headers',
  },
  {
    name: 'envSecrets',
    label: 'ENV_SECRET',
    category: 'enterprise',
    regex: /\b(?:DATABASE_URL|DB_PASSWORD|DB_PASS|REDIS_URL|MONGO_URI|SECRET_KEY|ENCRYPTION_KEY|MASTER_KEY|SMTP_PASSWORD|MAIL_PASSWORD)=[^\s]+/g,
    description: 'Environment variable secrets (DATABASE_URL, DB_PASSWORD, etc.)',
  },
  {
    name: 'googleAnalyticsId',
    label: 'GA_ID',
    category: 'enterprise',
    regex: /\bUA-\d{4,10}-\d{1,4}\b|\bG-[A-Z0-9]{10}\b/g,
    description: 'Google Analytics tracking IDs',
  },

  // ═══════════════════════════════════════════
  // GDPR ARTICLE 9 — Sensitive keyword detection
  // ═══════════════════════════════════════════
  {
    name: 'racialOriginCtx',
    label: 'RACIAL_ORIGIN',
    category: 'identity',
    regex: /(?:race|ethnicity|ethnic\s*origin|Rasse|Herkunft|racial\s*background)[:\s]+[a-zA-ZÀ-ÿ\s]{2,30}/gi,
    description: 'Racial/ethnic origin (GDPR Art.9, contextual)',
  },
  {
    name: 'politicalOpinionCtx',
    label: 'POLITICAL_OPINION',
    category: 'identity',
    regex: /(?:political\s*(?:party|affiliation|opinion)|Partei(?:zugehörigkeit)?|parti\s*politique)[:\s]+[a-zA-ZÀ-ÿ\s]{2,40}/gi,
    description: 'Political opinions/affiliations (GDPR Art.9, contextual)',
  },
  {
    name: 'religiousBeliefCtx',
    label: 'RELIGIOUS_BELIEF',
    category: 'identity',
    regex: /(?:religion|religious\s*(?:belief|affiliation)|faith|Konfession|Religionszugehörigkeit|confession)[:\s]+[a-zA-ZÀ-ÿ\s]{2,30}/gi,
    description: 'Religious beliefs/affiliations (GDPR Art.9, contextual)',
  },
  {
    name: 'tradeUnionCtx',
    label: 'TRADE_UNION',
    category: 'identity',
    regex: /(?:trade\s*union|union\s*member(?:ship)?|Gewerkschaft(?:smitgliedschaft)?|syndicat)[:\s]+[a-zA-ZÀ-ÿ\s]{2,40}/gi,
    description: 'Trade union membership (GDPR Art.9, contextual)',
  },
  {
    name: 'sexualOrientationCtx',
    label: 'SEXUAL_ORIENTATION',
    category: 'identity',
    regex: /(?:sexual\s*orientation|sexuelle\s*Orientierung|orientation\s*sexuelle)[:\s]+[a-zA-ZÀ-ÿ\s]{2,20}/gi,
    description: 'Sexual orientation (GDPR Art.9, contextual)',
  },
  {
    name: 'disabilityCtx',
    label: 'DISABILITY',
    category: 'medical',
    regex: /(?:disability|disabled|Behinderung|Schwerbehindertenausweis|GdB)\s*(?:status|degree|grad)?[:\s]*(?:\d{1,3}%?|[a-zA-ZÀ-ÿ\s]{2,30})/gi,
    description: 'Disability status/degree (GDPR Art.9, BDSG, contextual)',
  },
  {
    name: 'criminalRecordCtx',
    label: 'CRIMINAL_RECORD',
    category: 'identity',
    regex: /(?:criminal\s*record|conviction|felony|misdemeanor|Vorstrafe|casier\s*judiciaire|arrest\s*record)[:\s]+[a-zA-ZÀ-ÿ\s]{2,40}/gi,
    description: 'Criminal record references (GDPR Art.10, contextual)',
  },

  // ═══════════════════════════════════════════
  // EDUCATION — FERPA
  // ═══════════════════════════════════════════
  {
    name: 'studentIdCtx',
    label: 'STUDENT_ID',
    category: 'identity',
    regex: /(?:student\s*(?:ID|number|#|no))[:\s]*[A-Z0-9]{4,15}/gi,
    description: 'Student ID numbers (FERPA, contextual)',
  },
  {
    name: 'gpaCtx',
    label: 'GPA',
    category: 'identity',
    regex: /(?:GPA|grade\s*point)[:\s]*[0-4]\.\d{1,2}/gi,
    description: 'Grade point average (FERPA, contextual)',
  },
  {
    name: 'testScoreCtx',
    label: 'TEST_SCORE',
    category: 'identity',
    regex: /(?:SAT|ACT|GRE|GMAT|LSAT|MCAT)\s*(?:score)?[:\s]*\d{2,4}/gi,
    description: 'Standardized test scores (SAT, ACT, GRE, etc.)',
  },
  {
    name: 'eduEmail',
    label: 'EDU_EMAIL',
    category: 'contact',
    regex: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.edu/g,
    description: 'Educational email addresses (.edu)',
  },

  // ═══════════════════════════════════════════
  // UTILITY / SERVICE ACCOUNTS
  // ═══════════════════════════════════════════
  {
    name: 'loyaltyNumberCtx',
    label: 'LOYALTY_NUMBER',
    category: 'financial',
    regex: /(?:loyalty|rewards?|frequent\s*flyer|mileage|membership|FF)\s*(?:#|number|card|ID)[:\s]*[A-Z0-9\-]{6,20}/gi,
    description: 'Loyalty / rewards / frequent flyer numbers (contextual)',
  },
  {
    name: 'utilityAccountCtx',
    label: 'UTILITY_ACCOUNT',
    category: 'financial',
    regex: /(?:electricity|gas|water|utility)\s*(?:account|acct|#)[:\s]*[A-Z0-9\-]{6,20}/gi,
    description: 'Utility account numbers (electricity, gas, water)',
  },

  // ═══════════════════════════════════════════
  // LEGAL / JUDICIAL
  // ═══════════════════════════════════════════
  {
    name: 'caseNumberCtx',
    label: 'CASE_NUMBER',
    category: 'identity',
    regex: /(?:case|docket)\s*(?:#|number|no)[:\s]*\d{1,2}[\-:]\w{2,4}[\-:]\d{3,8}/gi,
    description: 'Court case / docket numbers (contextual)',
  },
  {
    name: 'inmateNumberCtx',
    label: 'INMATE_NUMBER',
    category: 'identity',
    regex: /(?:inmate|prisoner|offender|booking)\s*(?:#|number|ID)[:\s]*[A-Z0-9\-]{4,15}/gi,
    description: 'Inmate / prisoner / booking numbers (contextual)',
  },

  // ═══════════════════════════════════════════
  // VEHICLE — Extended license plates
  // ═══════════════════════════════════════════
  {
    name: 'licensePlateNL',
    label: 'LICENSE_PLATE_NL',
    category: 'vehicle',
    regex: /\b\d{1,2}-[A-Z]{2,3}-\d{1,2}\b|\b[A-Z]{2}-\d{2,3}-[A-Z]{1,2}\b/g,
    description: 'Dutch license plates',
  },
  {
    name: 'licensePlateIT',
    label: 'LICENSE_PLATE_IT',
    category: 'vehicle',
    regex: /\b[A-Z]{2}\s?\d{3}\s?[A-Z]{2}\b/g,
    description: 'Italian license plates (AB 123 CD)',
  },
  {
    name: 'licensePlateES',
    label: 'LICENSE_PLATE_ES',
    category: 'vehicle',
    regex: /\b\d{4}\s?[BCDFGHJKLMNPRSTVWXYZ]{3}\b/g,
    description: 'Spanish license plates (1234 BCD)',
  },

  // ═══════════════════════════════════════════
  // BIOMETRIC — Genetic / DNA
  // ═══════════════════════════════════════════
  {
    name: 'dnaSequence',
    label: 'DNA_SEQUENCE',
    category: 'biometric',
    regex: /\b[ACGT]{20,}\b/g,
    description: 'DNA nucleotide sequences (20+ bases)',
  },
  {
    name: 'geneticTestCtx',
    label: 'GENETIC_TEST',
    category: 'biometric',
    regex: /(?:BRCA[12]|genetic\s*test|genome|genotype|SNP|allele|karyotype)[:\s]+[^\n]{3,40}/gi,
    description: 'Genetic test results and markers (BRCA1/2, SNP, contextual)',
  },

  // ═══════════════════════════════════════════
  // TEMPORAL — Extended
  // ═══════════════════════════════════════════
  {
    name: 'ageCtx',
    label: 'AGE',
    category: 'temporal',
    regex: /(?:age|Alter|edad|eta|âge)[:\s]+\d{1,3}\s*(?:years?|yr|ans?|Jahre?|años?|anni)?/gi,
    description: 'Age with label (contextual, multi-language)',
  },
  {
    name: 'dateOfDeathCtx',
    label: 'DATE_OF_DEATH',
    category: 'temporal',
    regex: /(?:date\s*of\s*death|deceased|Sterbedatum|died\s*on)[:\s]*\d{1,2}[\/.\-]\d{1,2}[\/.\-]\d{2,4}/gi,
    description: 'Date of death (HIPAA, contextual)',
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
