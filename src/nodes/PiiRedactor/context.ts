/**
 * Context words and confidence scoring for PII patterns.
 *
 * Context words are keywords that appear near a PII match and boost confidence.
 * For example, "SSN" appearing before "123-45-6789" boosts confidence from 0.60 to 0.85.
 *
 * Base confidence scores reflect how reliable a pattern is:
 * - 0.95: Checksum validated (Luhn, IBAN, PESEL, etc.)
 * - 0.90: Semantic field-name match
 * - 0.85: Context-aware ambiguous field
 * - 0.80: Regex match WITH context words nearby
 * - 0.60: Regex match WITHOUT context words (bare pattern)
 * - 0.70: Custom pattern match
 */

/** Context words by pattern name. Case-insensitive matching. */
export const CONTEXT_WORDS: Record<string, string[]> = {
  // Contact
  email: ['email', 'e-mail', 'mail', 'contact', 'reach', 'send', 'Kontakt', 'correo', 'posta'],
  phone: ['phone', 'call', 'mobile', 'cell', 'tel', 'telephone', 'dial', 'ring', 'Telefon', 'anrufen', 'Handy', 'appeler', 'llamar'],
  phoneDE: ['Telefon', 'anrufen', 'Handy', 'Rufnummer', 'Festnetz', 'mobil'],
  phoneUK: ['phone', 'call', 'mobile', 'ring', 'dial', 'landline'],
  phoneAT: ['Telefon', 'anrufen', 'Handy'],
  phoneCH: ['Telefon', 'anrufen', 'Natel', 'Handy'],
  phoneFR: ['telephone', 'appeler', 'portable', 'fixe', 'numero'],
  phoneNL: ['telefoon', 'bellen', 'mobiel'],
  phoneES: ['telefono', 'llamar', 'movil', 'celular'],
  phoneIT: ['telefono', 'chiamare', 'cellulare'],
  phoneAU: ['phone', 'call', 'mobile'],
  phoneIN: ['phone', 'call', 'mobile'],
  phoneBR: ['telefone', 'ligar', 'celular'],
  phoneCN: ['phone', 'call', 'mobile'],
  phoneKR: ['phone', 'call'],
  phoneRU: ['telefon', 'pozvonit'],
  phoneMX: ['telefono', 'llamar', 'celular'],
  phoneZA: ['phone', 'call', 'mobile'],

  // Identity - person names
  personName: ['name', 'person', 'contact', 'customer', 'client', 'patient', 'employee', 'user', 'Mr', 'Mrs', 'Ms', 'Dr', 'Herr', 'Frau'],

  // Identity - government IDs
  ssn: ['social security', 'SSN', 'social', 'security number', 'Sozialversicherung'],
  itinUS: ['ITIN', 'taxpayer', 'individual taxpayer'],
  sinCA: ['SIN', 'social insurance', 'insurance number'],
  ninoUK: ['national insurance', 'NINO', 'NI number'],
  nhsNumber: ['NHS', 'national health', 'health service', 'patient'],
  passportUS: ['passport', 'travel document', 'Reisepass'],
  passportEU: ['passport', 'travel document', 'Reisepass', 'passeport'],
  passportDE: ['Reisepass', 'passport', 'Passnummer'],
  nationalIdDE: ['Personalausweis', 'Ausweis', 'ID card', 'identity card'],
  taxIdUS: ['EIN', 'employer identification', 'tax ID', 'federal tax'],
  taxIdDE: ['Steuer', 'Identifikationsnummer', 'Finanzamt'],
  sozialversicherungDE: ['Sozialversicherung', 'Rentenversicherung', 'SV-Nummer'],
  ahvCH: ['AHV', 'AVS', 'Sozialversicherung', 'assurance'],
  nationalIdFR: ['securite sociale', 'NIR', 'numero national'],
  codiceFiscaleIT: ['codice fiscale', 'fiscal code', 'CF'],
  dniES: ['DNI', 'documento nacional', 'identidad'],
  nieES: ['NIE', 'extranjero', 'foreigner'],
  peselPL: ['PESEL', 'numer identyfikacyjny'],
  bsnNL: ['BSN', 'burgerservicenummer', 'burger service'],
  ppsIE: ['PPS', 'personal public service'],
  tfnAU: ['TFN', 'tax file', 'tax number'],
  nricSG: ['NRIC', 'identity card', 'IC'],
  panIN: ['PAN', 'permanent account', 'income tax'],
  aadhaarIN: ['Aadhaar', 'UID', 'unique identification'],
  cpfBR: ['CPF', 'cadastro', 'pessoa fisica'],
  hetuFI: ['HETU', 'henkilotunnus', 'personal identity'],
  personnummerSE: ['personnummer', 'personal number'],
  fodselsnummerNO: ['fodselsnummer', 'personal number'],
  cprDK: ['CPR', 'personnummer'],
  nifPT: ['NIF', 'numero fiscal', 'contribuinte'],
  nationalIdCN: ['identity card', 'resident card', 'shenfenzheng'],
  nationalIdTR: ['TC Kimlik', 'kimlik no', 'identity'],
  curpMX: ['CURP', 'poblacion'],
  rfcMX: ['RFC', 'registro federal'],
  emiratesIdUAE: ['emirates ID', 'UAE ID'],

  // Financial
  creditCard: ['card', 'credit', 'debit', 'visa', 'mastercard', 'amex', 'payment', 'Kreditkarte', 'carte', 'tarjeta'],
  amex: ['amex', 'american express', 'card', 'payment'],
  iban: ['IBAN', 'bank account', 'Kontonummer', 'compte', 'cuenta', 'conto'],
  bic: ['BIC', 'SWIFT', 'bank', 'routing'],
  vatEU: ['VAT', 'MwSt', 'Umsatzsteuer', 'TVA', 'IVA', 'BTW'],
  abaRouting: ['routing', 'ABA', 'bank', 'transfer'],
  sortCodeUK: ['sort code', 'bank', 'branch'],
  cardExpiry: ['expiry', 'expiration', 'valid', 'exp', 'Gultig'],
  cvvCtx: ['CVV', 'CVC', 'security code', 'verification'],
  bankAccountCtx: ['account', 'bank', 'checking', 'savings', 'Konto'],
  insurancePolicyCtx: ['insurance', 'policy', 'Versicherung', 'assurance', 'polizza'],
  salaryCtx: ['salary', 'compensation', 'pay', 'wage', 'Gehalt', 'salaire'],

  // Network
  ipv4: ['IP', 'address', 'server', 'host', 'network'],
  ipv6: ['IP', 'address', 'server', 'IPv6'],
  macAddress: ['MAC', 'hardware', 'network', 'device', 'adapter'],
  url: ['URL', 'link', 'website', 'http', 'visit'],
  privateIp: ['internal', 'private', 'LAN', 'intranet', 'network'],

  // Location
  addressDE: ['Adresse', 'Anschrift', 'wohnt', 'Straße', 'address'],
  addressLabeledEN: ['address', 'lives', 'located', 'residing'],
  addressLabeledDE: ['Adresse', 'Anschrift', 'wohnt', 'Wohnort'],
  gpsCoordinates: ['GPS', 'coordinates', 'location', 'latitude', 'longitude', 'Standort'],

  // Medical
  medicalRecordNumber: ['MRN', 'medical record', 'patient', 'chart', 'Krankenakte'],
  deaNumber: ['DEA', 'drug enforcement', 'prescriber'],
  npiNumber: ['NPI', 'provider', 'physician', 'doctor'],
  rxNumber: ['prescription', 'Rx', 'pharmacy', 'medication', 'Rezept'],
  healthPlanCtx: ['health plan', 'insurance', 'member', 'subscriber', 'beneficiary'],
  bloodTypeCtx: ['blood', 'type', 'group', 'Blutgruppe'],

  // Enterprise
  awsAccessKey: ['AWS', 'amazon', 'access key', 'credential'],
  gcpApiKey: ['Google', 'GCP', 'API key', 'cloud'],
  stripeKey: ['Stripe', 'payment', 'API key'],
  openaiKey: ['OpenAI', 'API key', 'GPT'],
  githubToken: ['GitHub', 'token', 'personal access'],
  slackToken: ['Slack', 'token', 'bot'],
  jwtToken: ['JWT', 'token', 'auth', 'bearer', 'session'],
  pemPrivateKey: ['private key', 'RSA', 'certificate', 'SSL', 'TLS'],
  sshPublicKey: ['SSH', 'key', 'public key', 'authorized'],
  genericSecret: ['password', 'secret', 'credential', 'API key', 'token'],
  dbConnectionString: ['database', 'connection', 'JDBC', 'mongo', 'postgres', 'mysql'],
  internalHostname: ['server', 'host', 'internal', 'intranet'],

  // Vehicle
  vin: ['VIN', 'vehicle', 'chassis', 'Fahrgestell', 'vehicule'],

  // Crypto
  bitcoinAddress: ['bitcoin', 'BTC', 'wallet', 'crypto'],
  ethereumAddress: ['ethereum', 'ETH', 'wallet', 'crypto', 'contract'],
};

/**
 * Base confidence scores by pattern name.
 * Patterns with checksum validation get higher scores.
 */
export const BASE_CONFIDENCE: Record<string, number> = {
  // Checksum validated = 0.95
  creditCard: 0.95,
  amex: 0.95,
  iban: 0.95,
  nhsNumber: 0.95,
  sinCA: 0.95,
  peselPL: 0.95,
  bsnNL: 0.95,
  nifPT: 0.95,
  tfnAU: 0.95,
  abaRouting: 0.95,

  // Strong format (unique structure) = 0.85
  email: 0.90,
  codiceFiscaleIT: 0.90,
  hetuFI: 0.90,
  ahvCH: 0.90,
  nricSG: 0.90,
  panIN: 0.90,
  passportUS: 0.85,
  passportEU: 0.85,
  passportDE: 0.85,
  ssn: 0.85,
  ninoUK: 0.85,
  dniES: 0.85,
  nieES: 0.85,
  nationalIdCN: 0.85,
  nationalIdTH: 0.85,
  emiratesIdUAE: 0.85,
  curpMX: 0.85,
  bitcoinAddress: 0.85,
  ethereumAddress: 0.85,
  vin: 0.85,
  jwtToken: 0.85,
  awsAccessKey: 0.90,
  gcpApiKey: 0.90,
  stripeKey: 0.90,
  openaiKey: 0.90,
  githubToken: 0.90,
  pemPrivateKey: 0.90,
  sshPublicKey: 0.90,

  // Medium format = 0.70
  phone: 0.70,
  phoneDE: 0.75,
  phoneUK: 0.75,
  phoneAT: 0.75,
  phoneCH: 0.75,
  phoneFR: 0.75,
  personName: 0.80,
  ipv4: 0.70,
  ipv6: 0.80,
  macAddress: 0.80,
  url: 0.75,
  vatEU: 0.80,
  bic: 0.65,

  // Broad patterns (high false positive risk) = 0.50-0.60
  postalCodeDE: 0.40,
  postalCodeAT: 0.40,
  postalCodeCH: 0.40,
  postalCodeUS: 0.50,
  postalCodeIT: 0.40,
  postalCodeES: 0.50,
  postalCodeIN: 0.40,
  dateSlash: 0.50,
  dateDash: 0.50,
  dateDot: 0.50,
  sortCodeUK: 0.50,
  cardExpiry: 0.50,
  socialHandle: 0.60,
  licensePlateDE: 0.55,
  dnaSequence: 0.50,
};

/**
 * Default base confidence for patterns not in the BASE_CONFIDENCE map.
 */
export const DEFAULT_BASE_CONFIDENCE = 0.65;

/**
 * Confidence boost when context words are found nearby.
 */
export const CONTEXT_BOOST = 0.20;

/**
 * Confidence score for semantic field-name matches.
 */
export const SEMANTIC_CONFIDENCE = 0.90;

/**
 * Confidence score for context-aware ambiguous field matches.
 */
export const AMBIGUOUS_FIELD_CONFIDENCE = 0.85;

/**
 * Confidence score for custom pattern matches.
 */
export const CUSTOM_PATTERN_CONFIDENCE = 0.70;

/**
 * Confidence score for deny list matches.
 */
export const DENY_LIST_CONFIDENCE = 1.0;

/**
 * Window size (characters) to search for context words around a match.
 */
export const CONTEXT_WINDOW = 80;

/**
 * Check if any context words appear near a match position in the text.
 */
export function hasContextWords(
  text: string,
  matchStart: number,
  matchEnd: number,
  words: string[],
): boolean {
  if (!words || words.length === 0) return false;

  const windowStart = Math.max(0, matchStart - CONTEXT_WINDOW);
  const windowEnd = Math.min(text.length, matchEnd + CONTEXT_WINDOW);
  const surrounding = text.slice(windowStart, windowEnd).toLowerCase();

  return words.some((word) => surrounding.includes(word.toLowerCase()));
}

/**
 * Calculate confidence score for a pattern match.
 */
export function calculateConfidence(
  patternName: string,
  hasValidator: boolean,
  validatorPassed: boolean,
  text: string,
  matchStart: number,
  matchEnd: number,
): number {
  // Start with base confidence
  let confidence = BASE_CONFIDENCE[patternName] ?? DEFAULT_BASE_CONFIDENCE;

  // If has validator and passed, boost to at least 0.95
  if (hasValidator && validatorPassed) {
    confidence = Math.max(confidence, 0.95);
  }

  // Check context words
  const contextWords = CONTEXT_WORDS[patternName];
  if (contextWords && hasContextWords(text, matchStart, matchEnd, contextWords)) {
    confidence = Math.min(1.0, confidence + CONTEXT_BOOST);
  }

  return Math.round(confidence * 100) / 100;
}
