/**
 * Presidio Analyzer HTTP Client
 *
 * Optional integration with Microsoft Presidio for NLP-based entity detection.
 * Presidio uses spaCy NER models to detect person names, locations, and
 * organizations in free text — something regex alone cannot do reliably.
 *
 * This is OPTIONAL. The node works perfectly without Presidio.
 * Users who want NLP-level accuracy spin up the Presidio Docker container
 * and enable "Enhanced NLP Detection" in the node settings.
 *
 * Docker setup (one command):
 *   docker run -d -p 127.0.0.1:5002:3000 mcr.microsoft.com/presidio-analyzer
 *
 * Or with docker-compose alongside n8n:
 *   services:
 *     n8n:
 *       image: n8nio/n8n
 *       ports: ["5678:5678"]
 *     presidio:
 *       image: mcr.microsoft.com/presidio-analyzer
 *       ports: ["127.0.0.1:5002:3000"]
 */
import { PII_PATTERNS } from './patterns';

/** HTTP transport supplied by the node (this.helpers.httpRequest). Keeps this module free of http/https. */
export type PresidioRequester = (options: {
  method: 'GET' | 'POST';
  url: string;
  body?: object;
  timeout: number;
}) => Promise<{ statusCode: number; body: unknown }>;

/** Result from Presidio /analyze endpoint */
export interface PresidioEntity {
  entity_type: string;
  start: number;
  end: number;
  score: number;
  analysis_explanation?: {
    recognizer: string;
    pattern_name?: string;
    pattern?: string;
    original_score: number;
    score: number;
    textual_explanation?: string;
    score_context_improvement?: number;
    supportive_context_word?: string;
    validation_result?: number;
  };
  recognition_metadata?: {
    recognizer_name: string;
    recognizer_identifier?: string;
  };
}

/** Presidio /analyze request body */
interface PresidioAnalyzeRequest {
  text: string;
  language: string;
  entities?: string[];
  correlation_id?: string;
  score_threshold?: number;
  return_decision_process?: boolean;
}

/** Map Presidio entity types to our label format */
const PRESIDIO_TO_REDACTOR_LABEL: Record<string, string> = {
  PERSON: 'PERSON_NAME',
  EMAIL_ADDRESS: 'EMAIL',
  PHONE_NUMBER: 'PHONE',
  CREDIT_CARD: 'CREDIT_CARD',
  IBAN_CODE: 'IBAN',
  US_SSN: 'SSN',
  US_ITIN: 'ITIN_US',
  US_PASSPORT: 'PASSPORT_US',
  US_DRIVER_LICENSE: 'DRIVER_LICENSE',
  US_BANK_NUMBER: 'BANK_ACCOUNT',
  UK_NHS: 'NHS_NUMBER',
  LOCATION: 'ADDRESS',
  DATE_TIME: 'DATE',
  NRP: 'ETHNICITY',
  MEDICAL_LICENSE: 'MEDICAL',
  IP_ADDRESS: 'IP_ADDRESS',
  URL: 'URL',
  CRYPTO: 'BTC_ADDRESS',
  ORGANIZATION: 'COMPANY',
  AU_ABN: 'ABN_AU',
  AU_ACN: 'ACN_AU',
  AU_TFN: 'TFN_AU',
  AU_MEDICARE: 'MEDICARE_AU',
  SG_NRIC_FIN: 'NRIC_SG',
  IN_PAN: 'PAN_IN',
  IN_AADHAAR: 'AADHAAR_IN',
  ES_NIF: 'NIF_ES',
  IT_FISCAL_CODE: 'CODICE_FISCALE_IT',
  IT_DRIVER_LICENSE: 'DRIVER_LICENSE',
  IT_IDENTITY_CARD: 'CARTA_ID_IT',
  IT_PASSPORT: 'PASSPORT_EU',
  IT_VAT_CODE: 'VAT_EU',
  PL_PESEL: 'PESEL_PL',
};

/** Map Presidio entity types to our PII categories */
const PRESIDIO_TO_CATEGORY: Record<string, string> = {
  PERSON: 'identity',
  EMAIL_ADDRESS: 'contact',
  PHONE_NUMBER: 'contact',
  CREDIT_CARD: 'financial',
  IBAN_CODE: 'financial',
  US_SSN: 'identity',
  US_ITIN: 'identity',
  US_PASSPORT: 'identity',
  US_DRIVER_LICENSE: 'identity',
  US_BANK_NUMBER: 'financial',
  UK_NHS: 'identity',
  LOCATION: 'location',
  DATE_TIME: 'temporal',
  NRP: 'identity',
  MEDICAL_LICENSE: 'medical',
  IP_ADDRESS: 'network',
  URL: 'network',
  CRYPTO: 'crypto',
  ORGANIZATION: 'identity',
};

/**
 * Circuit breaker: after 3 consecutive failures, stop calling Presidio for this URL.
 * State is keyed by the requester, so each execution (one requester each) has its own breaker.
 */
let breakers = new WeakMap<PresidioRequester, Map<string, number>>();
const MAX_FAILURES = 3;

function failures(request: PresidioRequester): Map<string, number> {
  let table = breakers.get(request);
  if (!table) breakers.set(request, (table = new Map()));
  return table;
}

function circuitOpen(request: PresidioRequester, url: string): boolean {
  return (failures(request).get(url) || 0) >= MAX_FAILURES;
}

function recordSuccess(request: PresidioRequester, url: string): void {
  failures(request).set(url, 0);
}

// Texts Presidio did not scan, per requester, so the run can stop instead of passing them as scanned.
let unscanned = new WeakMap<PresidioRequester, number>();

function recordFailure(request: PresidioRequester, url: string): void {
  const table = failures(request);
  table.set(url, (table.get(url) || 0) + 1);
  unscanned.set(request, (unscanned.get(request) || 0) + 1);
}

/** How many texts this requester sent that Presidio never scanned, through errors or an open breaker. */
export function presidioUnscanned(request: PresidioRequester): number {
  return unscanned.get(request) || 0;
}

/** Forget every breaker state (tests use this to start clean). */
export function resetCircuitBreaker(): void {
  breakers = new WeakMap();
  unscanned = new WeakMap();
}

/**
 * Check if Presidio is reachable at the given URL.
 */
export async function checkPresidioHealth(baseUrl: string, request?: PresidioRequester): Promise<boolean> {
  if (!request || !isHttpUrl(baseUrl)) return false;
  try {
    const result = await request({ method: 'GET', url: `${baseUrl}/health`, timeout: 3000 });
    return result.statusCode === 200;
  } catch {
    return false;
  }
}

/**
 * Call Presidio /analyze endpoint to detect PII entities in text.
 * Returns empty array if Presidio is unreachable (graceful fallback).
 */
export async function analyzeWithPresidio(
  baseUrl: string,
  text: string,
  language: string = 'en',
  scoreThreshold: number = 0.4,
  timeoutMs: number = 10000,
  request?: PresidioRequester,
): Promise<PresidioEntity[]> {
  if (!text || text.trim().length === 0) return [];
  if (!request || !isHttpUrl(baseUrl)) return [];

  // Circuit breaker: skip if too many consecutive failures for this URL
  if (circuitOpen(request, baseUrl)) {
    unscanned.set(request, (unscanned.get(request) || 0) + 1);
    return [];
  }

  const requestBody: PresidioAnalyzeRequest = {
    text,
    language,
    score_threshold: scoreThreshold,
    return_decision_process: false,
  };

  try {
    const result = await request({
      method: 'POST',
      url: `${baseUrl}/analyze`,
      body: requestBody,
      timeout: timeoutMs,
    });

    if (result.statusCode !== 200) {
      recordFailure(request, baseUrl);
      return [];
    }

    const entities = parseBody(result.body) as PresidioEntity[];
    if (!Array.isArray(entities)) {
      recordFailure(request, baseUrl);
      return [];
    }

    recordSuccess(request, baseUrl);
    return entities;
  } catch {
    recordFailure(request, baseUrl);
    return [];
  }
}

/** A table lookup that ignores inherited names such as constructor or __proto__. */
function ownValue(table: Record<string, string>, key: string): string | undefined {
  return Object.prototype.hasOwnProperty.call(table, key) ? table[key] : undefined;
}

/**
 * Get the redactor label for a Presidio entity type.
 */
export function getRedactorLabel(presidioEntityType: string): string {
  return ownValue(PRESIDIO_TO_REDACTOR_LABEL, presidioEntityType) || presidioEntityType;
}

/**
 * Get the PII category for a Presidio entity type.
 */
export function getRedactorCategory(presidioEntityType: string): string {
  // A built-in pattern with the same label decides, so both detection paths agree on the category.
  const label = getRedactorLabel(presidioEntityType);
  const builtIn = PII_PATTERNS.find((p) => p.label === label);
  return builtIn?.category ?? ownValue(PRESIDIO_TO_CATEGORY, presidioEntityType) ?? 'identity';
}

/**
 * Get all supported Presidio entity types.
 */
export async function getPresidioEntities(baseUrl: string, request?: PresidioRequester): Promise<string[]> {
  if (!request || !isHttpUrl(baseUrl)) return [];
  try {
    const result = await request({ method: 'GET', url: `${baseUrl}/supportedentities`, timeout: 5000 });
    if (result.statusCode !== 200) return [];
    const entities = parseBody(result.body);
    return Array.isArray(entities) ? entities : [];
  } catch {
    return [];
  }
}

/** Only plain http(s) base URLs are called. Anything else is treated as Presidio being unavailable. */
function isHttpUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

function parseBody(body: unknown): unknown {
  return typeof body === 'string' ? JSON.parse(body) : body;
}
