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
 *   docker run -d -p 5002:3000 mcr.microsoft.com/presidio-analyzer
 *
 * Or with docker-compose alongside n8n:
 *   services:
 *     n8n:
 *       image: n8nio/n8n
 *       ports: ["5678:5678"]
 *     presidio:
 *       image: mcr.microsoft.com/presidio-analyzer
 *       ports: ["5002:3000"]
 */

import * as http from 'http';
import * as https from 'https';

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
export interface PresidioAnalyzeRequest {
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
 * Circuit breaker: after 3 consecutive failures, stop calling Presidio
 * for the rest of this execution. Per-URL to prevent cross-workflow bleed.
 * Resets on success or at start of each n8n execution.
 */
const failureCountByUrl: Map<string, number> = new Map();
const MAX_FAILURES = 3;

function circuitOpen(url?: string): boolean {
  if (!url) return false;
  return (failureCountByUrl.get(url) || 0) >= MAX_FAILURES;
}

function recordSuccess(url?: string): void {
  if (url) failureCountByUrl.set(url, 0);
}

function recordFailure(url?: string): void {
  if (url) failureCountByUrl.set(url, (failureCountByUrl.get(url) || 0) + 1);
}

/** Reset circuit breaker (call at start of each n8n execution) */
export function resetCircuitBreaker(): void {
  failureCountByUrl.clear();
}

/**
 * Check if Presidio is reachable at the given URL.
 */
export async function checkPresidioHealth(baseUrl: string): Promise<boolean> {
  try {
    const result = await httpGet(`${baseUrl}/health`, 3000);
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
): Promise<PresidioEntity[]> {
  if (!text || text.trim().length === 0) return [];

  // Circuit breaker: skip if too many consecutive failures for this URL
  if (circuitOpen(baseUrl)) return [];

  const requestBody: PresidioAnalyzeRequest = {
    text,
    language,
    score_threshold: scoreThreshold,
    return_decision_process: false,
  };

  try {
    const result = await httpPost(
      `${baseUrl}/analyze`,
      JSON.stringify(requestBody),
      timeoutMs,
    );

    if (result.statusCode !== 200) {
      recordFailure(baseUrl);
      return [];
    }

    const entities: PresidioEntity[] = JSON.parse(result.body);
    if (!Array.isArray(entities)) {
      recordFailure(baseUrl);
      return [];
    }

    recordSuccess(baseUrl);
    return entities;
  } catch {
    recordFailure();
    return [];
  }
}

/**
 * Get the redactor label for a Presidio entity type.
 */
export function getRedactorLabel(presidioEntityType: string): string {
  return PRESIDIO_TO_REDACTOR_LABEL[presidioEntityType] || presidioEntityType;
}

/**
 * Get the PII category for a Presidio entity type.
 */
export function getRedactorCategory(presidioEntityType: string): string {
  return PRESIDIO_TO_CATEGORY[presidioEntityType] || 'identity';
}

/**
 * Get all supported Presidio entity types.
 */
export async function getPresidioEntities(baseUrl: string): Promise<string[]> {
  try {
    const result = await httpGet(`${baseUrl}/supportedentities`, 5000);
    if (result.statusCode !== 200) return [];
    const entities = JSON.parse(result.body);
    return Array.isArray(entities) ? entities : [];
  } catch {
    return [];
  }
}

// ═══════════════════════════════════════════
// HTTP utilities (no external dependencies)
// ═══════════════════════════════════════════

interface HttpResponse {
  statusCode: number;
  body: string;
}

function httpGet(url: string, timeoutMs: number): Promise<HttpResponse> {
  return new Promise((resolve, reject) => {
    const client = url.startsWith('https') ? https : http;
    const req = client.get(url, { timeout: timeoutMs }, (res) => {
      let body = '';
      res.on('data', (chunk) => { body += chunk; });
      res.on('end', () => {
        resolve({ statusCode: res.statusCode || 0, body });
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
  });
}

function httpPost(url: string, data: string, timeoutMs: number): Promise<HttpResponse> {
  return new Promise((resolve, reject) => {
    const parsedUrl = new URL(url);
    const client = parsedUrl.protocol === 'https:' ? https : http;
    const options = {
      hostname: parsedUrl.hostname,
      port: parsedUrl.port,
      path: parsedUrl.pathname,
      method: 'POST',
      timeout: timeoutMs,
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(data),
      },
    };

    const req = client.request(options, (res) => {
      let body = '';
      res.on('data', (chunk) => { body += chunk; });
      res.on('end', () => {
        resolve({ statusCode: res.statusCode || 0, body });
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
    req.write(data);
    req.end();
  });
}
