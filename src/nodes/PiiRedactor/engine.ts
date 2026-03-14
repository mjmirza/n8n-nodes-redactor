import * as crypto from 'crypto';
import { PII_PATTERNS, getPatternsByNames } from './patterns';
import { IVault } from './vault';
import {
  CustomPattern,
  PiiCategory,
  PiiPattern,
  RedactionContext,
  RedactionHit,
  RedactionMode,
  RedactionReport,
  VaultEntry,
} from './types';

/**
 * Generate a deterministic token for a given label + index.
 */
function generateToken(label: string, index: number): string {
  return `[${label}_${index}]`;
}

/**
 * Token format regex — used to skip already-redacted regions.
 */
const TOKEN_RE = /^\[[A-Z][A-Z0-9_]*_\d+\]$/;

/**
 * Generate a masked version of a string.
 */
function maskValue(value: string, label: string): string {
  if (value.length <= 2) return '*'.repeat(value.length);

  if (label === 'EMAIL' && value.includes('@')) {
    const [local, domain] = value.split('@');
    const maskedLocal = local[0] + '***';
    const domainParts = domain.split('.');
    const maskedDomain = domainParts[0][0] + '***.' + domainParts.slice(1).join('.');
    return maskedLocal + '@' + maskedDomain;
  }

  if (label.startsWith('PHONE') || label === 'FAX') {
    const digits = value.replace(/\D/g, '');
    if (digits.length >= 4) {
      return '***' + digits.slice(-4);
    }
  }

  if (label === 'CREDIT_CARD' || label === 'AMEX') {
    const digits = value.replace(/\D/g, '');
    return '****-****-****-' + digits.slice(-4);
  }

  return value[0] + '*'.repeat(value.length - 2) + value[value.length - 1];
}

/**
 * Generate a truncated hash of a value.
 */
function hashValue(value: string): string {
  return crypto.createHash('sha256').update(value).digest('hex').slice(0, 12);
}

/**
 * Apply redaction with proper category on the vault entry.
 */
function applyRedaction(
  match: string,
  pattern: PiiPattern | { label: string; category: PiiCategory },
  mode: RedactionMode,
  vault: IVault,
  sessionId: string,
  dedup: boolean,
): string {
  switch (mode) {
    case 'token': {
      if (dedup) {
        const existing = vault.findByOriginal(sessionId, match);
        if (existing) return existing.token;
      }
      const session = vault.getSession(sessionId);
      const index = session ? Object.keys(session.entries).length : 0;
      const token = generateToken(pattern.label, index);
      vault.addEntry(sessionId, {
        token,
        original: match,
        patternLabel: pattern.label,
        category: ('category' in pattern ? pattern.category : 'identity') as PiiCategory,
        createdAt: new Date().toISOString(),
      });
      return token;
    }
    case 'mask':
      return maskValue(match, pattern.label);
    case 'hash':
      return `[${pattern.label}:${hashValue(match)}]`;
    case 'redact':
      return `[REDACTED]`;
    default:
      return match;
  }
}

/**
 * Check if a JSON path should be processed given the field rules.
 */
function shouldProcessField(
  fieldPath: string,
  fieldMode: 'all' | 'allowlist' | 'denylist',
  fieldRules: Array<{ field: string; mode: string }>,
): boolean {
  if (fieldMode === 'all') return true;

  if (fieldMode === 'allowlist') {
    return fieldRules.some(
      (r) => r.mode === 'include' && fieldPathMatches(fieldPath, r.field),
    );
  }

  if (fieldMode === 'denylist') {
    return !fieldRules.some(
      (r) => r.mode === 'exclude' && fieldPathMatches(fieldPath, r.field),
    );
  }

  return true;
}

/**
 * Safe wildcard matching for JSON paths.
 * Escapes all regex special chars before applying wildcard transformations.
 * Supports: "user.email", "*.email", "contacts[*].phone"
 */
function fieldPathMatches(actual: string, pattern: string): boolean {
  // Escape ALL regex special characters first
  let regexStr = pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  // Now unescape our wildcards
  regexStr = regexStr
    .replace(/\\\[\\*\\]/g, '\\[\\d+\\]')  // [*] -> [\d+]
    .replace(/\\[*]/g, '[^.]+');            // escaped * -> [^.]+
  try {
    return new RegExp(`^${regexStr}$`).test(actual);
  } catch {
    return false;
  }
}

/**
 * Validate a user-supplied regex for safety (prevent ReDoS).
 * Rejects nested quantifiers and other dangerous patterns.
 */
function isSafeRegex(regexStr: string): boolean {
  // Reject nested quantifiers like (a+)+, (a*)+, (a?)+, (a{1,})+
  if (/(\+|\*|\?|\{[^}]+\})\s*(\+|\*|\?|\{)/.test(regexStr)) return false;
  // Reject patterns longer than 500 chars
  if (regexStr.length > 500) return false;
  // Try to compile it
  try {
    new RegExp(regexStr);
    return true;
  } catch {
    return false;
  }
}

/**
 * Semantic field-name mapping: when the JSON key name matches,
 * redact the ENTIRE value regardless of regex matches.
 * This catches structured data where the field name IS the context.
 */
const SEMANTIC_FIELD_MAP: Array<{
  keys: RegExp;
  label: string;
  category: PiiCategory;
}> = [
  // Person names
  {
    keys: /^(?:name|first_?name|last_?name|full_?name|given_?name|family_?name|surname|maiden_?name|vorname|nachname|familienname|prenom|nom|nombre|apellido|displayName|display_name|contactName|contact_name|customerName|customer_name|userName|user_name|recipient|sender|author|owner)$/i,
    label: 'PERSON_NAME',
    category: 'identity',
  },
  // Employee / Staff IDs
  {
    keys: /^(?:employee_?id|staff_?id|personnel_?(?:id|number|nr)|personalnummer|mitarbeiter_?(?:id|nummer|nr)|worker_?id|emp_?id|empId|staffNumber|badge_?(?:id|number))$/i,
    label: 'EMPLOYEE_ID',
    category: 'identity',
  },
  // Department
  {
    keys: /^(?:department|dept|abteilung|division|business_?unit|team|group|service|unit)$/i,
    label: 'DEPARTMENT',
    category: 'identity',
  },
  // Job title / position / role
  {
    keys: /^(?:position|job_?title|title|role|designation|occupation|berufsbezeichnung|stelle|poste|titulo|function|jobRole|job_role)$/i,
    label: 'JOB_TITLE',
    category: 'identity',
  },
  // Salary / compensation
  {
    keys: /^(?:salary|compensation|wage|wages|income|pay|pay_?rate|hourly_?rate|annual_?salary|monthly_?salary|gehalt|lohn|remuneration|base_?pay|gross_?pay|net_?pay|bonus|commission)$/i,
    label: 'SALARY',
    category: 'financial',
  },
  // Hire / start date
  {
    keys: /^(?:hire_?date|start_?date|joining_?date|date_?of_?hire|employment_?date|eintrittsdatum|einstellungsdatum|onboarding_?date|termination_?date|end_?date|leaving_?date|resignation_?date)$/i,
    label: 'HIRE_DATE',
    category: 'temporal',
  },
  // Date of birth
  {
    keys: /^(?:dob|date_?of_?birth|birth_?date|birthday|geburtsdatum|born|fecha_?de_?nacimiento|data_?di_?nascita)$/i,
    label: 'DOB',
    category: 'temporal',
  },
  // Address
  {
    keys: /^(?:address|street_?address|home_?address|mailing_?address|shipping_?address|billing_?address|postal_?address|residence|domicile|anschrift|adresse|wohnadresse|wohnort|street|street_?line|address_?line|city|state|province|country|region|zip|zip_?code|postal_?code|plz|postleitzahl)$/i,
    label: 'ADDRESS',
    category: 'location',
  },
  // Phone
  {
    keys: /^(?:phone|phone_?number|mobile|cell|telephone|tel|fax|contact_?number|telefon|telefonnummer|handy|rufnummer|numero_?de_?telephone)$/i,
    label: 'PHONE',
    category: 'contact',
  },
  // SSN / National ID
  {
    keys: /^(?:ssn|social_?security|social_?security_?number|national_?id|national_?id_?number|identity_?number|id_?number|tax_?id|tax_?number|steuer_?id|steuer_?nummer|nif|nie|dni|bsn|nino|pps|pesel|cpf|aadhaar|pan)$/i,
    label: 'NATIONAL_ID',
    category: 'identity',
  },
  // Account numbers
  {
    keys: /^(?:account_?number|account_?no|acct|acct_?number|bank_?account|iban|routing_?number|sort_?code|kontonummer|bankleitzahl)$/i,
    label: 'ACCOUNT_NUMBER',
    category: 'financial',
  },
  // Credit card
  {
    keys: /^(?:card_?number|credit_?card|cc_?number|pan|card_?no|kartennummer)$/i,
    label: 'CREDIT_CARD',
    category: 'financial',
  },
  // Insurance
  {
    keys: /^(?:insurance_?(?:id|number|policy|no)|policy_?(?:number|no|id)|health_?plan|member_?id|subscriber_?id|beneficiary_?id|versicherungsnummer|krankenversicherung)$/i,
    label: 'INSURANCE',
    category: 'financial',
  },
  // Passport
  {
    keys: /^(?:passport|passport_?number|passport_?no|reisepass|passnummer)$/i,
    label: 'PASSPORT',
    category: 'identity',
  },
  // Driver license
  {
    keys: /^(?:driver_?license|drivers_?license|driving_?licence|dl_?number|fuehrerschein|permis_?de_?conduire|license_?number)$/i,
    label: 'DRIVER_LICENSE',
    category: 'identity',
  },
  // Medical
  {
    keys: /^(?:mrn|medical_?record|patient_?id|health_?id|diagnosis|icd_?code|medication|prescription|blood_?type|allergy|allergies|condition|disability)$/i,
    label: 'MEDICAL',
    category: 'medical',
  },
  // Company / Organization
  {
    keys: /^(?:company|company_?name|organization|organisation|employer|firma|unternehmen|arbeitgeber|business_?name|corp|corporation|subsidiary|parent_?company)$/i,
    label: 'COMPANY',
    category: 'identity',
  },
  // Notes / free text (likely contains PII)
  {
    keys: /^(?:notes|comment|comments|description|message|body|text|content|remarks|internal_?notes|agent_?notes|case_?notes|memo|narrative|summary|details|reason|explanation)$/i,
    label: '', // empty = run regex patterns, don't redact whole value
    category: 'identity',
  },
];

/**
 * Check if a field key matches a semantic field and should be fully redacted.
 * Returns the label if the entire value should be redacted, empty string if
 * regex scanning should be used, or null if no semantic match.
 */
function getSemanticLabel(fieldKey: string): { label: string; category: PiiCategory } | null {
  // Extract the last key segment (e.g., "user.profile.name" -> "name")
  const lastKey = fieldKey.includes('.') ? fieldKey.split('.').pop()! : fieldKey;
  // Also try the key without array indices (e.g., "contacts[0].name" -> "name")
  const cleanKey = lastKey.replace(/\[\d+\]/g, '');

  for (const mapping of SEMANTIC_FIELD_MAP) {
    if (mapping.keys.test(cleanKey)) {
      return { label: mapping.label, category: mapping.category };
    }
  }
  return null;
}

/**
 * Main redaction engine - recursively walks JSON and applies redaction.
 * Uses BOTH semantic field-name detection AND regex pattern matching.
 */
export function redactValue(
  value: unknown,
  ctx: RedactionContext,
  vault: IVault,
  sessionId: string,
  hits: RedactionHit[],
  itemIndex: number,
  currentPath: string = '',
): unknown {
  if (typeof value === 'string') {
    if (!shouldProcessField(currentPath, ctx.fieldMode, ctx.fieldRules)) {
      return value;
    }

    // Semantic field-name detection: if the field name tells us what this is,
    // redact the ENTIRE value without needing regex to match
    const semantic = getSemanticLabel(currentPath);
    if (semantic && semantic.label && value.trim().length > 0) {
      const replacement = applyRedaction(
        value, { label: semantic.label, category: semantic.category },
        ctx.mode, vault, sessionId, ctx.dedup,
      );
      hits.push({
        token: replacement,
        original: '***',
        patternName: `semantic_${semantic.label}`,
        patternLabel: semantic.label,
        category: semantic.category,
        field: currentPath,
        itemIndex,
      });
      return replacement;
    }

    // Fall through to regex-based detection
    return redactText(value, ctx, vault, sessionId, hits, itemIndex, currentPath);
  }

  if (typeof value === 'number') {
    // Semantic detection for numeric values (salary, age, etc.)
    const semantic = getSemanticLabel(currentPath);
    if (semantic && semantic.label && value !== 0) {
      const strValue = String(value);
      const replacement = applyRedaction(
        strValue, { label: semantic.label, category: semantic.category },
        ctx.mode, vault, sessionId, ctx.dedup,
      );
      hits.push({
        token: replacement,
        original: '***',
        patternName: `semantic_${semantic.label}`,
        patternLabel: semantic.label,
        category: semantic.category,
        field: currentPath,
        itemIndex,
      });
      return replacement;
    }
  }

  if (Array.isArray(value)) {
    return value.map((v, i) =>
      redactValue(v, ctx, vault, sessionId, hits, itemIndex, `${currentPath}[${i}]`),
    );
  }

  if (value !== null && typeof value === 'object') {
    const obj: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      const fieldPath = currentPath ? `${currentPath}.${k}` : k;
      obj[k] = redactValue(v, ctx, vault, sessionId, hits, itemIndex, fieldPath);
    }
    return obj;
  }

  return value;
}

/**
 * Redact PII in a text string.
 */
function redactText(
  text: string,
  ctx: RedactionContext,
  vault: IVault,
  sessionId: string,
  hits: RedactionHit[],
  itemIndex: number,
  fieldPath: string,
): string {
  let result = text;

  // Built-in patterns
  const activePatterns = getPatternsByNames(ctx.enabledPatterns);
  for (const pattern of activePatterns) {
    // Create fresh regex instance (avoid lastIndex issues with /g flag)
    const re = new RegExp(pattern.regex.source, pattern.regex.flags);
    result = result.replace(re, (match) => {
      // Skip already-redacted tokens
      if (TOKEN_RE.test(match) || (match.startsWith('[') && match.endsWith(']'))) return match;

      // Run validator if present
      if (pattern.validate && !pattern.validate(match)) return match;

      const replacement = applyRedaction(
        match, pattern, ctx.mode, vault, sessionId, ctx.dedup,
      );

      hits.push({
        token: replacement,
        original: '***', // NEVER expose raw PII in reports
        patternName: pattern.name,
        patternLabel: pattern.label,
        category: pattern.category,
        field: fieldPath,
        itemIndex,
      });

      return replacement;
    });
  }

  // Custom patterns — with safety validation
  for (const cp of ctx.customPatterns) {
    if (!cp.label || !cp.regex) continue;
    if (!isSafeRegex(cp.regex)) continue; // Reject dangerous regex
    try {
      const re = new RegExp(cp.regex, 'g');
      result = result.replace(re, (match) => {
        if (TOKEN_RE.test(match)) return match;

        const pseudoPattern = {
          label: cp.label.toUpperCase(),
          category: (cp.category as PiiCategory) || 'identity',
        };

        const replacement = applyRedaction(
          match, pseudoPattern, ctx.mode, vault, sessionId, ctx.dedup,
        );

        hits.push({
          token: replacement,
          original: '***',
          patternName: `custom_${cp.label}`,
          patternLabel: pseudoPattern.label,
          category: pseudoPattern.category,
          field: fieldPath,
          itemIndex,
        });

        return replacement;
      });
    } catch {
      // Skip invalid regex
    }
  }

  return result;
}

/**
 * Restore redacted tokens back to original values.
 * Uses single-pass replacement to avoid infinite loops.
 */
export function restoreValue(value: unknown, vault: IVault, sessionId: string): unknown {
  const session = vault.getSession(sessionId);
  if (!session) return value;

  if (typeof value === 'string') {
    let result = value;
    // Single-pass: replace each token exactly once per occurrence.
    // Use split/join which is safe against infinite loops.
    for (const [token, entry] of Object.entries(session.entries)) {
      result = result.split(token).join(entry.original);
    }
    return result;
  }

  if (Array.isArray(value)) {
    return value.map((v) => restoreValue(v, vault, sessionId));
  }

  if (value !== null && typeof value === 'object') {
    const obj: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      obj[k] = restoreValue(v, vault, sessionId);
    }
    return obj;
  }

  return value;
}

/**
 * Build a redaction audit report from collected hits.
 * SECURITY: Original PII values are NEVER included in the report.
 */
export function buildReport(sessionId: string, hits: RedactionHit[]): RedactionReport {
  const hitsByCategory: Record<string, number> = {};
  const hitsByPattern: Record<string, number> = {};

  for (const hit of hits) {
    hitsByCategory[hit.category] = (hitsByCategory[hit.category] || 0) + 1;
    hitsByPattern[hit.patternLabel] = (hitsByPattern[hit.patternLabel] || 0) + 1;
  }

  return {
    sessionId,
    timestamp: new Date().toISOString(),
    totalHits: hits.length,
    hitsByCategory,
    hitsByPattern,
    hits,
  };
}
