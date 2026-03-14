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
 * Main redaction engine — recursively walks JSON and applies redaction.
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
    return redactText(value, ctx, vault, sessionId, hits, itemIndex, currentPath);
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
