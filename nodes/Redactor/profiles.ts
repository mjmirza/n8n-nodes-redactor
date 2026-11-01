// CODE_DELETE_OK: disk profile load/save/list/delete removed in 2.0 (n8n bans fs); 1.x keeps them on release/1.x.
/**
 * Per-tenant profiles. Supplied as JSON in the node, so they work on n8n Cloud.
 * parseTenantProfile validates the shape and throws a readable Error on bad input.
 */

import { RedactionMode, CustomPattern, AllowDenyEntry, FieldRule } from './types';

export interface TenantProfile {
  profileId?: string;
  displayName?: string;

  // Detection config
  enabledPatterns?: string[];
  customPatterns?: CustomPattern[];
  confidenceThreshold?: number;

  // Redaction behavior
  redactionMode?: RedactionMode;
  dedup?: boolean;

  // Field targeting
  fieldMode?: 'all' | 'allowlist' | 'denylist';
  fieldRules?: FieldRule[];

  // Allow/Deny lists
  allowList?: AllowDenyEntry[];
  denyList?: AllowDenyEntry[];

  // Compliance
  region?: string;
  retentionMinutes?: number;
  auditLog?: boolean;

  // Metadata
  createdAt?: string;
  updatedAt?: string;
}

const MODES: RedactionMode[] = ['token', 'mask', 'hash', 'redact', 'pseudonymize', 'blackout', 'remove'];
const FIELD_MODES = ['all', 'allowlist', 'denylist'];
const MATCH_TYPES = ['exact', 'contains', 'regex'];

function fail(message: string): never {
  throw new Error(`Invalid tenant profile: ${message}`);
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function stringArray(value: unknown, name: string): string[] {
  if (!Array.isArray(value) || value.some((v) => typeof v !== 'string')) fail(`${name} must be an array of strings`);
  return value as string[];
}

function entries(value: unknown, name: string, defaultType: AllowDenyEntry['type']): AllowDenyEntry[] {
  if (!Array.isArray(value)) fail(`${name} must be an array`);
  return value.map((e, i) => {
    if (!isObject(e) || typeof e.value !== 'string') fail(`${name}[${i}].value must be a string`);
    const type = e.type ?? defaultType;
    if (typeof type !== 'string' || !MATCH_TYPES.includes(type)) fail(`${name}[${i}].type must be one of ${MATCH_TYPES.join(', ')}`);
    return { value: e.value, type: type as AllowDenyEntry['type'] };
  });
}

type FieldParser = (value: unknown, knownPatterns?: string[]) => unknown;

function str(name: string): FieldParser {
  return (v) => (typeof v === 'string' ? v : fail(`${name} must be a string`));
}

function bool(name: string): FieldParser {
  return (v) => (typeof v === 'boolean' ? v : fail(`${name} must be true or false`));
}

function oneOf(name: string, allowed: string[]): FieldParser {
  return (v) => (typeof v === 'string' && allowed.includes(v) ? v : fail(`${name} must be one of ${allowed.join(', ')}`));
}

function parseEnabledPatterns(value: unknown, knownPatterns?: string[]): string[] {
  const names = stringArray(value, 'enabledPatterns');
  if (knownPatterns) {
    const known = new Set(knownPatterns);
    const bad = names.filter((n) => !known.has(n));
    if (bad.length) fail(`unknown pattern name(s) ${bad.join(', ')}`);
  }
  return names;
}

function parseCustomPatterns(value: unknown): CustomPattern[] {
  if (!Array.isArray(value)) fail('customPatterns must be an array');
  return value.map((c, i) => {
    if (!isObject(c) || typeof c.label !== 'string' || typeof c.regex !== 'string') {
      fail(`customPatterns[${i}] needs string label and regex`);
    }
    try {
      new RegExp(c.regex);
    } catch {
      fail(`customPatterns[${i}].regex is not a valid regular expression`);
    }
    return { label: c.label, regex: c.regex, category: typeof c.category === 'string' ? c.category : undefined };
  });
}

function parseFieldRules(value: unknown): FieldRule[] {
  if (!Array.isArray(value)) fail('fieldRules must be an array');
  return value.map((r, i) => {
    if (!isObject(r) || typeof r.field !== 'string') fail(`fieldRules[${i}].field must be a string`);
    const mode = r.mode ?? 'exclude';
    if (mode !== 'include' && mode !== 'exclude') fail(`fieldRules[${i}].mode must be include or exclude`);
    return { field: r.field, mode };
  });
}

function parseThreshold(value: unknown): number {
  if (typeof value !== 'number' || value < 0 || value > 1) fail('confidenceThreshold must be a number from 0 to 1');
  return value;
}

function parseRetention(value: unknown): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
    fail('retentionMinutes must be a number of minutes, 0 or more');
  }
  return value;
}

const PARSERS: Record<keyof TenantProfile, FieldParser> = {
  profileId: str('profileId'),
  displayName: str('displayName'),
  enabledPatterns: parseEnabledPatterns,
  customPatterns: parseCustomPatterns,
  confidenceThreshold: parseThreshold,
  redactionMode: oneOf('redactionMode', MODES),
  dedup: bool('dedup'),
  fieldMode: oneOf('fieldMode', FIELD_MODES),
  fieldRules: parseFieldRules,
  allowList: (v) => entries(v, 'allowList', 'contains'),
  denyList: (v) => entries(v, 'denyList', 'exact'),
  region: str('region'),
  retentionMinutes: parseRetention,
  auditLog: bool('auditLog'),
  createdAt: str('createdAt'),
  updatedAt: str('updatedAt'),
};

/**
 * Parse and validate a profile from a JSON string or object.
 * knownPatterns, when given, rejects unknown names in enabledPatterns.
 */
export function parseTenantProfile(input: unknown, knownPatterns?: string[]): TenantProfile {
  let raw: unknown = input;
  if (typeof input === 'string') {
    if (input.trim() === '') return {};
    try {
      raw = JSON.parse(input);
    } catch {
      fail('not valid JSON');
    }
  }
  if (!isObject(raw)) fail('must be a JSON object');

  const unknown = Object.keys(raw).filter((k) => !(k in PARSERS));
  if (unknown.length) fail(`unknown field(s) ${unknown.join(', ')}`);

  const profile: Record<string, unknown> = {};
  for (const [key, parse] of Object.entries(PARSERS)) {
    if (raw[key] !== undefined) profile[key] = parse(raw[key], knownPatterns);
  }
  return profile as TenantProfile;
}
