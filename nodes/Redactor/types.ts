import type { PresidioRequester } from './presidio';
/** Shared type definitions for the PII Redactor node */

export interface PiiPattern {
  name: string;
  label: string;
  category: PiiCategory;
  regex: RegExp;
  /** Optional validator to reduce false positives */
  validate?: (match: string) => boolean;
  // A character every match contains. Text without it is skipped.
  anchor?: string;
  // A linear scanner used instead of the regex where the regex would backtrack.
  scan?: (text: string) => Array<{ start: number; end: number }>;
  /** Description shown in the UI */
  description?: string;
  /** Context words that boost confidence when found near a match */
  contextWords?: string[];
  /** Base confidence score (0.0 to 1.0) before context boosting */
  baseConfidence?: number;
}

export const PII_CATEGORIES = [
  'identity', 'financial', 'contact', 'network', 'location', 'temporal',
  'medical', 'crypto', 'enterprise', 'vehicle', 'biometric', 'other',
] as const;

export const isPiiCategory = (value: unknown): value is PiiCategory =>
  typeof value === 'string' && (PII_CATEGORIES as readonly string[]).includes(value);

export type PiiCategory =
  | 'identity'
  | 'financial'
  | 'contact'
  | 'network'
  | 'location'
  | 'temporal'
  | 'medical'
  | 'crypto'
  | 'enterprise'
  | 'vehicle'
  | 'biometric'
  | 'other';

export type RedactionMode =
  | 'token'           // [EMAIL_0] — reversible via vault
  | 'mask'            // j***@e*****.com — partial visibility, NOT reversible
  | 'hash'            // sha256 truncated — deterministic, NOT reversible
  | 'redact'          // [REDACTED] — full removal, NOT reversible
  | 'pseudonymize'    // sarah.miller@example.com — fake but realistic, reversible via vault
  | 'blackout'        // ████████ — visual black bars, NOT reversible
  | 'remove';         // (empty string) — complete removal, no trace, NOT reversible

export type VaultStorage = 'memory' | 'workflow' | 'file';

export interface RedactionHit {
  token: string;
  original: string;
  patternName: string;
  patternLabel: string;
  category: PiiCategory;
  field: string;
  itemIndex: number;
  /** Confidence score 0.0 to 1.0 */
  confidence: number;
}

export interface RedactionReport {
  sessionId: string;
  timestamp: string;
  totalHits: number;
  hitsByCategory: Record<string, number>;
  hitsByPattern: Record<string, number>;
  hits: RedactionHit[];
}

export interface VaultEntry {
  token: string;
  original: string;
  patternLabel: string;
  category: PiiCategory;
  createdAt: string;
  // Set when the original was a JSON number, so Restore returns a number.
  numeric?: boolean;
}

export interface VaultSession {
  sessionId: string;
  entries: Record<string, VaultEntry>;
  createdAt: string;
  ttl: number; // ms, 0 = no expiry
}

export interface CustomPattern {
  label: string;
  regex: string;
  category?: string;
}

export interface FieldRule {
  field: string;
  mode: 'include' | 'exclude';
}

export interface AllowDenyEntry {
  value: string;
  type: 'exact' | 'contains' | 'regex';
}

export interface RedactionContext {
  enabledPatterns: string[];
  customPatterns: CustomPattern[];
  mode: RedactionMode;
  dedup: boolean;
  fieldRules: FieldRule[];
  fieldMode: 'all' | 'allowlist' | 'denylist';
  skipSemantic?: boolean;
  /** Scan numeric values as text (Detect and Verify) */
  scanNumbers?: boolean;
  /** Values to NEVER redact (bypass) */
  allowList?: AllowDenyEntry[];
  /** Values to ALWAYS redact even if no pattern matches */
  denyList?: AllowDenyEntry[];
  /** Minimum confidence score to trigger redaction (0.0 to 1.0) */
  confidenceThreshold?: number;
  /** Presidio Analyzer base URL (e.g., http://localhost:5002) */
  presidioUrl?: string;
  /** Language for Presidio analysis (default: en) */
  presidioLanguage?: string;
  /** HTTP transport for Presidio, supplied by the node */
  presidioRequest?: PresidioRequester;
  // Token-shaped text already in the input; generated tokens never reuse it.
  reservedTokens?: Set<string>;
  // Output object to its key origins, so Presidio applies field rules to original paths.
  keyOrigins?: WeakMap<object, Map<string, string>>;
  // Every string, key and number of the input; a pseudonym never equals text already present.
  inputText?: string;
  // Positions of replacements per output container and key, so Presidio never re-redacts them.
  lockedSpans?: WeakMap<object, Map<string, Array<[number, number]>>>;
  // Replacement positions inside output keys, per container and key, for Presidio.
  keyLocks?: WeakMap<object, Map<string, Array<[number, number]>>>;
  // Spans of the value most recently produced, picked up by its container.
  lastLocked?: Array<[number, number]>;
  // Matches tokens the session mapped before this run, so equal input text gets its own mapping.
  priorTokens?: RegExp;
  // Set while redacting a number, so its mapping never merges with a text mapping.
  numeric?: boolean;
}
