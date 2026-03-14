/** Shared type definitions for the PII Redactor node */

export interface PiiPattern {
  name: string;
  label: string;
  category: PiiCategory;
  regex: RegExp;
  /** Optional validator to reduce false positives */
  validate?: (match: string) => boolean;
  /** Description shown in the UI */
  description?: string;
}

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
  | 'biometric';

export type RedactionMode =
  | 'token'       // [EMAIL_0] — reversible via vault
  | 'mask'        // j***@e*****.com — partial visibility, NOT reversible
  | 'hash'        // sha256 truncated — deterministic, NOT reversible
  | 'redact';     // [REDACTED] — full removal, NOT reversible

export type VaultStorage = 'memory' | 'file';

export interface RedactionHit {
  token: string;
  original: string;
  patternName: string;
  patternLabel: string;
  category: PiiCategory;
  field: string;
  itemIndex: number;
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

export interface RedactionContext {
  enabledPatterns: string[];
  customPatterns: CustomPattern[];
  mode: RedactionMode;
  dedup: boolean;
  fieldRules: FieldRule[];
  fieldMode: 'all' | 'allowlist' | 'denylist';
}
