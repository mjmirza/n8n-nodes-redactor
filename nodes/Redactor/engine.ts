import * as crypto from 'crypto';
import { getPatternsByNames } from './patterns';
import { IVault } from './vault';
import { checkRegex } from './regexSafety';
import {
  AllowDenyEntry,
  PiiCategory,
  PiiPattern,
  RedactionContext,
  RedactionHit,
  RedactionReport,
  VaultEntry,
  isPiiCategory,
} from './types';
import {
  calculateConfidence,
  SEMANTIC_CONFIDENCE,
  AMBIGUOUS_FIELD_CONFIDENCE,
  CUSTOM_PATTERN_CONFIDENCE,
  DENY_LIST_CONFIDENCE, hasContextWords 
} from './context';
import { detectNamesInText, NAME_CONTEXT_WORDS } from './names';
import { generatePseudonym } from './pseudonymize';
import { countHits } from './audit';
import {
  analyzeWithPresidio,
  getRedactorLabel,
  getRedactorCategory,
} from './presidio';

/**
 * Check if a value matches any entry in the allow list (should be SKIPPED).
 */
function isAllowListed(value: string, allowList?: AllowDenyEntry[]): boolean {
  if (!allowList || allowList.length === 0) return false;
  return allowList.some((entry) => {
    try {
      switch (entry.type) {
        case 'exact':
          return value === entry.value;
        case 'contains':
          return value.includes(entry.value);
        case 'regex':
          // Too long to test safely, so the value is not allow-listed and stays redacted.
          if (!isSafeRegex(entry.value) || value.length > USER_REGEX_MAX_INPUT) return false;
          return new RegExp(entry.value, 'i').test(value);
        default:
          return value === entry.value;
      }
    } catch {
      return false;
    }
  });
}

/**
 * Generate a deterministic token for a given label + index.
 */
function generateToken(label: string, index: number): string {
  // Labels are reduced to the token grammar, so every generated token is reserved against the input.
  const safe = label.toUpperCase().replace(/[^A-Z0-9_]/g, '_');
  return `[${/^[A-Z]/.test(safe) ? safe : `X${safe}`}_${index}]`;
}

/** Sets an own property, so a key such as __proto__ stays data and never changes the prototype. */
function setOwn(obj: Record<string, unknown>, key: string, value: unknown): void {
  Object.defineProperty(obj, key, { value, enumerable: true, writable: true, configurable: true });
}

/**
 * Token format regex — used to skip already-redacted regions.
 */

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

type RedactionPattern = PiiPattern | { label: string; category: PiiCategory };

/** Stores a reversible replacement in the vault, reusing an existing one when dedup is on. */
function storeReversible(
  match: string,
  pattern: RedactionPattern,
  ctx: RedactionContext,
  vault: IVault,
  sessionId: string,
  makeToken: () => string,
): string {
  if (ctx.dedup) {
    const existing = vault.findByOriginal(sessionId, match);
    if (existing && !existing.numeric && !existing.boolean) return existing.token;
  }
  const token = makeToken();
  addMapping(vault, sessionId, {
    token,
    original: match,
    patternLabel: pattern.label,
    category: ('category' in pattern ? pattern.category : 'identity') as PiiCategory,
    createdAt: new Date().toISOString(),
    ...(ctx.boolean ? { boolean: true } : {}),
  });
  return token;
}

const IRREVERSIBLE: Record<string, (match: string, label: string) => string> = {
  mask: (match, label) => maskValue(match, label),
  hash: (match, label) => `[${label}:${hashValue(match)}]`,
  redact: () => '[REDACTED]',
  blackout: (match) => '\u2588'.repeat(match.length), // visual black bars
  remove: () => '', // Complete removal, no trace left
};

/** Applies the context's mode to one match. Reversible modes store the mapping in the vault. */
function applyRedaction(
  match: string,
  pattern: RedactionPattern,
  ctx: RedactionContext,
  vault: IVault,
  sessionId: string,
): string {
  if (ctx.mode === 'token') {
    return storeReversible(match, pattern, ctx, vault, sessionId, () => freshToken(pattern.label, vault, sessionId, ctx.reservedTokens));
  }
  if (ctx.mode === 'pseudonymize') {
    // The pseudonym is stored as the token so Restore can map it back.
    return storeReversible(match, pattern, ctx, vault, sessionId, () => uniquePseudonym(vault, sessionId, match, pattern.label, ctx));
  }
  const irreversible = Object.prototype.hasOwnProperty.call(IRREVERSIBLE, ctx.mode) ? IRREVERSIBLE[ctx.mode] : undefined;
  if (!irreversible) throw new Error(`Unknown redaction mode "${String(ctx.mode)}"`);
  return irreversible(match, pattern.label);
}

// The next index per session's entry table, so a fresh token never recounts every entry.
const nextIndex = new WeakMap<object, number>();

/** Next unused token for the label, skipping vault tokens and token-shaped input text. */
function freshToken(label: string, vault: IVault, sessionId: string, reserved?: Set<string>): string {
  const entries = vault.getSession(sessionId)?.entries ?? {};
  let index = nextIndex.get(entries) ?? Object.keys(entries).length;
  let token = generateToken(label, index);
  while (entries[token] || reserved?.has(token)) token = generateToken(label, ++index);
  nextIndex.set(entries, index + 1);
  return token;
}

const TOKEN_LIKE_RE = /\[[A-Z][A-Z0-9_]*_\d+\]/g;

/** Visits every string, key and number in a JSON value. */
function walkText(value: unknown, visit: (text: string) => void): void {
  if (typeof value === 'string' || typeof value === 'number') visit(String(value));
  else if (Array.isArray(value)) value.forEach((v) => walkText(v, visit));
  else if (value !== null && typeof value === 'object') {
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      visit(k);
      walkText(v, visit);
    }
  }
}

/** Collects token-shaped text from every string and key, so generated tokens never collide with input. */
export function collectTokenLike(value: unknown, into: Set<string> = new Set()): Set<string> {
  walkText(value, (text) => {
    for (const m of text.matchAll(TOKEN_LIKE_RE)) into.add(m[0]);
  });
  return into;
}

/** Joins every string, key and number of the input, so pseudonyms can avoid text already present. */
export function collectInputText(value: unknown): string {
  const parts: string[] = [];
  walkText(value, (text) => parts.push(text));
  return parts.join('\u0000');
}

/** A same-original mapping is reused only when it has the same type: number, boolean or text. */
function reusable(taken: VaultEntry | undefined, original: string, ctx: RedactionContext): boolean {
  return !!taken && taken.original === original && !!taken.numeric === !!ctx.numeric && !!taken.boolean === !!ctx.boolean;
}

/** Retries deterministically until the pseudonym is free in this session and absent from the input. */
function uniquePseudonym(vault: IVault, sessionId: string, original: string, label: string, ctx: RedactionContext): string {
  const entries = vault.getSession(sessionId)?.entries ?? {};
  for (let attempt = 0; attempt < 32; attempt++) {
    const seed = attempt === 0 ? original : `${original}\u0000${attempt}`;
    const candidate = generatePseudonym(sessionId, seed, label);
    if (candidate === original || inputContains(ctx, candidate)) continue;
    const taken = entries[candidate];
    if (!taken || reusable(taken, original, ctx)) return candidate;
  }
  return freshToken(label, vault, sessionId, ctx.reservedTokens);
}

// Short input is searched directly. Longer input gets a suffix array once per run, kept on the run's context and
// released with it, so each candidate costs O(length log n) and no copy of the input outlives the run.
const DIRECT_SEARCH_MAX = 4096;

/** Whether text occurs anywhere in the run's input. */
function inputContains(ctx: RedactionContext, text: string): boolean {
  const input = ctx.inputText;
  if (!input) return false;
  if (input.length <= DIRECT_SEARCH_MAX) return input.includes(text);
  const holder = ctx.inputIndex ?? (ctx.inputIndex = {});
  const sa = holder.sa ?? (holder.sa = suffixArray(input));
  let lo = 0;
  let hi = sa.length;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if (compareSuffix(input, sa[mid], text) < 0) lo = mid + 1;
    else hi = mid;
  }
  return lo < sa.length && input.startsWith(text, sa[lo]);
}

/** Orders the suffix at pos against text, comparing at most text.length characters. */
function compareSuffix(input: string, pos: number, text: string): number {
  for (let k = 0; k < text.length; k++) {
    if (pos + k >= input.length) return -1;
    const d = input.charCodeAt(pos + k) - text.charCodeAt(k);
    if (d !== 0) return d;
  }
  return 0;
}

interface SuffixSort {
  n: number;
  sa: Int32Array;
  rank: Int32Array;
  next: Int32Array;
  order: Int32Array;
  counts: Int32Array;
}

/** Sorts suffixes by their first character and returns the highest rank. */
function sortByFirstChar(text: string, s: SuffixSort): number {
  const { n, sa, rank, counts } = s;
  for (let i = 0; i < n; i++) counts[text.charCodeAt(i) + 1]++;
  for (let c = 1; c <= 65536; c++) counts[c] += counts[c - 1];
  for (let i = 0; i < n; i++) sa[counts[text.charCodeAt(i)]++] = i;
  let classes = 0;
  for (let p = 0; p < n; p++) {
    if (p > 0 && text.charCodeAt(sa[p]) !== text.charCodeAt(sa[p - 1])) classes++;
    rank[sa[p]] = classes;
  }
  return classes;
}

/** Orders suffixes by the rank of their second half: those without one first, then the sorted ones shifted back by k. */
function orderBySecondHalf(s: SuffixSort, k: number): void {
  const { n, sa, order } = s;
  let w = 0;
  for (let i = n - k; i < n; i++) order[w++] = i;
  for (let p = 0; p < n; p++) if (sa[p] >= k) order[w++] = sa[p] - k;
}

/** Stable counting sort of that order by the rank of the first half. */
function sortByFirstHalf(s: SuffixSort, classes: number): void {
  const { n, sa, rank, order, counts } = s;
  counts.fill(0, 0, classes + 2);
  for (let i = 0; i < n; i++) counts[rank[i] + 1]++;
  for (let c = 1; c <= classes + 1; c++) counts[c] += counts[c - 1];
  for (let p = 0; p < n; p++) sa[counts[rank[order[p]]]++] = order[p];
}

/** Sorts by the first 2k characters, given the order by the first k. Returns the highest new rank. */
function doubleSortKey(s: SuffixSort, k: number, classes: number): number {
  const { n, sa, rank, next } = s;
  orderBySecondHalf(s, k);
  sortByFirstHalf(s, classes);
  const second = (i: number) => (i + k < n ? rank[i + k] : -1);
  let ranks = 0;
  next[sa[0]] = 0;
  for (let p = 1; p < n; p++) {
    if (rank[sa[p - 1]] !== rank[sa[p]] || second(sa[p - 1]) !== second(sa[p])) ranks++;
    next[sa[p]] = ranks;
  }
  return ranks;
}

/** Suffix array by prefix doubling with counting sorts, O(n log n). */
function suffixArray(text: string): Int32Array {
  const n = text.length;
  const s: SuffixSort = {
    n, sa: new Int32Array(n), rank: new Int32Array(n), next: new Int32Array(n), order: new Int32Array(n),
    counts: new Int32Array(Math.max(n, 65536) + 1),
  };
  let classes = sortByFirstChar(text, s);
  for (let k = 1; classes < n - 1 && k < n; k <<= 1) {
    classes = doubleSortKey(s, k, classes);
    [s.rank, s.next] = [s.next, s.rank];
  }
  return s.sa;
}

/** Token lengths per first character for one session table, so a composition check tests only lengths that exist. */
interface TokenShape {
  byFirst: Map<number, number[]>;
  // A hash and length of every proper prefix of every token. Text that is not the start of some token cannot be
  // extended into one, so most positions cost one lookup.
  prefixes: Set<number>;
  maxLen: number;
}

const HASH_BASE = 131;
const HASH_MOD = 67108859; // a prime below 2^26, so every product stays exact in a double
const prefixKey = (hash: number, length: number): number => hash * 64 + Math.min(length, 63);
const tokenShapes = new WeakMap<object, TokenShape>();

function shapeAdd(shape: TokenShape, token: string): void {
  if (token.length === 0) return;
  const first = token.charCodeAt(0);
  const lengths = shape.byFirst.get(first) ?? [];
  if (!lengths.includes(token.length)) {
    lengths.push(token.length);
    lengths.sort((a, b) => a - b);
  }
  shape.byFirst.set(first, lengths);
  let hash = 0;
  for (let k = 0; k < token.length - 1; k++) {
    hash = (hash * HASH_BASE + token.charCodeAt(k)) % HASH_MOD;
    shape.prefixes.add(prefixKey(hash, k + 1));
  }
  shape.maxLen = Math.max(shape.maxLen, token.length);
}

function tokenShape(entries: Record<string, VaultEntry>): TokenShape {
  let shape = tokenShapes.get(entries);
  if (!shape) {
    shape = { byFirst: new Map(), prefixes: new Set(), maxLen: 0 };
    for (const token of Object.keys(entries)) shapeAdd(shape, token);
    tokenShapes.set(entries, shape);
  }
  return shape;
}

/** Adds a mapping and keeps the session's token shape current. */
function addMapping(vault: IVault, sessionId: string, entry: VaultEntry): void {
  vault.addEntry(sessionId, entry);
  const entries = vault.getSession(sessionId)?.entries;
  const shape = entries ? tokenShapes.get(entries) : undefined;
  if (shape) shapeAdd(shape, entry.token);
}

/** Whether a stored token starts before at, or at at and is longer than len, and runs into the text at window[at, at + len). */
function crossedBy(window: string, at: number, len: number, entries: Record<string, VaultEntry>, shape: TokenShape): boolean {
  const tokenAt = (p: number): boolean => {
    for (const l of shape.byFirst.get(window.charCodeAt(p)) ?? []) {
      if (p + l <= at || (p === at && l <= len)) continue;
      if (p + l > window.length) break;
      if (Object.prototype.hasOwnProperty.call(entries, window.substr(p, l))) return true;
    }
    return false;
  };
  // Starts before at: window[p, at) must be a proper prefix of a token. Its hash grows one character to the left.
  let hash = 0;
  let power = 1;
  for (let p = at - 1; p >= 0 && at - p < shape.maxLen; p--) {
    hash = (window.charCodeAt(p) * power + hash) % HASH_MOD;
    power = (power * HASH_BASE) % HASH_MOD;
    if (shape.prefixes.has(prefixKey(hash, at - p)) && tokenAt(p)) return true;
  }
  // Starts at at: the replacement itself must be a proper prefix of a longer token.
  let own = 0;
  for (let k = 0; k < len; k++) own = (own * HASH_BASE + window.charCodeAt(at + k)) % HASH_MOD;
  return shape.prefixes.has(prefixKey(own, len)) && tokenAt(at);
}

/** Text of the segments before index i, up to want characters, nearest last. */
function textBefore(segs: Segment[], i: number, want: number): string {
  let out = '';
  for (let j = i - 1; j >= 0 && out.length < want; j--) out = segs[j].text + out;
  return out.slice(Math.max(0, out.length - want));
}

function textAfter(segs: Segment[], i: number, want: number): string {
  let out = '';
  for (let j = i + 1; j < segs.length && out.length < want; j++) out += segs[j].text;
  return out.slice(0, want);
}

/**
 * Pseudonyms carry no delimiters, so text next to one can spell another stored pseudonym, and Restore would decode
 * the wrong value. Such a replacement gets a bracketed token instead, which no neighbouring text can extend.
 */
function separatePseudonyms(pass: TextPass): void {
  const { vault, sessionId } = pass;
  const entries = vault.getSession(sessionId)?.entries;
  if (!entries) return;
  const shape = tokenShape(entries);
  for (let i = pass.segs.length - 1; i >= 0; i--) {
    const seg = pass.segs[i];
    const entry = seg.locked && Object.prototype.hasOwnProperty.call(entries, seg.text) ? entries[seg.text] : undefined;
    if (!entry || seg.text.length === 0) continue;
    const before = textBefore(pass.segs, i, shape.maxLen - 1);
    const window = before + seg.text + textAfter(pass.segs, i, shape.maxLen);
    if (crossedBy(window, before.length, seg.text.length, entries, shape)) rebracket(pass, seg, entry);
  }
}

/** Gives one replacement a bracketed token of its own, and points its report hit at it. */
function rebracket(pass: TextPass, seg: Segment, entry: VaultEntry): void {
  const { vault, sessionId, ctx } = pass;
  const token = freshToken(entry.patternLabel || 'PSEUDONYM', vault, sessionId, ctx.reservedTokens);
  addMapping(vault, sessionId, {
    token, original: pass.source.slice(seg.src, seg.end), patternLabel: entry.patternLabel, category: entry.category,
    createdAt: new Date().toISOString(),
  });
  const hit = lastHitFor(pass.hits, seg.text);
  if (hit) hit.token = token;
  seg.text = token;
}

/** The latest report hit for a token. The replacement just made is the last one recorded for it. */
function lastHitFor(hits: RedactionHit[], token: string): RedactionHit | undefined {
  for (let h = hits.length - 1; h >= 0; h--) if (hits[h].token === token) return hits[h];
  return undefined;
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

type GlobToken = { kind: 'char'; ch: string } | { kind: 'star' } | { kind: 'digits' };

/** Splits a field rule into tokens: a literal character, * for one or more characters other than a dot, or [*] for an array index. */
function globTokens(pattern: string): GlobToken[] {
  const tokens: GlobToken[] = [];
  for (let i = 0; i < pattern.length; i++) {
    if (pattern.startsWith('[*]', i)) {
      tokens.push({ kind: 'char', ch: '[' }, { kind: 'digits' }, { kind: 'char', ch: ']' });
      i += 2;
    } else if (pattern[i] === '*') {
      tokens.push({ kind: 'star' });
    } else {
      tokens.push({ kind: 'char', ch: pattern[i] });
    }
  }
  return tokens;
}

/**
 * Wildcard matching for JSON paths: "user.email", "*.email", "contacts[*].phone".
 * Dynamic programming over the path, so any number of stars costs path length times pattern length, never backtracking.
 */
function fieldPathMatches(actual: string, pattern: string): boolean {
  const tokens = globTokens(pattern);
  // reach[j]: the path read so far can end after token j.
  let reach = new Array<boolean>(tokens.length + 1).fill(false);
  reach[0] = true;
  for (let i = 0; i < actual.length; i++) {
    const next = new Array<boolean>(tokens.length + 1).fill(false);
    for (let j = 0; j < tokens.length; j++) next[j + 1] = globStep(tokens[j], actual[i], reach[j], reach[j + 1]);
    reach = next;
  }
  return reach[tokens.length];
}

/** Whether token can end on ch: before is "the path so far ended before the token", within "ended inside it". */
function globStep(token: GlobToken, ch: string, before: boolean, within: boolean): boolean {
  if (token.kind === 'char') return before && token.ch === ch;
  const fits = token.kind === 'star' ? ch !== '.' : ch >= '0' && ch <= '9';
  // A repeat takes this character to start its run, or to continue the run it already began.
  return fits && (before || within);
}

/** Shared with profile parsing so both accept and refuse the same patterns. */
function isSafeRegex(regexStr: string): boolean {
  return checkRegex(regexStr) === null;
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
  // ═══════════════════════════════════════════
  // PERSON NAMES (EN/DE/FR/ES/IT/PT/NL/SV/NO/DA/PL/RU/JA/KO/ZH/AR/TR)
  // Covers: camelCase, snake_case, PascalCase, abbreviations, prefixed, suffixed
  // ═══════════════════════════════════════════
  {
    keys: /^(?:name|first_?name|last_?name|full_?name|given_?name|family_?name|middle_?name|surname|maiden_?name|nick_?name|salutation|display_?name|contact_?name|customer_?name|client_?name|patient_?name|user_?name|member_?name|subscriber_?name|account_?name|holder_?name|card_?holder|cardholder_?name|beneficiary_?name|recipient_?name|sender_?name|author_?name|owner_?name|guardian_?name|parent_?name|spouse_?name|partner_?name|emergency_?contact|next_?of_?kin|applicant_?name|candidate_?name|student_?name|teacher_?name|employee_?name|manager_?name|supervisor_?name|guarantor|witness|signatory|cosigner|fname|lname|mname|fn|ln|mn|firstname|lastname|middlename|fullname|givenname|familyname|sur_?name|name_?first|name_?last|name_?full|legal_?name|birth_?name|married_?name|former_?name|known_?as|aka|vorname|nachname|familienname|geburtsname|anzeige_?name|kundenname|prenom|nom|nom_?de_?famille|nom_?complet|nom_?de_?jeune_?fille|nombre|apellido|apellidos|nombre_?completo|nome|cognome|nome_?completo|naam|achternaam|voornaam|volledige_?naam|fornamn|efternamn|fornavn|etternavn|imie|nazwisko|imya|familiya|sei|mei|shimei|seimei|xing|ming|xingming|isim|soyisim|soyad|ism|nasab)$/i,
    label: 'PERSON_NAME',
    category: 'identity',
  },

  // ═══════════════════════════════════════════
  // EMPLOYEE / STAFF / WORKER IDs
  // ═══════════════════════════════════════════
  {
    keys: /^(?:employee_?id|emp_?id|emp_?no|emp_?num|emp_?number|staff_?id|staff_?no|staff_?number|personnel_?(?:id|number|no|nr)|worker_?id|worker_?number|workforce_?id|badge_?(?:id|number|no)|clock_?(?:id|number)|payroll_?(?:id|number|no)|hr_?id|hr_?number|contractor_?id|temp_?id|intern_?id|associate_?id|team_?member_?id|personalnummer|mitarbeiter_?(?:id|nummer|nr|number)|arbeitnehmer_?nr|numero_?employe|matricule|numero_?dipendente|medewerkernummer|personeelsnummer|anstallningsnummer|ansattnummer|numer_?pracownika)$/i,
    label: 'EMPLOYEE_ID',
    category: 'identity',
  },

  // ═══════════════════════════════════════════
  // DEPARTMENT / DIVISION / TEAM / BUSINESS UNIT
  // ═══════════════════════════════════════════
  {
    keys: /^(?:department|dept|department_?name|dept_?name|dept_?code|division|division_?name|business_?unit|bu|cost_?center|cost_?centre|profit_?center|team|team_?name|group|group_?name|unit|unit_?name|section|section_?name|branch|branch_?name|office|office_?name|site|site_?name|location_?name|work_?location|facility|plant|factory|warehouse|abteilung|abteilungsname|bereich|referat|dienststelle|departement|service|direction|dipartimento|reparto|ufficio|afdeling|divisie|avdelning|avdeling|wydzial|dzial|otdel|bu_?name|org_?unit)$/i,
    label: 'DEPARTMENT',
    category: 'identity',
  },

  // ═══════════════════════════════════════════
  // JOB TITLE / POSITION / ROLE / DESIGNATION / OCCUPATION
  // ═══════════════════════════════════════════
  {
    keys: /^(?:position|job_?title|job_?role|job_?function|job_?type|job_?name|job_?description|job_?code|job_?level|job_?grade|job_?band|job_?family|job_?category|designation|occupation|profession|seniority|career_?level|functional_?title|working_?title|official_?title|employment_?type|contract_?type|work_?type|engagement_?type|berufsbezeichnung|stelle|stellenbezeichnung|position_?title|funktion|dienstbezeichnung|beruf|taetigkeit|poste|fonction|intitule_?du_?poste|titulo|cargo|puesto|posizione|ruolo|qualifica|mansione|functie|functietitel|befattning|stilling|stanowisko|zawod|dolzhnost|shokumei|yakushoku|zhiwei|zhicheng|gorev|unvan|pozisyon)$/i,
    label: 'JOB_TITLE',
    category: 'identity',
  },

  // ═══════════════════════════════════════════
  // SALARY / COMPENSATION / PAY / INCOME / WAGES
  // ═══════════════════════════════════════════
  {
    keys: /^(?:salary|compensation|wage|wages|income|pay|pay_?rate|hourly_?rate|daily_?rate|annual_?salary|monthly_?salary|weekly_?salary|yearly_?salary|base_?pay|base_?salary|gross_?pay|gross_?salary|net_?pay|net_?salary|take_?home|total_?comp|total_?compensation|total_?pay|total_?earnings|earnings|remuneration|stipend|allowance|bonus|bonus_?amount|commission|commission_?amount|overtime|overtime_?pay|severance|severance_?pay|pension|pension_?amount|retirement_?contribution|stock_?options|equity|rsu|vesting|deduction|deductions|tax_?withholding|withholding|benefits_?value|ctc|cost_?to_?company|package|comp_?package|offer_?amount|starting_?salary|current_?salary|previous_?salary|expected_?salary|desired_?salary|salary_?range|pay_?grade|pay_?band|pay_?scale|gehalt|brutto_?gehalt|netto_?gehalt|grundgehalt|jahresgehalt|monatsgehalt|lohn|bruttolohn|nettolohn|verguetung|entgelt|bezuege|zuschlag|praemie|provision|salaire|remuneration_?brute|remuneration_?nette|stipendio|retribuzione|salario|sueldo|remuneracao|loon|salaris|lon|lonn|wynagrodzenie|pensja|zarplata|oklad|kyuyo|nenshu|gongzi|xinshui|maas|ucret)$/i,
    label: 'SALARY',
    category: 'financial',
  },

  // ═══════════════════════════════════════════
  // DATES: Hire, Start, End, Termination, Birth, Death, etc.
  // ═══════════════════════════════════════════
  {
    keys: /^(?:hire_?date|start_?date|joining_?date|date_?of_?hire|date_?of_?joining|employment_?date|employment_?start|onboarding_?date|effective_?date|commencement_?date|appointment_?date|probation_?(?:start|end)_?date|termination_?date|end_?date|leaving_?date|resignation_?date|separation_?date|exit_?date|last_?day|last_?working_?day|notice_?date|retirement_?date|contract_?(?:start|end)_?date|trial_?(?:start|end)_?date|review_?date|appraisal_?date|promotion_?date|transfer_?date|anniversary_?date|tenure_?start|eintrittsdatum|einstellungsdatum|austrittsdatum|kuendigungsdatum|probezeitende|vertragsbeginn|vertragsende|date_?embauche|date_?de_?debut|date_?de_?fin|date_?sortie|fecha_?de_?inicio|fecha_?de_?fin|data_?assunzione|data_?cessazione|datum_?indiensttreding|datum_?uitdiensttreding|anstallningsdatum|ansettelsesdato|data_?zatrudnienia)$/i,
    label: 'EMPLOYMENT_DATE',
    category: 'temporal',
  },
  {
    keys: /^(?:dob|date_?of_?birth|birth_?date|birthday|birth_?day|born|born_?on|born_?date|geburtsdatum|geburtstag|date_?de_?naissance|fecha_?de_?nacimiento|data_?di_?nascita|geboortedatum|fodelsedatum|fodselsdato|syntymapaiva|data_?de_?nascimento|data_?urodzenia|den_?rozhdeniya|seinengappi|shengri|dogum_?tarihi)$/i,
    label: 'DOB',
    category: 'temporal',
  },
  {
    keys: /^(?:date_?of_?death|death_?date|deceased_?date|died_?on|died|sterbedatum|todesdatum|date_?de_?deces|fecha_?de_?defuncion|data_?di_?morte)$/i,
    label: 'DATE_OF_DEATH',
    category: 'temporal',
  },
  {
    keys: /^(?:person_?age|patient_?age|customer_?age|employee_?age|age_?years|current_?age|alter|edad|eta|yaş|wiek|vozrast|nenrei|nianling)$/i,
    label: 'AGE',
    category: 'temporal',
  },

  // ═══════════════════════════════════════════
  // ADDRESS / LOCATION (every variation in 15+ languages)
  // ═══════════════════════════════════════════
  {
    keys: /^(?:address|street_?address|home_?address|mailing_?address|shipping_?address|billing_?address|postal_?address|residential_?address|permanent_?address|temporary_?address|current_?address|previous_?address|work_?address|office_?address|business_?address|delivery_?address|correspondence_?address|legal_?address|registered_?address|address_?line_?[123]|addr_?[123]|addr|street|street_?name|street_?line|street_?line_?[12]|house_?number|house_?no|building|apartment|apt|flat|suite|floor|room|unit_?number|block|lot|po_?box|post_?box|city|town|municipality|village|locality|suburb|district|borough|county|state|province|region|territory|country|country_?code|country_?name|nation|zip|zip_?code|zipcode|postal_?code|postcode|post_?code|pin_?code|area_?code|geo_?location|latitude|longitude|lat|lng|coordinates|place|place_?of_?birth|birth_?place|place_?of_?residence|domicile|residence|neighborhood|neighbourhood|quarter|canton|prefecture|commune|departement|land|bundesland|kreis|bezirk|ortsteil|stadtteil|gemeinde|anschrift|adresse|wohnadresse|wohnort|strasse|hausnummer|plz|postleitzahl|ort|stadt|wohnhaft|rue|ville|code_?postal|cedex|calle|direccion|codigo_?postal|localidad|poblacion|provincia|comunidad|via|indirizzo|cap|citta|comune|straat|huisnummer|postbus|plaats|woonplaats|gata|postnummer|sted|ulica|kod_?pocztowy|miasto|adres|gorod|pochta|jyusho|jutaku|dizhi|chengshi|youbian|adres|mahalle|ilce|il|posta_?kodu)$/i,
    label: 'ADDRESS',
    category: 'location',
  },

  // ═══════════════════════════════════════════
  // PHONE / MOBILE / FAX / CONTACT NUMBERS
  // ═══════════════════════════════════════════
  {
    keys: /^(?:phone|phone_?number|phone_?no|mobile|mobile_?number|mobile_?no|cell|cell_?phone|cell_?number|telephone|tel|tel_?number|fax|fax_?number|fax_?no|contact_?number|contact_?phone|home_?phone|work_?phone|office_?phone|business_?phone|direct_?line|direct_?dial|extension|ext|callback|callback_?number|sms_?number|whatsapp|whatsapp_?number|primary_?phone|secondary_?phone|alternate_?phone|emergency_?phone|telefon|telefonnummer|mobilnummer|handy|handynummer|festnetz|rufnummer|durchwahl|faxnummer|telephone_?portable|portable|fixe|numero_?de_?telephone|numero_?de_?portable|telefono|cellulare|numero_?di_?telefono|numero_?de_?telefone|celular|telefoon|mobiel|telefoonnummer|mobilnummer_?2|telefonnr|tlf|telefon_?komorkowy|telefon_?stacjonarny|nomer_?telefona|denwabangou|keitai|dianhua|shouji|telefon_?numarasi|cep_?telefonu)$/i,
    label: 'PHONE',
    category: 'contact',
  },

  // ═══════════════════════════════════════════
  // EMAIL (every variation)
  // ═══════════════════════════════════════════
  {
    keys: /^(?:email|email_?address|e_?mail|mail|mail_?address|primary_?email|secondary_?email|work_?email|personal_?email|business_?email|contact_?email|login_?email|notification_?email|recovery_?email|backup_?email|alternate_?email|alt_?email|reply_?to|from_?email|to_?email|cc|bcc|email_?id|e_?mail_?adresse|elektronische_?post|correo|correo_?electronico|indirizzo_?email|posta_?elettronica|emailadres|epostadress|epost|adres_?email|pochta|mail_?adresi|eposta)$/i,
    label: 'EMAIL',
    category: 'contact',
  },

  // ═══════════════════════════════════════════
  // SSN / NATIONAL ID / TAX ID / GOV ID
  // ═══════════════════════════════════════════
  {
    keys: /^(?:ssn|social_?security|social_?security_?number|social_?insurance|social_?insurance_?number|sin|national_?id|national_?id_?number|national_?identity|identity_?number|identity_?card|id_?number|id_?card|id_?no|id_?document|personal_?id|personal_?number|personal_?code|citizen_?id|resident_?id|registration_?number|civil_?id|civil_?registration|gov_?id|government_?id|tax_?id|tax_?number|tax_?identification|taxpayer_?id|tin|itin|ein|vat_?number|vat_?id|steuer_?id|steuer_?nummer|steueridentifikationsnummer|steuernummer|sozialversicherungsnummer|personalausweisnummer|ausweisnummer|nif|nie|dni|cif|nif_?numero|bsn|burger_?service_?nummer|nino|national_?insurance|national_?insurance_?number|pps|pps_?number|pesel|nip|regon|personnummer|fodselsnummer|cpr|cpr_?nummer|hetu|henkilotunnus|cpf|rg|cnpj|curp|rfc|aadhaar|aadhar|pan|pan_?number|nric|fin|my_?number|rrn|ahv|avs|codice_?fiscale|carta_?identita|carte_?identite|numero_?securite_?sociale|nir|rijksregisternummer|numero_?identite|kimlik|tc_?kimlik|emirates_?id|iqama)$/i,
    label: 'NATIONAL_ID',
    category: 'identity',
  },

  // ═══════════════════════════════════════════
  // BANK ACCOUNT / FINANCIAL ACCOUNTS
  // ═══════════════════════════════════════════
  {
    keys: /^(?:account_?number|account_?no|acct|acct_?number|acct_?no|bank_?account|bank_?account_?number|bank_?acct|checking_?account|savings_?account|current_?account|deposit_?account|iban|bic|swift|swift_?code|routing_?number|routing_?no|aba|sort_?code|bsb|bsb_?number|clabe|transit_?number|branch_?code|branch_?number|kontonummer|bankleitzahl|blz|konto|girokonto|sparkonto|numero_?de_?compte|rib|numero_?conto|numero_?de_?cuenta|rekeningnummer|bankgiro|plusgiro|numer_?konta|schet|kouza_?bangou)$/i,
    label: 'ACCOUNT_NUMBER',
    category: 'financial',
  },

  // ═══════════════════════════════════════════
  // CREDIT / DEBIT CARD
  // ═══════════════════════════════════════════
  {
    keys: /^(?:card_?number|credit_?card|credit_?card_?number|debit_?card|debit_?card_?number|cc_?number|cc_?no|pan|card_?no|card_?num|payment_?card|kartennummer|kreditkarte|kreditkartennummer|numero_?de_?carte|numero_?carta|numero_?de_?tarjeta|kaartnummer|cvv|cvc|cvv2|cvc2|cid|security_?code|card_?verification|card_?expiry|expiry_?date|expiration_?date|exp_?date|valid_?thru|valid_?through|card_?holder|cardholder_?name)$/i,
    label: 'CREDIT_CARD',
    category: 'financial',
  },

  // ═══════════════════════════════════════════
  // INSURANCE (health, life, auto, property, etc.)
  // ═══════════════════════════════════════════
  {
    keys: /^(?:insurance|insurance_?(?:id|number|no|policy|claim|type|provider|company|plan|group)|policy_?(?:number|no|id)|policy_?holder|claim_?(?:number|no|id|ref|reference)|health_?plan|health_?plan_?id|member_?id|member_?number|subscriber_?id|subscriber_?number|beneficiary_?id|beneficiary_?number|group_?number|group_?id|plan_?id|plan_?number|coverage_?id|enrollment_?id|certificate_?number|versicherungsnummer|versicherung|krankenversicherung|krankenkasse|police_?nummer|police_?nr|numero_?assurance|numero_?police|polizza|numero_?polizza|numero_?de_?seguro|verzekeringsnummer|polisnummer)$/i,
    label: 'INSURANCE',
    category: 'financial',
  },

  // ═══════════════════════════════════════════
  // PASSPORT
  // ═══════════════════════════════════════════
  {
    keys: /^(?:passport|passport_?number|passport_?no|passport_?id|passport_?num|travel_?document|travel_?doc_?number|reisepass|reisepassnummer|passnummer|numero_?passeport|passeport|passaporto|numero_?passaporto|numero_?de_?pasaporte|paspoort|paspoortnummer|passnummer_?2|pass_?nr|pasaporte|pasaporte_?numero)$/i,
    label: 'PASSPORT',
    category: 'identity',
  },

  // ═══════════════════════════════════════════
  // DRIVER LICENSE
  // ═══════════════════════════════════════════
  {
    keys: /^(?:driver_?license|drivers_?license|driver_?licence|drivers_?licence|driving_?license|driving_?licence|dl|dl_?number|dl_?no|license_?number|licence_?number|license_?no|licence_?no|permit_?number|learner_?permit|fuehrerschein|fuehrerscheinnummer|permis_?de_?conduire|numero_?permis|patente|patente_?di_?guida|permiso_?de_?conducir|carnet_?de_?conducir|rijbewijs|rijbewijsnummer|koerkort|forerkort|prawo_?jazdy|voditelskoe_?udostoverenie|unten_?menkyo|jiashi_?zheng|ehliyet|surucu_?belgesi)$/i,
    label: 'DRIVER_LICENSE',
    category: 'identity',
  },

  // ═══════════════════════════════════════════
  // MEDICAL / HEALTH / PATIENT
  // ═══════════════════════════════════════════
  {
    keys: /^(?:mrn|medical_?record|medical_?record_?number|patient_?id|patient_?number|patient_?name|health_?id|health_?card|health_?number|hospital_?id|hospital_?number|chart_?number|case_?number|encounter_?id|visit_?id|admission_?id|discharge_?id|diagnosis|diagnosis_?code|icd|icd_?code|icd_?10|procedure_?code|cpt|cpt_?code|ndc|ndc_?code|medication|medications|drug|drug_?name|prescription|prescription_?id|rx|rx_?number|dosage|blood_?type|blood_?group|allergy|allergies|condition|conditions|medical_?condition|disability|disability_?status|disability_?type|disability_?degree|impairment|mental_?health|psychiatric|immunization|vaccination|vaccine|lab_?result|test_?result|vital_?signs|bmi|weight|height|npi|npi_?number|dea|dea_?number|provider_?id|physician_?id|doctor_?name|treating_?physician|primary_?care|attending|referring|insurance_?diagnosis|pre_?existing|chronic|krankenakte|patientennummer|diagnose|medikament|rezept|blutgruppe|behinderung|grad_?der_?behinderung|gdb|schwerbehindertenausweis|dossier_?medical|numero_?patient|groupe_?sanguin|cartella_?clinica|historia_?clinica|prontuario)$/i,
    label: 'MEDICAL',
    category: 'medical',
  },

  // ═══════════════════════════════════════════
  // COMPANY / ORGANIZATION / EMPLOYER / BUSINESS
  // ═══════════════════════════════════════════
  {
    keys: /^(?:company|company_?name|organization|organisation|org|org_?name|employer|employer_?name|business|business_?name|corporation|corp|corp_?name|subsidiary|parent_?company|holding|group_?name|entity|entity_?name|legal_?entity|legal_?name|registered_?name|trading_?name|brand|brand_?name|vendor|vendor_?name|supplier|supplier_?name|partner|partner_?name|client|client_?name|agency|agency_?name|institute|institution|school|school_?name|university|university_?name|college|hospital|hospital_?name|practice|practice_?name|firm|firm_?name|llc|gmbh|ag|inc|ltd|plc|sa|srl|bv|nv|firma|unternehmen|unternehmensname|arbeitgeber|betrieb|handelsname|societe|raison_?sociale|denominazione|ragione_?sociale|empresa|nombre_?empresa|bedrijf|bedrijfsnaam|werkgever|foretag|arbetsgivare|virksomhed|arbejdsgiver|firma_?2|spolka|pracodawca|kompaniya|rabotodatel|kaisha|kigyou|gongsi|guyong_?danwei|sirket|isveren)$/i,
    label: 'COMPANY',
    category: 'identity',
  },

  // ═══════════════════════════════════════════
  // EDUCATION / ACADEMIC
  // ═══════════════════════════════════════════
  {
    keys: /^(?:student_?id|student_?number|student_?name|enrollment_?id|enrollment_?number|matriculation|matriculation_?number|matrikel|matrikelnummer|gpa|grade_?point|test_?score|sat_?score|act_?score|gre_?score|gmat_?score|degree|diploma|qualification|major|minor|field_?of_?study|program|faculty|school_?name|university|college|campus|class_?of|graduation|graduation_?date|grad_?year|transcript|academic_?record|education_?level|highest_?education|studiengang|abschluss|zeugnis|schulname|hochschule|diplome|scolarite|titolo_?di_?studio|expediente)$/i,
    label: 'EDUCATION',
    category: 'identity',
  },

  // ═══════════════════════════════════════════
  // VEHICLE / TRANSPORT
  // ═══════════════════════════════════════════
  {
    keys: /^(?:vin|vehicle_?identification|vehicle_?id|vehicle_?number|chassis_?number|license_?plate|plate_?number|plate_?no|registration|registration_?number|reg_?number|reg_?no|tag_?number|kennzeichen|fahrzeug_?id|fahrgestellnummer|immatriculation|plaque|targa|matricula|kenteken|registreringsnummer|numer_?rejestracyjny)$/i,
    label: 'VEHICLE',
    category: 'vehicle',
  },

  // ═══════════════════════════════════════════
  // CREDENTIALS / AUTH / SECRETS / TOKENS
  // ═══════════════════════════════════════════
  {
    keys: /^(?:password|passwd|pwd|pass_?word|secret|secret_?key|api_?key|api_?secret|api_?token|access_?token|refresh_?token|auth_?token|bearer_?token|session_?token|session_?key|private_?key|encryption_?key|signing_?key|master_?key|client_?secret|consumer_?key|consumer_?secret|oauth_?token|credentials|authorization|proxy_?authorization|passwort|kennwort|schluessel|mot_?de_?passe|contrasena|clave|senha|wachtwoord|sleutel|losenord|haslo|parol|mima|sifre)$/i,
    label: 'CREDENTIAL',
    category: 'enterprise',
  },

  // ═══════════════════════════════════════════
  // RACE / ETHNICITY / NATIONALITY / CITIZENSHIP
  // ═══════════════════════════════════════════
  {
    keys: /^(?:race|ethnicity|ethnic|ethnic_?origin|ethnic_?group|nationality|citizenship|national_?origin|heritage|ancestry|background|rasse|herkunft|ethnische_?herkunft|nationalitaet|staatsangehoerigkeit|ethnie|origine|nationalite|citoyennete|raza|etnia|nacionalidad|ciudadania|razza|nazionalita|cittadinanza|nationaliteit|etnicitet|medborgarskap|narodowsc|rasa|natsionalnost|grazhdanstvo|kokuseki|minzu|guoji|milliyet|vatandaslik|uyruk)$/i,
    label: 'ETHNICITY',
    category: 'identity',
  },

  // ═══════════════════════════════════════════
  // RELIGION / BELIEF / POLITICAL
  // ═══════════════════════════════════════════
  {
    keys: /^(?:religion|religious|religious_?affiliation|religious_?belief|faith|creed|denomination|confession|church|mosque|synagogue|temple|spiritual|belief|philosophical_?belief|political_?(?:party|affiliation|opinion|preference|view)|party|party_?membership|union|union_?membership|trade_?union|konfession|religionszugehoerigkeit|glaubensbekenntnis|kirchenzugehoerigkeit|politische_?partei|gewerkschaft|religion_?2|culte|parti_?politique|syndicat|partido_?politico|sindicato|religie|politieke_?partij|vakbond|religion_?3|tro|parti|fagforening|religia|partia|zwiazek_?zawodowy|religiya|partiya|profsoyuz|shukyo|seitou|zongjiao|dangpai|din|mezhep|parti_?2|sendika)$/i,
    label: 'BELIEF_POLITICAL',
    category: 'identity',
  },

  // ═══════════════════════════════════════════
  // GENDER / SEX / MARITAL STATUS / FAMILY
  // ═══════════════════════════════════════════
  {
    keys: /^(?:gender|sex|gender_?identity|sexual_?orientation|sexuality|preferred_?pronouns|pronouns|marital_?status|civil_?status|relationship_?status|marriage|married|single|divorced|widowed|separated|domestic_?partner|spouse|partner|family_?status|number_?of_?(?:children|kids|dependents)|dependents|geschlecht|familienstand|sexuelle_?orientierung|sexe|etat_?civil|orientation_?sexuelle|genero|estado_?civil|orientacion_?sexual|sesso|stato_?civile|geslacht|burgerlijke_?staat|kon|civilstand|plec|stan_?cywilny|pol|semeynoe_?polozhenie|seibetsu|xingbie|hunyin|cinsiyet|medeni_?hal)$/i,
    label: 'PERSONAL_STATUS',
    category: 'identity',
  },

  // ═══════════════════════════════════════════
  // LEGAL / JUDICIAL / CRIMINAL
  // ═══════════════════════════════════════════
  {
    keys: /^(?:case_?number|case_?id|case_?ref|docket|docket_?number|court|court_?name|judge|attorney|lawyer|legal_?representative|legal_?counsel|criminal_?record|conviction|offense|offence|charge|charges|sentence|verdict|probation|parole|arrest|arrest_?date|booking|booking_?number|inmate|prisoner|offender|inmate_?(?:id|number)|mugshot|fingerprint|warrant|bail|bond|aktenzeichen|gerichtsaktenzeichen|strafregister|vorstrafe|verurteilung|anwalt|rechtsanwalt|richter|numero_?affaire|casier_?judiciaire|condamnation|avocat|juge|numero_?expediente|antecedentes_?penales|condena|abogado|juez)$/i,
    label: 'LEGAL',
    category: 'identity',
  },

  // ═══════════════════════════════════════════
  // BIOMETRIC / PHYSICAL CHARACTERISTICS
  // ═══════════════════════════════════════════
  {
    keys: /^(?:biometric|fingerprint|face_?id|facial|facial_?recognition|iris|retina|voiceprint|voice_?id|palm_?print|hand_?geometry|dna|genetic|genome|genotype|karyotype|blood_?type|blood_?group|eye_?color|hair_?color|skin_?color|height|weight|bmi|body_?mass|distinguishing_?marks|tattoo|scar|birthmark|photo|photograph|picture|image|avatar|headshot|portrait|mugshot|selfie|foto|bild|lichtbild|passfoto|passbild)$/i,
    label: 'BIOMETRIC',
    category: 'biometric',
  },

  // ═══════════════════════════════════════════
  // UTILITY / SUBSCRIPTION / LOYALTY / MEMBERSHIP
  // ═══════════════════════════════════════════
  {
    keys: /^(?:utility_?(?:account|number|id)|electricity_?(?:account|number)|gas_?(?:account|number)|water_?(?:account|number)|meter_?(?:number|id)|customer_?(?:number|id|no)|account_?(?:id|ref)|reference_?(?:number|id|no|code)|subscription_?(?:id|number)|membership_?(?:id|number|no)|member_?(?:number|no)|loyalty_?(?:id|number|card)|rewards?_?(?:id|number|card)|frequent_?flyer|frequent_?flyer_?(?:number|id)|mileage_?(?:number|id)|points_?(?:id|number)|library_?(?:card|id|number)|kundennummer|mitgliedsnummer|abonnement|vertragsnummer)$/i,
    label: 'ACCOUNT_REF',
    category: 'financial',
  },

  // ═══════════════════════════════════════════
  // IP / HOSTNAME / SERVER / NETWORK
  // ═══════════════════════════════════════════
  {
    keys: /^(?:ip|ip_?address|ipv4|ipv6|server|server_?name|server_?address|hostname|host|host_?name|domain|domain_?name|mac|mac_?address|subnet|gateway|proxy|vpn|dns|url|uri|endpoint|api_?url|webhook_?url|callback_?url|redirect_?url|origin|referrer|referer|user_?agent|device_?id|device_?name|machine_?name|computer_?name|workstation)$/i,
    label: 'NETWORK',
    category: 'network',
  },

  // ═══════════════════════════════════════════
  // CONTRACTS / INVOICES / LEGAL DOCUMENTS
  // ═══════════════════════════════════════════
  {
    keys: /^(?:contract_?(?:number|no|id|ref)|invoice_?(?:number|no|id|ref)|order_?(?:number|no|id|ref)|purchase_?order|po_?(?:number|no)|quote_?(?:number|no|id)|proposal_?(?:number|no|id)|agreement_?(?:number|no|id)|reference_?(?:number|no)|receipt_?(?:number|no|id)|transaction_?(?:id|ref|number)|payment_?(?:id|ref|reference)|billing_?(?:id|ref|number)|Rechnungsnummer|Vertragsnummer|Auftragsnummer|Bestellnummer|Angebotsnummer|numero_?(?:facture|contrat|commande)|numero_?(?:fattura|contratto|ordine))$/i,
    label: 'DOCUMENT_REF',
    category: 'financial',
  },

  // ═══════════════════════════════════════════
  // FINANCIAL AMOUNTS / REVENUE / SENSITIVE NUMBERS
  // ═══════════════════════════════════════════
  {
    keys: /^(?:amount|total|subtotal|grand_?total|tax_?amount|vat_?amount|discount|balance|outstanding|due|paid|refund|credit|debit|revenue|profit|loss|margin|cost|price|unit_?price|net_?amount|gross_?amount|fee|charge|interest|penalty|fine|deposit|withdrawal|transfer_?amount|Betrag|Gesamtbetrag|Steuerbetrag|Rabatt|Saldo|montant|somme|total_?ttc|total_?ht|importe|monto|importo)$/i,
    label: 'FINANCIAL_AMOUNT',
    category: 'financial',
  },

  // ═══════════════════════════════════════════
  // SIGNATURE / AUTHORIZATION / CONSENT
  // ═══════════════════════════════════════════
  {
    keys: /^(?:signature|signed_?by|authorized_?by|approved_?by|witnessed_?by|notarized_?by|certified_?by|consent|consent_?date|consent_?given|power_?of_?attorney|proxy|delegate|Unterschrift|unterzeichnet_?von|genehmigt_?von|Vollmacht)$/i,
    label: 'SIGNATURE',
    category: 'identity',
  },

  // ═══════════════════════════════════════════
  // BANK / PAYMENT DETAILS IN DOCUMENTS
  // ═══════════════════════════════════════════
  {
    keys: /^(?:bank_?name|bank|branch|branch_?name|beneficiary|beneficiary_?name|beneficiary_?account|payer|payer_?name|payee|payee_?name|remitter|sender_?(?:name|account|bank)|receiver_?(?:name|account|bank)|correspondent_?bank|intermediary_?bank|Bankname|Begünstigter|Zahlungsempfänger|Auftraggeber)$/i,
    label: 'BANK_DETAIL',
    category: 'financial',
  },

  // ═══════════════════════════════════════════
  // TAX / FISCAL DETAILS
  // ═══════════════════════════════════════════
  {
    keys: /^(?:tax_?(?:rate|class|bracket|status|year|period|return|filing)|fiscal_?(?:year|period|code)|withholding|exemption|deductible|taxable_?(?:income|amount)|gross_?income|net_?income|adjusted_?gross|agi|Steuerklasse|Steuerjahr|Steuererklärung|Freibetrag)$/i,
    label: 'TAX_DETAIL',
    category: 'financial',
  },

  // ═══════════════════════════════════════════
  // LANGUAGE / CULTURAL IDENTITY (GDPR Art.9)
  // ═══════════════════════════════════════════
  {
    keys: /^(?:language|mother_?tongue|native_?language|spoken_?language|preferred_?language|first_?language|primary_?language|sprache|muttersprache|langue|langue_?maternelle|idioma|lengua|lingua|taal|moedertaal|sprak|jezyk|yazyk|gengo|yuyan|dil|ana_?dil)$/i,
    label: 'LANGUAGE',
    category: 'identity',
  },

  // ═══════════════════════════════════════════
  // NOTES / FREE TEXT (run regex, don't redact whole value)
  // ═══════════════════════════════════════════
  {
    keys: /^(?:notes|note|comment|comments|description|desc|message|msg|body|text|content|remarks|remark|internal_?notes|agent_?notes|case_?notes|memo|memorandum|narrative|summary|abstract|details|detail|reason|explanation|history|log|changelog|audit|feedback|review|observation|assessment|evaluation|recommendation|instruction|instructions|notizen|bemerkung|kommentar|beschreibung|nachricht|anmerkung|vermerk|remarques|commentaire|observation_?2|nota|commento|descrizione|notas|comentario|descripcion|opmerkingen|beschrijving|anteckningar|kommentar_?2|uwagi|komentarz|opis|zametki|kommentariy|opisanie|bikou|beikou|beizhu|shuoming|not|aciklama|yorum)$/i,
    label: '',
    category: 'identity',
  },
];

/**
 * Ambiguous field names that MIGHT be personal data depending on context.
 * Only redacted when sibling fields suggest this is a person/PII record.
 */
const AMBIGUOUS_FIELDS: RegExp = /^(?:id|code|number|no|num|nr|ref|reference|key|identifier|value|data|info|source|origin|created_?by|updated_?by|modified_?by|assigned_?to|owned_?by|submitted_?by|requested_?by|approved_?by|reviewed_?by|reported_?by|signed_?by|verified_?by|processed_?by|handled_?by|managed_?by|contact|details|record|entry|item|subject|party|counterparty|client_?id|customer_?id|user_?id|member_?id|patient_?id|case_?id|ticket_?id|account_?id|subscriber_?id)$/i;

/**
 * Fields that CONFIRM the parent object is about a person/entity with PII.
 * If any sibling field matches this, ambiguous fields get redacted too.
 */
const PII_INDICATOR_FIELDS: RegExp = /^(?:name|first_?name|last_?name|full_?name|email|phone|mobile|ssn|iban|address|dob|birth|birthday|passport|salary|compensation|national_?id|tax_?id|nino|bsn|pesel|cpf|aadhaar|vorname|nachname|nom|prenom|nombre|apellido|nome|cognome|social_?security|employee_?id|patient_?name|customer_?name|contact_?name)$/i;

/**
 * Check if a field key matches a semantic field and should be fully redacted.
 * Returns the label if the entire value should be redacted, empty string if
 * regex scanning should be used, or null if no semantic match.
 */
function getSemanticLabel(fieldKey: string, siblingKeys?: string[]): { label: string; category: PiiCategory } | null {
  // Extract the last key segment (e.g., "user.profile.name" -> "name")
  const lastKey = fieldKey.includes('.') ? fieldKey.split('.').pop()! : fieldKey;
  // Also try the key without array indices (e.g., "contacts[0].name" -> "name")
  const cleanKey = lastKey.replace(/\[\d+\]/g, '');

  // First check explicit semantic mappings
  for (const mapping of SEMANTIC_FIELD_MAP) {
    if (mapping.keys.test(cleanKey)) {
      return { label: mapping.label, category: mapping.category };
    }
  }

  // Context-aware: if field is ambiguous (like bare "id") AND sibling fields
  // indicate this is a person/PII record, redact the ambiguous field too.
  if (siblingKeys && AMBIGUOUS_FIELDS.test(cleanKey)) {
    const hasPiiSiblings = siblingKeys.some((k) => PII_INDICATOR_FIELDS.test(k));
    if (hasPiiSiblings) {
      return { label: 'IDENTIFIER', category: 'identity' };
    }
  }

  return null;
}

/** Replaces a whole value whose field name says what it is. Returns null when not applicable. */
function redactSemantic(
  raw: string,
  ctx: RedactionContext,
  vault: IVault,
  sessionId: string,
  hits: RedactionHit[],
  itemIndex: number,
  path: string,
  display: string,
  siblingKeys?: string[],
): string | null {
  const semantic = getSemanticLabel(path, siblingKeys);
  if (!semantic || !semantic.label || raw.trim().length === 0) return null;
  if (isAllowListed(raw, ctx.allowList)) return null;
  const semConf = semantic.label === 'IDENTIFIER' ? AMBIGUOUS_FIELD_CONFIDENCE : SEMANTIC_CONFIDENCE;
  if (semConf < (ctx.confidenceThreshold ?? 0)) return null;
  const replacement = applyRedaction(raw, { label: semantic.label, category: semantic.category }, ctx, vault, sessionId);
  ctx.lastLocked = replacement ? [[0, replacement.length]] : undefined;
  hits.push({
    token: replacement, original: '***',
    patternName: `semantic_${semantic.label}`,
    patternLabel: semantic.label,
    category: semantic.category,
    field: display, itemIndex,
    confidence: semConf,
  });
  return replacement;
}

/** A whole-value mapping with the number's type, so Restore returns a number even for partial matches. */
function numericMapping(out: string, text: string, ctx: RedactionContext, vault: IVault, sessionId: string): string {
  const entries = vault.getSession(sessionId)?.entries ?? {};
  const existing = entries[out];
  if (existing?.original === text) {
    existing.numeric = true;
    return out;
  }
  // A composite like [DIG_0][DIG_1] can also come from a string, so the number gets its own token.
  const token = freshToken('NUMBER', vault, sessionId, ctx.reservedTokens);
  addMapping(vault, sessionId, {
    token, original: text, patternLabel: 'NUMBER', category: 'other', createdAt: new Date().toISOString(), numeric: true,
  });
  return token;
}

/** A boolean under a sensitive key, such as disability, is replaced. Restore returns the boolean. */
function redactBoolean(
  value: boolean,
  ctx: RedactionContext,
  vault: IVault,
  sessionId: string,
  hits: RedactionHit[],
  itemIndex: number,
  path: string,
  display: string,
  siblingKeys?: string[],
): unknown {
  const text = String(value);
  // A boolean gets a mapping of its own, typed at creation, and never shares one with the string "true" or "false".
  const boolCtx: RedactionContext = { ...ctx, dedup: false, boolean: true };
  const out = redactSemantic(text, boolCtx, vault, sessionId, hits, itemIndex, path, display, siblingKeys);
  if (out === null || out === text) return value;
  ctx.lastLocked = boolCtx.lastLocked;
  return out;
}

/** Numbers keep their type unless a semantic field or a pattern claims them. */
function redactNumber(
  value: number,
  ctx: RedactionContext,
  vault: IVault,
  sessionId: string,
  hits: RedactionHit[],
  itemIndex: number,
  path: string,
  display: string,
  siblingKeys?: string[],
): unknown {
  // String(-0) is "0", so negative zero is written out to survive Restore.
  const text = Object.is(value, -0) ? '-0' : String(value);
  // Numeric mappings never share an entry with a text occurrence of the same digits.
  const numCtx: RedactionContext = { ...ctx, dedup: false, numeric: true };
  let out: string | null = null;
  if (!ctx.skipSemantic) out = redactSemantic(text, numCtx, vault, sessionId, hits, itemIndex, path, display, siblingKeys);
  if (out === null && ctx.scanNumbers) out = redactText(text, numCtx, vault, sessionId, hits, itemIndex, display);
  if (out === null || out === text) return value;
  if (ctx.mode !== 'token' && ctx.mode !== 'pseudonymize') {
    // Only the replaced parts are locked, so untouched digits stay open to Presidio.
    ctx.lastLocked = numCtx.lastLocked;
    return out;
  }
  const mapped = numericMapping(out, text, ctx, vault, sessionId);
  ctx.lastLocked = [[0, mapped.length]];
  return mapped;
}

/** A key that would clash gets one reversible token for the whole original, or a numeric suffix when irreversible. */
function distinctKey(
  out: string,
  original: string,
  clashes: (k: string) => boolean,
  ctx: RedactionContext,
  vault: IVault,
  sessionId: string,
  reserved: Iterable<string>,
): string {
  if (ctx.mode === 'token' || ctx.mode === 'pseudonymize') {
    const token = freshToken('KEY', vault, sessionId, new Set([...(ctx.reservedTokens ?? []), ...reserved]));
    addMapping(vault, sessionId, { token, original, patternLabel: 'KEY', category: 'other', createdAt: new Date().toISOString() });
    ctx.lastLocked = [[0, token.length]];
    return token;
  }
  let suffixed = out;
  for (let n = 1; clashes(suffixed); n++) suffixed = `${out}_${n}`;
  return suffixed;
}

/** Keys can carry PII too, so they are scanned like text and never take another key's name. */
function redactKey(
  key: string,
  taken: Record<string, unknown>,
  sourceKeys: Set<string>,
  ctx: RedactionContext,
  vault: IVault,
  sessionId: string,
  itemIndex: number,
  keyHits: RedactionHit[],
): string {
  const out = redactText(key, ctx, vault, sessionId, keyHits, itemIndex, '');
  if (out === key) return key;
  const clashes = (k: string) => k === '' || Object.prototype.hasOwnProperty.call(taken, k) || sourceKeys.has(k);
  if (!clashes(out)) return out;
  return distinctKey(out, key, clashes, ctx, vault, sessionId, [...sourceKeys, ...Object.keys(taken)]);
}

/** Remembers where replacements sit in a key, so Presidio never re-redacts them. */
function rememberKeyLock(ctx: RedactionContext, container: object, key: string): void {
  if (ctx.lastLocked && ctx.keyLocks) {
    const byKey = ctx.keyLocks.get(container) ?? new Map<string, Array<[number, number]>>();
    byKey.set(key, ctx.lastLocked);
    ctx.keyLocks.set(container, byKey);
  }
  ctx.lastLocked = undefined;
}


function redactObject(
  value: Record<string, unknown>,
  ctx: RedactionContext,
  vault: IVault,
  sessionId: string,
  hits: RedactionHit[],
  itemIndex: number,
  path: string,
  display: string,
): Record<string, unknown> {
  const entries = Object.entries(value);
  const siblingKeys = entries.map(([k]) => k);
  const sourceKeys = new Set(siblingKeys);
  const origins = new Map<string, string>();
  const obj: Record<string, unknown> = {};
  for (const [k, v] of entries) {
    const fieldPath = path ? `${path}.${k}` : k;
    const keyHits: RedactionHit[] = [];
    ctx.lastLocked = undefined;
    const outKey = shouldProcessField(fieldPath, ctx.fieldMode, ctx.fieldRules)
      ? redactKey(k, obj, sourceKeys, ctx, vault, sessionId, itemIndex, keyHits)
      : protectLiterals(k, ctx, vault, sessionId, hits, itemIndex);
    rememberKeyLock(ctx, obj, outKey);
    origins.set(outKey, k);
    const childDisplay = display ? `${display}.${outKey}` : outKey;
    for (const h of keyHits) hits.push({ ...h, field: childDisplay });
    setOwn(obj, outKey, lockChild(ctx, obj, outKey, () =>
      redactValue(v, ctx, vault, sessionId, hits, itemIndex, fieldPath, siblingKeys, childDisplay)));
  }
  ctx.keyOrigins?.set(obj, origins);
  return obj;
}

/** Walks JSON and redacts with semantic field names and patterns. */
// currentPath keeps original keys for field rules; displayPath is the redacted path for reports.
export function redactValue(
  value: unknown,
  ctx: RedactionContext,
  vault: IVault,
  sessionId: string,
  hits: RedactionHit[],
  itemIndex: number,
  currentPath: string = '',
  siblingKeys?: string[],
  displayPath: string = currentPath,
): unknown {
  const processed = shouldProcessField(currentPath, ctx.fieldMode, ctx.fieldRules);
  if (typeof value === 'string') {
    if (!processed) return protectLiterals(value, ctx, vault, sessionId, hits, itemIndex);
    if (!ctx.skipSemantic) {
      const semantic = redactSemantic(value, ctx, vault, sessionId, hits, itemIndex, currentPath, displayPath, siblingKeys);
      if (semantic !== null) return semantic;
    }
    return redactText(value, ctx, vault, sessionId, hits, itemIndex, displayPath);
  }

  if (typeof value === 'number') {
    if (!processed) return value;
    return redactNumber(value, ctx, vault, sessionId, hits, itemIndex, currentPath, displayPath, siblingKeys);
  }

  if (typeof value === 'boolean') {
    if (!processed || ctx.skipSemantic) return value;
    return redactBoolean(value, ctx, vault, sessionId, hits, itemIndex, currentPath, displayPath, siblingKeys);
  }

  if (Array.isArray(value)) {
    // Elements keep the siblings of the array's key, so ["x"] under id is judged like id: "x".
    const out: unknown[] = [];
    value.forEach((v, i) => {
      out.push(lockChild(ctx, out, String(i), () =>
        redactValue(v, ctx, vault, sessionId, hits, itemIndex, `${currentPath}[${i}]`, siblingKeys, `${displayPath}[${i}]`)));
    });
    return out;
  }

  if (value !== null && typeof value === 'object') {
    return redactObject(value as Record<string, unknown>, ctx, vault, sessionId, hits, itemIndex, currentPath, displayPath);
  }

  return value;
}

const escapeRe = (text: string): string => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** A run of the output covering source[src, end). Free text is untouched source text, locked text is a replacement. */
interface Segment {
  text: string;
  locked: boolean;
  src: number;
  end: number;
}

// User regexes never run on longer text. Their matches would be missed silently, so the run stops instead.
const USER_REGEX_MAX_INPUT = 20_000;

/** Stops the run when a custom or deny-list regex would have to scan text over the limit. */
function assertUserRegexInput(text: string, what: string): void {
  if (text.length <= USER_REGEX_MAX_INPUT) return;
  throw new Error(
    `${what} cannot scan a value of ${text.length} characters, the limit is ${USER_REGEX_MAX_INPUT}. ` +
      'Exclude the field with field rules, or remove the regex.',
  );
}

type HitDetail = Pick<RedactionHit, 'patternName' | 'patternLabel' | 'category' | 'confidence'>;

/** What a detector decided about a match. store replaces the default vault mapping and hit. */
interface Decision {
  pattern: RedactionPattern;
  detail?: HitDetail;
  store?: (text: string) => string;
}

/** Decides whether a match is redacted. Offsets are source positions. */
type Decider = (match: string, sourceOffset: number) => Decision | null;

interface Pending {
  start: number;
  end: number;
  decision: Decision;
}

/** Walks the segments once per detector. Matches arrive in source order, so the walk never goes back. */
class SegmentCursor {
  readonly next: Segment[] = [];
  private i = 0;
  private cur: Segment | undefined;

  constructor(private readonly segs: Segment[]) {
    this.cur = segs[0];
  }

  /** The free segment that wholly contains the range, or undefined when any part is already claimed. */
  freeAt(start: number, end: number): Segment | undefined {
    while (this.cur && (this.cur.locked || this.cur.end <= start)) this.take();
    const cur = this.cur;
    return cur && cur.src <= start && end <= cur.end ? cur : undefined;
  }

  lock(start: number, end: number, replacement: string): void {
    const cur = this.cur!;
    if (start > cur.src) this.next.push(freeSlice(cur, cur.src, start));
    this.next.push({ text: replacement, locked: true, src: start, end });
    if (end < cur.end) this.cur = freeSlice(cur, end, cur.end);
    else this.cur = this.segs[++this.i];
  }

  finish(): Segment[] {
    while (this.cur) this.take();
    return this.next;
  }

  private take(): void {
    this.next.push(this.cur!);
    this.cur = this.segs[++this.i];
  }
}

function freeSlice(seg: Segment, start: number, end: number): Segment {
  return { text: seg.text.slice(start - seg.src, end - seg.src), locked: false, src: start, end };
}

/** Stores the replacement and records the hit. The caller locks it by position. */
function redactMatch(pass: TextPass, match: string, decision: Decision): string {
  if (decision.store) return decision.store(match);
  const replacement = applyRedaction(match, decision.pattern, pass.ctx, pass.vault, pass.sessionId);
  if (decision.detail) {
    pass.hits.push({ token: replacement, original: '***', field: pass.fieldPath, itemIndex: pass.itemIndex, ...decision.detail });
  }
  return replacement;
}

/** The earliest pending detection covering pos, advancing the cursor past detections that end before it. */
function coveringPending(pending: Pending[], cursor: { i: number }, pos: number): Pending | undefined {
  while (cursor.i < pending.length && pending[cursor.i].end <= pos) cursor.i++;
  for (let k = cursor.i; k < pending.length && pending[k].start <= pos; k++) {
    if (pending[k].end > pos) return pending[k];
  }
  return undefined;
}

/** Splits one free segment into the parts pending detections cover and the parts they leave free. */
function claimSegment(pass: TextPass, seg: Segment, pending: Pending[], cursor: { i: number }, into: Segment[]): void {
  let pos = seg.src;
  while (pos < seg.end) {
    const p = coveringPending(pending, cursor, pos);
    if (p) {
      const end = Math.min(seg.end, p.end);
      into.push({ text: redactMatch(pass, pass.source.slice(pos, end), p.decision), locked: true, src: pos, end });
      pos = end;
      continue;
    }
    const next = cursor.i < pending.length ? Math.max(pos + 1, pending[cursor.i].start) : seg.end;
    const end = Math.min(seg.end, next);
    into.push(freeSlice(seg, pos, end));
    pos = end;
  }
}

/** Redacts the free parts of detections that overlapped earlier replacements, in one ordered sweep. */
function claimPending(pass: TextPass, pending: Pending[]): void {
  if (pending.length === 0) return;
  pending.sort((a, b) => a.start - b.start);
  const next: Segment[] = [];
  const cursor = { i: 0 };
  for (const seg of pass.segs) {
    if (seg.locked || seg.end <= pending[cursor.i]?.start || cursor.i >= pending.length) next.push(seg);
    else claimSegment(pass, seg, pending, cursor, next);
  }
  pass.segs = next;
}

/** Claims one candidate: locked when free, queued when it touched earlier replacements, else rejected or touching. */
function claimOne(
  pass: TextPass, cursor: SegmentCursor, pending: Pending[], start: number, end: number, decide: Decider,
): 'locked' | 'queued' | 'rejected' | 'touching' {
  const text = pass.source.slice(start, end);
  const free = cursor.freeAt(start, end) !== undefined;
  const decision = decide(text, start);
  if (decision && free) cursor.lock(start, end, redactMatch(pass, text, decision));
  else if (decision) pending.push({ start, end, decision });
  if (!decision) return free ? 'rejected' : 'touching';
  return free ? 'locked' : 'queued';
}

/**
 * Matches against the whole source, so anchors and lookbehind keep their meaning, and replaces only free text.
 * retryQueued retries one position after a queued match too, so a later match that starts inside it and runs past it
 * is still found. User regexes need that and only scan bounded input. Built-in patterns go on after the match, which
 * keeps them linear on any input.
 */
function replaceFree(pass: TextPass, re: RegExp, decide: Decider, retryQueued = false): void {
  const global = new RegExp(re.source, re.flags.includes('g') ? re.flags : `${re.flags}g`);
  const cursor = new SegmentCursor(pass.segs);
  const pending: Pending[] = [];
  let m: RegExpExecArray | null;
  while ((m = global.exec(pass.source)) !== null) {
    const start = m.index;
    if (m[0] === '') {
      global.lastIndex = start + 1;
      continue;
    }
    // A queued match has its free parts redacted later. A rejected match that touched claimed text is retried one
    // position later, so a shorter free match it overlapped is still found.
    const outcome = claimOne(pass, cursor, pending, start, start + m[0].length, decide);
    if (outcome === 'touching' || (retryQueued && outcome === 'queued')) global.lastIndex = start + 1;
  }
  pass.segs = cursor.finish();
  claimPending(pass, pending);
}

/** Claims precomputed spans in source order, the longest first where two start together. */
function replaceSpans(pass: TextPass, spans: Array<{ start: number; end: number }>, decide: Decider): void {
  const ordered = [...spans].sort((a, b) => a.start - b.start || b.end - a.end);
  const cursor = new SegmentCursor(pass.segs);
  const pending: Pending[] = [];
  let reach = -1;
  for (const span of ordered) {
    if (span.end <= reach) continue;
    claimOne(pass, cursor, pending, span.start, span.end, decide);
    reach = span.end;
  }
  pass.segs = cursor.finish();
  claimPending(pass, pending);
}

/** State shared by the stages of one text pass. */
interface TextPass {
  source: string;
  segs: Segment[];
  threshold: number;
  ctx: RedactionContext;
  vault: IVault;
  sessionId: string;
  hits: RedactionHit[];
  itemIndex: number;
  fieldPath: string;
}

function denyListRegex(entry: AllowDenyEntry): RegExp | null {
  if (entry.type === 'regex') return isSafeRegex(entry.value) ? new RegExp(entry.value, 'gi') : null;
  return new RegExp(escapeRe(entry.value), 'gi'); // exact and contains match without \b, so #SECRET works
}

const DENY_DECISION: Decision = {
  pattern: { label: 'DENY_LIST', category: 'other' },
  detail: { patternName: 'denyList', patternLabel: 'DENY_LIST', category: 'other', confidence: DENY_LIST_CONFIDENCE },
};

function denyListStage(pass: TextPass): void {
  for (const entry of pass.ctx.denyList ?? []) {
    if (entry.type === 'regex') assertUserRegexInput(pass.source, `Deny list regex "${entry.value}"`);
    try {
      const re = denyListRegex(entry);
      if (re) replaceFree(pass, re, () => DENY_DECISION, entry.type === 'regex');
    } catch { /* skip invalid */ }
  }
}

function builtInDecision(pass: TextPass, pattern: PiiPattern, match: string, offset: number): Decision | null {
  const validatorPassed = pattern.validate ? pattern.validate(match) : true;
  if (!validatorPassed || isAllowListed(match, pass.ctx.allowList)) return null;
  const confidence = calculateConfidence(pattern.name, !!pattern.validate, validatorPassed, pass.source, offset, offset + match.length);
  if (confidence < pass.threshold) return null;
  return { pattern, detail: { patternName: pattern.name, patternLabel: pattern.label, category: pattern.category, confidence } };
}

// Checksum-validated patterns (IBAN, cards) claim their text first, so a loose pattern cannot grab digits inside them.
function builtInStage(pass: TextPass): void {
  const enabled = getPatternsByNames(pass.ctx.enabledPatterns);
  for (const pattern of [...enabled.filter((p) => p.validate), ...enabled.filter((p) => !p.validate)]) {
    if (pattern.anchor && !pass.source.includes(pattern.anchor)) continue;
    const decide: Decider = (match, offset) => builtInDecision(pass, pattern, match, offset);
    if (pattern.scan) replaceSpans(pass, pattern.scan(pass.source), decide);
    else replaceFree(pass, pattern.regex, decide);
  }
}

/** Name spans detected in the source and in free text, so the free rest of a partly claimed name is found too. */
function nameSpans(pass: TextPass): Array<{ start: number; end: number }> {
  const spans = detectNamesInText(pass.source).map((nm) => ({ start: nm.start, end: nm.end }));
  for (const seg of pass.segs) {
    if (seg.locked) continue;
    for (const nm of detectNamesInText(seg.text)) spans.push({ start: seg.src + nm.start, end: seg.src + nm.end });
  }
  return spans;
}

/** Each occurrence is scored on its own context and redacted on its own, so Dedup applies per mention. */
function nameStage(pass: TextPass): void {
  if (pass.ctx.skipNames ?? pass.ctx.skipSemantic) return;
  replaceSpans(pass, nameSpans(pass),
 (match, start) => {
    if (isAllowListed(match, pass.ctx.allowList)) return null;
    const confidence = hasContextWords(pass.source, start, start + match.length, NAME_CONTEXT_WORDS) ? 0.8 : 0.65;
    if (confidence < pass.threshold) return null;
    return {
      pattern: { label: 'PERSON_NAME', category: 'identity' },
      detail: { patternName: 'personNameDict', patternLabel: 'PERSON_NAME', category: 'identity', confidence },
    };
  });
}

function customStage(pass: TextPass): void {
  if (CUSTOM_PATTERN_CONFIDENCE < pass.threshold) return;
  for (const cp of pass.ctx.customPatterns) {
    if (!cp.label || !cp.regex || !isSafeRegex(cp.regex)) continue;
    const category: PiiCategory = isPiiCategory(cp.category) ? cp.category : cp.category ? 'other' : 'identity';
    const pattern = { label: cp.label.toUpperCase(), category };
    const decision: Decision = {
      pattern,
      detail: { patternName: `custom_${cp.label}`, patternLabel: pattern.label, category: pattern.category, confidence: CUSTOM_PATTERN_CONFIDENCE },
    };
    assertUserRegexInput(pass.source, `Custom pattern "${cp.label}"`);
    try {
      replaceFree(pass, new RegExp(cp.regex, 'g'), (match) => (isAllowListed(match, pass.ctx.allowList) ? null : decision), true);
    } catch { /* skip invalid regex */ }
  }
}

/** Remembers where replacements sit in the value just produced, so Presidio never re-redacts them. */
function recordLocked(ctx: RedactionContext, segs: Segment[]): void {
  const spans: Array<[number, number]> = [];
  let at = 0;
  for (const seg of segs) {
    if (seg.locked) spans.push([at, at + seg.text.length]);
    at += seg.text.length;
  }
  ctx.lastLocked = spans.length > 0 ? spans : undefined;
}

/** Stores the locked spans of a child value under its container and key, never under a path string. */
function lockChild(ctx: RedactionContext, container: object, key: string, compute: () => unknown): unknown {
  ctx.lastLocked = undefined;
  const out = compute();
  if (ctx.lastLocked && ctx.lockedSpans && typeof out === 'string') {
    const byKey = ctx.lockedSpans.get(container) ?? new Map<string, Array<[number, number]>>();
    byKey.set(key, ctx.lastLocked);
    ctx.lockedSpans.set(container, byKey);
  }
  ctx.lastLocked = undefined;
  return out;
}

/** Matches every token this session already maps, so input text equal to one can be protected. */
export function priorTokenMatcher(entries: Record<string, unknown> | undefined): RegExp | undefined {
  const tokens = Object.keys(entries ?? {}).filter((t) => t.length > 0).sort((a, b) => b.length - a.length);
  return tokens.length > 0 ? new RegExp(tokens.map(escapeRe).join('|'), 'g') : undefined;
}

/** Input text equal to an earlier mapping gets its own mapping, so Restore returns it unchanged. */
function literalStage(pass: TextPass): void {
  const { ctx, vault, sessionId } = pass;
  if (!ctx.priorTokens || (ctx.mode !== 'token' && ctx.mode !== 'pseudonymize')) return;
  const decision: Decision = {
    pattern: { label: 'LITERAL', category: 'other' },
    store: (match) => {
      const token = freshToken('LITERAL', vault, sessionId, ctx.reservedTokens);
      addMapping(vault, sessionId, { token, original: match, patternLabel: 'LITERAL', category: 'other', createdAt: new Date().toISOString() });
      return token;
    },
  };
  replaceFree(pass, ctx.priorTokens, () => decision);
}

/** Fields the rules exclude are not scanned, but earlier tokens in them still get their own mapping. */
function protectLiterals(
  text: string,
  ctx: RedactionContext,
  vault: IVault,
  sessionId: string,
  hits: RedactionHit[],
  itemIndex: number,
): string {
  if (!ctx.priorTokens) return text;
  const pass: TextPass = {
    source: text, segs: [{ text, locked: false, src: 0, end: text.length }], threshold: 0,
    ctx, vault, sessionId, hits, itemIndex, fieldPath: '',
  };
  literalStage(pass);
  recordLocked(ctx, pass.segs);
  return pass.segs.map((seg) => seg.text).join('');
}

/** Redacts PII in a text string. Each stage leaves earlier replacements untouched. */
function redactText(
  text: string,
  ctx: RedactionContext,
  vault: IVault,
  sessionId: string,
  hits: RedactionHit[],
  itemIndex: number,
  fieldPath: string,
): string {
  const pass: TextPass = {
    source: text, segs: [{ text, locked: false, src: 0, end: text.length }], threshold: ctx.confidenceThreshold ?? 0,
    ctx, vault, sessionId, hits, itemIndex, fieldPath,
  };
  literalStage(pass);
  denyListStage(pass);
  builtInStage(pass);
  nameStage(pass);
  customStage(pass);
  if (ctx.mode === 'pseudonymize') separatePseudonyms(pass);
  recordLocked(ctx, pass.segs);
  return pass.segs.map((s) => s.text).join('');
}

/** Single pass over the source string, so an inserted original is never rescanned as a token. */
function makeRestorer(entries: Record<string, { original: string }>): (text: string) => string {
  const tokens = Object.keys(entries).filter((t) => t.length > 0).sort((a, b) => b.length - a.length);
  if (tokens.length === 0) return (text) => text;
  const re = new RegExp(tokens.map((t) => t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|'), 'g');
  return (text) => text.replace(re, (token) => entries[token].original);
}

/** A string that is exactly one numeric or boolean mapping gets its original type back. */
function restoreString(value: string, restore: (text: string) => string, entries: Record<string, VaultEntry>): unknown {
  const exact = Object.prototype.hasOwnProperty.call(entries, value) ? entries[value] : undefined;
  if (exact?.numeric && Number.isFinite(Number(exact.original))) return Number(exact.original);
  if (exact?.boolean && (exact.original === 'true' || exact.original === 'false')) return exact.original === 'true';
  return restore(value);
}

function restoreWith(value: unknown, restore: (text: string) => string, entries: Record<string, VaultEntry>): unknown {
  if (typeof value === 'string') return restoreString(value, restore, entries);
  if (Array.isArray(value)) return value.map((v) => restoreWith(v, restore, entries));
  if (value !== null && typeof value === 'object') {
    const obj: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      setOwn(obj, restore(k), restoreWith(v, restore, entries));
    }
    return obj;
  }
  return value;
}

/** One bracketed token for a whole original string, so no text around it can be read as another mapping. */
function wholeToken(original: string, vault: IVault, sessionId: string, ctx: RedactionContext): string {
  const token = freshToken('TEXT', vault, sessionId, ctx.reservedTokens);
  addMapping(vault, sessionId, { token, original, patternLabel: 'TEXT', category: 'other', createdAt: new Date().toISOString() });
  return token;
}

type RestoreCheck = (input: string, output: string) => string;

/**
 * Pairs an input value with its redacted output and replaces any string or key that would not restore exactly.
 * Properties pair by the original key recorded during redaction, never by position, because a redacted integer-like
 * key moves within the object.
 */
function restorablePair(input: unknown, output: unknown, check: RestoreCheck, ctx: RedactionContext): unknown {
  if (typeof input === 'string' && typeof output === 'string') return check(input, output);
  if (Array.isArray(input) && Array.isArray(output)) return output.map((o, i) => restorablePair(input[i], o, check, ctx));
  if (!isPlainRecord(input) || !isPlainRecord(output)) return output;
  const origins = ctx.keyOrigins?.get(output);
  const fixed: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(output)) {
    const inKey = origins?.get(key) ?? key;
    if (!Object.prototype.hasOwnProperty.call(input, inKey)) {
      setOwn(fixed, key, value);
      continue;
    }
    setOwn(fixed, check(inKey, key), restorablePair(input[inKey], value, check, ctx));
  }
  return fixed;
}

const isPlainRecord = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);

/**
 * Pseudonyms carry no delimiters, and a mapping made for a later field can spell text next to a pseudonym in an
 * earlier one. After the run, every output string and key is restored with the final vault. One that would not
 * restore to its input is replaced whole by a bracketed token, so Restore always returns the exact input.
 */
export function ensureRestorable(inputs: unknown[], outputs: unknown[], ctx: RedactionContext, vault: IVault, sessionId: string): unknown[] {
  const session = vault.getSession(sessionId);
  if (!session || ctx.mode !== 'pseudonymize') return outputs;
  const restore = makeRestorer(session.entries);
  const check = (input: string, output: string): string => {
    if (input === output) return output;
    return restoreString(output, restore, session.entries) === input ? output : wholeToken(input, vault, sessionId, ctx);
  };
  return outputs.map((out, i) => restorablePair(inputs[i], out, check, ctx));
}

/**
 * Restore redacted tokens back to original values, in values and in keys.
 */
export function restoreValue(value: unknown, vault: IVault, sessionId: string): unknown {
  const session = vault.getSession(sessionId);
  if (!session) return value;
  return restoreWith(value, makeRestorer(session.entries), session.entries);
}

interface Span {
  start: number;
  end: number;
  score: number;
  entityType: string;
}

/** Presidio reports Python code point offsets. JavaScript strings index UTF-16 units. */
function toUtf16Spans(text: string, entities: Array<{ entity_type: string; start: number; end: number; score: number }>): Span[] {
  const offsets = [0];
  for (const ch of text) offsets.push(offsets[offsets.length - 1] + ch.length);
  return entities
    .filter((e) => Number.isInteger(e.start) && Number.isInteger(e.end) && e.start >= 0 && e.end > e.start && e.end < offsets.length)
    .map((e) => ({ start: offsets[e.start], end: offsets[e.end], score: e.score, entityType: e.entity_type }));
}

/** Higher score wins, then the longer span, then the earlier one. */
function outranks(a: Span, b: Span): boolean {
  if (a.score !== b.score) return a.score > b.score;
  const la = a.end - a.start;
  const lb = b.end - b.start;
  return la !== lb ? la > lb : a.start < b.start;
}

/** A max-heap of spans by rank. */
class SpanHeap {
  readonly items: Span[] = [];

  push(span: Span): void {
    const h = this.items;
    h.push(span);
    for (let i = h.length - 1; i > 0;) {
      const parent = (i - 1) >> 1;
      if (!outranks(h[i], h[parent])) break;
      [h[i], h[parent]] = [h[parent], h[i]];
      i = parent;
    }
  }

  pop(): void {
    const h = this.items;
    const last = h.pop()!;
    if (h.length === 0) return;
    h[0] = last;
    for (let i = 0; ;) {
      const l = 2 * i + 1;
      let best = i;
      if (l < h.length && outranks(h[l], h[best])) best = l;
      if (l + 1 < h.length && outranks(h[l + 1], h[best])) best = l + 1;
      if (best === i) break;
      [h[i], h[best]] = [h[best], h[i]];
      i = best;
    }
  }
}

/**
 * Covers the union of overlapping spans. Each stretch takes the strongest span covering it, and touching stretches of
 * the same entity type merge, so no part of any detected entity stays in clear text. O(n log n). Source order.
 */
function resolveOverlaps(spans: Span[]): Span[] {
  const points = [...new Set(spans.flatMap((s) => [s.start, s.end]))].sort((a, b) => a - b);
  const byStart = [...spans].sort((a, b) => a.start - b.start);
  const heap = new SpanHeap();
  const out: Span[] = [];
  let k = 0;
  for (let p = 0; p + 1 < points.length; p++) {
    const from = points[p];
    const to = points[p + 1];
    while (k < byStart.length && byStart[k].start <= from) heap.push(byStart[k++]);
    while (heap.items.length > 0 && heap.items[0].end <= from) heap.pop();
    const top = heap.items[0];
    if (top) paint(out, from, to, top);
  }
  return out;
}

/** Adds the stretch [from, to) under span, extending the previous stretch when it touches and has the same type. */
function paint(out: Span[], from: number, to: number, span: Span): void {
  const prev = out[out.length - 1];
  if (prev && prev.end === from && prev.entityType === span.entityType) {
    prev.end = to;
    prev.score = Math.max(prev.score, span.score);
  } else {
    out.push({ start: from, end: to, score: span.score, entityType: span.entityType });
  }
}

/** The parts of each span that no regex replacement covers, so an overlapped entity still loses its free tail. */
function subtractLocked(spans: Span[], locked: Array<[number, number]>): Span[] {
  const sortedLocks = [...locked].sort((a, b) => a[0] - b[0]);
  const out: Span[] = [];
  let k = 0;
  for (const span of spans) {
    while (k < sortedLocks.length && sortedLocks[k][1] <= span.start) k++;
    let pos = span.start;
    for (let j = k; j < sortedLocks.length && sortedLocks[j][0] < span.end; j++) {
      if (sortedLocks[j][0] > pos) out.push({ ...span, start: pos, end: sortedLocks[j][0] });
      pos = Math.max(pos, sortedLocks[j][1]);
    }
    if (pos < span.end) out.push({ ...span, start: pos, end: span.end });
  }
  return out;
}

/** Spans above the threshold, with any part a regex replacement covers removed, in source order. */
function presidioSpans(
  value: string,
  entities: Array<{ entity_type: string; start: number; end: number; score: number }>,
  ctx: RedactionContext,
  locked: Array<[number, number]>,
): Span[] {
  const threshold = ctx.confidenceThreshold ?? PRESIDIO_DEFAULT_THRESHOLD;
  return subtractLocked(resolveOverlaps(toUtf16Spans(value, entities).filter((s) => s.score >= threshold)), locked);
}

// Without a configured threshold, the Analyzer is asked for scores of 0.4 and up, as before.
const PRESIDIO_DEFAULT_THRESHOLD = 0.4;

async function presidioRedactString(
  value: string,
  ctx: RedactionContext,
  vault: IVault,
  sessionId: string,
  hits: RedactionHit[],
  itemIndex: number,
  path: string,
  locked: Array<[number, number]>,
): Promise<string> {
  if (value.trim().length === 0) return value;
  const entities = await analyzeWithPresidio(
    ctx.presidioUrl!, value, ctx.presidioLanguage || 'en', ctx.confidenceThreshold ?? PRESIDIO_DEFAULT_THRESHOLD, 10000,
    ctx.presidioRequest,
  );
  const parts: string[] = [];
  let last = 0;
  for (const span of presidioSpans(value, entities, ctx, locked)) {
    const matchedText = value.slice(span.start, span.end);
    if (isAllowListed(matchedText, ctx.allowList)) continue;
    const label = getRedactorLabel(span.entityType);
    const category = getRedactorCategory(span.entityType) as PiiCategory;
    const replacement = applyRedaction(matchedText, { label, category }, ctx, vault, sessionId);
    parts.push(value.slice(last, span.start), replacement);
    last = span.end;
    hits.push({
      token: replacement, original: '***',
      patternName: `presidio_${span.entityType}`, patternLabel: label,
      category, field: path, itemIndex, confidence: span.score,
    });
  }
  parts.push(value.slice(last));
  return parts.join('');
}

// A one-word identifier such as "note" or "customer_id" is a schema name, so only free-text keys go to Presidio.
const IDENTIFIER_KEY = /^[\p{L}_$][\p{L}\p{N}_$-]*$/u;

/** Keys can carry names too, so Presidio scans them under the same field rules and never merges two keys. */
async function presidioKey(
  key: string,
  original: string,
  source: Record<string, unknown>,
  sourceKeys: Set<string>,
  taken: Record<string, unknown>,
  ctx: RedactionContext,
  vault: IVault,
  sessionId: string,
  hits: RedactionHit[],
  itemIndex: number,
  path: string,
  policyPath: string,
): Promise<string> {
  if (IDENTIFIER_KEY.test(key) || !shouldProcessField(policyPath, ctx.fieldMode, ctx.fieldRules)) return key;
  const locked = ctx.keyLocks?.get(source)?.get(key) ?? [];
  let out = key;
  try {
    out = await presidioRedactString(key, ctx, vault, sessionId, hits, itemIndex, path, locked);
  } catch {
    return key; // Presidio failed for this key. Regex results stand.
  }
  if (out === key) return out;
  // Keys not written yet count too, so a renamed key never overwrites a later property.
  const clashes = (k: string) => k === '' || Object.prototype.hasOwnProperty.call(taken, k) || (k !== key && sourceKeys.has(k));
  if (!clashes(out)) return out;
  const others = [...sourceKeys].filter((k) => k !== key);
  return distinctKey(out, original, clashes, ctx, vault, sessionId, [...others, ...Object.keys(taken)]);
}

/**
 * Report paths from the regex pass, sorted once, so a key Presidio renames rewrites only the hits under it.
 * Lookups use the paths as the regex pass wrote them, so nested renames compose.
 */
class HitPaths {
  private readonly rows: Array<{ path: string; hit: RedactionHit }>;

  constructor(hits: RedactionHit[], itemIndex: number) {
    this.rows = hits
      .filter((h) => h.itemIndex === itemIndex)
      .map((hit) => ({ path: hit.field, hit }))
      .sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  }

  /** Hits at regexPath or below it now report under renamed. */
  rename(regexPath: string, renamed: string): void {
    this.each(regexPath, true, renamed, regexPath);
    this.each(`${regexPath}.`, false, renamed, regexPath);
    this.each(`${regexPath}[`, false, renamed, regexPath);
  }

  private each(prefix: string, exact: boolean, renamed: string, regexPath: string): void {
    let lo = 0;
    let hi = this.rows.length;
    while (lo < hi) {
      const mid = (lo + hi) >>> 1;
      if (this.rows[mid].path < prefix) lo = mid + 1;
      else hi = mid;
    }
    for (let i = lo; i < this.rows.length; i++) {
      const { path, hit } = this.rows[i];
      if (exact ? path !== prefix : !path.startsWith(prefix)) break;
      hit.field = renamed + path.slice(regexPath.length);
    }
  }
}

async function presidioWalk(
  value: unknown,
  ctx: RedactionContext,
  vault: IVault,
  sessionId: string,
  hits: RedactionHit[],
  itemIndex: number,
  path: string,
  policyPath: string,
  locked: Array<[number, number]> = [],
  regexPath: string = path,
  paths?: HitPaths,
): Promise<unknown> {
  if (typeof value === 'string') {
    if (!shouldProcessField(policyPath, ctx.fieldMode, ctx.fieldRules)) return value;
    try {
      return await presidioRedactString(value, ctx, vault, sessionId, hits, itemIndex, path, locked);
    } catch {
      return value; // Presidio failed for this field. Regex results stand.
    }
  }
  if (Array.isArray(value)) {
    const out: unknown[] = [];
    for (let i = 0; i < value.length; i++) {
      const lock = ctx.lockedSpans?.get(value)?.get(String(i));
      out.push(await presidioWalk(
        value[i], ctx, vault, sessionId, hits, itemIndex, `${path}[${i}]`, `${policyPath}[${i}]`, lock, `${regexPath}[${i}]`, paths,
      ));
    }
    return out;
  }
  if (value !== null && typeof value === 'object') {
    return presidioObject(value as Record<string, unknown>, ctx, vault, sessionId, hits, itemIndex, path, policyPath, regexPath, paths);
  }
  return value;
}

/** Scans the keys and values of one object. A renamed key carries the report paths below it. */
async function presidioObject(
  source: Record<string, unknown>,
  ctx: RedactionContext,
  vault: IVault,
  sessionId: string,
  hits: RedactionHit[],
  itemIndex: number,
  path: string,
  policyPath: string,
  regexPath: string,
  paths?: HitPaths,
): Promise<Record<string, unknown>> {
  const origins = ctx.keyOrigins?.get(source);
  const out: Record<string, unknown> = {};
  const sourceKeys = new Set(Object.keys(source));
  const finalOrigins = new Map<string, string>();
  const join = (base: string, k: string) => (base ? `${base}.${k}` : k);
  for (const [k, v] of Object.entries(source)) {
    const original = origins?.get(k) ?? k;
    const childPolicy = join(policyPath, original);
    const keyHits: RedactionHit[] = [];
    const key = await presidioKey(k, original, source, sourceKeys, out, ctx, vault, sessionId, keyHits, itemIndex, join(path, k), childPolicy);
    const finalChild = join(path, key);
    if (key !== k) paths?.rename(join(regexPath, k), finalChild);
    for (const h of keyHits) hits.push({ ...h, field: finalChild });
    const lock = ctx.lockedSpans?.get(source)?.get(k);
    setOwn(out, key, await presidioWalk(v, ctx, vault, sessionId, hits, itemIndex, finalChild, childPolicy, lock, join(regexPath, k), paths));
    finalOrigins.set(key, original);
  }
  ctx.keyOrigins?.set(out, finalOrigins);
  return out;
}

/**
 * Run Presidio NLP analysis on every string in an item, in objects and arrays alike,
 * honouring the same field rules as regex redaction. Called AFTER regex-based redaction.
 */
export async function enhanceWithPresidio(
  data: Record<string, unknown>,
  ctx: RedactionContext,
  vault: IVault,
  sessionId: string,
  hits: RedactionHit[],
  itemIndex: number,
): Promise<Record<string, unknown>> {
  if (!ctx.presidioUrl) return data;
  const paths = new HitPaths(hits, itemIndex);
  return (await presidioWalk(data, ctx, vault, sessionId, hits, itemIndex, '', '', [], '', paths)) as Record<string, unknown>;
}

/**
 * Build a redaction audit report from collected hits.
 * SECURITY: Original PII values are NEVER included in the report.
 */
export function buildReport(sessionId: string, hits: RedactionHit[]): RedactionReport {
  const hitsByCategory = countHits(hits, 'category');
  const hitsByPattern = countHits(hits, 'patternLabel');

  return {
    sessionId,
    timestamp: new Date().toISOString(),
    totalHits: hits.length,
    hitsByCategory,
    hitsByPattern,
    hits,
  };
}
