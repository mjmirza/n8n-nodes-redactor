/**
 * One structural regex check, shared by profile parsing and runtime matching.
 * It rejects patterns whose backtracking can grow exponentially with input length.
 */
const MAX_REGEX_LENGTH = 500;

interface Quantifier {
  min: number;
  max: number;
  length: number;
}

interface GroupFrame {
  hasVariableQuantifier: boolean;
  hasAlternation: boolean;
}

function readBraces(src: string, i: number): Quantifier | null {
  const m = /^\{(\d+)(,(\d*))?\}/.exec(src.slice(i));
  if (!m) return null;
  const min = Number(m[1]);
  const max = m[2] === undefined ? min : m[3] === '' ? Infinity : Number(m[3]);
  return { min, max, length: m[0].length };
}

function readQuantifier(src: string, i: number): Quantifier | null {
  const c = src[i];
  let q: Quantifier | null = null;
  if (c === '*') q = { min: 0, max: Infinity, length: 1 };
  else if (c === '+') q = { min: 1, max: Infinity, length: 1 };
  else if (c === '?') q = { min: 0, max: 1, length: 1 };
  else if (c === '{') q = readBraces(src, i);
  if (q && src[i + q.length] === '?') q.length += 1;
  return q;
}

function skipClass(src: string, i: number): number {
  let j = i + 1;
  if (src[j] === '^') j++;
  if (src[j] === ']') j++;
  while (j < src.length && src[j] !== ']') j += src[j] === '\\' ? 2 : 1;
  return j + 1;
}

function groupPrefixLength(src: string, i: number): number {
  if (src[i + 1] !== '?') return 1;
  const named = /^\(\?<[A-Za-z_$][\w$]*>/.exec(src.slice(i));
  if (named) return named[0].length;
  const look = /^\(\?(?::|=|!|<=|<!)/.exec(src.slice(i));
  return look ? look[0].length : 1;
}

interface Step {
  atomEnd: number;
  closed: GroupFrame | null;
  next?: number;
  error?: string;
}

/** Reads one token at i. Groups and alternation only change the frame stack. */
function readToken(src: string, i: number, stack: GroupFrame[]): Step {
  const c = src[i];
  if (c === '\\') {
    if (/[1-9k]/.test(src[i + 1] ?? '')) return { atomEnd: i, closed: null, error: 'back-references are not supported' };
    return { atomEnd: i + 2, closed: null };
  }
  if (c === '[') return { atomEnd: skipClass(src, i), closed: null };
  if (c === '(') {
    stack.push({ hasVariableQuantifier: false, hasAlternation: false });
    return { atomEnd: i, closed: null, next: i + groupPrefixLength(src, i) };
  }
  if (c === '|') {
    stack[stack.length - 1].hasAlternation = true;
    return { atomEnd: i, closed: null, next: i + 1 };
  }
  const closed = c === ')' && stack.length > 1 ? stack.pop()! : null;
  return { atomEnd: i + 1, closed };
}

const NESTED = 'a repeated group contains a quantifier or alternation (catastrophic backtracking)';

function isRisky(frame: GroupFrame | null): boolean {
  return !!frame && (frame.hasVariableQuantifier || frame.hasAlternation);
}

const NO_GROUP: GroupFrame = { hasVariableQuantifier: false, hasAlternation: false };
const repeats = (q: Quantifier | null): boolean => q !== null && q.max > 1;
const isVariable = (q: Quantifier | null): boolean => q !== null && q.min !== q.max;

/** Applies a quantifier to the atom just read. Returns an error for nested repetition. */
function applyQuantifier(q: Quantifier | null, closed: GroupFrame | null, top: GroupFrame): string | null {
  if (repeats(q) && isRisky(closed)) return NESTED;
  // Optional atoms count as variable, and alternation survives closing a group, so wrappers cannot hide either.
  const inner = closed ?? NO_GROUP;
  top.hasVariableQuantifier ||= isVariable(q) || inner.hasVariableQuantifier;
  top.hasAlternation ||= inner.hasAlternation;
  return null;
}

/** Returns why the pattern was refused, or null when it is safe to run. */
function structuralProblem(src: string): string | null {
  const stack: GroupFrame[] = [{ hasVariableQuantifier: false, hasAlternation: false }];
  let i = 0;
  while (i < src.length) {
    const step = readToken(src, i, stack);
    if (step.error) return step.error;
    if (step.next !== undefined) {
      i = step.next;
      continue;
    }
    const q = readQuantifier(src, step.atomEnd);
    const problem = applyQuantifier(q, step.closed, stack[stack.length - 1]);
    if (problem) return problem;
    i = step.atomEnd + (q ? q.length : 0);
  }
  return null;
}

/** Validates a user-supplied regex. Returns null when safe, else a reason. */
export function checkRegex(regexStr: string): string | null {
  if (typeof regexStr !== 'string' || regexStr.length === 0) return 'is empty';
  if (regexStr.length > MAX_REGEX_LENGTH) return `is longer than ${MAX_REGEX_LENGTH} characters`;
  try {
    new RegExp(regexStr, 'g');
  } catch {
    return 'is not a valid regular expression';
  }
  return structuralProblem(regexStr);
}
