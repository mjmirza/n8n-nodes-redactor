/**
 * One structural regex check, shared by profile parsing and runtime matching.
 * It rejects patterns whose backtracking can grow exponentially with input length.
 */
import { atomCharset, Charset, emptySet, overlaps, readEscape, union } from './regexCharset';

const MAX_REGEX_LENGTH = 500;

interface Quantifier {
  min: number;
  max: number;
  length: number;
}

interface GroupFrame {
  hasVariableQuantifier: boolean;
  hasAlternation: boolean;
  // Characters the variable repetitions since the last disjoint required atom can absorb.
  run: Charset | null;
  chars: Charset;
  zeroWidth: boolean;
  // Whether the current branch, and every earlier branch, must consume at least one character.
  branchConsumes: boolean;
  allConsume: boolean;
  nullable: boolean;
  // Inside a lookahead or lookbehind, where a repetition can be re-evaluated at every position.
  inLook: boolean;
}

const newFrame = (zeroWidth = false, inLook = zeroWidth): GroupFrame => ({
  hasVariableQuantifier: false, hasAlternation: false, run: null, chars: emptySet(), zeroWidth,
  branchConsumes: false, allConsume: true, nullable: false, inLook,
});

/** Ends a branch at | or ). A group that can match nothing never separates repetitions. */
function endBranch(frame: GroupFrame): void {
  frame.allConsume &&= frame.branchConsumes;
  frame.branchConsumes = false;
  frame.nullable = !frame.allConsume;
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
  const named = /^\(\?<[^=!>][^>]*>/.exec(src.slice(i));
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

function alternation(stack: GroupFrame[], i: number): Step {
  const top = stack[stack.length - 1];
  top.hasAlternation = true;
  top.run = null;
  endBranch(top);
  return { atomEnd: i, closed: null, next: i + 1 };
}

function closeGroup(c: string, stack: GroupFrame[]): GroupFrame | null {
  if (c !== ')' || stack.length <= 1) return null;
  const closed = stack.pop()!;
  endBranch(closed);
  return closed;
}

/** Reads one token at i. Groups and alternation only change the frame stack. */
function readToken(src: string, i: number, stack: GroupFrame[]): Step {
  const c = src[i];
  if (c === '\\') {
    if (/[1-9k]/.test(src[i + 1] ?? '')) return { atomEnd: i, closed: null, error: 'back-references are not supported' };
    return { atomEnd: i + readEscape(src, i).length, closed: null };
  }
  if (c === '[') return { atomEnd: skipClass(src, i), closed: null };
  if (c === '(') {
    const look = /^\(\?(?:=|!|<=|<!)/.test(src.slice(i));
    stack.push(newFrame(look, look || stack[stack.length - 1].inLook));
    return { atomEnd: i, closed: null, next: i + groupPrefixLength(src, i) };
  }
  if (c === '|') return alternation(stack, i);
  return { atomEnd: i + 1, closed: closeGroup(c, stack) };
}

const NESTED = 'a repeated group contains a quantifier or alternation (catastrophic backtracking)';

function isRisky(frame: GroupFrame | null): boolean {
  return !!frame && (frame.hasVariableQuantifier || frame.hasAlternation);
}

const NO_GROUP: GroupFrame = newFrame();
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

const SEQUENTIAL = 'two repetitions in a row can match the same characters (catastrophic backtracking)';

/** Refuses a variable repetition that can absorb what an earlier one in the same sequence can. */
function applySequence(chars: Charset | null, variable: boolean, required: boolean, top: GroupFrame): string | null {
  if (chars === null) return null;
  top.chars = union(top.chars, chars);
  const shared = top.run !== null && overlaps(top.run, chars);
  if (variable) {
    if (shared) return SEQUENTIAL;
    top.run = top.run ? union(top.run, chars) : chars;
  } else if (required && !shared) top.run = null;
  return null;
}

/** The characters an atom or closed group can match, or null when it is zero-width. */
function stepChars(src: string, i: number, step: Step): Charset | null {
  const closed = step.closed;
  if (!closed) return atomCharset(src, i, step.atomEnd);
  return closed.zeroWidth ? null : closed.chars;
}

/** Whether the atom must consume at least one character, so it can separate repetitions. */
function consumes(q: Quantifier | null, chars: Charset | null, closed: GroupFrame | null): boolean {
  if (chars === null || (q !== null && q.min < 1)) return false;
  return !closed?.nullable;
}

const IN_LOOK = 'repeats a variable part inside a lookahead or lookbehind, which is not supported';

function stepProblem(src: string, i: number, step: Step, q: Quantifier | null, top: GroupFrame): string | null {
  if (top.inLook && isVariable(q)) return IN_LOOK;
  const problem = applyQuantifier(q, step.closed, top);
  if (problem || q?.max === 0) return problem;
  const chars = stepChars(src, i, step);
  const required = consumes(q, chars, step.closed);
  if (required) top.branchConsumes = true;
  return applySequence(chars, isVariable(q) || !!step.closed?.hasVariableQuantifier, required, top);
}

/** Returns why the pattern was refused, or null when it is safe to run. */
function structuralProblem(src: string): string | null {
  const stack: GroupFrame[] = [newFrame()];
  let i = 0;
  while (i < src.length) {
    const step = readToken(src, i, stack);
    if (step.error) return step.error;
    if (step.next !== undefined) {
      i = step.next;
      continue;
    }
    const q = readQuantifier(src, step.atomEnd);
    const problem = stepProblem(src, i, step, q, stack[stack.length - 1]);
    if (problem) return problem;
    i = step.atomEnd + (q ? q.length : 0);
  }
  return null;
}

const KNOWN_ESCAPES = /^(?:[dDwWsSbBnrtvf]|x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|c[A-Za-z]|0(?![0-9])|[^A-Za-z0-9])/;
const CLASS_ESCAPE_RANGE = /\\[dDwWsS]-[^\]]|[^[^\\]-\\[dDwWsS]/;

const BAD_ESCAPE = 'uses an escape that is not supported (octal, back-reference or unknown letter)';
const EMPTY_CLASS = 'uses an empty class [] or [^], which is not supported';
const ESCAPE_RANGE = 'uses a range with \\d, \\w or \\s as an end, which is not supported';

/** Checks the bracket class starting at i. Returns its end index and any problem. */
function classProblem(src: string, i: number): { end: number; problem: string | null } {
  if (/^\[\^?\]/.test(src.slice(i))) return { end: i, problem: EMPTY_CLASS };
  const end = skipClass(src, i);
  const body = src.slice(i, end);
  for (let j = 1; j < body.length; j++) {
    if (body[j] === '\\' && !KNOWN_ESCAPES.test(body.slice(j + 1))) return { end, problem: BAD_ESCAPE };
    if (body[j] === '\\') j++;
  }
  return { end, problem: CLASS_ESCAPE_RANGE.test(body) ? ESCAPE_RANGE : null };
}

/** Refuses syntax the structural check cannot model exactly, so it never underestimates a pattern. */
function unsupportedSyntax(src: string): string | null {
  let i = 0;
  while (i < src.length) {
    if (src[i] === '[') {
      const { end, problem } = classProblem(src, i);
      if (problem) return problem;
      i = end;
    } else if (src[i] === '\\') {
      if (!KNOWN_ESCAPES.test(src.slice(i + 1))) return BAD_ESCAPE;
      i += 2;
    } else i++;
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
  return unsupportedSyntax(regexStr) ?? structuralProblem(regexStr);
}
