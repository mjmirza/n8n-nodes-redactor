/**
 * Coarse character sets for regex atoms. ASCII is exact, letters are case folded after
 * complement, and every non-ASCII character shares one bucket, so overlap checks err safe.
 */
export interface Charset {
  ascii: boolean[];
  other: boolean;
}

export const emptySet = (): Charset => ({ ascii: new Array<boolean>(128).fill(false), other: false });
const fullSet = (): Charset => ({ ascii: new Array<boolean>(128).fill(true), other: true });

function addCode(set: Charset, code: number): void {
  if (code >= 128) set.other = true;
  else set.ascii[code] = true;
}

function addRange(set: Charset, from: number, to: number): void {
  for (let c = from; c <= Math.min(to, 127); c++) addCode(set, c);
  if (to >= 128) set.other = true;
}

export function union(a: Charset, b: Charset): Charset {
  return { ascii: a.ascii.map((v, i) => v || b.ascii[i]), other: a.other || b.other };
}

export function overlaps(a: Charset, b: Charset): boolean {
  return (a.other && b.other) || a.ascii.some((v, i) => v && b.ascii[i]);
}

function complement(set: Charset): Charset {
  return { ascii: set.ascii.map((v) => !v), other: true };
}

/** Adds the other case of every letter, so a set never underestimates a case-insensitive match. */
function fold(set: Charset): Charset {
  const ascii = [...set.ascii];
  for (let c = 65; c <= 90; c++) ascii[c] = ascii[c + 32] = set.ascii[c] || set.ascii[c + 32];
  return { ascii, other: set.other };
}

const CLASS_ESCAPES: Record<string, (set: Charset) => void> = {
  d: (s) => addRange(s, 48, 57),
  w: (s) => {
    addRange(s, 48, 57);
    addRange(s, 65, 90);
    addRange(s, 97, 122);
    addCode(s, 95);
  },
  s: (s) => {
    for (const c of [9, 10, 11, 12, 13, 32]) addCode(s, c);
    s.other = true;
  },
};

const HEX = /^[0-9a-fA-F]+$/;
const CONTROL: Record<string, number> = { n: 10, r: 13, t: 9, v: 11, f: 12 };

/** Length and code point of the escape at i: \xHH, \uHHHH, \cX, \0, or one escaped character. */
export function readEscape(src: string, i: number): { length: number; code: number | null } {
  const e = src[i + 1] ?? '';
  const hex = (n: number) => (HEX.test(src.slice(i + 2, i + 2 + n)) && src.length >= i + 2 + n ? n : 0);
  if (e === 'x' && hex(2)) return { length: 4, code: parseInt(src.slice(i + 2, i + 4), 16) };
  if (e === 'u' && hex(4)) return { length: 6, code: parseInt(src.slice(i + 2, i + 6), 16) };
  if (e === 'c' && /[A-Za-z]/.test(src[i + 2] ?? '')) return { length: 3, code: src.charCodeAt(i + 2) % 32 };
  if (e === '0') return { length: 2, code: 0 };
  const control = CONTROL[e];
  if (control !== undefined) return { length: 2, code: control };
  if (/[a-zA-Z0-9]/.test(e)) return { length: 2, code: null };
  return { length: 2, code: e.charCodeAt(0) };
}

function codeSet(code: number): Charset {
  const set = emptySet();
  addCode(set, code);
  return set;
}

/** The set for the escape at i, unfolded. Unknown letter escapes count as anything. */
function escapeSet(src: string, i: number): Charset {
  const { code } = readEscape(src, i);
  const set = emptySet();
  if (code !== null) {
    addCode(set, code);
    return set;
  }
  const letter = src[i + 1] ?? '';
  const fill = CLASS_ESCAPES[letter.toLowerCase()];
  if (!fill) return fullSet();
  fill(set);
  return letter === letter.toLowerCase() ? set : complement(set);
}

/** Reads one class member at j. Returns its set, the index after it, and its code for ranges. */
function classMember(body: string, j: number): { set: Charset; next: number; code: number | null } {
  if (body[j] === '\\' && body[j + 1] === 'b') return { set: codeSet(8), next: j + 2, code: 8 };
  // Inside a class, backslash B is a literal B, never a boundary.
  if (body[j] === '\\' && body[j + 1] === 'B') return { set: codeSet(66), next: j + 2, code: 66 };
  if (body[j] === '\\') {
    const { length, code } = readEscape(body, j);
    return { set: escapeSet(body, j), next: j + length, code };
  }
  const set = emptySet();
  addCode(set, body.charCodeAt(j));
  return { set, next: j + 1, code: body.charCodeAt(j) };
}

/** The set for a bracket class body, the text between [ and ], before case folding. */
function classSet(body: string): Charset {
  const negated = body.startsWith('^');
  let set = emptySet();
  let j = negated ? 1 : 0;
  while (j < body.length) {
    const first = classMember(body, j);
    j = first.next;
    if (body[j] === '-' && j + 1 < body.length && first.code !== null) {
      const last = classMember(body, j + 1);
      if (last.code !== null) addRange(set, first.code, last.code);
      else set = union(union(set, first.set), last.set);
      j = last.next;
    } else set = union(set, first.set);
  }
  return negated ? complement(set) : set;
}

function rawCharset(src: string, start: number, end: number): Charset | null {
  const c = src[start];
  if (c === '^' || c === '$') return null;
  if (c === '\\') return /[bB]/.test(src[start + 1] ?? '') ? null : escapeSet(src, start);
  if (c === '[') return classSet(src.slice(start + 1, end - 1));
  if (c === '.') return fullSet();
  const set = emptySet();
  addCode(set, src.charCodeAt(start));
  return set;
}

/** The folded set an atom from start to end can match, or null for a zero-width atom like ^, $ or \b. */
export function atomCharset(src: string, start: number, end: number): Charset | null {
  const set = rawCharset(src, start, end);
  return set && fold(set);
}
