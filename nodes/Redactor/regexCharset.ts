/**
 * Coarse character sets for regex atoms. ASCII is exact, letters are case folded,
 * and every non-ASCII character shares one bucket, so overlap checks err on the safe side.
 */
export interface Charset {
  ascii: boolean[];
  other: boolean;
}

export const emptySet = (): Charset => ({ ascii: new Array<boolean>(128).fill(false), other: false });
const fullSet = (): Charset => ({ ascii: new Array<boolean>(128).fill(true), other: true });

function addCode(set: Charset, code: number): void {
  if (code >= 128) {
    set.other = true;
    return;
  }
  set.ascii[code] = true;
  const ch = String.fromCharCode(code);
  for (const folded of [ch.toLowerCase(), ch.toUpperCase()]) set.ascii[folded.charCodeAt(0)] = true;
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

const CLASS_ESCAPES: Record<string, (set: Charset) => void> = {
  d: (s) => addRange(s, 48, 57),
  w: (s) => {
    addRange(s, 48, 57);
    addRange(s, 65, 90);
    addCode(s, 95);
  },
  s: (s) => {
    for (const c of [9, 10, 11, 12, 13, 32]) addCode(s, c);
    s.other = true;
  },
};

/** The set for an escape like \d or \W. Unknown escapes such as \u or \x count as anything. */
function escapeSet(letter: string): Charset {
  const lower = letter.toLowerCase();
  const fill = CLASS_ESCAPES[lower];
  if (fill) {
    const set = emptySet();
    fill(set);
    return letter === lower ? set : complement(set);
  }
  if (/[a-zA-Z0-9]/.test(letter)) return fullSet();
  const set = emptySet();
  addCode(set, letter.charCodeAt(0));
  return set;
}

/** Reads one class member at j. Returns its set and the index after it. */
function classMember(body: string, j: number): { set: Charset; next: number; code: number | null } {
  if (body[j] === '\\') {
    const set = escapeSet(body[j + 1] ?? '\\');
    const single = /[a-zA-Z0-9]/.test(body[j + 1] ?? '') ? null : body.charCodeAt(j + 1);
    return { set, next: j + 2, code: single };
  }
  const set = emptySet();
  addCode(set, body.charCodeAt(j));
  return { set, next: j + 1, code: body.charCodeAt(j) };
}

/** The set for a bracket class body, the text between [ and ]. */
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

/** The set an atom from start to end can match, or null for a zero-width atom like ^, $ or \b. */
export function atomCharset(src: string, start: number, end: number): Charset | null {
  const c = src[start];
  if (c === '^' || c === '$') return null;
  if (c === '\\') return /[bB]/.test(src[start + 1] ?? '') ? null : escapeSet(src[start + 1] ?? '\\');
  if (c === '[') return classSet(src.slice(start + 1, end - 1));
  if (c === '.') return fullSet();
  const set = emptySet();
  addCode(set, src.charCodeAt(start));
  return set;
}
