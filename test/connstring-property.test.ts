import fc from 'fast-check';
import { cpuNow, run } from './harness';

const SEED = 7012026;
const whitespace = fc.array(fc.constantFrom(
  ' ', '\t', '\u00a0', '\u1680', '\u2000', '\u2001', '\u2002', '\u2003', '\u2004',
  '\u2005', '\u2006', '\u2007', '\u2008', '\u2009', '\u200a', '\u202f', '\u205f', '\u3000',
), { maxLength: 3 }).map((parts) => parts.join(''));
// f, j and z appear in no key name, scheme, wrapper text or replacement token, so a window holding one can only
// be a piece of a generated credential. A marker letter follows every third character of every value.
const MARKER = /[fjz]/;
const marker = fc.array(fc.constantFrom('f', 'j', 'z'), { minLength: 6, maxLength: 6 }).map((letters) => letters.join(''));
const value = (prefix: string) => fc.tuple(
  fc.integer({ min: 0, max: 0xffffff }),
  fc.array(fc.constantFrom('{', '}', ';', '=', '"', "'", '!', '@', ':', 'é'), { maxLength: 8 }),
  fc.constantFrom('alpha', 'bravo', 'delta', 'zulu'),
  marker,
).map(([number, punctuation, word, mark]) => interleave([prefix, number.toString(16), ...punctuation, word].join(''), mark));

/** Puts a marker letter after every third character, so every four-character window holds at least one. */
function interleave(text: string, mark: string): string {
  const chars = [...text];
  let out = '';
  chars.forEach((ch, i) => {
    out += ch;
    if (i % 3 === 2) out += mark[(i / 3) % mark.length | 0];
  });
  return out;
}

/** The output as written, and with URL percent-escapes and doubled quote or brace escapes undone. */
function views(output: string): string[] {
  const unescaped = output.replace(/""/g, '"').replace(/''/g, "'").replace(/}}/g, '}');
  const decoded = output.replace(/%[0-9A-Fa-f]{2}/g, (hex) => {
    try { return decodeURIComponent(hex); } catch { return hex; }
  });
  return [output, unescaped, decoded];
}
const casedKey = (keys: string[]) => fc.tuple(
  fc.constantFrom(...keys), fc.array(fc.boolean(), { minLength: 32, maxLength: 32 }),
).map(([key, upper]) => [...key].map((ch, i) => upper[i] ? ch.toUpperCase() : ch.toLowerCase()).join(''));
const layout = fc.record({ before: whitespace, keyEnd: whitespace, valueStart: whitespace, after: whitespace });
const notePrefix = fc.array(fc.constantFrom(
  'Deployment note: ', 'User=guest. ', 'Host=x, ', 'note: a=b ', 'Connection: ',
), { minLength: 1, maxLength: 4 }).map((parts) => parts.join(''));

function encodeKv(raw: string, grammar: string, quote: string): string {
  if (grammar === 'odbc') return `{${raw.replace(/}/g, '}}')}}`;
  if (quote === 'plain' && !/[;"']/.test(raw)) return raw;
  const delimiter = quote === "'" ? "'" : '"';
  return delimiter + raw.split(delimiter).join(delimiter.repeat(2)) + delimiter;
}

const connection = fc.record({
  notePrefix,
  grammar: fc.constantFrom('ado', 'odbc', 'url'),
  username: value('acct'), password: value('p4ss'), secret: value('s3cr'),
  serverKey: casedKey(['Server', 'Data Source', 'Host']),
  userKey: casedKey(['User ID', 'Uid', 'User']), passwordKey: casedKey(['Password', 'Pwd']),
  secretKey: casedKey(['Access Token', 'Secret']),
  order: fc.shuffledSubarray([0, 1, 2, 3], { minLength: 4, maxLength: 4 }),
  layouts: fc.array(layout, { minLength: 4, maxLength: 4 }),
  quotes: fc.array(fc.constantFrom('plain', '"', "'"), { minLength: 4, maxLength: 4 }),
  scheme: casedKey(['postgres', 'mysql', 'mongodb', 'redis', 'amqp', 'mssql']),
  trailing: fc.boolean(),
}).map((sample) => {
  const { username, password, secret, grammar } = sample;
  let encoded: string[];
  let text: string;
  if (grammar === 'url') {
    encoded = [username, password, secret].map(encodeURIComponent);
    text = `${sample.scheme}://${encoded[0]}:${encoded[1]}@db.example/db?token=${encoded[2]}`;
  } else {
    const keys = [sample.serverKey, sample.userKey, sample.passwordKey, sample.secretKey];
    encoded = ['db', username, password, secret].map((raw, i) => encodeKv(raw, grammar, sample.quotes[i]));
    text = sample.order.map((i) => {
      const space = sample.layouts[i];
      return `${space.before}${keys[i]}${space.keyEnd}=${space.valueStart}${encoded[i]}${space.after}`;
    }).join(';') + (sample.trailing ? ';' : '');
  }
  // Escaped and encoded forms are matched through the unescaped and decoded views of the output, so only the raw
  // values are listed, and every one of their four-character windows holds a marker.
  return { note: `${sample.notePrefix}${text}; ready.`, sensitive: [username, password, secret] };
});

it('redacts every credential fragment and fails version 2 Verify for 10,000 generated connection strings', async () => {
  // The full node keeps Redact's recommended set and Verify's complete set in sync automatically.
  const started = cpuNow();
  let caseNumber = 0;
  process.stdout.write(`Connection-string property seed: ${SEED}\n`);
  await fc.assert(fc.asyncProperty(connection, async ({ note, sensitive }) => {
    // A fresh session per case, as each workflow run would have, so the vault never grows across 10,000 cases.
    const [redacted] = await run({ operation: 'redact', sessionId: `conn-property-${++caseNumber}`, vaultStorage: 'memory' }, [{ note }]);
    const output = redacted[0].json.note as string;
    for (const credential of sensitive) {
      // Every four-character window holds a marker letter, which cannot occur in the fixed text, so a match in any
      // view of the output is a leak. Longer surviving substrings contain such windows.
      for (let i = 0; i <= credential.length - 4; i++) {
        const fragment = credential.slice(i, i + 4);
        if (!MARKER.test(fragment)) throw new Error(`Generator produced a window without a marker: ${JSON.stringify(fragment)}`);
        if (views(output).some((view) => view.includes(fragment))) throw new Error(`Surviving credential fragment ${JSON.stringify(fragment)} in ${JSON.stringify(output)}`);
      }
    }
    const [verified] = await run({ operation: 'verify' }, [{ note }], { typeVersion: 2 });
    expect(verified[0].json.status).toBe('FAIL');
  }), { numRuns: 10000, seed: SEED });
  const elapsed = cpuNow() - started;
  process.stdout.write(`Connection-string property CPU runtime: ${elapsed.toFixed(1)} ms\n`);
  // Ten thousand runs of the full node, twice each: a generous CPU budget, still far below a quadratic blow-up.
  expect(elapsed).toBeLessThan(180000);
}, 300000);
