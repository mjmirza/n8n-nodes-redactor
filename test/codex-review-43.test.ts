/**
 * Regression tests for the 4.3.0 Codex re-review, one block per finding.
 */
import type { IDataObject } from 'n8n-workflow';
import { checkRegex } from '../nodes/Redactor/regexSafety';
import { resetCircuitBreaker } from '../nodes/Redactor/presidio';
import { MemoryVault } from '../nodes/Redactor/vault';
import { redactValue } from '../nodes/Redactor/engine';
import type { RedactionContext, RedactionHit } from '../nodes/Redactor/types';

import { run, persist, expectRegexRefused } from './harness';

function redactWith(input: Record<string, unknown>, overrides: Partial<RedactionContext>): Record<string, unknown> {
  const vault = new MemoryVault();
  vault.getOrCreateSession('s', 0);
  const ctx: RedactionContext = {
    enabledPatterns: ['email'], customPatterns: [], mode: 'redact', dedup: true, fieldRules: [], fieldMode: 'all',
    ...overrides,
  };
  const hits: RedactionHit[] = [];
  return redactValue(input, ctx, vault, 's', hits, 0) as Record<string, unknown>;
}

const presidioFinding = (needle: RegExp, entity: string) =>
  jest.fn(async (req: { body?: { text?: string } }) => ({
    statusCode: 200,
    body: req.body?.text
      ? [...req.body.text.matchAll(needle)].map((m) => ({
          entity_type: entity, start: m.index ?? 0, end: (m.index ?? 0) + m[0].length, score: 0.99,
        }))
      : [],
  }));

describe('re-review 43-1: built-in patterns always scan the full text', () => {
  it('redacts an email past 2048 characters while a deny regex is set', () => {
    const out = redactWith(
      { note: 'x'.repeat(2044) + ':a@example.com' },
      { denyList: [{ value: 'NEVER_MATCH', type: 'regex' }] },
    );
    expect(out.note).toBe('x'.repeat(2044) + ':[REDACTED]');
  });

  it('finds a deny regex match past 2048 characters', () => {
    const out = redactWith({ note: 'x'.repeat(2045) + 'SECRET' }, { enabledPatterns: [], denyList: [{ value: 'SECRET', type: 'regex' }] });
    expect(String(out.note)).not.toContain('SECRET');
  });
});

describe('re-review 43-2: user regex anchors keep their meaning', () => {
  it('never matches ^ in the middle of the text', () => {
    const text = 'x'.repeat(2048) + 'SECRET';
    const out = redactWith({ note: text }, { enabledPatterns: [], customPatterns: [{ label: 'secret', regex: '^SECRET' }] });
    expect(out.note).toBe(text);
  });

  it('stops with a clear error instead of skipping text over the limit', () => {
    expect(() =>
      redactWith({ note: 'x'.repeat(25_000) }, { enabledPatterns: [], customPatterns: [{ label: 'secret', regex: 'SECRET' }] }),
    ).toThrow(/limit is 20000/);
  });
});

describe('re-review 43-3: validator bypasses are refused', () => {
  it.each([
    '^a+(?:b|)a+(?:b|)a+(?:b|)a+!$',
    String.raw`^\x61+\x61+\x61+\x61+!$`,
    '^A+[^a]A+[^a]A+[^a]A+!$',
  ])('rejects %p', (re) => expectRegexRefused(re));

  it.each(['[A-Z]{2}[0-9]+', 'EMP-[0-9]{6}?', String.raw`\d{3}-\d{4}`, '[0-9]{3}', String.raw`\x41-[0-9]+`])('accepts %p', (re) => {
    expect(checkRegex(re)).toBeNull();
  });
});

describe('re-review 43-4: allow-list regexes are bounded too', () => {
  it('redacts a huge value quickly instead of testing the allow-list regex on it', () => {
    const started = Date.now();
    const out = redactWith({ name: 'a'.repeat(200_000) }, { allowList: [{ value: 'a+!', type: 'regex' }] });
    expect(Date.now() - started).toBeLessThan(5000);
    expect(out.name).toBe('[REDACTED]');
  });
});

describe('re-review 43-5: Presidio locks never collide across paths', () => {
  beforeEach(() => resetCircuitBreaker());
  it('still masks a nested name whose path text equals a dotted key', async () => {
    const httpRequest = presidioFinding(/Xylophora Zzyzx/g, 'PERSON');
    const [out] = await run(
      { operation: 'redact', sessionId: 'pc', redactionMode: 'mask', enablePresidio: true, presidioUrl: 'http://presidio:3000' },
      [{ 'a.b': 'alice@example.com', a: { b: 'Xylophora Zzyzx' } }],
      { httpRequest },
    );
    expect(JSON.stringify(out[0].json)).not.toContain('Xylophora Zzyzx');
  });
});

describe('re-review 43-6: an empty key never causes double pseudonymization', () => {
  beforeEach(() => resetCircuitBreaker());
  it('restores the original email under an empty key', async () => {
    const httpRequest = presidioFinding(/[\w.+-]+@[\w-]+[.][\w.]+/g, 'EMAIL_ADDRESS');
    const store: IDataObject = {};
    const input = { '': 'alice@example.com' };
    const params = {
      operation: 'redact', sessionId: 'empty-node', redactionMode: 'pseudonymize',
      enablePresidio: true, presidioUrl: 'http://presidio:3000',
    };
    const [out] = await run(params, [input], { staticData: store, httpRequest });
    const [back] = await run({ operation: 'restore', sessionId: 'empty-node' }, [out[0].json], { staticData: persist(store) });
    expect(back[0].json).toEqual(input);
  });
});

describe('re-review 43-7: a number never shares a composite token with a string', () => {
  it('restores the string as a string and the number as a number', async () => {
    const store: IDataObject = {};
    const input = [{ x: 123456 }, { x: '123456' }];
    const params = { operation: 'redact', sessionId: 'cmp', customPatterns: { patterns: [{ label: 'dig', regex: '[0-9]{3}' }] } };
    const [out] = await run(params, input, { staticData: store });
    const [back] = await run({ operation: 'restore', sessionId: 'cmp' }, out.map((o) => o.json), { staticData: persist(store) });
    expect(back.map((b) => b.json)).toEqual(input);
  });
});

describe('re-review 43-8: every occurrence of a name is scored', () => {
  it('redacts a later mention that has context even when the first has none', () => {
    const note = 'Alice Baker ' + 'neutral filler words '.repeat(10) + 'spoke with Alice Baker';
    const out = redactWith({ note }, { confidenceThreshold: 0.75 });
    expect(String(out.note)).toContain('spoke with [REDACTED]');
  });
});
