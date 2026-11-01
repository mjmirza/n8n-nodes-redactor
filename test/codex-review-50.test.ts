/**
 * Regression tests for the 5.0.0 Codex re-review, one block per finding.
 */
import type { IDataObject } from 'n8n-workflow';
import { resetCircuitBreaker } from '../nodes/Redactor/presidio';
import { MemoryVault } from '../nodes/Redactor/vault';
import { redactValue, restoreValue, enhanceWithPresidio } from '../nodes/Redactor/engine';
import type { RedactionContext, RedactionHit } from '../nodes/Redactor/types';

import { expectRegexRefused, run, persist } from './harness';

function setup(overrides: Partial<RedactionContext>): { vault: MemoryVault; ctx: RedactionContext; hits: RedactionHit[] } {
  const vault = new MemoryVault();
  vault.getOrCreateSession('s', 0);
  const ctx: RedactionContext = {
    enabledPatterns: [], customPatterns: [], mode: 'token', dedup: true, fieldRules: [], fieldMode: 'all',
    lockedSpans: new WeakMap(), keyOrigins: new WeakMap(), skipSemantic: true, scanNumbers: true,
    ...overrides,
  };
  return { vault, ctx, hits: [] };
}

function redactWith(input: unknown, overrides: Partial<RedactionContext>): IDataObject {
  const { vault, ctx, hits } = setup(overrides);
  return redactValue(input, ctx, vault, 's', hits, 0) as IDataObject;
}

describe('re-review 50-1: a partly redacted number leaves its other digits open to Presidio', () => {
  beforeEach(() => resetCircuitBreaker());
  it('masks the untouched digits Presidio finds', async () => {
    const { vault, ctx, hits } = setup({
      mode: 'redact',
      customPatterns: [{ label: 'prefix', regex: '^12' }],
      presidioUrl: 'http://presidio:3000',
      presidioRequest: async ({ body }) => ({
        statusCode: 200,
        body: (body as { text?: string })?.text ? [{ entity_type: 'PHONE_NUMBER', start: 10, end: 20, score: 0.99 }] : [],
      }),
    });
    const redacted = redactValue({ x: 121234567890 }, ctx, vault, 's', hits, 0) as Record<string, unknown>;
    const out = await enhanceWithPresidio(redacted, ctx, vault, 's', hits, 0);
    expect(out.x).toBe('[REDACTED][REDACTED]');
  });
});

describe('re-review 50-2 to 5: the regex check refuses syntax it cannot model', () => {
  it.each([
    '^[^](a+)+!$',
    String.raw`^1+\0611+\0611+\0611+!$`,
    String.raw`^a+[^\n]a+[^\n]a+[^\n]a+!$`,
    String.raw`^-+[a-\d]-+[a-\d]-+[a-\d]-+!$`,
  ])('rejects %p', (re) => expectRegexRefused(re));
});

describe('re-review 50-6: user regexes see the original text', () => {
  it('keeps lookbehind context after an earlier replacement', () => {
    const out = redactWith(
      { note: 'Contact alice@example.com SECRET' },
      { enabledPatterns: ['email'], customPatterns: [{ label: 'secret', regex: '(?<=alice@example[.]com )SECRET' }] },
    );
    expect(out.note).toMatch(/^Contact \[EMAIL_\d+\] \[SECRET_\d+\]$/);
  });

  it('never moves ^ to the end of an earlier replacement', () => {
    const out = redactWith({ note: 'AAABBB' }, {
      customPatterns: [{ label: 'first', regex: 'AAA' }, { label: 'second', regex: '^BBB' }],
    });
    expect(out.note).toMatch(/^\[FIRST_\d+\]BBB$/);
  });
});

describe('re-review 50-7: a shorter name never splits a longer one', () => {
  it('gives the longer name its own token', () => {
    const out = redactWith({ note: 'Alice Baker. Alice Baker Smith.' }, { skipSemantic: false });
    expect(out.note).not.toContain('Smith');
  });
});

describe('re-review 50-8: tokens never collide with token-like input for any label', () => {
  it('restores input that looks like a custom label token', async () => {
    const store: IDataObject = {};
    const input = { note: '[MY-SECRET_0] SENSITIVE' };
    const params = { operation: 'redact', sessionId: 'lbl', customPatterns: { patterns: [{ label: 'my-secret', regex: 'SENSITIVE' }] } };
    const [out] = await run(params, [input], { staticData: store });
    const [back] = await run({ operation: 'restore', sessionId: 'lbl' }, [out[0].json], { staticData: persist(store) });
    expect(back[0].json).toEqual(input);
  });
});

describe('re-review 50-9: an own __proto__ key survives a round trip', () => {
  it('keeps both properties', () => {
    const { vault, ctx, hits } = setup({ enabledPatterns: ['email'] });
    const input = JSON.parse('{"__proto__":"keep","note":"alice@example.com"}') as IDataObject;
    const out = redactValue(input, ctx, vault, 's', hits, 0) as IDataObject;
    expect(Object.keys(out)).toEqual(['__proto__', 'note']);
    const back = restoreValue(out, vault, 's') as IDataObject;
    expect(Object.getOwnPropertyDescriptor(back, '__proto__')?.value).toBe('keep');
    expect(back.note).toBe('alice@example.com');
  });
});
