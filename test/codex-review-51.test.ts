/**
 * Regression tests for the 5.1.0 Codex re-review, one block per finding.
 */
import type { IDataObject } from 'n8n-workflow';
import { MemoryVault } from '../nodes/Redactor/vault';
import { redactValue } from '../nodes/Redactor/engine';
import type { RedactionContext, RedactionHit } from '../nodes/Redactor/types';

import { expectRegexRefused, run, persist, cpuNow } from './harness';

function redactWith(input: unknown, overrides: Partial<RedactionContext>): IDataObject {
  const vault = new MemoryVault();
  vault.getOrCreateSession('s', 0);
  const ctx: RedactionContext = {
    enabledPatterns: [], customPatterns: [], mode: 'token', dedup: true, fieldRules: [], fieldMode: 'all', skipSemantic: true,
    ...overrides,
  };
  const hits: RedactionHit[] = [];
  return redactValue(input, ctx, vault, 's', hits, 0) as IDataObject;
}

describe('re-review 51-1: a rejected overlap never hides a later free match', () => {
  it('finds a free match that starts inside a rejected one', () => {
    const out = redactWith({ note: 'ABCSECRET' }, {
      customPatterns: [{ label: 'first', regex: '^A' }, { label: 'second', regex: 'ABC|BCSECRET' }],
    });
    expect(out.note).toMatch(/^\[FIRST_\d+\]\[SECOND_\d+\]$/);
  });

  it('redacts the rest of a name after a deny list claims part of it', () => {
    const out = redactWith({ note: 'Alice Baker Smith' }, {
      skipSemantic: false, denyList: [{ value: 'Alice', type: 'exact' }],
    });
    expect(out.note).not.toContain('Baker');
  });
});

describe('re-review 51-2 to 4: the regex check refuses the remaining slow shapes', () => {
  it.each([
    String.raw`^a+[^\B]a+[^\B]a+[^\B]a+!$`,
    '^a+(?<é>)a+(?<ß>)a+(?<λ>)a+!$',
    '(?=a+(?=a+(?=a+$)))a',
  ])('rejects %p', (re) => expectRegexRefused(re));
});

describe('re-review 51-5: input equal to an earlier token round trips', () => {
  it('restores a literal token from an earlier run unchanged', async () => {
    const store: IDataObject = {};
    await run({ operation: 'redact', sessionId: 'lit' }, [{ note: 'alice@example.com' }], { staticData: store });
    const input = { note: 'Literal [EMAIL_0]; alice@example.com' };
    const saved = persist(store);
    const [out] = await run({ operation: 'redact', sessionId: 'lit' }, [input], { staticData: saved });
    const [back] = await run({ operation: 'restore', sessionId: 'lit' }, [out[0].json], { staticData: persist(saved) });
    expect(back[0].json).toEqual(input);
  });
});

describe('re-review 51-6: matching stays linear in the number of matches', () => {
  it('redacts 64,000 emails quickly', () => {
    const started = cpuNow();
    const out = redactWith({ note: 'alice@example.com;'.repeat(64000) }, { enabledPatterns: ['email'], mode: 'redact' });
    expect(cpuNow() - started).toBeLessThan(2500);
    expect(out.note).toBe('[REDACTED];'.repeat(64000));
  });
});
