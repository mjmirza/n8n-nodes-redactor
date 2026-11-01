/**
 * Regression tests for the fourth Codex review of the 7.0.0 branch, one block per finding, using the review's inputs.
 */
import { detectNamesInText } from '../nodes/Redactor/names';

import { redactNote as redactIn, run, verifyStatus } from './harness';

const redactNote = (note: string): Promise<string> => redactIn(note, 'r73');

describe('re-review 73-1: quoted secrets', () => {
  it.each([
    ['{"password":"supersecret"}', 'supersecret'],
    ['password="alpha\\"supersecret tail"', 'supersecret tail'],
  ])('%s is redacted and fails Verify', async (text, secret) => {
    expect(await redactNote(text)).not.toContain(secret);
    expect(await verifyStatus(text)).toBe('FAIL');
  });
});

describe('re-review 73-2: titled and all-capitals names', () => {
  it.each([
    ['Mr. JOHN SMITH', ['JOHN', 'SMITH']],
    ['Dr. Xochitl Quispe Aiyana Nizhoni Tallchief', ['Xochitl', 'Tallchief']],
    ['JOHN SMITH called', ['JOHN', 'SMITH']],
    ['first name: Xochitl Quispe Aiyana Nizhoni Tallchief', ['Xochitl', 'Tallchief']],
  ])('%s is covered', async (text, words) => {
    const out = await redactNote(text);
    for (const word of words) expect(out).not.toContain(word);
    expect(await verifyStatus(text)).toBe('FAIL');
  });

  it('leaves a lower-case sentence after a labelled name alone', async () => {
    const out = await run({ operation: 'redact', sessionId: 'r73b', piiTypes: ['fullNameCtx'], detectionScope: 'select' },
      [{ note: 'first name: Alice and then we left the office early' }]);
    expect(out[0][0].json.note).toMatch(/left the office early$/);
  });
});

describe('re-review 73-3: compact international phones', () => {
  it.each(['+436641234567', '+393331234567', '+919876543210'])('redacts call %s', async (phone) => {
    expect(await redactNote(`call ${phone}`)).not.toContain(phone);
  });
});

describe('re-review 73-4: very long name runs', () => {
  it('handles 500,000 repeated names without a stack overflow', () => {
    expect(() => detectNamesInText('Alice '.repeat(500_000))).not.toThrow();
  });
});

describe('re-review 73-5: Detect reporting settings', () => {
  it('stops when Include Audit Report differs per item', async () => {
    await expect(run({ operation: 'detect' }, [{ note: 'a' }, { note: 'b' }], { perItem: { includeReport: [true, false] } }))
      .rejects.toThrow(/different value for item 1/);
  });

  it('stops when the Audit Log expression fails', async () => {
    await expect(run({ operation: 'detect' }, [{ note: 'a' }], { failingParams: ['auditLog'] }))
      .rejects.toThrow(/Could not evaluate expression/);
  });
});
