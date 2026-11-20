/** Regression coverage for re-review 84 against 7.0.4. */
import { run } from './harness';

// RU is 33 characters. The grouped Belgian IBAN sits on a group boundary inside it, and its length is a
// multiple of four, so the longer candidate runs on past it. RU00 fails the checksum. RU36 passes.
const INNER = 'BE68 5390 0754 7034';
const TAIL = 'ABCD EFGH IJKL M';
const rejected = `RU00 ${INNER} ${TAIL}`;
const accepted = `RU36 ${INNER} ${TAIL}`;

const settings = {
  vaultStorage: 'memory',
  detectionScope: 'select',
  piiTypes: ['iban'],
};

describe('re-review 84-1: a rejected span does not hide a valid IBAN', () => {
  it('redacts the valid IBAN inside a longer candidate that fails its checksum, and restores it', async () => {
    const [redacted] = await run({ ...settings, operation: 'redact', sessionId: 'r84-rejected' }, [
      { note: rejected },
    ]);
    expect(redacted[0].json.note).toBe(`RU00 [IBAN_0] ${TAIL}`);
    const [restored] = await run({ ...settings, operation: 'restore', sessionId: 'r84-rejected' }, [
      redacted[0].json,
    ]);
    expect(restored[0].json.note).toBe(rejected);
  });

  it('still redacts a valid longer IBAN as one span, including the valid IBAN inside it', async () => {
    const [redacted] = await run({ ...settings, operation: 'redact', sessionId: 'r84-accepted' }, [
      { note: accepted },
    ]);
    expect(redacted[0].json.note).toBe('[IBAN_0]');
    const [restored] = await run({ ...settings, operation: 'restore', sessionId: 'r84-accepted' }, [
      redacted[0].json,
    ]);
    expect(restored[0].json.note).toBe(accepted);
  });
});
