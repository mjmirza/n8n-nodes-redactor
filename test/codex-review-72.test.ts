/**
 * Regression tests for the third Codex review of the 7.0.0 branch, one block per finding, using the review's inputs.
 */
import { resetCircuitBreaker } from '../nodes/Redactor/presidio';

import { redactNote as redactIn, run, verifyStatus } from './harness';

const redactNote = (note: string): Promise<string> => redactIn(note, 'r72');

describe('re-review 72-1 and 2: credentials', () => {
  it.each([
    ['bearer abcdefghijklmnop', 'abcdefghijklmnop'],
    ['authorization: basic dXNlcjpwYXNz', 'dXNlcjpwYXNz'],
    ['password=admin', 'admin'],
    ['password="correct horse battery staple"', 'horse battery'],
    ['password="supersecret rest-of-passphrase"', 'rest-of-passphrase'],
  ])('%s is redacted and fails Verify', async (text, secret) => {
    expect(await redactNote(text)).not.toContain(secret);
    expect(await verifyStatus(text)).toBe('FAIL');
  });

  it('leaves prose about a bearer alone', async () => {
    expect(await redactNote('the bearer of bad news')).toBe('the bearer of bad news');
  });
});

describe('re-review 72-3: the legacy passphrase is one per run', () => {
  it('stops when items give different passphrases', async () => {
    await expect(run(
      { operation: 'redact', sessionId: 'pp' },
      [{ note: 'alice@example.com' }, { note: 'bob@example.com' }],
      { perItem: { vaultPassphrase: ['first-passphrase-1', 'second-passphrase-2'] } },
    )).rejects.toThrow(/different value for item 1/);
  });
});

describe('re-review 72-4: escaped LDAP commas', () => {
  it('covers CN=Doe\\, John,OU=Sales,DC=corp', async () => {
    const out = await redactNote('CN=Doe\\, John,OU=Sales,DC=corp');
    expect(out).not.toMatch(/Doe|John/);
  });
});

describe('re-review 72-5: five-word names with unknown words', () => {
  it('covers Alice Beth Claire Xochitl Quispe', async () => {
    expect(await redactNote('Alice Beth Claire Xochitl Quispe')).not.toMatch(/Xochitl|Quispe|Alice/);
  });
});

describe('re-review 72-6: Bitcoin address formats', () => {
  it.each([
    'BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4',
    'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0',
  ])('redacts %s', async (address) => {
    expect(await redactNote(`send to ${address} now`)).not.toContain(address);
  });
});

describe('re-review 72-7: a session that expires during Redact', () => {
  it('stops instead of returning tokens that cannot be restored', async () => {
    resetCircuitBreaker();
    const realNow = Date.now.bind(Date);
    let offset = 0;
    const spy = jest.spyOn(Date, 'now').mockImplementation(() => realNow() + offset);
    const httpRequest = jest.fn(async () => {
      offset = 3 * 60 * 60 * 1000;
      return { statusCode: 200, body: [] };
    });
    try {
      await expect(run(
        { operation: 'redact', sessionId: 'exp', vaultStorage: 'memory', enablePresidio: true, presidioUrl: 'http://presidio:3000' },
        [{ note: 'alice@example.com' }],
        { httpRequest },
      )).rejects.toThrow(/expired during the run/);
    } finally {
      spy.mockRestore();
    }
  });
});
