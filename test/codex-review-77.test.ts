/**
 * Regression tests for the eighth Codex review of the 7.0.0 branch, one block per finding, using the review's inputs.
 */
import { readFileSync } from 'fs';

import { run, redactNote as redactIn, verifyStatus } from './harness';

const redactNote = (note: string): Promise<string> => redactIn(note, 'r77');
const presidio = { operation: 'redact', enablePresidio: true, presidioUrl: 'http://presidio:3000' };

describe('re-review 77-1: Slack app and refresh tokens', () => {
  // Built from parts so secret scanners never read the fixtures as live Slack credentials.
  const body = ['1', 'A0123456789', '1234567890123', 'abcdef0123456789'].join('-');
  it.each([
    ['xapp-' + body],
    ['xoxe.' + 'xapp-' + body],
    ['xoxe.' + 'xoxp-' + '1-' + 'AbCdEfGhIjKlMnOpQrStUv'],
  ])('%s is redacted and fails Verify', async (token) => {
    const out = await redactNote(`use ${token} here`);
    // Nothing of the token survives between replacements, and the Slack pattern claimed it.
    expect(out).toContain('[SLACK_TOKEN_');
    expect(out.replace(/\[[A-Z_]+_\d+\]/g, '')).toBe('use  here');
    expect(await verifyStatus(`use ${token} here`)).toBe('FAIL');
  });
});

describe('re-review 77-2: an invalid Presidio URL', () => {
  it.each([[''], [' '], ['not a url']])('%j stops the run', async (presidioUrl) => {
    await expect(run({ ...presidio, sessionId: 'r77u', presidioUrl }, [{ note: 'Xochitl Quispe' }])).rejects.toThrow(
      /Presidio URL must be an http or https address/,
    );
  });
});

describe('re-review 77-3: a malformed Presidio answer', () => {
  it.each([
    [[null]],
    [[{ entity_type: 'PERSON', start: 0, end: 7 }]],
  ])('%j counts as unscanned and stops the run', async (body) => {
    const httpRequest = jest.fn(async () => ({ statusCode: 200, body }));
    await expect(run({ ...presidio, sessionId: 'r77m' }, [{ note: 'xochitl quispe' }], { httpRequest })).rejects.toThrow(
      /Presidio could not scan 1 text/,
    );
  });

  it('a valid answer still redacts the same input', async () => {
    const httpRequest = jest.fn(async () => ({ statusCode: 200, body: [{ entity_type: 'PERSON', start: 0, end: 14, score: 0.9 }] }));
    const [out] = await run({ ...presidio, sessionId: 'r77v' }, [{ note: 'xochitl quispe' }], { httpRequest });
    expect(out[0].json.note).not.toContain('xochitl');
  });
});

describe('re-review 77-4: a Confidence Threshold outside 0 to 1', () => {
  it.each([[2], [-0.5], [Number.NaN]])('%p stops the run', async (confidenceThreshold) => {
    await expect(run({ operation: 'redact', sessionId: 'r77t', confidenceThreshold }, [{ note: 'alice@example.com' }])).rejects.toThrow(
      /Confidence Threshold must be a number from 0 to 1/,
    );
  });
});

describe('re-review 77-5: a Restore key collision never names the key', () => {
  it('keeps the restored original out of the error', async () => {
    const [redacted] = await run({ operation: 'redact', sessionId: 'r77r', vaultStorage: 'memory' }, [{ e: 'alice@example.com' }]);
    const token = redacted[0].json.e as string;
    let message = '';
    try {
      await run({ operation: 'restore', sessionId: 'r77r', vaultStorage: 'memory' }, [{ [token]: 1, 'alice@example.com': 2 }]);
    } catch (error) {
      message = (error as Error).message;
    }
    expect(message).toMatch(/would merge two keys/);
    expect(message).not.toContain('alice@example.com');
  });
});

describe('re-review 77-6: the audit record shows a Presidio outage', () => {
  it('is PARTIAL and counts unscanned texts without Include Audit Report', async () => {
    const httpRequest = jest.fn(async () => {
      throw new Error('ECONNREFUSED');
    });
    const [, report] = await run(
      { ...presidio, sessionId: 'r77a', presidioOnFailure: 'continue', auditLog: true },
      [{ note: 'Xochitl Quispe' }],
      { httpRequest },
    );
    const audit = report[0].json.audit as Record<string, unknown>;
    expect(audit.status).toBe('PARTIAL');
    expect(audit.presidioUnscannedTexts).toBe(1);
    expect(report[0].json.presidioUnscannedTexts).toBe(1);
  });
});

describe('re-review 77-7: the docs describe the outage default', () => {
  it('README and the setup guide no longer promise a silent fallback', () => {
    const root = `${__dirname}/..`;
    for (const file of ['README.md', 'docs/PRESIDIO_SETUP.md']) {
      const text = readFileSync(`${root}/${file}`, 'utf8');
      expect(text).not.toMatch(/falls? back (silently|to built-in patterns when unreachable)|silently fall back/i);
      expect(text).toContain('If Presidio Fails');
    }
  });
});
