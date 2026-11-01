/**
 * Regression tests for the fifth Codex review of the 7.0.0 branch, one block per finding, using the review's inputs.
 */
import { readFileSync } from 'fs';
import { join } from 'path';

import { Redactor } from '../nodes/Redactor/Redactor.node';
import { analyzeWithPresidio, PresidioRequester } from '../nodes/Redactor/presidio';

import { run } from './harness';

const CREDENTIAL = 'dXNlcjpwYXNz';

describe('re-review 74-1: an unknown redaction mode is refused', () => {
  it('a TOKEN expression stops the run instead of passing data through', async () => {
    await expect(
      run({ operation: 'redact', sessionId: 'r74', redactionMode: 'TOKEN' }, [{ note: 'mail jane.doe@example.com' }]),
    ).rejects.toThrow(/Unknown redaction mode "TOKEN"/);
  });

  it('an inherited object name is not treated as a mode', async () => {
    await expect(
      run({ operation: 'redact', sessionId: 'r74', redactionMode: 'constructor' }, [{ note: 'mail jane.doe@example.com' }]),
    ).rejects.toThrow(/Unknown redaction mode/);
  });
});

describe('re-review 74-2: Basic credentials outside a raw header line', () => {
  it.each([
    [{ headers: { Authorization: `Basic ${CREDENTIAL}` } }],
    [{ note: `{"Authorization":"Basic ${CREDENTIAL}"}` }],
    [{ note: `Authorization: Basic ${CREDENTIAL}` }],
  ])('%j is redacted and fails Verify', async (item) => {
    const [out] = await run({ operation: 'redact', sessionId: 'r74b' }, [item]);
    expect(JSON.stringify(out[0].json)).not.toContain(CREDENTIAL);
    const [verified] = await run({ operation: 'verify' }, [item], { typeVersion: 2 });
    expect(verified[0].json.status).toBe('FAIL');
  });

  it('keeps serialized JSON parseable', async () => {
    const [out] = await run({ operation: 'redact', sessionId: 'r74c' }, [{ note: `{"Authorization":"Basic ${CREDENTIAL}"}` }]);
    expect(() => JSON.parse(out[0].json.note as string)).not.toThrow();
  });
});

describe('re-review 74-3: the Presidio breaker belongs to one execution', () => {
  it('failures from one requester do not stop another', async () => {
    const failing: PresidioRequester = async () => ({ statusCode: 500, body: 'down' });
    for (let i = 0; i < 4; i++) await analyzeWithPresidio('http://shared', 'John Smith', 'en', 0.4, 1000, failing);
    const calls: string[] = [];
    const healthy: PresidioRequester = async ({ url }) => {
      calls.push(url);
      return { statusCode: 200, body: '[]' };
    };
    await analyzeWithPresidio('http://shared', 'John Smith', 'en', 0.4, 1000, healthy);
    expect(calls).toEqual(['http://shared/analyze']);
  });
});

describe('re-review 74-4 and 74-5: Presidio binds to localhost everywhere it is documented', () => {
  const nodeText = JSON.stringify(new Redactor().description);
  const setupDoc = readFileSync(join(__dirname, '..', 'docs', 'PRESIDIO_SETUP.md'), 'utf8');

  it.each([
    ['node setup notice', nodeText],
    ['docs/PRESIDIO_SETUP.md', setupDoc],
  ])('%s publishes the port on 127.0.0.1 only', (_name, text) => {
    expect(text).toContain('127.0.0.1:5002:3000');
    expect(text).not.toMatch(/-p 5002:3000/);
  });
});
