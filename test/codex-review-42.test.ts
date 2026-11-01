/**
 * Regression tests for the 4.2.0 Codex re-review, one block per finding.
 */
import type { IDataObject } from 'n8n-workflow';
import { checkRegex } from '../nodes/Redactor/regexSafety';
import { parseTenantProfile } from '../nodes/Redactor/profiles';
import { resetCircuitBreaker } from '../nodes/Redactor/presidio';
import { MemoryVault } from '../nodes/Redactor/vault';
import { redactValue } from '../nodes/Redactor/engine';
import type { RedactionContext } from '../nodes/Redactor/types';

import { run, persist, cpuNow } from './harness';

const EMAIL_RE = String.raw`\w+@\w+[.]\w+`;

describe('re-review 42-1: a pseudonym never hides another original', () => {
  it('redacts both names when one pseudonym equals the other original', async () => {
    const store: IDataObject = {};
    const input = { note: 'Alice Baker spoke with Elena Reynolds' };
    const [out] = await run({ operation: 'redact', sessionId: 'test', redactionMode: 'pseudonymize' }, [input], {
      staticData: store,
    });
    const note = String(out[0].json.note);
    expect(note).not.toContain('Alice Baker');
    expect(note).not.toContain('Elena Reynolds');
    const [back] = await run({ operation: 'restore', sessionId: 'test' }, [out[0].json], { staticData: persist(store) });
    expect(back[0].json).toEqual(input);
  });
});

describe('re-review 42-2: a failed legacy passphrase never stores plaintext', () => {
  it('stops when the legacy passphrase expression cannot be evaluated', async () => {
    const store: IDataObject = {};
    const params: Record<string, unknown> = { operation: 'redact', sessionId: 'lp' };
    Object.defineProperty(params, 'vaultPassphrase', {
      enumerable: true,
      get: () => {
        throw new Error('Referenced node does not exist');
      },
    });
    await expect(run(params, [{ email: 'victim@example.com' }], { staticData: store })).rejects.toThrow(/passphrase/i);
    expect(JSON.stringify(store)).not.toContain('victim@example.com');
  });

  it('still allows an absent or empty legacy passphrase', async () => {
    const [out] = await run({ operation: 'redact', sessionId: 'lp2', vaultPassphrase: '' }, [{ email: 'a@example.com' }]);
    expect(String(out[0].json.email)).not.toContain('a@example.com');
  });
});

describe('re-review 42-3: confidence context uses source positions', () => {
  it('redacts an SSN after an earlier replacement at threshold 0.9', async () => {
    const note = 'neutral filler words '.repeat(20) + 'alice@example.com SSN 123-45-6789';
    const [out] = await run({ operation: 'redact', sessionId: 'conf', confidenceThreshold: 0.9 }, [{ note }]);
    expect(String(out[0].json.note)).not.toContain('123-45-6789');
  });
});

describe('re-review 42-4: Presidio never re-pseudonymizes a regex replacement', () => {
  beforeEach(() => resetCircuitBreaker());
  it('restores the original email after both passes', async () => {
    const emailSpans = (text: string) =>
      [...text.matchAll(/[\w.+-]+@[\w-]+[.][\w.]+/g)].map((m) => ({
        entity_type: 'EMAIL_ADDRESS', start: m.index ?? 0, end: (m.index ?? 0) + m[0].length, score: 0.99,
      }));
    const httpRequest = jest.fn(async (req: { body?: { text?: string } }) => ({
      statusCode: 200,
      body: req.body?.text ? emailSpans(req.body.text) : [],
    }));
    const store: IDataObject = {};
    const input = { contact: 'write to alice@example.com today' };
    const params = {
      operation: 'redact', sessionId: 'pres', redactionMode: 'pseudonymize',
      enablePresidio: true, presidioUrl: 'http://presidio:3000',
    };
    const [out] = await run(params, [input], { staticData: store, httpRequest });
    expect(String(out[0].json.contact)).not.toContain('alice@example.com');
    const [back] = await run({ operation: 'restore', sessionId: 'pres' }, [out[0].json], { staticData: persist(store) });
    expect(back[0].json).toEqual(input);
  });
});

describe('re-review 42-5: numeric and string mappings stay distinct', () => {
  it('restores a string salary as a string and a numeric one as a number', async () => {
    const store: IDataObject = {};
    const input = [{ salary: '50000' }, { salary: 50000 }];
    const [out] = await run({ operation: 'redact', sessionId: 'mixed-numeric', redactionMode: 'pseudonymize' }, input, {
      staticData: store,
    });
    const [back] = await run({ operation: 'restore', sessionId: 'mixed-numeric' }, out.map((o) => o.json), {
      staticData: persist(store),
    });
    expect(back.map((b) => b.json)).toEqual(input);
  });

  it('restores a partly matched number as a number', async () => {
    const store: IDataObject = {};
    const params = { operation: 'redact', sessionId: 'dig', customPatterns: { patterns: [{ label: 'dig', regex: '[0-9]{3}' }] } };
    const [out] = await run(params, [{ x: 123456 }], { staticData: store });
    expect(out[0].json.x).not.toBe(123456);
    const [back] = await run({ operation: 'restore', sessionId: 'dig' }, [out[0].json], { staticData: persist(store) });
    expect(back[0].json).toEqual({ x: 123456 });
  });
});

describe('re-review 42-6: sequential overlapping repetition is refused', () => {
  it.each(['^a+a+a+a+a+a+a+a+a+a+!$', 'a*a*b', String.raw`\d+\d+x`, String.raw`[a-z]+\w+@`, '.*.*='])('rejects %p', (re) => {
    expect(checkRegex(re)).not.toBeNull();
    expect(() => parseTenantProfile({ customPatterns: [{ label: 'x', regex: re }] })).toThrow();
  });

  it.each([
    '[A-Z]{2}[0-9]+', 'EMP-[0-9]{6}?', String.raw`\d{3}-\d{4}`, EMAIL_RE, '[0-9]{3}', '[A-Z]+-[0-9]+', String.raw`[a-z]+\s+[0-9]+`,
  ])('accepts %p', (re) => {
    expect(checkRegex(re)).toBeNull();
  });

  it('matches user regexes on long input up to the length limit', () => {
    const vault = new MemoryVault();
    vault.getOrCreateSession('cap', 0);
    const ctx: RedactionContext = {
      enabledPatterns: [], customPatterns: [{ label: 'w', regex: EMAIL_RE }], mode: 'token', dedup: true,
      fieldRules: [], fieldMode: 'all', skipSemantic: true,
    };
    const started = cpuNow();
    const out = redactValue({ note: 'a'.repeat(19_000) + '? mail bob@example.com' }, ctx, vault, 'cap', [], 0);
    expect(cpuNow() - started).toBeLessThan(10_000);
    expect(JSON.stringify(out)).not.toContain('bob@example.com');
  });
});
