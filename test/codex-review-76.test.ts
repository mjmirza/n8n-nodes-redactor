/**
 * Regression tests for the seventh Codex review of the 7.0.0 branch, one block per finding, using the review's inputs.
 */
import { redactValue } from '../nodes/Redactor/engine';
import { generatePseudonym } from '../nodes/Redactor/pseudonymize';

import { engineSetup, run } from './harness';

describe('re-review 76-1: a blank allow-list row', () => {
  it('allows nothing', async () => {
    const [out] = await run(
      { operation: 'redact', sessionId: 'r76a', allowList: { entries: [{ value: '', type: 'contains' }] } },
      [{ note: 'mail alice@example.com, SSN 123-45-6789' }],
    );
    expect(out[0].json.note).not.toContain('alice@example.com');
    expect(out[0].json.note).not.toContain('123-45-6789');
  });
});

describe('re-review 76-2: a Presidio outage', () => {
  const down = jest.fn(async () => {
    throw new Error('ECONNREFUSED');
  });

  it('stops the run by default instead of passing unscanned text', async () => {
    await expect(run(
      { operation: 'redact', sessionId: 'r76b', enablePresidio: true, presidioUrl: 'http://presidio:3000' },
      [{ note: 'Xochitl Quispe' }],
      { httpRequest: down },
    )).rejects.toThrow(/Presidio could not scan 1 text/);
  });

  it('counts unscanned texts in the report when fallback is chosen', async () => {
    const [, report] = await run(
      {
        operation: 'redact', sessionId: 'r76c', enablePresidio: true, presidioUrl: 'http://presidio:3000',
        presidioOnFailure: 'continue', includeReport: true,
      },
      [{ note: 'Xochitl Quispe' }],
      { httpRequest: down },
    );
    expect(report[0].json.presidioUnscannedTexts).toBe(1);
  });
});

describe('re-review 76-3: Restore never merges two keys', () => {
  it('stops when a restored key collides with another key', async () => {
    const [redacted] = await run({ operation: 'redact', sessionId: 'r76d', vaultStorage: 'memory' }, [{ e: 'alice@example.com' }]);
    const token = redacted[0].json.e as string;
    await expect(run(
      { operation: 'restore', sessionId: 'r76d', vaultStorage: 'memory' },
      [{ [token]: 1, 'alice@example.com': 2 }],
    )).rejects.toThrow(/would merge two keys into "alice@example.com"/);
  });
});

describe('re-review 76-4: Presidio keeps its 0.4 floor at the default threshold', () => {
  it('a saved node with threshold 0 asks for 0.4 and ignores a 0.01 detection', async () => {
    const bodies: Array<{ score_threshold?: number }> = [];
    const httpRequest = jest.fn(async (opts: { body?: { score_threshold?: number; text?: string } }) => {
      bodies.push(opts.body ?? {});
      return { statusCode: 200, body: [{ entity_type: 'PERSON', start: 0, end: 5, score: 0.01 }] };
    });
    const [out] = await run(
      { operation: 'redact', sessionId: 'r76e', enablePresidio: true, presidioUrl: 'http://presidio:3000', confidenceThreshold: 0 },
      [{ note: 'hello world' }],
      { httpRequest, typeVersion: 1 },
    );
    expect(bodies[0].score_threshold).toBe(0.4);
    expect(out[0].json.note).toBe('hello world');
  });
});

describe('re-review 76-5: deduplication keeps equal numbers and booleans equal', () => {
  it('repeated salaries and disability flags share one token each', () => {
    const { vault, ctx, hits } = engineSetup({ dedup: true, skipSemantic: false });
    const out = redactValue(
      [{ salary: 85000, disability: true }, { salary: 85000, disability: true }], ctx, vault, 's', hits, 0,
    ) as Array<{ salary: unknown; disability: unknown }>;
    expect(out[0].salary).not.toBe(85000);
    expect(out[0].salary).toBe(out[1].salary);
    expect(out[0].disability).not.toBe(true);
    expect(out[0].disability).toBe(out[1].disability);
  });

  it('a number never shares a token with the same digits as text', () => {
    const { vault, ctx, hits } = engineSetup({ dedup: true, skipSemantic: false });
    const out = redactValue({ salary: 85000, note: { salary: '85000' } }, ctx, vault, 's', hits, 0) as {
      salary: unknown; note: { salary: unknown };
    };
    expect(out.salary).not.toBe(out.note.salary);
  });
});

describe('re-review 76-6: demo email pseudonyms', () => {
  const reserved = /(^|\.)(example\.(com|net|org)|example|test|invalid)$/;

  it('every pseudonym domain is reserved for documentation', () => {
    for (let i = 0; i < 200; i++) {
      expect(generatePseudonym('session-8', `user${i}@customer.example`, 'EMAIL').split('@')[1]).toMatch(reserved);
    }
  });

  it('the review input gets a reserved domain', () => {
    const pseudonym = generatePseudonym('session-8', 'alice@customer.example', 'EMAIL');
    expect(pseudonym.split('@')[1]).toMatch(reserved);
  });
});

describe('re-review 76-7: report hits after a pseudonym repair', () => {
  it('name the repaired key and fields that exist in the output', async () => {
    const [out, report] = await run(
      {
        operation: 'redact', sessionId: 's2', redactionMode: 'pseudonymize', includeReport: true,
        customPatterns: { patterns: [{ label: 'SALARY', regex: 'EMP[0-9]+' }] },
      },
      [{ '1EMP81': 'EMP567', other: 'EMP164' }],
    );
    const json = out[0].json as Record<string, unknown>;
    const hits = report[0].json.hits as Array<{ field: string; token: string }>;
    for (const hit of hits) {
      expect(Object.keys(json)).toContain(hit.field);
      const text = `${hit.field} ${String(json[hit.field])}`;
      expect(text).toContain(hit.token);
    }
  });
});
