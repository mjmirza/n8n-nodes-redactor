/**
 * Regression tests for the first Codex review of the 7.0.0 branch, one block per finding, using the review's inputs.
 */
import type { IDataObject } from 'n8n-workflow';
import { redactValue, restoreValue, enhanceWithPresidio, buildReport } from '../nodes/Redactor/engine';
import { buildAuditEntry } from '../nodes/Redactor/audit';
import { resetCircuitBreaker } from '../nodes/Redactor/presidio';
import type { RedactionHit } from '../nodes/Redactor/types';
import { MemoryVault } from '../nodes/Redactor/vault';

import { run, persist, engineSetup } from './harness';

const binary = { file: { data: Buffer.from('alice@example.com').toString('base64'), mimeType: 'text/plain', fileName: 'note.txt' } };

describe('re-review 70-1: unscanned attachments', () => {
  it('Redact removes attachments by default', async () => {
    const [out] = await run({ operation: 'redact', sessionId: 'b1' }, [{ note: 'hi' }], { binary: [binary] });
    expect(out[0].binary).toBeUndefined();
  });

  it('Redact keeps them only when asked', async () => {
    const [out] = await run({ operation: 'redact', sessionId: 'b2', binaryAttachments: 'keep' }, [{ note: 'hi' }], { binary: [binary] });
    expect(out[0].binary).toEqual(binary);
  });

  it('Verify fails on an attachment it cannot scan', async () => {
    const [out] = await run({ operation: 'verify' }, [{ note: 'hi' }], { binary: [binary], typeVersion: 2 });
    expect(out[0].json.status).toBe('FAIL');
    expect(out[0].json.unscannedAttachments).toBe(1);
  });
});

describe('re-review 70-2: pseudonyms composed across fields', () => {
  it('restores {note:"1EMP309", other:"EMP608"} exactly', async () => {
    const store: IDataObject = {};
    const input = { note: '1EMP309', other: 'EMP608' };
    const params = {
      operation: 'redact', sessionId: 's', redactionMode: 'pseudonymize', enabledPatterns: [],
      customPatterns: { patterns: [{ label: 'SALARY', regex: 'EMP[0-9]+' }] },
    };
    const [out] = await run(params, [input], { staticData: store });
    const [back] = await run({ operation: 'restore', sessionId: 's' }, [out[0].json], { staticData: persist(store) });
    expect(back[0].json).toEqual(input);
  });

  it('restores items whose pseudonyms compose across items', async () => {
    const store: IDataObject = {};
    const items = Array.from({ length: 60 }, (_, i) => ({ note: `${i % 10}EMP${i}`, other: `EMP${i * 7}` }));
    const params = {
      operation: 'redact', sessionId: 's', redactionMode: 'pseudonymize', enabledPatterns: [],
      customPatterns: { patterns: [{ label: 'SALARY', regex: 'EMP[0-9]+' }] },
    };
    const [out] = await run(params, items, { staticData: store });
    const [back] = await run({ operation: 'restore', sessionId: 's' }, out.map((o) => o.json), { staticData: persist(store) });
    expect(back.map((b) => b.json)).toEqual(items);
  });
});

describe('re-review 70-3: booleans keep their own type', () => {
  it.each([
    [{ diagnosis: 'true', disability: true }],
    [{ disability: true, diagnosis: 'true' }],
  ])('pseudonymize restores %p', (input) => {
    const { vault, ctx, hits } = engineSetup({ mode: 'pseudonymize', skipSemantic: false });
    vault.deleteSession('s');
    vault.getOrCreateSession('s', 0);
    const out = redactValue(input, ctx, vault, 's', hits, 0);
    expect(restoreValue(out, vault, 's')).toEqual(input);
  });
});

describe('re-review 70-4: no copy of the input outlives the run', () => {
  it('keeps the search index on the context', () => {
    const input = { note: 'alice@example.com', other: 'x'.repeat(5000) };
    const { vault, ctx, hits } = engineSetup({ mode: 'pseudonymize', enabledPatterns: ['email'], inputText: JSON.stringify(input) });
    redactValue(input, ctx, vault, 's', hits, 0);
    expect(ctx.inputIndex?.sa).toBeInstanceOf(Int32Array);
  });
});

describe('re-review 70-5: failed Presidio settings', () => {
  it('propagates a failed URL expression', async () => {
    await expect(run(
      { operation: 'redact', sessionId: 'p', enablePresidio: true },
      [{ note: 'Xochitl Quispe' }],
      { failingParams: ['presidioUrl'] },
    )).rejects.toThrow(/Could not evaluate expression/);
  });
});

describe('re-review 70-7: counters for inherited names', () => {
  const hits: RedactionHit[] = ['constructor', '__proto__', 'toString'].map((label) => ({
    token: `[${label}_0]`, original: '***', patternName: label, patternLabel: label, category: 'identity', field: 'note', itemIndex: 0, confidence: 1,
  }));

  it('counts them in the report', () => {
    const counts = JSON.parse(JSON.stringify(buildReport('s', hits).hitsByPattern));
    expect(counts).toEqual(Object.fromEntries([['constructor', 1], ['__proto__', 1], ['toString', 1]]));
  });

  it('counts them in the audit entry', () => {
    const entry = buildAuditEntry('REDACT', 'token', hits, 1, 1, 1, true);
    expect(JSON.parse(JSON.stringify(entry.hitsByPattern))).toEqual(Object.fromEntries([['constructor', 1], ['__proto__', 1], ['toString', 1]]));
  });

  it('counts Presidio entities named like object properties', async () => {
    resetCircuitBreaker();
    const vault = new MemoryVault();
    vault.deleteSession('s');
    const { ctx } = engineSetup({
      presidioUrl: 'http://presidio:3000',
      presidioRequest: async () => ({ statusCode: 200, body: [{ entity_type: 'constructor', start: 0, end: 14, score: 0.99 }] }),
    });
    vault.getOrCreateSession('s', 0);
    const found: RedactionHit[] = [];
    await enhanceWithPresidio({ note: 'Xochitl Quispe' }, ctx, vault, 's', found, 0);
    expect(JSON.parse(JSON.stringify(buildReport('s', found).hitsByPattern))).toEqual({ constructor: 1 });
  });
});
