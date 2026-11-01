/**
 * Regression tests for the second Codex review of the 7.0.0 branch, one block per finding, using the review's inputs.
 */
import type { IDataObject } from 'n8n-workflow';
import { readFileSync } from 'fs';
import { join } from 'path';

import { run, persist } from './harness';

describe('re-review 71-1: Restore pairs properties by original key', () => {
  it('restores {"1":true,"2":false} with a pattern on key 1', async () => {
    const store: IDataObject = {};
    const input = { 1: true, 2: false };
    const params = {
      operation: 'redact', sessionId: 'k', redactionMode: 'pseudonymize', enabledPatterns: [],
      customPatterns: { patterns: [{ label: 'secret', regex: '^1$' }] },
    };
    const [out] = await run(params, [input], { staticData: store });
    const [back] = await run({ operation: 'restore', sessionId: 'k' }, [out[0].json], { staticData: persist(store) });
    expect(back[0].json).toEqual(input);
  });
});

describe('re-review 71-2: current provider credentials', () => {
  const projectKey = ['sk-proj-', 'Ab3dEf6hIj9kLm2nOp5q_Rs8tUv1wXy4zA7b-Cd0eF3gH6iJ9kL2mN5oP8qR1s'].join('');
  const fineGrained = ['github_pat_', '11AAAAAAA0aaaaaaaaaaaa_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'].join('');

  it.each([[projectKey], [fineGrained]])('redacts and fails Verify on %s', async (secret) => {
    const [out] = await run({ operation: 'redact', sessionId: 'c' }, [{ note: `key ${secret} end` }]);
    expect(out[0].json.note).not.toContain(secret.slice(12, 30));
    const [verify] = await run({ operation: 'verify' }, [{ note: `key ${secret} end` }], { typeVersion: 2 });
    expect(verify[0].json.status).toBe('FAIL');
  });
});

describe('re-review 71-3: one run, one set of settings', () => {
  it('stops when the session differs per item', async () => {
    await expect(run({ operation: 'redact' }, [{ note: 'a' }, { note: 'b' }], { perItem: { sessionId: ['t1', 't2'] } }))
      .rejects.toThrow(/different value for item 1/);
  });

  it('stops when the tenant profile differs per item', async () => {
    const profiles = [{ enabledPatterns: [] }, { enabledPatterns: ['email'] }];
    await expect(run(
      { operation: 'redact', sessionId: 's', useTenantProfile: true },
      [{ note: 'alice@example.com' }, { note: 'bob@example.com' }],
      { perItem: { tenantProfile: profiles } },
    )).rejects.toThrow(/different value for item 1/);
  });

  it('runs when every item has the same settings', async () => {
    const [out] = await run({ operation: 'redact' }, [{ note: 'alice@example.com' }, { note: 'bob@example.com' }],
      { perItem: { sessionId: ['t1', 't1'] } });
    expect(out).toHaveLength(2);
  });
});

describe('re-review 71-4: German ID card serial number', () => {
  it('redacts a nine-character serial', async () => {
    const [out] = await run({ operation: 'redact', sessionId: 'id', enabledPatterns: ['nationalIdDE'] }, [{ note: 'L01X00T47' }]);
    expect(out[0].json.note).not.toContain('L01X00T47');
  });
});

describe('re-review 71-5: Verify can gate the LLM', () => {
  it('passes the items through when nothing leaks', async () => {
    const [out] = await run({ operation: 'verify', verifyOutput: 'gate' }, [{ note: 'hello' }], { typeVersion: 2 });
    expect(out.map((o) => o.json)).toEqual([{ note: 'hello' }]);
  });

  it('stops the run when something leaks', async () => {
    await expect(run({ operation: 'verify', verifyOutput: 'gate' }, [{ note: 'alice@example.com' }], { typeVersion: 2 }))
      .rejects.toThrow(/potential PII leak/);
  });
});

describe('re-review 71-6: examples use node version 2', () => {
  it('has no Redactor node on version 1', () => {
    for (const name of ['multi-stage-verify', 'demo-workflow', 'openai-privacy-shield', 'data-classification-audit']) {
      const flow = JSON.parse(readFileSync(join(__dirname, '..', 'examples', `${name}.json`), 'utf8')) as { nodes: Array<{ type: string; typeVersion: number }> };
      for (const node of flow.nodes.filter((n) => n.type === 'n8n-nodes-redactor.redactor')) expect(node.typeVersion).toBe(2);
    }
  });
});

describe('re-review 71-7: Presidio stays on localhost', () => {
  it('publishes the analyzer port on 127.0.0.1 only', () => {
    const doc = readFileSync(join(__dirname, '..', 'docs', 'PRESIDIO_SETUP.md'), 'utf8');
    expect(doc).not.toMatch(/(?<![\d.]:?)\b5002:3000/);
    expect(doc).toContain('127.0.0.1:5002:3000');
  });
});
