/** Regression coverage for all ten findings in re-review 78. */
import { readFileSync } from 'fs';
import { createHmac } from 'crypto';
import type { IDataObject } from 'n8n-workflow';
import { run, redactNote, verifyStatus, persist } from './harness';

const presidio = { operation: 'redact', sessionId: 'r78', enablePresidio: true, presidioUrl: 'http://presidio:3000' };
const personal = 'alice@example.com';
const read = (file: string): string => readFileSync(`${__dirname}/../${file}`, 'utf8');

async function failureMessage(params: Record<string, unknown>, note: string): Promise<string> {
  try {
    await run({ operation: 'redact', sessionId: 'r78', ...params }, [{ note }]);
  } catch (error) {
    return (error as Error).message;
  }
  throw new Error('Expected the run to fail');
}

describe('re-review 78-1: repair tokens reserve every output', () => {
  it('restores the exact input after 30,317 persisted email mappings', async () => {
    const store: IDataObject = {};
    const emails = Array.from({ length: 30317 }, (_, i) => `user${i}@example.com`);
    await run({ operation: 'redact', sessionId: 's', detectionScope: 'select', piiTypes: ['email'] }, [{ emails }], { staticData: store });
    const reloaded = persist(store);
    const input = { compose: '[TEXT_EMP440]', note: '1EMP309', other: 'EMP608' };
    const [out] = await run({
      operation: 'redact', sessionId: 's', redactionMode: 'pseudonymize', detectionScope: 'select', piiTypes: [],
      customPatterns: { patterns: [{ regex: 'EMP[0-9]+', label: 'SALARY' }] },
    }, [input], { staticData: reloaded });
    const [back] = await run({ operation: 'restore', sessionId: 's' }, [out[0].json], { staticData: persist(reloaded) });
    expect(back[0].json).toEqual(input);
  }, 30000);
});

describe('re-review 78-2: quoted connection-string passwords', () => {
  const connection = ['Server=db;User ID=alice;', 'Pass' + 'word=', '"alpha""bravo;charlie";'].join('');
  it('redacts the entire quoted password including doubled quotes and semicolons', async () => {
    expect(await redactNote(connection, 'r78conn')).toMatch(/^\[CONN_STRING_\d+\];$/);
    expect(await verifyStatus(connection)).toBe('FAIL');
  });
});

describe('re-review 78-3: JWT claims may start with whitespace', () => {
  const header = Buffer.from('{"alg":"HS256","typ":"JWT"}').toString('base64url');
  const payload = Buffer.from(` {"email":"${personal}"}`).toString('base64url');
  const signingInput = [header, payload].join('.');
  const token = [signingInput, createHmac('sha256', ['test', 'signing', 'key'].join('-')).update(signingInput).digest('base64url')].join('.');
  it('redacts a signed HS256 JWT with whitespace before the claims object', async () => {
    expect(await redactNote(token, 'r78jwt')).toMatch(/^\[JWT_\d+\]$/);
  });
  it('fails Verify for that JWT', async () => {
    expect(await verifyStatus(token)).toBe('FAIL');
  });
});

describe('re-review 78-4: unusable Presidio offsets are scan failures', () => {
  const httpRequest = jest.fn(async () => ({ statusCode: 200, body: [{ entity_type: 'PERSON', start: 0, end: 999, score: 0.9 }] }));
  it('stops by default for an entity beyond the submitted text', async () => {
    await expect(run(presidio, [{ note: 'xochitl quispe' }], { httpRequest })).rejects.toThrow(/Presidio could not scan 1 text/);
    const validStringBody = jest.fn(async () => ({
      statusCode: 200, body: JSON.stringify([{ entity_type: 'PERSON', start: 0, end: 14, score: 0.9 }]),
    }));
    const [out] = await run(presidio, [{ note: 'xochitl quispe' }], { httpRequest: validStringBody });
    expect(out[0].json.note).toMatch(/^\[PERSON_NAME_\d+\]$/);
  });
  it('marks explicit continuation as partial and unscanned', async () => {
    const [, report] = await run({ ...presidio, presidioOnFailure: 'continue', auditLog: true }, [{ note: 'xochitl quispe' }], { httpRequest });
    expect(report[0].json.audit).toMatchObject({ status: 'PARTIAL', presidioUnscannedTexts: 1 });
  });
});

describe('re-review 78-5: direct pattern selection must be valid', () => {
  it.each([[["emali"]], ['email'], [[null]]])('rejects invalid selection %j', async (piiTypes) => {
    await expect(run({ operation: 'redact', sessionId: 'r78sel', detectionScope: 'select', piiTypes }, [{ note: personal }]))
      .rejects.toThrow(/known pattern names/);
  });
  it('rejects an unknown detection scope', async () => {
    await expect(run({ operation: 'redact', sessionId: 'r78sel', detectionScope: 'selected', piiTypes: [] }, [{ note: personal }]))
      .rejects.toThrow(/Detection Scope/);
  });
});

describe('re-review 78-6: Presidio failure policy must be explicit', () => {
  it('refuses Stop before scanning instead of permitting an outage', async () => {
    const httpRequest = jest.fn(async () => { throw new Error('ECONNREFUSED'); });
    await expect(run({ ...presidio, presidioOnFailure: 'Stop' }, [{ note: 'xochitl quispe' }], { httpRequest }))
      .rejects.toThrow(/If Presidio Fails must be stop or continue/);
    expect(httpRequest).not.toHaveBeenCalled();
  });
});

describe('re-review 78-7: deny-list diagnostics contain no entry values', () => {
  it.each([
    [personal + '(', 'short'],
    [personal.replace('.', '[.]'), 'x'.repeat(20001)],
  ])('identifies the row without copying its regex', async (value, note) => {
    const message = await failureMessage({ denyList: { entries: [{ value, type: 'regex' }] } }, note);
    expect(message).toMatch(/Deny list entry 1/);
    expect(message).not.toContain(value);
    expect(message).not.toContain(personal);
  });
});

describe('re-review 78-8: personal session IDs stay out of diagnostics', () => {
  it('emits the same opaque reference in the full report and audit', async () => {
    const [data, report] = await run({ operation: 'redact', auditLog: true, includeReport: true }, [{ email: personal }], { perItem: { sessionId: [personal] } });
    expect(data[0].json.email).not.toContain(personal);
    expect(JSON.stringify(report)).not.toContain(personal);
    const audit = report[0].json.audit as IDataObject;
    expect(audit.sessionId).toMatch(/^session:[a-f0-9]{64}$/);
    expect(report[0].json.sessionId).toBe(audit.sessionId);
  });
  it('omits the raw ID from a missing-session error', async () => {
    const message = await failureMessage({ operation: 'restore', sessionId: personal }, 'unmapped');
    expect(message).toContain('No vault found');
    expect(message).not.toContain(personal);
  });
});

describe('re-review 78-9: audit retention belongs to downstream storage', () => {
  it('documents Report output and external retention instead of JSONL persistence', () => {
    const comparison = read('docs/COMPARISON.md');
    expect(comparison).not.toMatch(/Yes \((?:7-year JSONL logs|JSONL, daily rotation|JSONL logs)\)/);
    expect(comparison).not.toMatch(/^\| SOX \|[^\n]*Yes \(configurable\)/m);
    expect(comparison).toContain('downstream storage controls retention');
    expect(comparison).toContain('Report output');
  });
});

describe('re-review 78-10: CI covers pushes to every branch', () => {
  it('has no branch filter on pushes and keeps actions pinned', () => {
    const ci = read('.github/workflows/ci.yml');
    const push = ci.match(/^  push:([^]*?)(?=^\S)/m)?.[1];
    expect(push).toBeDefined();
    expect(push).not.toMatch(/branches|tags|paths/);
    expect(ci.match(/uses: actions\/[\w-]+@[a-f0-9]{40}\b/g)).toHaveLength(2);
  });
});
