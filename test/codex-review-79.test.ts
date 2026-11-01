/** Regression coverage for all six findings in re-review 79. */
import type { IDataObject } from 'n8n-workflow';
import { ensureRestorable } from '../nodes/Redactor/engine';
import { getPatternsByNames } from '../nodes/Redactor/patterns';
import { run, redactNote, verifyStatus, engineSetup, fast } from './harness';

describe('re-review 79-1: braced ODBC passwords', () => {
  const connection = ['Server=db;Uid=alice;', 'Pwd', '={alpha;bravo charlie};'].join('');
  it('redacts the complete brace-enclosed value', async () => {
    expect(await redactNote(connection, 'r79braces')).toMatch(/^\[CONN_STRING_\d+\];$/);
    expect(await verifyStatus(connection)).toBe('FAIL');
    const escaped = ['Server=db;Uid=alice;', 'Pwd', '={alpha;bra}}vo charlie};'].join('');
    expect(await redactNote(escaped, 'r79escaped')).toMatch(/^\[CONN_STRING_\d+\];$/);
  });
});

describe('re-review 79-2: whitespace around connection-string equals signs', () => {
  const connection = ['Server=db;User ID=alice;', 'Pass', 'word', ' = "alpha""bravo charlie";'].join('');
  it('redacts the complete quoted password after a trimmed key', async () => {
    expect(await redactNote(connection, 'r79spaces')).toMatch(/^\[CONN_STRING_\d+\];$/);
    expect(await verifyStatus(connection)).toBe('FAIL');
    const spaced = ['Server \t= db;User ID = alice; ', 'Pass', 'word', '\t = "alpha""bravo charlie";'].join('');
    expect(await redactNote(spaced, 'r79allspaces')).toMatch(/^\[CONN_STRING_\d+\];$/);
  });
});

describe('re-review 79-3: hyphen-prefixed JWTs', () => {
  const token = [
    ['eyJhbGciOiJIUzI1NiIs', 'InR5cCI6IkpXVCJ9'].join(''),
    ['eyJlbWFpbCI6ImFsaWNl', 'QGV4YW1wbGUuY29tIn0'].join(''),
    ['OalRnpJ3V5hGFxmmS6_3', 'AWXt7InLVLq1-QaiE_-Y0D4'].join(''),
  ].join('.');
  const input = ['/reset-', token].join('');
  it('finds the header after the hyphen', async () => {
    expect(await redactNote(input, 'r79prefix')).toMatch(/^\/reset-\[JWT_\d+\]$/);
    const scan = getPatternsByNames(['jwtToken'])[0].scan!;
    // Every Base64 alignment, with nested objects, escaped quotes and leading JSON whitespace.
    const header = Buffer.from(' \n {"alg":"HS256","extra":{"text":"}\\\"{","list":[1,2]}}').toString('base64url');
    const nested = [header, ...token.split('.').slice(1)].join('.');
    for (const prefix of ['a-', 'ab-', 'abc-', 'abcd-']) {
      expect(scan(prefix + nested)).toEqual([{ start: prefix.length, end: prefix.length + nested.length }]);
    }
    // Many apparent header starts must not cause one decode of every remaining suffix.
    const longPrefix = 'eyJ-'.repeat(40000);
    fast(() => {
      expect(scan(longPrefix + token)).toEqual([{ start: longPrefix.length, end: longPrefix.length + token.length }]);
    }, 1000);
  });
  it('fails Verify for the encoded personal data', async () => {
    expect(await verifyStatus(input)).toBe('FAIL');
  });
});

describe('re-review 79-4: empty-signature unsecured JWTs', () => {
  const token = [
    ['eyJhbGciOi', 'Jub25lIn0'].join(''),
    ['eyJlbWFpbCI6ImFsaWNl', 'QGV4YW1wbGUuY29tIn0'].join(''),
    '',
  ].join('.');
  it('redacts the trailing dot with the unsecured JWT', async () => {
    expect(await redactNote(token, 'r79none')).toMatch(/^\[JWT_\d+\]$/);
    const scan = getPatternsByNames(['jwtToken'])[0].scan!;
    const signedHeader = Buffer.from('{"alg":"HS256"}').toString('base64url');
    expect(scan([signedHeader, token.split('.')[1], ''].join('.'))).toEqual([]);
    expect(scan('noise.' + token)).toEqual([{ start: 6, end: 6 + token.length }]);
    expect(scan('/reset-' + token)).toEqual([{ start: 7, end: 7 + token.length }]);
  });
  it('fails Verify for the encoded personal data', async () => {
    expect(await verifyStatus(token)).toBe('FAIL');
  });
});

describe('re-review 79-5: numeric personal Session IDs', () => {
  it.each([false, true])('normalizes storage and references with auditLog=%s', async (auditLog) => {
    const input = { note: 'alice@example.com' };
    const [data, report] = await run({
      operation: 'redact', vaultStorage: 'memory', sessionId: 123456789, includeReport: true, auditLog,
    }, [input]);
    expect(data[0].json.note).toMatch(/^\[EMAIL_\d+\]$/);
    expect(report[0].json.sessionId).toMatch(/^session:[a-f0-9]{64}$/);
    expect(JSON.stringify(report)).not.toMatch(/123456789|alice@example\.com/);
    if (auditLog) expect((report[0].json.audit as IDataObject).sessionId).toBe(report[0].json.sessionId);
    const [restored] = await run({ operation: 'restore', vaultStorage: 'memory', sessionId: '123456789' }, [data[0].json]);
    expect(restored[0].json).toEqual(input);
  });
});

describe('re-review 79-6: restoration ignores object property enumeration order', () => {
  it('repairs pseudonyms and restores every key and value in the review input', async () => {
    const input = { EMP90001: '', EMP90000: '', compose: '1EMP35', other: 'EMP14800' };
    const [data] = await run({
      operation: 'redact', sessionId: 'order', vaultStorage: 'memory', redactionMode: 'pseudonymize',
      detectionScope: 'select', piiTypes: [], customPatterns: { patterns: [{ regex: 'EMP[0-9]+', label: 'SALARY' }] },
    }, [input]);
    const [restored] = await run({ operation: 'restore', sessionId: 'order', vaultStorage: 'memory' }, [data[0].json]);
    expect(restored[0].json).toEqual(input);
    // The final guard must still reject changed array order and changed value types after a repair.
    const { vault, ctx } = engineSetup({ mode: 'pseudonymize' });
    const original = { note: 'original', checks: [1, true, '1'] };
    for (const checks of [[true, 1, '1'], [1, true, 1]]) {
      expect(() => ensureRestorable([original], [{ note: 'changed', checks }], ctx, vault, 's'))
        .toThrow(/could not preserve restoration/);
    }
  });
});
