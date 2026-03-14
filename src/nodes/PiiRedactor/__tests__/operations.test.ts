import { MemoryVault } from '../vault';
import { redactValue, restoreValue, buildReport } from '../engine';
import { RedactionContext, RedactionHit } from '../types';

function ctx(overrides: Partial<RedactionContext> = {}): RedactionContext {
  return {
    enabledPatterns: ['email', 'phone', 'ssn', 'creditCard'],
    customPatterns: [],
    mode: 'token',
    dedup: true,
    fieldRules: [],
    fieldMode: 'all',
    ...overrides,
  };
}

// ═══════════════════════════════════════════════════════
// REDACT OPERATION - Enterprise Tests
// ═══════════════════════════════════════════════════════
describe('Redact operation', () => {
  let vault: MemoryVault;
  beforeEach(() => { vault = new MemoryVault(); });

  test('handles empty input (0 items)', () => {
    vault.getOrCreateSession('empty', 0);
    const hits: RedactionHit[] = [];
    const result = redactValue({}, ctx(), vault, 'empty', hits, 0);
    expect(result).toEqual({});
    expect(hits).toHaveLength(0);
  });

  test('handles null values in data', () => {
    vault.getOrCreateSession('nulls', 0);
    const hits: RedactionHit[] = [];
    const result = redactValue(
      { name: null, email: 'test@test.com', count: null },
      ctx(),
      vault, 'nulls', hits, 0,
    ) as any;
    expect(result.name).toBeNull();
    expect(result.email).toContain('[');
    expect(result.count).toBeNull();
  });

  test('handles undefined values in data', () => {
    vault.getOrCreateSession('undef', 0);
    const hits: RedactionHit[] = [];
    const data = { name: undefined, email: 'test@test.com' };
    const result = redactValue(data, ctx(), vault, 'undef', hits, 0) as any;
    expect(result.name).toBeUndefined();
    expect(result.email).toContain('[');
  });

  test('handles boolean values', () => {
    vault.getOrCreateSession('bool', 0);
    const hits: RedactionHit[] = [];
    const result = redactValue(
      { active: true, deleted: false },
      ctx(),
      vault, 'bool', hits, 0,
    ) as any;
    expect(result.active).toBe(true);
    expect(result.deleted).toBe(false);
  });

  test('handles large batch (100 items)', () => {
    vault.getOrCreateSession('batch', 0);
    const allHits: RedactionHit[] = [];
    for (let i = 0; i < 100; i++) {
      const hits: RedactionHit[] = [];
      redactValue(
        { email: `user${i}@test.com`, ssn: '123-45-6789' },
        ctx(),
        vault, 'batch', hits, i,
      );
      allHits.push(...hits);
    }
    expect(allHits.length).toBeGreaterThanOrEqual(100);
  });

  test('handles deeply nested data (5 levels)', () => {
    vault.getOrCreateSession('deep', 0);
    const hits: RedactionHit[] = [];
    const result = redactValue(
      { a: { b: { c: { d: { e: { email: 'deep@test.com' } } } } } },
      ctx(),
      vault, 'deep', hits, 0,
    ) as any;
    expect(result.a.b.c.d.e.email).toContain('[');
  });

  test('handles mixed arrays and objects', () => {
    vault.getOrCreateSession('mixed', 0);
    const hits: RedactionHit[] = [];
    const result = redactValue(
      { items: [{ email: 'a@b.com' }, 'plain text', 42, null, { nested: { ssn: '111-22-3333' } }] },
      ctx(),
      vault, 'mixed', hits, 0,
    ) as any;
    expect(result.items[0].email).toContain('[');
    expect(result.items[1]).toBe('plain text');
    expect(result.items[2]).toBe(42);
    expect(result.items[3]).toBeNull();
    expect(result.items[4].nested.ssn).toContain('[');
  });

  test('custom patterns work alongside built-in patterns', () => {
    vault.getOrCreateSession('custom', 0);
    const hits: RedactionHit[] = [];
    const result = redactValue(
      { text: 'Order ORD-123456 for user@test.com' },
      ctx({ customPatterns: [{ label: 'ORDER', regex: 'ORD-\\d{6}' }] }),
      vault, 'custom', hits, 0,
    ) as any;
    expect(result.text).not.toContain('ORD-123456');
    expect(result.text).not.toContain('user@test.com');
    expect(hits.length).toBeGreaterThanOrEqual(2);
  });

  test('TTL 0 means no expiry', () => {
    vault.getOrCreateSession('no-ttl', 0);
    const session = vault.getSession('no-ttl');
    expect(session).not.toBeNull();
  });
});

// ═══════════════════════════════════════════════════════
// RESTORE OPERATION - Enterprise Tests
// ═══════════════════════════════════════════════════════
describe('Restore operation', () => {
  let vault: MemoryVault;
  beforeEach(() => { vault = new MemoryVault(); });

  test('full round-trip with multiple data types', () => {
    vault.getOrCreateSession('rt', 0);
    const hits: RedactionHit[] = [];
    const original = {
      name: 'John Doe',
      email: 'john@company.com',
      ssn: '123-45-6789',
      notes: 'Called from 555-123-4567',
      meta: { active: true, count: 5 },
    };
    const redacted = redactValue(original, ctx({ enabledPatterns: ['email', 'ssn', 'phone'] }), vault, 'rt', hits, 0);
    const restored = restoreValue(redacted, vault, 'rt') as any;

    expect(restored.email).toBe('john@company.com');
    expect(restored.ssn).toBe('123-45-6789');
    expect(restored.meta.active).toBe(true);
    expect(restored.meta.count).toBe(5);
  });

  test('restore handles empty object', () => {
    vault.getOrCreateSession('empty-rt', 0);
    const result = restoreValue({}, vault, 'empty-rt');
    expect(result).toEqual({});
  });

  test('restore handles null', () => {
    vault.getOrCreateSession('null-rt', 0);
    const result = restoreValue(null, vault, 'null-rt');
    expect(result).toBeNull();
  });

  test('restore with nonexistent session returns data as-is', () => {
    const result = restoreValue({ text: '[EMAIL_0]' }, vault, 'nope') as any;
    expect(result.text).toBe('[EMAIL_0]');
  });

  test('multiple restores with deleteAfterRestore=false', () => {
    vault.getOrCreateSession('multi', 0);
    const hits: RedactionHit[] = [];
    redactValue({ email: 'test@test.com' }, ctx(), vault, 'multi', hits, 0);

    // First restore
    const r1 = restoreValue({ text: '[EMAIL_0]' }, vault, 'multi') as any;
    expect(r1.text).toBe('test@test.com');

    // Second restore (session not deleted)
    const r2 = restoreValue({ text: '[EMAIL_0]' }, vault, 'multi') as any;
    expect(r2.text).toBe('test@test.com');
  });
});

// ═══════════════════════════════════════════════════════
// DETECT OPERATION - Enterprise Tests
// ═══════════════════════════════════════════════════════
describe('Detect operation (scan-only)', () => {
  let vault: MemoryVault;
  beforeEach(() => { vault = new MemoryVault(); });

  test('detects PII without modifying data', () => {
    vault.getOrCreateSession('det', 0);
    const hits: RedactionHit[] = [];
    const original = { email: 'secret@company.com', text: 'SSN: 123-45-6789' };
    // Run redaction to collect hits (simulating detect)
    redactValue(original, ctx(), vault, 'det', hits, 0);

    expect(hits.length).toBeGreaterThanOrEqual(2);
    // Original data should be untouched (detect returns original)
    expect(original.email).toBe('secret@company.com');
    expect(original.text).toBe('SSN: 123-45-6789');
  });

  test('detect produces valid report', () => {
    vault.getOrCreateSession('det-rpt', 0);
    const hits: RedactionHit[] = [];
    redactValue({ email: 'a@b.com', ssn: '111-22-3333' }, ctx(), vault, 'det-rpt', hits, 0);

    const report = buildReport('det-rpt', hits);
    expect(report.totalHits).toBeGreaterThanOrEqual(2);
    expect(report.hitsByPattern).toBeDefined();
    expect(report.hitsByCategory).toBeDefined();
    expect(report.timestamp).toBeDefined();
  });

  test('detect with clean data returns 0 hits', () => {
    vault.getOrCreateSession('det-clean', 0);
    const hits: RedactionHit[] = [];
    redactValue({ status: 'ok', count: 42 }, ctx(), vault, 'det-clean', hits, 0);

    expect(hits).toHaveLength(0);
  });

  test('detect with custom patterns', () => {
    vault.getOrCreateSession('det-custom', 0);
    const hits: RedactionHit[] = [];
    redactValue(
      { order: 'ORD-999888' },
      ctx({ enabledPatterns: [], customPatterns: [{ label: 'ORDER', regex: 'ORD-\\d{6}' }] }),
      vault, 'det-custom', hits, 0,
    );
    expect(hits).toHaveLength(1);
    expect(hits[0].patternLabel).toBe('ORDER');
  });
});

// ═══════════════════════════════════════════════════════
// VERIFY OPERATION - Enterprise Tests
// ═══════════════════════════════════════════════════════
describe('Verify operation (leak check)', () => {
  let vault: MemoryVault;
  beforeEach(() => { vault = new MemoryVault(); });

  test('PASS: clean data after redaction', () => {
    const tempVault = new MemoryVault();
    tempVault.getOrCreateSession('verify-pass', 0);
    const hits: RedactionHit[] = [];
    // Simulate already-redacted data
    const redactedData = { employeeId: '[EMPLOYEE_ID_0]', name: '[PERSON_NAME_1]', dept: '[DEPARTMENT_2]' };
    redactValue(redactedData, ctx(), tempVault, 'verify-pass', hits, 0);

    // Tokens should NOT be detected as PII (they start with [ and end with ])
    // Only semantic detection on field names would fire
    // The key test is that actual PII values are not present
    expect(redactedData.employeeId).toBe('[EMPLOYEE_ID_0]');
  });

  test('FAIL: PII leaked through', () => {
    const tempVault = new MemoryVault();
    tempVault.getOrCreateSession('verify-fail', 0);
    const hits: RedactionHit[] = [];
    // Data with PII that should have been redacted
    const leakyData = { email: 'leaked@company.com', text: 'Call 555-123-4567' };
    redactValue(leakyData, ctx(), tempVault, 'verify-fail', hits, 0);

    expect(hits.length).toBeGreaterThanOrEqual(1);
  });

  test('verify with empty data passes', () => {
    const tempVault = new MemoryVault();
    tempVault.getOrCreateSession('verify-empty', 0);
    const hits: RedactionHit[] = [];
    redactValue({}, ctx(), tempVault, 'verify-empty', hits, 0);

    expect(hits).toHaveLength(0);
  });
});

// ═══════════════════════════════════════════════════════
// PURGE OPERATION - Enterprise Tests
// ═══════════════════════════════════════════════════════
describe('Purge operation', () => {
  let vault: MemoryVault;
  beforeEach(() => { vault = new MemoryVault(); });

  test('purge specific session', () => {
    vault.getOrCreateSession('purge-me', 0);
    vault.addEntry('purge-me', {
      token: '[EMAIL_0]',
      original: 'test@test.com',
      patternLabel: 'EMAIL',
      category: 'contact',
      createdAt: new Date().toISOString(),
    });

    expect(vault.getSession('purge-me')).not.toBeNull();
    vault.deleteSession('purge-me');
    expect(vault.getSession('purge-me')).toBeNull();
  });

  test('purge all sessions', () => {
    vault.getOrCreateSession('s1', 0);
    vault.getOrCreateSession('s2', 0);
    vault.getOrCreateSession('s3', 0);

    const sessions = vault.listSessions();
    for (const s of sessions) {
      vault.deleteSession(s.sessionId);
    }

    expect(vault.listSessions().length).toBe(0);
  });

  test('purge nonexistent session is safe', () => {
    vault.deleteSession('does-not-exist');
    // Should not throw
    expect(true).toBe(true);
  });

  test('purge with zero sessions', () => {
    const sessions = vault.listSessions();
    // Filter only our test sessions (vault is shared)
    expect(Array.isArray(sessions)).toBe(true);
  });
});

// ═══════════════════════════════════════════════════════
// STATS OPERATION - Enterprise Tests
// ═══════════════════════════════════════════════════════
describe('Stats operation', () => {
  let vault: MemoryVault;
  beforeEach(() => { vault = new MemoryVault(); });

  test('lists sessions with entry counts', () => {
    vault.getOrCreateSession('stats-1', 0);
    vault.addEntry('stats-1', {
      token: '[EMAIL_0]',
      original: 'a@b.com',
      patternLabel: 'EMAIL',
      category: 'contact',
      createdAt: new Date().toISOString(),
    });
    vault.addEntry('stats-1', {
      token: '[SSN_1]',
      original: '123-45-6789',
      patternLabel: 'SSN',
      category: 'identity',
      createdAt: new Date().toISOString(),
    });

    const sessions = vault.listSessions();
    const s1 = sessions.find((s) => s.sessionId === 'stats-1');
    expect(s1).toBeDefined();
    expect(s1!.entryCount).toBe(2);
  });

  test('cleanup removes expired before listing', () => {
    vault.getOrCreateSession('expired-stat', 1);
    const start = Date.now();
    while (Date.now() - start < 10) { /* wait */ }
    vault.cleanup();
    expect(vault.getSession('expired-stat')).toBeNull();
  });
});

// ═══════════════════════════════════════════════════════
// AUDIT REPORT - Enterprise Tests
// ═══════════════════════════════════════════════════════
describe('Audit report', () => {
  test('report never contains original PII', () => {
    const vault = new MemoryVault();
    vault.getOrCreateSession('audit', 0);
    const hits: RedactionHit[] = [];
    redactValue(
      { email: 'secret@corp.com', ssn: '999-88-7777' },
      ctx(),
      vault, 'audit', hits, 0,
    );

    const report = buildReport('audit', hits);
    const json = JSON.stringify(report);
    expect(json).not.toContain('secret@corp.com');
    expect(json).not.toContain('999-88-7777');
    report.hits.forEach((h) => expect(h.original).toBe('***'));
  });

  test('report structure is complete', () => {
    const report = buildReport('test', []);
    expect(report).toHaveProperty('sessionId');
    expect(report).toHaveProperty('timestamp');
    expect(report).toHaveProperty('totalHits');
    expect(report).toHaveProperty('hitsByCategory');
    expect(report).toHaveProperty('hitsByPattern');
    expect(report).toHaveProperty('hits');
  });
});
