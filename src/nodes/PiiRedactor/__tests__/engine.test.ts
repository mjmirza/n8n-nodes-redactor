import { MemoryVault } from '../vault';
import { redactValue, restoreValue, buildReport } from '../engine';
import { RedactionContext, RedactionHit } from '../types';

function createContext(overrides: Partial<RedactionContext> = {}): RedactionContext {
  return {
    enabledPatterns: ['email', 'phone', 'personName', 'ssn', 'creditCard', 'iban', 'ipv4'],
    customPatterns: [],
    mode: 'token',
    dedup: true,
    fieldRules: [],
    fieldMode: 'all',
    ...overrides,
  };
}

// ═══════════════════════════════════════════════════════
// BASIC REDACTION
// ═══════════════════════════════════════════════════════
describe('Redaction engine — basic', () => {
  let vault: MemoryVault;

  beforeEach(() => {
    vault = new MemoryVault();
  });

  test('redacts email in simple string field', () => {
    vault.getOrCreateSession('s1', 0);
    const hits: RedactionHit[] = [];
    const result = redactValue(
      { message: 'Contact me at john@example.com' },
      createContext(),
      vault,
      's1',
      hits,
      0,
    ) as Record<string, unknown>;

    expect(result.message).toBe('Contact me at [EMAIL_0]');
    expect(hits).toHaveLength(1);
    expect(hits[0].patternLabel).toBe('EMAIL');
    expect(hits[0].original).toBe('***'); // SECURITY: originals never exposed in reports
  });

  test('redacts multiple PII types in one field', () => {
    vault.getOrCreateSession('s2', 0);
    const hits: RedactionHit[] = [];
    const result = redactValue(
      { info: 'Mr. John Smith, email: john@test.com, SSN: 123-45-6789' },
      createContext(),
      vault,
      's2',
      hits,
      0,
    ) as Record<string, unknown>;

    expect(result.info).not.toContain('john@test.com');
    expect(result.info).not.toContain('123-45-6789');
    expect(result.info).not.toContain('Mr. John Smith');
    expect(hits.length).toBeGreaterThanOrEqual(3);
  });

  test('redacts nested JSON objects', () => {
    vault.getOrCreateSession('s3', 0);
    const hits: RedactionHit[] = [];
    const data = {
      user: {
        profile: {
          email: 'deep@nested.com',
          phone: '+49 30 1234-5678',
        },
      },
    };
    const result = redactValue(data, createContext(), vault, 's3', hits, 0) as any;

    expect(result.user.profile.email).toContain('[EMAIL_');
    expect(result.user.profile.phone).toContain('[PHONE_');
    expect(hits).toHaveLength(2);
  });

  test('redacts arrays', () => {
    vault.getOrCreateSession('s4', 0);
    const hits: RedactionHit[] = [];
    const data = {
      emails: ['alice@foo.com', 'bob@bar.com'],
    };
    const result = redactValue(data, createContext(), vault, 's4', hits, 0) as any;

    expect(result.emails[0]).toContain('[EMAIL_');
    expect(result.emails[1]).toContain('[EMAIL_');
    expect(hits).toHaveLength(2);
  });

  test('preserves non-string values', () => {
    vault.getOrCreateSession('s5', 0);
    const hits: RedactionHit[] = [];
    const data = {
      count: 42,
      active: true,
      tags: null,
      score: 3.14,
    };
    const result = redactValue(data, createContext(), vault, 's5', hits, 0) as any;

    expect(result.count).toBe(42);
    expect(result.active).toBe(true);
    expect(result.tags).toBeNull();
    expect(result.score).toBe(3.14);
    expect(hits).toHaveLength(0);
  });

  test('handles empty strings', () => {
    vault.getOrCreateSession('s6', 0);
    const hits: RedactionHit[] = [];
    const result = redactValue({ field: '' }, createContext(), vault, 's6', hits, 0) as any;
    expect(result.field).toBe('');
    expect(hits).toHaveLength(0);
  });

  test('handles deeply nested arrays of objects', () => {
    vault.getOrCreateSession('s7', 0);
    const hits: RedactionHit[] = [];
    const data = {
      contacts: [
        { name: 'Mr. Alice Smith', email: 'alice@test.com' },
        { name: 'Dr. Bob Jones', email: 'bob@test.com' },
      ],
    };
    const result = redactValue(data, createContext(), vault, 's7', hits, 0) as any;

    expect(result.contacts[0].email).toContain('[EMAIL_');
    expect(result.contacts[1].email).toContain('[EMAIL_');
    expect(result.contacts[0].name).toContain('[PERSON_');
    expect(hits.length).toBeGreaterThanOrEqual(4);
  });
});

// ═══════════════════════════════════════════════════════
// DEDUPLICATION
// ═══════════════════════════════════════════════════════
describe('Deduplication', () => {
  let vault: MemoryVault;

  beforeEach(() => {
    vault = new MemoryVault();
  });

  test('same email gets same token when dedup=true', () => {
    vault.getOrCreateSession('dedup-1', 0);
    const hits: RedactionHit[] = [];
    const data = {
      primary: 'Contact: same@email.com',
      secondary: 'Also: same@email.com',
    };
    const result = redactValue(data, createContext({ dedup: true }), vault, 'dedup-1', hits, 0) as any;

    // Both fields should have the SAME token
    const token1 = result.primary.match(/\[EMAIL_\d+\]/)?.[0];
    const token2 = result.secondary.match(/\[EMAIL_\d+\]/)?.[0];
    expect(token1).toBe(token2);
  });

  test('same email gets different tokens when dedup=false', () => {
    vault.getOrCreateSession('dedup-2', 0);
    const hits: RedactionHit[] = [];
    const data = {
      primary: 'Contact: same@email.com',
      secondary: 'Also: same@email.com',
    };
    const result = redactValue(data, createContext({ dedup: false }), vault, 'dedup-2', hits, 0) as any;

    const token1 = result.primary.match(/\[EMAIL_\d+\]/)?.[0];
    const token2 = result.secondary.match(/\[EMAIL_\d+\]/)?.[0];
    expect(token1).not.toBe(token2);
  });
});

// ═══════════════════════════════════════════════════════
// REDACTION MODES
// ═══════════════════════════════════════════════════════
describe('Redaction modes', () => {
  let vault: MemoryVault;

  beforeEach(() => {
    vault = new MemoryVault();
  });

  test('token mode produces [LABEL_N] format', () => {
    vault.getOrCreateSession('mode-token', 0);
    const hits: RedactionHit[] = [];
    const result = redactValue(
      { email: 'test@example.com' },
      createContext({ mode: 'token' }),
      vault,
      'mode-token',
      hits,
      0,
    ) as any;

    expect(result.email).toMatch(/^\[EMAIL_\d+\]$/);
  });

  test('mask mode partially hides email', () => {
    vault.getOrCreateSession('mode-mask', 0);
    const hits: RedactionHit[] = [];
    const result = redactValue(
      { email: 'john@example.com' },
      createContext({ mode: 'mask' }),
      vault,
      'mode-mask',
      hits,
      0,
    ) as any;

    expect(result.email).toContain('***');
    expect(result.email).toContain('@');
    expect(result.email).not.toBe('john@example.com');
  });

  test('hash mode produces [LABEL:hash] format', () => {
    vault.getOrCreateSession('mode-hash', 0);
    const hits: RedactionHit[] = [];
    const result = redactValue(
      { email: 'test@example.com' },
      createContext({ mode: 'hash' }),
      vault,
      'mode-hash',
      hits,
      0,
    ) as any;

    expect(result.email).toMatch(/^\[EMAIL:[a-f0-9]{12}\]$/);
  });

  test('hash mode is deterministic', () => {
    vault.getOrCreateSession('mode-hash-det', 0);
    const hits1: RedactionHit[] = [];
    const hits2: RedactionHit[] = [];
    const r1 = redactValue(
      { email: 'test@example.com' },
      createContext({ mode: 'hash' }),
      vault,
      'mode-hash-det',
      hits1,
      0,
    ) as any;
    const r2 = redactValue(
      { email: 'test@example.com' },
      createContext({ mode: 'hash' }),
      vault,
      'mode-hash-det',
      hits2,
      0,
    ) as any;

    expect(r1.email).toBe(r2.email);
  });

  test('redact mode produces [REDACTED]', () => {
    vault.getOrCreateSession('mode-redact', 0);
    const hits: RedactionHit[] = [];
    const result = redactValue(
      { email: 'test@example.com' },
      createContext({ mode: 'redact' }),
      vault,
      'mode-redact',
      hits,
      0,
    ) as any;

    expect(result.email).toContain('[REDACTED]');
  });

  test('mask mode for credit card shows last 4', () => {
    vault.getOrCreateSession('mode-mask-cc', 0);
    const hits: RedactionHit[] = [];
    const result = redactValue(
      { card: '4532 0151 1283 0366' },
      createContext({ mode: 'mask', enabledPatterns: ['creditCard'] }),
      vault,
      'mode-mask-cc',
      hits,
      0,
    ) as any;

    expect(result.card).toContain('0366');
    expect(result.card).toContain('****');
  });
});

// ═══════════════════════════════════════════════════════
// FIELD TARGETING
// ═══════════════════════════════════════════════════════
describe('Field targeting', () => {
  let vault: MemoryVault;

  beforeEach(() => {
    vault = new MemoryVault();
  });

  test('allowlist — only scans specified fields', () => {
    vault.getOrCreateSession('field-allow', 0);
    const hits: RedactionHit[] = [];
    const data = {
      email: 'scan@me.com',
      notes: 'skip@me.com',
    };
    const result = redactValue(
      data,
      createContext({
        fieldMode: 'allowlist',
        fieldRules: [{ field: 'email', mode: 'include' }],
      }),
      vault,
      'field-allow',
      hits,
      0,
    ) as any;

    expect(result.email).toContain('[EMAIL_');
    expect(result.notes).toBe('skip@me.com'); // Not redacted
  });

  test('denylist — skips specified fields', () => {
    vault.getOrCreateSession('field-deny', 0);
    const hits: RedactionHit[] = [];
    const data = {
      email: 'scan@me.com',
      internalId: 'skip@me.com',
    };
    const result = redactValue(
      data,
      createContext({
        fieldMode: 'denylist',
        fieldRules: [{ field: 'internalId', mode: 'exclude' }],
      }),
      vault,
      'field-deny',
      hits,
      0,
    ) as any;

    expect(result.email).toContain('[EMAIL_');
    expect(result.internalId).toBe('skip@me.com');
  });

  test('wildcard field matching with *.field', () => {
    vault.getOrCreateSession('field-wild', 0);
    const hits: RedactionHit[] = [];
    const data = {
      user: { email: 'user@test.com' },
      admin: { email: 'admin@test.com' },
    };
    const result = redactValue(
      data,
      createContext({
        fieldMode: 'allowlist',
        fieldRules: [{ field: '*.email', mode: 'include' }],
      }),
      vault,
      'field-wild',
      hits,
      0,
    ) as any;

    expect(result.user.email).toContain('[EMAIL_');
    expect(result.admin.email).toContain('[EMAIL_');
  });

  test('all mode scans everything', () => {
    vault.getOrCreateSession('field-all', 0);
    const hits: RedactionHit[] = [];
    const data = {
      a: 'a@test.com',
      b: { c: 'b@test.com' },
    };
    const result = redactValue(
      data,
      createContext({ fieldMode: 'all' }),
      vault,
      'field-all',
      hits,
      0,
    ) as any;

    expect(result.a).toContain('[EMAIL_');
    expect(result.b.c).toContain('[EMAIL_');
  });
});

// ═══════════════════════════════════════════════════════
// CUSTOM PATTERNS
// ═══════════════════════════════════════════════════════
describe('Custom patterns', () => {
  let vault: MemoryVault;

  beforeEach(() => {
    vault = new MemoryVault();
  });

  test('matches custom regex pattern', () => {
    vault.getOrCreateSession('custom-1', 0);
    const hits: RedactionHit[] = [];
    const result = redactValue(
      { order: 'Your order ORD-123456 is confirmed' },
      createContext({
        enabledPatterns: [],
        customPatterns: [{ label: 'ORDER_ID', regex: 'ORD-\\d{6}' }],
      }),
      vault,
      'custom-1',
      hits,
      0,
    ) as any;

    expect(result.order).toContain('[ORDER_ID_');
    expect(result.order).not.toContain('ORD-123456');
    expect(hits).toHaveLength(1);
  });

  test('skips invalid regex gracefully', () => {
    vault.getOrCreateSession('custom-bad', 0);
    const hits: RedactionHit[] = [];
    const result = redactValue(
      { text: 'hello world' },
      createContext({
        enabledPatterns: [],
        customPatterns: [{ label: 'BAD', regex: '[invalid(' }],
      }),
      vault,
      'custom-bad',
      hits,
      0,
    ) as any;

    // Should not crash
    expect(result.text).toBe('hello world');
    expect(hits).toHaveLength(0);
  });

  test('custom pattern with category', () => {
    vault.getOrCreateSession('custom-cat', 0);
    const hits: RedactionHit[] = [];
    redactValue(
      { ticket: 'TICKET-999' },
      createContext({
        enabledPatterns: [],
        customPatterns: [{ label: 'TICKET', regex: 'TICKET-\\d+', category: 'identity' }],
      }),
      vault,
      'custom-cat',
      hits,
      0,
    );

    expect(hits[0].category).toBe('identity');
  });
});

// ═══════════════════════════════════════════════════════
// RESTORE
// ═══════════════════════════════════════════════════════
describe('Restore engine', () => {
  let vault: MemoryVault;

  beforeEach(() => {
    vault = new MemoryVault();
  });

  test('full round-trip: redact then restore', () => {
    vault.getOrCreateSession('rt-1', 0);
    const original = {
      message: 'Contact Mr. John Smith at john@example.com or 555-123-4567',
      meta: { ssn: '123-45-6789' },
    };

    const hits: RedactionHit[] = [];
    const redacted = redactValue(original, createContext(), vault, 'rt-1', hits, 0);

    // Verify redaction happened
    expect(JSON.stringify(redacted)).not.toContain('john@example.com');
    expect(JSON.stringify(redacted)).not.toContain('123-45-6789');

    // Restore
    const restored = restoreValue(redacted, vault, 'rt-1') as any;
    expect(restored.message).toContain('john@example.com');
    expect(restored.meta.ssn).toBe('123-45-6789');
  });

  test('restore handles arrays', () => {
    vault.getOrCreateSession('rt-arr', 0);
    const original = { emails: ['alice@test.com', 'bob@test.com'] };
    const hits: RedactionHit[] = [];
    const redacted = redactValue(original, createContext(), vault, 'rt-arr', hits, 0);
    const restored = restoreValue(redacted, vault, 'rt-arr') as any;

    expect(restored.emails).toContain('alice@test.com');
    expect(restored.emails).toContain('bob@test.com');
  });

  test('restore preserves non-string values', () => {
    vault.getOrCreateSession('rt-nonstr', 0);
    const data = { count: 42, active: true };
    const restored = restoreValue(data, vault, 'rt-nonstr') as any;
    expect(restored.count).toBe(42);
    expect(restored.active).toBe(true);
  });

  test('restore returns data as-is if session missing', () => {
    const data = { message: 'no session here [EMAIL_0]' };
    const result = restoreValue(data, vault, 'nonexistent') as any;
    expect(result.message).toBe('no session here [EMAIL_0]');
  });

  test('restore works when LLM rephrases around tokens', () => {
    vault.getOrCreateSession('rt-llm', 0);
    const original = { text: 'Email me at alice@company.com' };
    const hits: RedactionHit[] = [];
    redactValue(original, createContext(), vault, 'rt-llm', hits, 0);

    // Simulate LLM response that uses the token in a different sentence
    const llmResponse = { text: 'I will send the report to [EMAIL_0] by tomorrow.' };
    const restored = restoreValue(llmResponse, vault, 'rt-llm') as any;
    expect(restored.text).toBe('I will send the report to alice@company.com by tomorrow.');
  });

  test('restore handles multiple tokens in one field', () => {
    vault.getOrCreateSession('rt-multi', 0);
    const original = { text: 'From alice@a.com to bob@b.com' };
    const hits: RedactionHit[] = [];
    redactValue(original, createContext(), vault, 'rt-multi', hits, 0);

    // Simulate LLM using both tokens
    const session = vault.getSession('rt-multi')!;
    const tokens = Object.keys(session.entries);
    const llmResponse = { text: `Forwarded from ${tokens[0]} to ${tokens[1]}` };
    const restored = restoreValue(llmResponse, vault, 'rt-multi') as any;

    expect(restored.text).toContain('alice@a.com');
    expect(restored.text).toContain('bob@b.com');
  });

  test('restore with deduplication — same token appears twice', () => {
    vault.getOrCreateSession('rt-dedup', 0);
    const original = {
      field1: 'Contact: same@email.com',
      field2: 'CC: same@email.com',
    };
    const hits: RedactionHit[] = [];
    const redacted = redactValue(original, createContext({ dedup: true }), vault, 'rt-dedup', hits, 0) as any;

    // Both should have same token
    const token = redacted.field1.match(/\[EMAIL_\d+\]/)[0];

    // LLM uses the token once
    const llmResponse = { reply: `I sent it to ${token}` };
    const restored = restoreValue(llmResponse, vault, 'rt-dedup') as any;
    expect(restored.reply).toBe('I sent it to same@email.com');
  });
});

// ═══════════════════════════════════════════════════════
// AUDIT REPORT
// ═══════════════════════════════════════════════════════
describe('Audit report', () => {
  test('buildReport creates accurate summary', () => {
    const hits: RedactionHit[] = [
      { token: '[EMAIL_0]', original: 'a@b.com', patternName: 'email', patternLabel: 'EMAIL', category: 'contact', field: 'email', itemIndex: 0, confidence: 0.90 },
      { token: '[PHONE_1]', original: '555-1234', patternName: 'phone', patternLabel: 'PHONE', category: 'contact', field: 'phone', itemIndex: 0, confidence: 0.70 },
      { token: '[SSN_2]', original: '123-45-6789', patternName: 'ssn', patternLabel: 'SSN', category: 'identity', field: 'ssn', itemIndex: 0, confidence: 0.85 },
      { token: '[EMAIL_3]', original: 'c@d.com', patternName: 'email', patternLabel: 'EMAIL', category: 'contact', field: 'email2', itemIndex: 1, confidence: 0.90 },
    ];

    const report = buildReport('test-session', hits);

    expect(report.sessionId).toBe('test-session');
    expect(report.totalHits).toBe(4);
    expect(report.hitsByCategory.contact).toBe(3);
    expect(report.hitsByCategory.identity).toBe(1);
    expect(report.hitsByPattern.EMAIL).toBe(2);
    expect(report.hitsByPattern.PHONE).toBe(1);
    expect(report.hitsByPattern.SSN).toBe(1);
    expect(report.hits).toHaveLength(4);
    expect(report.timestamp).toBeDefined();
  });

  test('buildReport handles empty hits', () => {
    const report = buildReport('empty', []);
    expect(report.totalHits).toBe(0);
    expect(report.hits).toHaveLength(0);
    expect(report.hitsByCategory).toEqual({});
    expect(report.hitsByPattern).toEqual({});
  });
});

// ═══════════════════════════════════════════════════════
// EDGE CASES & STRESS TESTS
// ═══════════════════════════════════════════════════════
describe('Edge cases', () => {
  let vault: MemoryVault;

  beforeEach(() => {
    vault = new MemoryVault();
  });

  test('does not re-redact already-tokenized text', () => {
    vault.getOrCreateSession('no-re-redact', 0);
    const hits: RedactionHit[] = [];
    const data = { text: 'This is [EMAIL_0] already tokenized' };
    const result = redactValue(data, createContext(), vault, 'no-re-redact', hits, 0) as any;

    expect(result.text).toBe('This is [EMAIL_0] already tokenized');
  });

  test('handles long strings', () => {
    vault.getOrCreateSession('long-str', 0);
    const hits: RedactionHit[] = [];
    const longText = 'x'.repeat(5000) + ' john@test.com ' + 'y'.repeat(5000);
    const result = redactValue({ text: longText }, createContext(), vault, 'long-str', hits, 0) as any;

    expect(result.text).toContain('[EMAIL_');
    expect(result.text).not.toContain('john@test.com');
    expect(hits).toHaveLength(1);
  });

  test('handles data with many PII items', () => {
    vault.getOrCreateSession('many-pii', 0);
    const hits: RedactionHit[] = [];
    const emails: Record<string, string> = {};
    for (let i = 0; i < 100; i++) {
      emails[`email_${i}`] = `user${i}@domain${i}.com`;
    }
    const result = redactValue(emails, createContext(), vault, 'many-pii', hits, 0) as any;

    expect(hits).toHaveLength(100);
    for (let i = 0; i < 100; i++) {
      expect(result[`email_${i}`]).toContain('[EMAIL_');
    }
  });

  test('handles Unicode/emoji in surrounding text', () => {
    vault.getOrCreateSession('unicode', 0);
    const hits: RedactionHit[] = [];
    const data = { text: 'Send to test@example.com please' };
    const result = redactValue(data, createContext(), vault, 'unicode', hits, 0) as any;

    expect(result.text).toContain('[EMAIL_');
    expect(result.text).not.toContain('test@example.com');
  });

  test('mixed PII in one sentence — all detected', () => {
    vault.getOrCreateSession('mixed', 0);
    const hits: RedactionHit[] = [];
    const data = {
      text: 'Mr. John Doe, SSN 123-45-6789, email john@test.com, IP 192.168.1.100',
    };
    const result = redactValue(
      data,
      createContext({ enabledPatterns: ['personName', 'ssn', 'email', 'ipv4'] }),
      vault,
      'mixed',
      hits,
      0,
    ) as any;

    expect(result.text).not.toContain('Mr. John Doe');
    expect(result.text).not.toContain('123-45-6789');
    expect(result.text).not.toContain('john@test.com');
    expect(result.text).not.toContain('192.168.1.100');
    expect(hits.length).toBeGreaterThanOrEqual(4);
  });

  test('empty object returns empty object', () => {
    vault.getOrCreateSession('empty-obj', 0);
    const hits: RedactionHit[] = [];
    const result = redactValue({}, createContext(), vault, 'empty-obj', hits, 0);
    expect(result).toEqual({});
    expect(hits).toHaveLength(0);
  });

  test('null values are preserved', () => {
    vault.getOrCreateSession('null-val', 0);
    const hits: RedactionHit[] = [];
    const result = redactValue(null, createContext(), vault, 'null-val', hits, 0);
    expect(result).toBeNull();
  });

  test('credit card Luhn validation prevents false positives', () => {
    vault.getOrCreateSession('luhn-fp', 0);
    const hits: RedactionHit[] = [];
    // 1234567890123456 fails Luhn — should NOT be redacted
    const result = redactValue(
      { text: 'Code: 1234 5678 9012 3456' },
      createContext({ enabledPatterns: ['creditCard'] }),
      vault,
      'luhn-fp',
      hits,
      0,
    ) as any;

    expect(hits).toHaveLength(0);
    expect(result.text).toBe('Code: 1234 5678 9012 3456');
  });

  test('IBAN checksum validation prevents false positives', () => {
    vault.getOrCreateSession('iban-fp', 0);
    const hits: RedactionHit[] = [];
    // DE00... is an invalid checksum
    const result = redactValue(
      { text: 'IBAN: DE00370400440532013000' },
      createContext({ enabledPatterns: ['iban'] }),
      vault,
      'iban-fp',
      hits,
      0,
    ) as any;

    expect(hits).toHaveLength(0);
  });

  test('full lifecycle with file-like data structure', () => {
    vault.getOrCreateSession('lifecycle', 0);
    const hits: RedactionHit[] = [];
    const customerTicket = {
      id: 'TICKET-001',
      customer: {
        name: 'Mrs. Sarah Johnson',
        email: 'sarah.johnson@bigcorp.com',
        phone: '+1-555-987-6543',
        address: {
          street: '123 Main St',
          zip: '90210',
        },
      },
      issue: 'Customer Mrs. Sarah Johnson reported billing error. SSN on file: 987-65-4321. Card ending 0366.',
      internal: {
        agentNotes: 'Called back at +1-555-987-6543, confirmed identity via SSN 987-65-4321.',
      },
    };

    const redacted = redactValue(
      customerTicket,
      createContext({ enabledPatterns: ['email', 'phone', 'personName', 'ssn'] }),
      vault,
      'lifecycle',
      hits,
      0,
    ) as any;

    // Verify redaction
    const json = JSON.stringify(redacted);
    expect(json).not.toContain('sarah.johnson@bigcorp.com');
    expect(json).not.toContain('987-65-4321');
    expect(json).not.toContain('Mrs. Sarah Johnson');

    // Verify restore
    const restored = restoreValue(redacted, vault, 'lifecycle') as any;
    expect(restored.customer.email).toBe('sarah.johnson@bigcorp.com');
    expect(restored.internal.agentNotes).toContain('987-65-4321');
  });
});
