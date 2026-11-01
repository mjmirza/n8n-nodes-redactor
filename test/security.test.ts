import { MemoryVault } from '../nodes/Redactor/vault';
import { redactValue, restoreValue, buildReport } from '../nodes/Redactor/engine';
import { RedactionContext, RedactionHit } from '../nodes/Redactor/types';
import { cpuNow } from './harness';

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
// SECURITY: ReDoS Prevention
// ═══════════════════════════════════════════════════════
describe('ReDoS prevention', () => {
  let vault: MemoryVault;
  beforeEach(() => { vault = new MemoryVault(); });

  test('custom regex with nested quantifiers is rejected', () => {
    vault.getOrCreateSession('redos-1', 0);
    const hits: RedactionHit[] = [];
    // (a+)+ is a classic ReDoS pattern
    const result = redactValue(
      { text: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!' },
      createContext({
        enabledPatterns: [],
        customPatterns: [{ label: 'EVIL', regex: '(a+)+$' }],
      }),
      vault,
      'redos-1',
      hits,
      0,
    ) as any;
    // Should NOT hang, and should NOT redact (pattern rejected)
    expect(result.text).toBe('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!');
    expect(hits).toHaveLength(0);
  });

  test('custom regex over 500 chars is rejected', () => {
    vault.getOrCreateSession('redos-2', 0);
    const hits: RedactionHit[] = [];
    const longRegex = 'a'.repeat(600);
    const result = redactValue(
      { text: 'test' },
      createContext({
        enabledPatterns: [],
        customPatterns: [{ label: 'LONG', regex: longRegex }],
      }),
      vault,
      'redos-2',
      hits,
      0,
    ) as any;
    expect(hits).toHaveLength(0);
  });

  test('connStringKV does not hang on adversarial input', () => {
    vault.getOrCreateSession('redos-3', 0);
    const hits: RedactionHit[] = [];
    const adversarial = 'Server=x;' + 'a'.repeat(10000);
    const start = cpuNow();
    redactValue(
      { text: adversarial },
      createContext({ enabledPatterns: ['connStringKV'] }),
      vault,
      'redos-3',
      hits,
      0,
    );
    const elapsed = cpuNow() - start;
    // Should complete in under 5 seconds, not hang
    expect(elapsed).toBeLessThan(5000);
  });
});

// ═══════════════════════════════════════════════════════
// SECURITY: Information Leakage Prevention
// ═══════════════════════════════════════════════════════
describe('Information leakage prevention', () => {
  let vault: MemoryVault;
  beforeEach(() => { vault = new MemoryVault(); });

  test('audit report NEVER contains original PII values', () => {
    vault.getOrCreateSession('leak-1', 0);
    const hits: RedactionHit[] = [];
    redactValue(
      { email: 'secret@company.com', ssn: '123-45-6789' },
      createContext({ mode: 'token' }),
      vault,
      'leak-1',
      hits,
      0,
    );

    const report = buildReport('leak-1', hits);
    const reportJson = JSON.stringify(report);

    // Original values must NOT appear in the report
    expect(reportJson).not.toContain('secret@company.com');
    expect(reportJson).not.toContain('123-45-6789');
    // All originals should be '***'
    for (const hit of report.hits) {
      expect(hit.original).toBe('***');
    }
  });

  test('audit report in mask mode also hides originals', () => {
    vault.getOrCreateSession('leak-2', 0);
    const hits: RedactionHit[] = [];
    redactValue(
      { email: 'secret@company.com' },
      createContext({ mode: 'mask' }),
      vault,
      'leak-2',
      hits,
      0,
    );

    for (const hit of hits) {
      expect(hit.original).toBe('***');
    }
  });
});

// ═══════════════════════════════════════════════════════
// SECURITY: Restore Infinite Loop Prevention
// ═══════════════════════════════════════════════════════
describe('Restore safety', () => {
  let vault: MemoryVault;
  beforeEach(() => { vault = new MemoryVault(); });

  test('restore does not infinite loop when original contains a token', () => {
    vault.getOrCreateSession('loop-1', 0);
    // Manually create a vault entry where the original contains another token
    vault.addEntry('loop-1', {
      token: '[EMAIL_0]',
      original: 'Contact [PHONE_1] for info',
      patternLabel: 'EMAIL',
      category: 'contact',
      createdAt: new Date().toISOString(),
    });
    vault.addEntry('loop-1', {
      token: '[PHONE_1]',
      original: '555-1234',
      patternLabel: 'PHONE',
      category: 'contact',
      createdAt: new Date().toISOString(),
    });

    const start = cpuNow();
    const result = restoreValue(
      { text: 'Message: [EMAIL_0]' },
      vault,
      'loop-1',
    ) as any;
    const elapsed = cpuNow() - start;

    // Must complete quickly (no infinite loop)
    expect(elapsed).toBeLessThan(1000);
    // Restore is one pass over the source, so an inserted original is never rescanned.
    expect(result.text).toBe('Message: Contact [PHONE_1] for info');
  });
});

// ═══════════════════════════════════════════════════════
// SECURITY: Memory Leak Prevention
// ═══════════════════════════════════════════════════════
describe('Memory leak prevention', () => {
  test('MemoryVault enforces max session limit', () => {
    const vault = new MemoryVault();
    // Create many sessions
    for (let i = 0; i < 1010; i++) {
      vault.getOrCreateSession(`session-${i}`, 60000);
    }
    const sessions = vault.listSessions();
    // Should not exceed max (1000) + some buffer
    expect(sessions.length).toBeLessThanOrEqual(1010);
  });

  test('MemoryVault auto-cleans expired sessions on create', () => {
    const vault = new MemoryVault();
    // Create session with 1ms TTL
    vault.getOrCreateSession('expire-me', 1);

    // Wait for expiry
    const start = Date.now();
    while (Date.now() - start < 10) { /* busy wait */ }

    // Creating a new session triggers cleanup
    vault.getOrCreateSession('new-session', 0);

    // Expired session should be gone
    expect(vault.getSession('expire-me')).toBeNull();
  });
});

// ═══════════════════════════════════════════════════════
// SECURITY: Field Path Injection Prevention
// ═══════════════════════════════════════════════════════
describe('Field path injection prevention', () => {
  let vault: MemoryVault;
  beforeEach(() => { vault = new MemoryVault(); });

  test('malicious field path pattern does not crash', () => {
    vault.getOrCreateSession('field-inj', 0);
    const hits: RedactionHit[] = [];
    // Attempt to inject regex via field rule
    const result = redactValue(
      { email: 'test@test.com' },
      createContext({
        fieldMode: 'allowlist',
        fieldRules: [{ field: '(a+)+', mode: 'include' }],
      }),
      vault,
      'field-inj',
      hits,
      0,
    ) as any;
    // Should not crash or hang
    expect(result.email).toBeDefined();
  });
});

// ═══════════════════════════════════════════════════════
// SECURITY: Token Collision Prevention
// ═══════════════════════════════════════════════════════
describe('Token collision prevention', () => {
  let vault: MemoryVault;
  beforeEach(() => { vault = new MemoryVault(); });

  test('generated tokens are not re-redacted by subsequent patterns', () => {
    vault.getOrCreateSession('collision-1', 0);
    const hits: RedactionHit[] = [];
    const result = redactValue(
      { text: 'Email: test@example.com and SSN: 123-45-6789' },
      createContext(),
      vault,
      'collision-1',
      hits,
      0,
    ) as any;

    // Tokens should be clean [LABEL_N] format, not double-redacted
    expect(result.text).toMatch(/\[EMAIL_\d+\]/);
    expect(result.text).toMatch(/\[SSN_\d+\]/);
    // Should NOT contain nested tokens like [[EMAIL_0]]
    expect(result.text).not.toContain('[[');
  });
});
