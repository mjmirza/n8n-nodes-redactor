import { MemoryVault } from '../vault';
import { redactValue, restoreValue } from '../engine';
import { RedactionContext, RedactionHit } from '../types';
import { calculateConfidence, hasContextWords, CONTEXT_WORDS } from '../context';
import { detectNamesInText, FIRST_NAMES, LAST_NAMES } from '../names';

function ctx(overrides: Partial<RedactionContext> = {}): RedactionContext {
  return {
    enabledPatterns: ['email', 'phone', 'ssn', 'creditCard', 'iban'],
    customPatterns: [],
    mode: 'token',
    dedup: true,
    fieldRules: [],
    fieldMode: 'all',
    ...overrides,
  };
}

// ═══════════════════════════════════════════════════════
// 1.1 ALLOW LIST TESTS
// ═══════════════════════════════════════════════════════
describe('Allow List', () => {
  let vault: MemoryVault;
  beforeEach(() => { vault = new MemoryVault(); });

  test('exact match: bypass specific email', () => {
    vault.getOrCreateSession('al1', 0);
    const hits: RedactionHit[] = [];
    const result = redactValue(
      { text: 'Contact support@mycompany.com or john@gmail.com' },
      ctx({ allowList: [{ value: 'support@mycompany.com', type: 'exact' }] }),
      vault, 'al1', hits, 0,
    ) as any;
    expect(result.text).toContain('support@mycompany.com'); // NOT redacted
    expect(result.text).not.toContain('john@gmail.com'); // redacted
  });

  test('contains match: bypass company domain', () => {
    vault.getOrCreateSession('al2', 0);
    const hits: RedactionHit[] = [];
    const result = redactValue(
      { text: 'Email alice@mycompany.com and bob@mycompany.com and external@gmail.com' },
      ctx({ allowList: [{ value: '@mycompany.com', type: 'contains' }] }),
      vault, 'al2', hits, 0,
    ) as any;
    expect(result.text).toContain('alice@mycompany.com');
    expect(result.text).toContain('bob@mycompany.com');
    expect(result.text).not.toContain('external@gmail.com');
  });

  test('regex match: bypass pattern', () => {
    vault.getOrCreateSession('al3', 0);
    const hits: RedactionHit[] = [];
    const result = redactValue(
      { text: 'Public: info@acme.com, private: ceo@acme.com, external: john@gmail.com' },
      ctx({ allowList: [{ value: 'info@.*\\.com', type: 'regex' }] }),
      vault, 'al3', hits, 0,
    ) as any;
    expect(result.text).toContain('info@acme.com');
    expect(result.text).not.toContain('ceo@acme.com');
    expect(result.text).not.toContain('john@gmail.com');
  });

  test('allow list works with semantic detection', () => {
    vault.getOrCreateSession('al4', 0);
    const hits: RedactionHit[] = [];
    const result = redactValue(
      { name: 'Support Team', email: 'support@mycompany.com' },
      ctx({ allowList: [
        { value: 'Support Team', type: 'exact' },
        { value: '@mycompany.com', type: 'contains' },
      ]}),
      vault, 'al4', hits, 0,
    ) as any;
    expect(result.name).toBe('Support Team');
    expect(result.email).toBe('support@mycompany.com');
  });

  test('empty allow list does not affect redaction', () => {
    vault.getOrCreateSession('al5', 0);
    const hits: RedactionHit[] = [];
    const result = redactValue(
      { email: 'test@test.com' },
      ctx({ allowList: [] }),
      vault, 'al5', hits, 0,
    ) as any;
    expect(result.email).not.toBe('test@test.com');
  });

  test('allow list with invalid regex does not crash', () => {
    vault.getOrCreateSession('al6', 0);
    const hits: RedactionHit[] = [];
    const result = redactValue(
      { email: 'test@test.com' },
      ctx({ allowList: [{ value: '[invalid(', type: 'regex' }] }),
      vault, 'al6', hits, 0,
    ) as any;
    // Should not crash, email should still be redacted
    expect(result.email).not.toBe('test@test.com');
  });

  test('multiple allow list entries combined', () => {
    vault.getOrCreateSession('al7', 0);
    const hits: RedactionHit[] = [];
    const result = redactValue(
      { text: 'a@safe.com, b@safe.org, c@unsafe.com' },
      ctx({ allowList: [
        { value: '@safe.com', type: 'contains' },
        { value: '@safe.org', type: 'contains' },
      ]}),
      vault, 'al7', hits, 0,
    ) as any;
    expect(result.text).toContain('a@safe.com');
    expect(result.text).toContain('b@safe.org');
    expect(result.text).not.toContain('c@unsafe.com');
  });
});

// ═══════════════════════════════════════════════════════
// 1.2 DENY LIST TESTS
// ═══════════════════════════════════════════════════════
describe('Deny List', () => {
  let vault: MemoryVault;
  beforeEach(() => { vault = new MemoryVault(); });

  test('exact match: always redact specific value', () => {
    vault.getOrCreateSession('dl1', 0);
    const hits: RedactionHit[] = [];
    const result = redactValue(
      { text: 'Project codename: Project Falcon is confidential' },
      ctx({ enabledPatterns: [], denyList: [{ value: 'Project Falcon', type: 'exact' }] }),
      vault, 'dl1', hits, 0,
    ) as any;
    expect(result.text).not.toContain('Project Falcon');
    expect(hits).toHaveLength(1);
    expect(hits[0].patternLabel).toBe('DENY_LIST');
    expect(hits[0].confidence).toBe(1.0);
  });

  test('contains match: redact any occurrence', () => {
    vault.getOrCreateSession('dl2', 0);
    const hits: RedactionHit[] = [];
    const result = redactValue(
      { text: 'INTERNAL-SECRET-2024 and INTERNAL-SECRET-2025 are classified' },
      ctx({ enabledPatterns: [], denyList: [{ value: 'INTERNAL-SECRET', type: 'contains' }] }),
      vault, 'dl2', hits, 0,
    ) as any;
    expect(result.text).not.toContain('INTERNAL-SECRET');
  });

  test('deny list combined with allow list (deny takes priority)', () => {
    vault.getOrCreateSession('dl3', 0);
    const hits: RedactionHit[] = [];
    const result = redactValue(
      { text: 'Contact ceo@acme.com for Project Falcon details' },
      ctx({
        denyList: [{ value: 'Project Falcon', type: 'exact' }],
        allowList: [{ value: '@acme.com', type: 'contains' }],
      }),
      vault, 'dl3', hits, 0,
    ) as any;
    expect(result.text).toContain('ceo@acme.com'); // allowed
    expect(result.text).not.toContain('Project Falcon'); // denied
  });

  test('empty deny list does not affect redaction', () => {
    vault.getOrCreateSession('dl4', 0);
    const hits: RedactionHit[] = [];
    const result = redactValue(
      { text: 'Normal text' },
      ctx({ denyList: [] }),
      vault, 'dl4', hits, 0,
    ) as any;
    expect(result.text).toBe('Normal text');
  });
});

// ═══════════════════════════════════════════════════════
// 1.3 CONTEXT WORD BOOSTING TESTS
// ═══════════════════════════════════════════════════════
describe('Context Word Boosting', () => {
  test('hasContextWords finds nearby keywords', () => {
    const text = 'Please provide your SSN: 123-45-6789 for verification';
    expect(hasContextWords(text, 25, 36, ['SSN', 'social security'])).toBe(true);
  });

  test('hasContextWords returns false when no keywords nearby', () => {
    const text = 'The code is 123-45-6789 in the system';
    expect(hasContextWords(text, 12, 23, ['SSN', 'social security'])).toBe(false);
  });

  test('context words are case-insensitive', () => {
    const text = 'your ssn is 123-45-6789';
    expect(hasContextWords(text, 12, 23, ['SSN'])).toBe(true);
  });

  test('CONTEXT_WORDS has entries for key patterns', () => {
    expect(CONTEXT_WORDS.email).toBeDefined();
    expect(CONTEXT_WORDS.email!.length).toBeGreaterThan(0);
    expect(CONTEXT_WORDS.ssn).toBeDefined();
    expect(CONTEXT_WORDS.creditCard).toBeDefined();
    expect(CONTEXT_WORDS.iban).toBeDefined();
    expect(CONTEXT_WORDS.phone).toBeDefined();
  });

  test('context boost increases confidence score', () => {
    const textWithContext = 'SSN: 123-45-6789';
    const textWithout = 'Code: 123-45-6789';
    const confWith = calculateConfidence('ssn', false, true, textWithContext, 5, 16);
    const confWithout = calculateConfidence('ssn', false, true, textWithout, 6, 17);
    expect(confWith).toBeGreaterThan(confWithout);
  });
});

// ═══════════════════════════════════════════════════════
// 1.4 CONFIDENCE SCORING TESTS
// ═══════════════════════════════════════════════════════
describe('Confidence Scoring', () => {
  let vault: MemoryVault;
  beforeEach(() => { vault = new MemoryVault(); });

  test('checksum-validated patterns get 0.95 confidence', () => {
    const conf = calculateConfidence('creditCard', true, true, 'Card: 4532015112830366', 6, 22);
    expect(conf).toBeGreaterThanOrEqual(0.95);
  });

  test('email gets high confidence', () => {
    const conf = calculateConfidence('email', false, true, 'test@example.com', 0, 16);
    expect(conf).toBeGreaterThanOrEqual(0.85);
  });

  test('broad patterns get lower confidence', () => {
    const conf = calculateConfidence('postalCodeDE', false, true, '80331', 0, 5);
    expect(conf).toBeLessThanOrEqual(0.50);
  });

  test('confidence threshold filters out low-confidence matches', () => {
    vault.getOrCreateSession('ct1', 0);
    const hits: RedactionHit[] = [];
    const result = redactValue(
      { text: 'Email: test@example.com' },
      ctx({ confidenceThreshold: 0.80 }),
      vault, 'ct1', hits, 0,
    ) as any;
    // Email has high confidence, should be redacted
    expect(result.text).not.toContain('test@example.com');
    expect(hits.length).toBeGreaterThan(0);
    expect(hits[0].confidence).toBeGreaterThanOrEqual(0.80);
  });

  test('high threshold blocks low-confidence patterns', () => {
    vault.getOrCreateSession('ct2', 0);
    const hits: RedactionHit[] = [];
    // With threshold 0.99, only checksum-validated should pass
    const result = redactValue(
      { text: 'Random number: 80331' },
      ctx({
        enabledPatterns: ['postalCodeDE'],
        confidenceThreshold: 0.99,
      }),
      vault, 'ct2', hits, 0,
    ) as any;
    // postalCodeDE has low confidence (0.40), should NOT be redacted
    expect(result.text).toBe('Random number: 80331');
    expect(hits).toHaveLength(0);
  });

  test('threshold 0 redacts everything (default)', () => {
    vault.getOrCreateSession('ct3', 0);
    const hits: RedactionHit[] = [];
    const result = redactValue(
      { text: 'test@test.com' },
      ctx({ confidenceThreshold: 0 }),
      vault, 'ct3', hits, 0,
    ) as any;
    expect(result.text).not.toContain('test@test.com');
  });

  test('all hits include confidence field', () => {
    vault.getOrCreateSession('ct4', 0);
    const hits: RedactionHit[] = [];
    redactValue(
      { text: 'Email: a@b.com, SSN: 123-45-6789' },
      ctx(),
      vault, 'ct4', hits, 0,
    );
    for (const hit of hits) {
      expect(hit.confidence).toBeDefined();
      expect(hit.confidence).toBeGreaterThan(0);
      expect(hit.confidence).toBeLessThanOrEqual(1.0);
    }
  });
});

// ═══════════════════════════════════════════════════════
// 1.5 NAME DICTIONARY TESTS
// ═══════════════════════════════════════════════════════
describe('Name Dictionary', () => {
  test('FIRST_NAMES contains common English names', () => {
    expect(FIRST_NAMES.has('James')).toBe(true);
    expect(FIRST_NAMES.has('Mary')).toBe(true);
    expect(FIRST_NAMES.has('Michael')).toBe(true);
  });

  test('FIRST_NAMES contains German names', () => {
    expect(FIRST_NAMES.has('Hans')).toBe(true);
    expect(FIRST_NAMES.has('Klaus')).toBe(true);
    expect(FIRST_NAMES.has('Ursula')).toBe(true);
  });

  test('FIRST_NAMES contains French names', () => {
    expect(FIRST_NAMES.has('Jean')).toBe(true);
    expect(FIRST_NAMES.has('Marie')).toBe(true);
  });

  test('FIRST_NAMES contains Spanish names', () => {
    expect(FIRST_NAMES.has('Antonio')).toBe(true);
    expect(FIRST_NAMES.has('Carmen')).toBe(true);
  });

  test('FIRST_NAMES contains Indian names', () => {
    expect(FIRST_NAMES.has('Adeel')).toBe(true);
    expect(FIRST_NAMES.has('Priya')).toBe(true);
    expect(FIRST_NAMES.has('Rahul')).toBe(true);
  });

  test('LAST_NAMES contains common surnames', () => {
    expect(LAST_NAMES.has('Smith')).toBe(true);
    expect(LAST_NAMES.has('Mueller')).toBe(true);
    expect(LAST_NAMES.has('Garcia')).toBe(true);
    expect(LAST_NAMES.has('Patel')).toBe(true);
    expect(LAST_NAMES.has('Solangi')).toBe(true);
  });

  test('detectNamesInText finds names in free text', () => {
    const names = detectNamesInText('Spoke with Sarah Johnson about her account');
    expect(names.length).toBeGreaterThan(0);
    expect(names[0].name).toBe('Sarah Johnson');
  });

  test('detectNamesInText finds German names', () => {
    const names = detectNamesInText('Der Kunde ist Hans Mueller aus Berlin');
    const hansMatch = names.find((n) => n.name.includes('Hans'));
    expect(hansMatch).toBeDefined();
  });

  test('detectNamesInText does NOT match city names', () => {
    const names = detectNamesInText('We visited New York and Los Angeles');
    expect(names).toHaveLength(0);
  });

  test('detectNamesInText does NOT match months', () => {
    const names = detectNamesInText('Meeting scheduled for January February');
    expect(names).toHaveLength(0);
  });

  test('detectNamesInText does NOT match tech terms', () => {
    const names = detectNamesInText('Data Server Client Table Field');
    expect(names).toHaveLength(0);
  });

  test('name dictionary works in redaction engine', () => {
    const vault = new MemoryVault();
    vault.getOrCreateSession('nd1', 0);
    const hits: RedactionHit[] = [];
    const result = redactValue(
      { notes: 'Spoke with Sarah Johnson about her billing issue' },
      ctx(),
      vault, 'nd1', hits, 0,
    ) as any;
    // Sarah Johnson should be detected by name dictionary
    expect(result.notes).not.toContain('Sarah Johnson');
  });

  test('name dictionary respects allow list', () => {
    const vault = new MemoryVault();
    vault.getOrCreateSession('nd2', 0);
    const hits: RedactionHit[] = [];
    const result = redactValue(
      { notes: 'Spoke with Sarah Johnson at the office' },
      ctx({ allowList: [{ value: 'Sarah Johnson', type: 'exact' }] }),
      vault, 'nd2', hits, 0,
    ) as any;
    expect(result.notes).toContain('Sarah Johnson');
  });
});

// ═══════════════════════════════════════════════════════
// INTEGRATION: All Phase 1 features combined
// ═══════════════════════════════════════════════════════
describe('Phase 1 Integration', () => {
  let vault: MemoryVault;
  beforeEach(() => { vault = new MemoryVault(); });

  test('allow + deny + confidence + names all working together', () => {
    vault.getOrCreateSession('int1', 0);
    const hits: RedactionHit[] = [];
    const result = redactValue(
      {
        message: 'Contact Sarah Johnson at support@acme.com about Project Falcon. Her SSN is 123-45-6789.',
        notes: 'Internal ref: CLASSIFIED-2024',
      },
      ctx({
        allowList: [{ value: '@acme.com', type: 'contains' }],
        denyList: [
          { value: 'Project Falcon', type: 'exact' },
          { value: 'CLASSIFIED', type: 'contains' },
        ],
        confidenceThreshold: 0,
      }),
      vault, 'int1', hits, 0,
    ) as any;

    // Allow list: support@acme.com should NOT be redacted
    expect(result.message).toContain('support@acme.com');
    // Deny list: Project Falcon should be redacted
    expect(result.message).not.toContain('Project Falcon');
    // SSN: should be redacted (regex pattern)
    expect(result.message).not.toContain('123-45-6789');
    // Name: Sarah Johnson should be detected by dictionary
    expect(result.message).not.toContain('Sarah Johnson');
    // Deny list: CLASSIFIED should be redacted in notes
    expect(result.notes).not.toContain('CLASSIFIED-2024');
  });

  test('full round-trip with allow/deny lists', () => {
    vault.getOrCreateSession('int2', 0);
    const hits: RedactionHit[] = [];
    const original = {
      text: 'Email support@safe.com or private@gmail.com. Secret: CODENAME-X.',
    };
    const redacted = redactValue(
      original,
      ctx({
        allowList: [{ value: '@safe.com', type: 'contains' }],
        denyList: [{ value: 'CODENAME-X', type: 'exact' }],
      }),
      vault, 'int2', hits, 0,
    ) as any;

    // Verify redaction
    expect(redacted.text).toContain('support@safe.com');
    expect(redacted.text).not.toContain('private@gmail.com');
    expect(redacted.text).not.toContain('CODENAME-X');

    // Restore
    const restored = restoreValue(redacted, vault, 'int2') as any;
    expect(restored.text).toContain('private@gmail.com');
    expect(restored.text).toContain('CODENAME-X');
    expect(restored.text).toContain('support@safe.com');
  });

  test('confidence scores in report output', () => {
    vault.getOrCreateSession('int3', 0);
    const hits: RedactionHit[] = [];
    redactValue(
      { text: 'SSN: 123-45-6789, email: test@test.com' },
      ctx(),
      vault, 'int3', hits, 0,
    );

    // Every hit should have a confidence score
    expect(hits.length).toBeGreaterThan(0);
    for (const hit of hits) {
      expect(typeof hit.confidence).toBe('number');
      expect(hit.confidence).toBeGreaterThan(0);
      expect(hit.confidence).toBeLessThanOrEqual(1.0);
    }
  });
});
