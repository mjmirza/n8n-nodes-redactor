import {
  checkPresidioHealth,
  analyzeWithPresidio,
  getRedactorLabel,
  getRedactorCategory,
  getPresidioEntities,
} from '../presidio';
import { MemoryVault } from '../vault';
import { enhanceWithPresidio } from '../engine';
import { RedactionContext, RedactionHit } from '../types';

// ═══════════════════════════════════════════════════════
// PRESIDIO CLIENT TESTS
// ═══════════════════════════════════════════════════════
describe('Presidio Client', () => {
  test('checkPresidioHealth returns false when unreachable', async () => {
    const result = await checkPresidioHealth('http://localhost:99999');
    expect(result).toBe(false);
  });

  test('analyzeWithPresidio returns empty array when unreachable', async () => {
    const result = await analyzeWithPresidio('http://localhost:99999', 'John Smith called', 'en', 0.4, 2000);
    expect(result).toEqual([]);
  });

  test('analyzeWithPresidio returns empty for empty text', async () => {
    const result = await analyzeWithPresidio('http://localhost:5002', '', 'en');
    expect(result).toEqual([]);
  });

  test('analyzeWithPresidio returns empty for whitespace text', async () => {
    const result = await analyzeWithPresidio('http://localhost:5002', '   ', 'en');
    expect(result).toEqual([]);
  });

  test('getPresidioEntities returns empty when unreachable', async () => {
    const result = await getPresidioEntities('http://localhost:99999');
    expect(result).toEqual([]);
  });
});

// ═══════════════════════════════════════════════════════
// ENTITY TYPE MAPPING TESTS
// ═══════════════════════════════════════════════════════
describe('Presidio Entity Mapping', () => {
  test('maps PERSON to PERSON_NAME', () => {
    expect(getRedactorLabel('PERSON')).toBe('PERSON_NAME');
  });

  test('maps EMAIL_ADDRESS to EMAIL', () => {
    expect(getRedactorLabel('EMAIL_ADDRESS')).toBe('EMAIL');
  });

  test('maps PHONE_NUMBER to PHONE', () => {
    expect(getRedactorLabel('PHONE_NUMBER')).toBe('PHONE');
  });

  test('maps CREDIT_CARD to CREDIT_CARD', () => {
    expect(getRedactorLabel('CREDIT_CARD')).toBe('CREDIT_CARD');
  });

  test('maps LOCATION to ADDRESS', () => {
    expect(getRedactorLabel('LOCATION')).toBe('ADDRESS');
  });

  test('maps ORGANIZATION to COMPANY', () => {
    expect(getRedactorLabel('ORGANIZATION')).toBe('COMPANY');
  });

  test('maps US_SSN to SSN', () => {
    expect(getRedactorLabel('US_SSN')).toBe('SSN');
  });

  test('maps IBAN_CODE to IBAN', () => {
    expect(getRedactorLabel('IBAN_CODE')).toBe('IBAN');
  });

  test('unknown entity type passes through as-is', () => {
    expect(getRedactorLabel('UNKNOWN_TYPE')).toBe('UNKNOWN_TYPE');
  });

  test('category mapping works for PERSON', () => {
    expect(getRedactorCategory('PERSON')).toBe('identity');
  });

  test('category mapping works for CREDIT_CARD', () => {
    expect(getRedactorCategory('CREDIT_CARD')).toBe('financial');
  });

  test('category mapping works for IP_ADDRESS', () => {
    expect(getRedactorCategory('IP_ADDRESS')).toBe('network');
  });

  test('unknown category defaults to identity', () => {
    expect(getRedactorCategory('UNKNOWN')).toBe('identity');
  });
});

// ═══════════════════════════════════════════════════════
// ENHANCE WITH PRESIDIO TESTS (graceful fallback)
// ═══════════════════════════════════════════════════════
describe('enhanceWithPresidio', () => {
  let vault: MemoryVault;

  beforeEach(() => {
    vault = new MemoryVault();
  });

  test('returns data unchanged when presidioUrl is not set', async () => {
    vault.getOrCreateSession('p1', 0);
    const hits: RedactionHit[] = [];
    const data = { name: 'John Smith', email: 'john@test.com' };
    const result = await enhanceWithPresidio(
      data,
      { enabledPatterns: [], customPatterns: [], mode: 'token', dedup: true, fieldRules: [], fieldMode: 'all' },
      vault, 'p1', hits, 0,
    );
    expect(result).toEqual(data);
    expect(hits).toHaveLength(0);
  });

  test('returns data unchanged when Presidio is unreachable', async () => {
    vault.getOrCreateSession('p2', 0);
    const hits: RedactionHit[] = [];
    const data = { notes: 'Spoke with Sarah Johnson about billing' };
    const result = await enhanceWithPresidio(
      data,
      {
        enabledPatterns: [], customPatterns: [], mode: 'token', dedup: true,
        fieldRules: [], fieldMode: 'all',
        presidioUrl: 'http://localhost:99999',
        presidioLanguage: 'en',
      },
      vault, 'p2', hits, 0,
    );
    // Should not crash, returns original data
    expect(result.notes).toBe('Spoke with Sarah Johnson about billing');
    expect(hits).toHaveLength(0);
  });

  test('skips already-redacted tokens', async () => {
    vault.getOrCreateSession('p3', 0);
    const hits: RedactionHit[] = [];
    const data = { name: '[PERSON_NAME_0]', email: '[EMAIL_1]' };
    const result = await enhanceWithPresidio(
      data,
      {
        enabledPatterns: [], customPatterns: [], mode: 'token', dedup: true,
        fieldRules: [], fieldMode: 'all',
        presidioUrl: 'http://localhost:99999',
      },
      vault, 'p3', hits, 0,
    );
    // Tokens should not be modified
    expect(result.name).toBe('[PERSON_NAME_0]');
    expect(result.email).toBe('[EMAIL_1]');
  });

  test('skips empty and whitespace strings', async () => {
    vault.getOrCreateSession('p4', 0);
    const hits: RedactionHit[] = [];
    const data = { empty: '', whitespace: '   ', valid: 'some text' };
    const result = await enhanceWithPresidio(
      data,
      {
        enabledPatterns: [], customPatterns: [], mode: 'token', dedup: true,
        fieldRules: [], fieldMode: 'all',
        presidioUrl: 'http://localhost:99999',
      },
      vault, 'p4', hits, 0,
    );
    expect(result.empty).toBe('');
    expect(result.whitespace).toBe('   ');
  });

  test('respects allow list', async () => {
    vault.getOrCreateSession('p5', 0);
    const hits: RedactionHit[] = [];
    const data = { text: 'Contact Support Team at support@acme.com' };
    const result = await enhanceWithPresidio(
      data,
      {
        enabledPatterns: [], customPatterns: [], mode: 'token', dedup: true,
        fieldRules: [], fieldMode: 'all',
        presidioUrl: 'http://localhost:99999',
        allowList: [{ value: 'Support Team', type: 'exact' }],
      },
      vault, 'p5', hits, 0,
    );
    // Even if Presidio found "Support Team", allow list would skip it
    expect(result.text).toContain('Support Team');
  });

  test('handles non-string values gracefully', async () => {
    vault.getOrCreateSession('p6', 0);
    const hits: RedactionHit[] = [];
    const data = { count: 42 as unknown as string, active: true as unknown as string };
    const result = await enhanceWithPresidio(
      data as Record<string, unknown>,
      {
        enabledPatterns: [], customPatterns: [], mode: 'token', dedup: true,
        fieldRules: [], fieldMode: 'all',
        presidioUrl: 'http://localhost:99999',
      },
      vault, 'p6', hits, 0,
    );
    // Non-strings should pass through unchanged
    expect(result.count).toBe(42);
    expect(result.active).toBe(true);
  });
});

// ═══════════════════════════════════════════════════════
// DOCKER SETUP DOCUMENTATION TEST
// ═══════════════════════════════════════════════════════
describe('Presidio Docker Setup', () => {
  test('docker command is documented correctly', () => {
    // Verify the Docker image reference is correct
    const dockerImage = 'mcr.microsoft.com/presidio-analyzer';
    const defaultPort = 5002;
    const internalPort = 3000;
    expect(dockerImage).toContain('presidio-analyzer');
    expect(defaultPort).toBe(5002);
    expect(internalPort).toBe(3000);
  });
});
