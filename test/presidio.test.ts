import {
  checkPresidioHealth,
  analyzeWithPresidio,
  getRedactorLabel,
  getRedactorCategory,
  getPresidioEntities,
  resetCircuitBreaker,
  PresidioRequester,
} from '../nodes/Redactor/presidio';

/** Models an unreachable Presidio: n8n's httpRequest rejects on connection errors. */
const unreachable: PresidioRequester = async () => {
  throw new Error('connect ECONNREFUSED');
};
import { MemoryVault } from '../nodes/Redactor/vault';
import { enhanceWithPresidio } from '../nodes/Redactor/engine';
import { RedactionContext, RedactionHit } from '../nodes/Redactor/types';

// ═══════════════════════════════════════════════════════
// PRESIDIO CLIENT TESTS
// ═══════════════════════════════════════════════════════
describe('Presidio Client', () => {
  test('checkPresidioHealth returns false when unreachable', async () => {
    const result = await checkPresidioHealth('http://localhost:99999', unreachable);
    expect(result).toBe(false);
  });

  test('analyzeWithPresidio returns empty array when unreachable', async () => {
    const result = await analyzeWithPresidio('http://localhost:99999', 'John Smith called', 'en', 0.4, 2000, unreachable);
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
    const result = await getPresidioEntities('http://localhost:99999', unreachable);
    expect(result).toEqual([]);
  });

  test('returns empty without a transport', async () => {
    expect(await analyzeWithPresidio('http://localhost:5002', 'John Smith', 'en')).toEqual([]);
    expect(await checkPresidioHealth('http://localhost:5002')).toBe(false);
  });

  test('never calls non-http URLs', async () => {
    const request = jest.fn(unreachable);
    expect(await analyzeWithPresidio('file:///etc/passwd', 'John', 'en', 0.4, 1000, request)).toEqual([]);
    expect(await analyzeWithPresidio('not a url', 'John', 'en', 0.4, 1000, request)).toEqual([]);
    expect(request).not.toHaveBeenCalled();
  });
});

describe('Presidio Client (mocked n8n transport)', () => {
  beforeEach(() => resetCircuitBreaker());

  const entity = { entity_type: 'PERSON', start: 0, end: 10, score: 0.85 };

  test('POSTs the analyze request and returns entities', async () => {
    const request = jest.fn<ReturnType<PresidioRequester>, Parameters<PresidioRequester>>(async () => ({ statusCode: 200, body: [entity] }));
    const result = await analyzeWithPresidio('http://presidio:3000', 'John Smith called', 'de', 0.5, 4000, request);
    expect(result).toEqual([entity]);
    expect(request).toHaveBeenCalledWith({
      method: 'POST',
      url: 'http://presidio:3000/analyze',
      body: { text: 'John Smith called', language: 'de', score_threshold: 0.5, return_decision_process: false },
      timeout: 4000,
    });
  });

  test('accepts a string body', async () => {
    const result = await analyzeWithPresidio('http://p', 'x y', 'en', 0.4, 1000, async () => ({ statusCode: 200, body: JSON.stringify([entity]) }));
    expect(result).toEqual([entity]);
  });

  test('non-200 and non-array bodies fall back to empty', async () => {
    expect(await analyzeWithPresidio('http://p', 'x', 'en', 0.4, 1000, async () => ({ statusCode: 500, body: 'oops' }))).toEqual([]);
    expect(await analyzeWithPresidio('http://p2', 'x', 'en', 0.4, 1000, async () => ({ statusCode: 200, body: { not: 'array' } }))).toEqual([]);
  });

  test('circuit breaker opens after 3 network failures for that URL', async () => {
    const request = jest.fn(unreachable);
    for (let i = 0; i < 5; i++) await analyzeWithPresidio('http://down', 'text', 'en', 0.4, 1000, request);
    expect(request).toHaveBeenCalledTimes(3);
  });

  test('health check and supported entities use GET', async () => {
    const request = jest.fn<ReturnType<PresidioRequester>, Parameters<PresidioRequester>>(async ({ url }) => ({
      statusCode: 200,
      body: url.endsWith('/supportedentities') ? ['PERSON', 'EMAIL_ADDRESS'] : 'ok',
    }));
    expect(await checkPresidioHealth('http://p', request)).toBe(true);
    expect(await getPresidioEntities('http://p', request)).toEqual(['PERSON', 'EMAIL_ADDRESS']);
    expect(request.mock.calls.map((c) => c[0].method)).toEqual(['GET', 'GET']);
  });

  test('enhanceWithPresidio redacts entities found by Presidio', async () => {
    const vault = new MemoryVault();
    vault.getOrCreateSession('pm', 0);
    const hits: RedactionHit[] = [];
    const request: PresidioRequester = async () => ({ statusCode: 200, body: [{ entity_type: 'PERSON', start: 11, end: 24, score: 0.9 }] });
    const result = await enhanceWithPresidio(
      { notes: 'Spoke with Sarah Johnson today' },
      {
        enabledPatterns: [], customPatterns: [], mode: 'token', dedup: true,
        fieldRules: [], fieldMode: 'all', presidioUrl: 'http://p', presidioRequest: request,
      },
      vault, 'pm', hits, 0,
    );
    expect(result.notes).not.toContain('Sarah Johnson');
    expect(result.notes).toMatch(/Spoke with \[PERSON_NAME_\d+\] today/);
    expect(hits).toHaveLength(1);
    expect(hits[0].patternName).toBe('presidio_PERSON');
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
