import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { loadProfile, saveProfile, listProfiles, deleteProfile, TenantProfile } from '../nodes/Redactor/profiles';
import { generateRopaRecord } from '../nodes/Redactor/ropa';
import { classifyData } from '../nodes/Redactor/classification';
import { RedactionHit } from '../nodes/Redactor/types';

// ═══════════════════════════════════════════════════════
// 4.1 PER-TENANT PROFILES
// ═══════════════════════════════════════════════════════
describe('Per-Tenant Profiles', () => {
  let testDir: string;

  beforeEach(() => {
    testDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pii-profiles-test-'));
  });

  afterEach(() => {
    try { fs.rmSync(testDir, { recursive: true, force: true }); } catch { /* ignore */ }
  });

  test('save and load profile', () => {
    const profile: TenantProfile = {
      profileId: 'acme-corp',
      displayName: 'Acme Corporation',
      enabledPatterns: ['email', 'phone', 'ssn'],
      redactionMode: 'token',
      confidenceThreshold: 0.7,
      allowList: [{ value: '@acme.com', type: 'contains' }],
      denyList: [{ value: 'Project Falcon', type: 'exact' }],
      region: 'EU',
      auditLog: true,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    expect(saveProfile(profile, testDir)).toBe(true);

    const loaded = loadProfile('acme-corp', testDir);
    expect(loaded).not.toBeNull();
    expect(loaded!.displayName).toBe('Acme Corporation');
    expect(loaded!.enabledPatterns).toEqual(['email', 'phone', 'ssn']);
    expect(loaded!.confidenceThreshold).toBe(0.7);
    expect(loaded!.allowList![0].value).toBe('@acme.com');
  });

  test('load nonexistent profile returns null', () => {
    expect(loadProfile('nonexistent', testDir)).toBeNull();
  });

  test('load empty profileId returns null', () => {
    expect(loadProfile('', testDir)).toBeNull();
  });

  test('list profiles', () => {
    saveProfile({ profileId: 'tenant-a', displayName: 'Tenant A', createdAt: '', updatedAt: '' }, testDir);
    saveProfile({ profileId: 'tenant-b', displayName: 'Tenant B', createdAt: '', updatedAt: '' }, testDir);

    const profiles = listProfiles(testDir);
    expect(profiles).toHaveLength(2);
    expect(profiles.map((p) => p.profileId).sort()).toEqual(['tenant-a', 'tenant-b']);
  });

  test('delete profile', () => {
    saveProfile({ profileId: 'delete-me', displayName: 'Delete Me', createdAt: '', updatedAt: '' }, testDir);
    expect(loadProfile('delete-me', testDir)).not.toBeNull();

    expect(deleteProfile('delete-me', testDir)).toBe(true);
    expect(loadProfile('delete-me', testDir)).toBeNull();
  });

  test('delete nonexistent profile returns false', () => {
    expect(deleteProfile('nonexistent', testDir)).toBe(false);
  });

  test('profileId is sanitized against path traversal', () => {
    const result = saveProfile({
      profileId: '../../../etc/passwd',
      displayName: 'Evil',
      createdAt: '',
      updatedAt: '',
    }, testDir);

    // Should save with sanitized name, not escape the directory
    const files = fs.readdirSync(testDir);
    expect(files.every((f) => !f.includes('..'))).toBe(true);
  });

  test('list profiles from empty directory', () => {
    expect(listProfiles(testDir)).toEqual([]);
  });

  test('list profiles from nonexistent directory', () => {
    expect(listProfiles('/tmp/nonexistent-' + Date.now())).toEqual([]);
  });
});

// ═══════════════════════════════════════════════════════
// 4.4 GDPR ART.30 ROPA REPORT
// ═══════════════════════════════════════════════════════
describe('GDPR Art.30 ROPA Report', () => {
  test('generates complete ROPA record', () => {
    const hits: RedactionHit[] = [
      { token: '[E_0]', original: '***', patternName: 'email', patternLabel: 'EMAIL', category: 'contact', field: 'email', itemIndex: 0, confidence: 0.90 },
      { token: '[S_1]', original: '***', patternName: 'ssn', patternLabel: 'SSN', category: 'identity', field: 'ssn', itemIndex: 0, confidence: 0.85 },
      { token: '[C_2]', original: '***', patternName: 'creditCard', patternLabel: 'CREDIT_CARD', category: 'financial', field: 'card', itemIndex: 0, confidence: 0.95 },
    ];
    const classification = classifyData(hits);

    const ropa = generateRopaRecord(
      hits, classification, 100, 90, 'token', 60, true, true,
      { name: 'Acme Corp', contactEmail: 'dpo@acme.com', dpo: 'John DPO' },
      ['PII redaction before LLM processing'],
      'Art.6(1)(f) Legitimate interest',
      ['customers', 'employees'],
      ['LLM provider (OpenAI)'],
      [{ country: 'US', organization: 'OpenAI', safeguards: 'Standard Contractual Clauses' }],
    );

    // Art.30(1)(a) - Controller
    expect(ropa.controller.name).toBe('Acme Corp');
    expect(ropa.controller.dpo).toBe('John DPO');

    // Art.30(1)(b) - Purposes
    expect(ropa.processingPurposes).toContain('PII redaction before LLM processing');
    expect(ropa.legalBasis).toBe('Art.6(1)(f) Legitimate interest');

    // Art.30(1)(c) - Data subjects
    expect(ropa.dataSubjectCategories).toContain('customers');

    // Art.30(1)(d) - Personal data categories
    expect(ropa.personalDataCategories.length).toBeGreaterThanOrEqual(3);
    const contactCat = ropa.personalDataCategories.find((c) => c.category === 'contact');
    expect(contactCat).toBeDefined();
    expect(contactCat!.patternLabels).toContain('EMAIL');

    // Art.30(1)(e) - Recipients
    expect(ropa.recipientCategories).toContain('LLM provider (OpenAI)');

    // Art.30(1)(f) - Transfers
    expect(ropa.thirdCountryTransfers).toHaveLength(1);
    expect(ropa.thirdCountryTransfers[0].country).toBe('US');

    // Art.30(1)(g) - Retention
    expect(ropa.retentionPolicy.vaultTtlMinutes).toBe(60);

    // Art.30(1)(h) - Security measures
    expect(ropa.securityMeasures.encryptionAtRest).toBe(true);
    expect(ropa.securityMeasures.encryptionAlgorithm).toBe('AES-256-GCM');
    expect(ropa.securityMeasures.auditLogging).toBe(true);

    // Processing summary
    expect(ropa.processingSummary.totalItemsProcessed).toBe(100);
    expect(ropa.processingSummary.totalPiiDetected).toBe(3);
    expect(ropa.processingSummary.classificationLevel).toBe('RESTRICTED');

    // Meta
    expect(ropa.version).toBe('1.0');
    expect(ropa.generatedBy).toBe('n8n-nodes-redactor');
    expect(ropa.recordId).toBeDefined();
    expect(ropa.generatedAt).toBeDefined();
  });

  test('ROPA with no PII detected', () => {
    const classification = classifyData([]);
    const ropa = generateRopaRecord(
      [], classification, 50, 90, 'token', 60, false, false,
      { name: 'Test Corp', contactEmail: 'test@test.com' },
      ['Data analysis'], 'Art.6(1)(f)', ['users'], [], [],
    );

    expect(ropa.personalDataCategories).toHaveLength(0);
    expect(ropa.processingSummary.totalPiiDetected).toBe(0);
    expect(ropa.processingSummary.classificationLevel).toBe('PUBLIC');
    expect(ropa.securityMeasures.encryptionAtRest).toBe(false);
  });

  test('ROPA report does not contain original PII values', () => {
    const hits: RedactionHit[] = [
      { token: '[E_0]', original: '***', patternName: 'email', patternLabel: 'EMAIL', category: 'contact', field: 'email', itemIndex: 0, confidence: 0.90 },
    ];
    const classification = classifyData(hits);
    const ropa = generateRopaRecord(
      hits, classification, 1, 90, 'token', 60, false, false,
      { name: 'Test', contactEmail: 'test@test.com' },
      ['test'], 'Art.6(1)(f)', [], [], [],
    );

    const json = JSON.stringify(ropa);
    // Original values should never appear (they're already '***' in hits)
    expect(json).not.toContain('original');
    // Pattern labels are fine (they describe TYPES not VALUES)
    expect(json).toContain('EMAIL');
  });
});
