import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { encryptVaultData, decryptVaultData, isEncryptedVault, isPlaintextVault } from '../encryption';
import { FileVault } from '../vault';

describe('Encryption Engine', () => {
  const testData = '{"sessionId":"test","entries":{},"createdAt":"2026-01-01T00:00:00Z","ttl":3600000}';

  test('encrypt then decrypt returns original data', () => {
    const encrypted = encryptVaultData(testData, 'my-secret-passphrase');
    const decrypted = decryptVaultData(encrypted, 'my-secret-passphrase');
    expect(decrypted).toBe(testData);
  });

  test('encrypted data starts with version byte 0x01', () => {
    const encrypted = encryptVaultData(testData, 'pass');
    expect(encrypted[0]).toBe(0x01);
    expect(isEncryptedVault(encrypted)).toBe(true);
    expect(isPlaintextVault(encrypted)).toBe(false);
  });

  test('plaintext JSON is detected correctly', () => {
    const plain = Buffer.from(testData, 'utf-8');
    expect(isPlaintextVault(plain)).toBe(true);
    expect(isEncryptedVault(plain)).toBe(false);
  });

  test('wrong passphrase throws error', () => {
    const encrypted = encryptVaultData(testData, 'correct-pass');
    expect(() => decryptVaultData(encrypted, 'wrong-pass')).toThrow('decryption failed');
  });

  test('tampered ciphertext throws error', () => {
    const encrypted = encryptVaultData(testData, 'pass');
    // Flip a byte in the ciphertext
    encrypted[encrypted.length - 1] ^= 0xFF;
    expect(() => decryptVaultData(encrypted, 'pass')).toThrow();
  });

  test('truncated data throws error', () => {
    const encrypted = encryptVaultData(testData, 'pass');
    const truncated = encrypted.subarray(0, 10);
    expect(() => decryptVaultData(truncated, 'pass')).toThrow('too short');
  });

  test('different passphrases produce different ciphertext', () => {
    const e1 = encryptVaultData(testData, 'pass1');
    const e2 = encryptVaultData(testData, 'pass2');
    expect(e1.equals(e2)).toBe(false);
  });

  test('same passphrase produces different ciphertext (random IV)', () => {
    const e1 = encryptVaultData(testData, 'same-pass');
    const e2 = encryptVaultData(testData, 'same-pass');
    expect(e1.equals(e2)).toBe(false);
    // But both decrypt to the same data
    expect(decryptVaultData(e1, 'same-pass')).toBe(testData);
    expect(decryptVaultData(e2, 'same-pass')).toBe(testData);
  });

  test('empty buffer returns false for both checks', () => {
    expect(isEncryptedVault(Buffer.alloc(0))).toBe(false);
    expect(isPlaintextVault(Buffer.alloc(0))).toBe(false);
  });
});

describe('FileVault with Encryption', () => {
  let testDir: string;

  beforeEach(() => {
    testDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-enc-test-'));
  });

  afterEach(() => {
    try { fs.rmSync(testDir, { recursive: true, force: true }); } catch { /* ignore */ }
  });

  test('encrypted vault: save and reload', () => {
    const vault = new FileVault(testDir, 'my-secret');
    vault.getOrCreateSession('enc-test', 0);
    vault.addEntry('enc-test', {
      token: '[EMAIL_0]',
      original: 'secret@company.com',
      patternLabel: 'EMAIL',
      category: 'contact',
      createdAt: new Date().toISOString(),
    });
    vault.save('enc-test');

    // New vault instance with same passphrase should read it
    const vault2 = new FileVault(testDir, 'my-secret');
    const session = vault2.getSession('enc-test');
    expect(session).not.toBeNull();
    expect(session!.entries['[EMAIL_0]'].original).toBe('secret@company.com');
  });

  test('wrong passphrase cannot read vault', () => {
    const vault = new FileVault(testDir, 'correct-pass');
    vault.getOrCreateSession('secure', 0);
    vault.addEntry('secure', {
      token: '[SSN_0]',
      original: '123-45-6789',
      patternLabel: 'SSN',
      category: 'identity',
      createdAt: new Date().toISOString(),
    });
    vault.save('secure');

    // Different passphrase should NOT read the data
    const vault2 = new FileVault(testDir, 'wrong-pass');
    const session = vault2.getSession('secure');
    expect(session).toBeNull();
  });

  test('no passphrase cannot read encrypted vault', () => {
    const vault = new FileVault(testDir, 'my-secret');
    vault.getOrCreateSession('protected', 0);
    vault.save('protected');

    // No passphrase — cannot read encrypted file
    const vault2 = new FileVault(testDir);
    const session = vault2.getSession('protected');
    expect(session).toBeNull();
  });

  test('vault without passphrase writes plaintext', () => {
    const vault = new FileVault(testDir);
    vault.getOrCreateSession('plain', 0);
    vault.save('plain');

    // Should be readable without passphrase
    const vault2 = new FileVault(testDir);
    const session = vault2.getSession('plain');
    expect(session).not.toBeNull();
  });

  test('tenant A cannot read tenant B vault (different passphrases)', () => {
    // Tenant A
    const vaultA = new FileVault(testDir, 'tenant-A-secret');
    vaultA.getOrCreateSession('tenant-a-data', 0);
    vaultA.addEntry('tenant-a-data', {
      token: '[NAME_0]',
      original: 'Alice Smith',
      patternLabel: 'PERSON',
      category: 'identity',
      createdAt: new Date().toISOString(),
    });
    vaultA.save('tenant-a-data');

    // Tenant B tries to read Tenant A's vault
    const vaultB = new FileVault(testDir, 'tenant-B-secret');
    const sessionB = vaultB.getSession('tenant-a-data');

    // MUST be null — cross-tenant isolation
    expect(sessionB).toBeNull();

    // Tenant A can still read their own vault
    const vaultA2 = new FileVault(testDir, 'tenant-A-secret');
    const sessionA = vaultA2.getSession('tenant-a-data');
    expect(sessionA).not.toBeNull();
    expect(sessionA!.entries['[NAME_0]'].original).toBe('Alice Smith');
  });

  test('encrypted vault file on disk is not human-readable', () => {
    const vault = new FileVault(testDir, 'encrypt-me');
    vault.getOrCreateSession('secret-session', 0);
    vault.addEntry('secret-session', {
      token: '[CC_0]',
      original: '4532-0151-1283-0366',
      patternLabel: 'CREDIT_CARD',
      category: 'financial',
      createdAt: new Date().toISOString(),
    });
    vault.save('secret-session');

    // Read raw file from disk
    const files = fs.readdirSync(testDir).filter((f) => f.startsWith('vault_'));
    expect(files.length).toBe(1);
    const rawContent = fs.readFileSync(path.join(testDir, files[0]));

    // Raw content should NOT contain the original PII
    const asString = rawContent.toString('utf-8');
    expect(asString).not.toContain('4532-0151-1283-0366');
    expect(asString).not.toContain('secret-session');
    expect(asString).not.toContain('CREDIT_CARD');

    // First byte should be the version marker
    expect(rawContent[0]).toBe(0x01);
  });
});
