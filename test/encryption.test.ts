import { encryptVaultData, decryptVaultData, isEncryptedVault, isPlaintextVault } from '../nodes/Redactor/encryption';
import { WorkflowVault, VaultStore } from '../nodes/Redactor/vault';

/** n8n persists static data as JSON, so a round trip models a later execution. */
const persist = (store: VaultStore): VaultStore => JSON.parse(JSON.stringify(store));

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

describe('WorkflowVault with Encryption', () => {
  let store: VaultStore;

  beforeEach(() => {
    store = {};
  });

  test('encrypted vault: save and reload', () => {
    const vault = new WorkflowVault(store, 'my-secret');
    vault.getOrCreateSession('enc-test', 0);
    vault.addEntry('enc-test', {
      token: '[EMAIL_0]',
      original: 'secret@company.com',
      patternLabel: 'EMAIL',
      category: 'contact',
      createdAt: new Date().toISOString(),
    });
    vault.save('enc-test');

    // A later execution with the same passphrase reads it
    const vault2 = new WorkflowVault(persist(store), 'my-secret');
    const session = vault2.getSession('enc-test');
    expect(session).not.toBeNull();
    expect(session!.entries['[EMAIL_0]'].original).toBe('secret@company.com');
  });

  test('wrong passphrase cannot read vault', () => {
    const vault = new WorkflowVault(store, 'correct-pass');
    vault.getOrCreateSession('secure', 0);
    vault.addEntry('secure', {
      token: '[SSN_0]',
      original: '123-45-6789',
      patternLabel: 'SSN',
      category: 'identity',
      createdAt: new Date().toISOString(),
    });
    vault.save('secure');

    const vault2 = new WorkflowVault(persist(store), 'wrong-pass');
    expect(vault2.getSession('secure')).toBeNull();
  });

  test('no passphrase cannot read encrypted vault', () => {
    const vault = new WorkflowVault(store, 'my-secret');
    vault.getOrCreateSession('protected', 0);
    vault.save('protected');

    const vault2 = new WorkflowVault(persist(store));
    expect(vault2.getSession('protected')).toBeNull();
  });

  test('vault without passphrase stores plaintext and reloads', () => {
    const vault = new WorkflowVault(store);
    vault.getOrCreateSession('plain', 0);
    vault.save('plain');

    const vault2 = new WorkflowVault(persist(store));
    expect(vault2.getSession('plain')).not.toBeNull();
  });

  test('tenant A cannot read tenant B vault (different passphrases)', () => {
    const vaultA = new WorkflowVault(store, 'tenant-A-secret');
    vaultA.getOrCreateSession('tenant-a-data', 0);
    vaultA.addEntry('tenant-a-data', {
      token: '[NAME_0]',
      original: 'Alice Smith',
      patternLabel: 'PERSON',
      category: 'identity',
      createdAt: new Date().toISOString(),
    });
    vaultA.save('tenant-a-data');

    const vaultB = new WorkflowVault(persist(store), 'tenant-B-secret');
    expect(vaultB.getSession('tenant-a-data')).toBeNull();

    const vaultA2 = new WorkflowVault(persist(store), 'tenant-A-secret');
    const sessionA = vaultA2.getSession('tenant-a-data');
    expect(sessionA).not.toBeNull();
    expect(sessionA!.entries['[NAME_0]'].original).toBe('Alice Smith');
  });

  test('stored encrypted session is not human-readable', () => {
    const vault = new WorkflowVault(store, 'encrypt-me');
    vault.getOrCreateSession('secret-session', 0);
    vault.addEntry('secret-session', {
      token: '[CC_0]',
      original: '4532-0151-1283-0366',
      patternLabel: 'CREDIT_CARD',
      category: 'financial',
      createdAt: new Date().toISOString(),
    });
    vault.save('secret-session');

    const asString = JSON.stringify(store);
    expect(asString).not.toContain('4532-0151-1283-0366');
    expect(asString).not.toContain('secret-session');
    expect(asString).not.toContain('CREDIT_CARD');

    const sessions = (store.redactorVault as Record<string, { cipher?: string }>);
    const cipher = Object.values(sessions)[0].cipher!;
    expect(Buffer.from(cipher, 'base64')[0]).toBe(0x01);
  });

  test('tampered ciphertext is rejected, not decoded', () => {
    const vault = new WorkflowVault(store, 'pw');
    vault.getOrCreateSession('t', 0);
    vault.save('t');
    const sessions = store.redactorVault as Record<string, { cipher?: string }>;
    const k = Object.keys(sessions)[0];
    const raw = Buffer.from(sessions[k].cipher!, 'base64');
    raw[raw.length - 1] ^= 0xff;
    sessions[k].cipher = raw.toString('base64');
    expect(new WorkflowVault(persist(store), 'pw').getSession('t')).toBeNull();
  });
});
