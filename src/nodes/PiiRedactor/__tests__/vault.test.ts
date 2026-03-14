import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { MemoryVault, FileVault, createVault } from '../vault';
import { VaultEntry } from '../types';

function makeEntry(token: string, original: string): VaultEntry {
  return {
    token,
    original,
    patternLabel: 'EMAIL',
    category: 'contact',
    createdAt: new Date().toISOString(),
  };
}

// ═══════════════════════════════════════════════════════
// MEMORY VAULT
// ═══════════════════════════════════════════════════════
describe('MemoryVault', () => {
  let vault: MemoryVault;

  beforeEach(() => {
    vault = new MemoryVault();
  });

  test('creates a new session', () => {
    const session = vault.getOrCreateSession('test-1', 0);
    expect(session.sessionId).toBe('test-1');
    expect(Object.keys(session.entries)).toHaveLength(0);
  });

  test('returns existing session on second call', () => {
    vault.getOrCreateSession('test-2', 0);
    vault.addEntry('test-2', makeEntry('[EMAIL_0]', 'a@b.com'));
    const session = vault.getOrCreateSession('test-2', 0);
    expect(Object.keys(session.entries)).toHaveLength(1);
  });

  test('adds and retrieves entries', () => {
    vault.getOrCreateSession('test-3', 0);
    vault.addEntry('test-3', makeEntry('[EMAIL_0]', 'alice@example.com'));
    vault.addEntry('test-3', makeEntry('[PHONE_1]', '+49123456'));

    const session = vault.getSession('test-3');
    expect(session).not.toBeNull();
    expect(Object.keys(session!.entries)).toHaveLength(2);
    expect(session!.entries['[EMAIL_0]'].original).toBe('alice@example.com');
  });

  test('findByOriginal returns matching entry', () => {
    vault.getOrCreateSession('test-4', 0);
    vault.addEntry('test-4', makeEntry('[EMAIL_0]', 'test@test.com'));

    const found = vault.findByOriginal('test-4', 'test@test.com');
    expect(found).toBeDefined();
    expect(found!.token).toBe('[EMAIL_0]');
  });

  test('findByOriginal returns undefined for non-existent', () => {
    vault.getOrCreateSession('test-5', 0);
    expect(vault.findByOriginal('test-5', 'nope')).toBeUndefined();
  });

  test('deleteSession removes session', () => {
    vault.getOrCreateSession('test-6', 0);
    vault.deleteSession('test-6');
    expect(vault.getSession('test-6')).toBeNull();
  });

  test('listSessions returns all active sessions', () => {
    vault.getOrCreateSession('s1', 0);
    vault.getOrCreateSession('s2', 0);
    vault.addEntry('s1', makeEntry('[EMAIL_0]', 'a@b.com'));

    const sessions = vault.listSessions();
    expect(sessions.length).toBeGreaterThanOrEqual(2);
    const s1 = sessions.find((s) => s.sessionId === 's1');
    expect(s1?.entryCount).toBe(1);
  });

  test('TTL expiry — expired session returns null', () => {
    // Create session with 1ms TTL
    vault.getOrCreateSession('ttl-test', 1);
    vault.addEntry('ttl-test', makeEntry('[EMAIL_0]', 'a@b.com'));

    // Wait for expiry
    const start = Date.now();
    while (Date.now() - start < 10) {
      // busy wait
    }

    expect(vault.getSession('ttl-test')).toBeNull();
  });

  test('TTL = 0 means no expiry', () => {
    vault.getOrCreateSession('no-ttl', 0);
    vault.addEntry('no-ttl', makeEntry('[EMAIL_0]', 'a@b.com'));
    expect(vault.getSession('no-ttl')).not.toBeNull();
  });

  test('cleanup removes expired sessions', () => {
    vault.getOrCreateSession('expired', 1);
    vault.getOrCreateSession('alive', 0);

    const start = Date.now();
    while (Date.now() - start < 10) {
      // busy wait
    }

    const removed = vault.cleanup();
    expect(removed).toBeGreaterThanOrEqual(1);
    expect(vault.getSession('alive')).not.toBeNull();
  });
});

// ═══════════════════════════════════════════════════════
// FILE VAULT
// ═══════════════════════════════════════════════════════
describe('FileVault', () => {
  let vault: FileVault;
  let testDir: string;

  beforeEach(() => {
    testDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pii-vault-test-'));
    vault = new FileVault(testDir);
  });

  afterEach(() => {
    // Cleanup
    try {
      fs.rmSync(testDir, { recursive: true, force: true });
    } catch {
      // ignore
    }
  });

  test('creates vault directory', () => {
    expect(fs.existsSync(testDir)).toBe(true);
  });

  test('creates and persists session to file', () => {
    vault.getOrCreateSession('file-test-1', 0);
    vault.addEntry('file-test-1', makeEntry('[EMAIL_0]', 'test@file.com'));
    vault.save('file-test-1');

    // Verify file was created
    const files = fs.readdirSync(testDir);
    expect(files.some((f) => f.startsWith('vault_') && f.endsWith('.json'))).toBe(true);
  });

  test('loads session from file after re-instantiation', () => {
    vault.getOrCreateSession('persist-test', 0);
    vault.addEntry('persist-test', makeEntry('[EMAIL_0]', 'persisted@test.com'));
    vault.save('persist-test');

    // Create a new vault instance pointing to same dir
    const vault2 = new FileVault(testDir);
    const session = vault2.getSession('persist-test');
    expect(session).not.toBeNull();
    expect(session!.entries['[EMAIL_0]'].original).toBe('persisted@test.com');
  });

  test('deleteSession removes file', () => {
    vault.getOrCreateSession('delete-test', 0);
    vault.addEntry('delete-test', makeEntry('[EMAIL_0]', 'x@y.com'));
    vault.save('delete-test');

    vault.deleteSession('delete-test');

    const vault2 = new FileVault(testDir);
    expect(vault2.getSession('delete-test')).toBeNull();
  });

  test('listSessions reads all vault files', () => {
    vault.getOrCreateSession('list-1', 0);
    vault.save('list-1');
    vault.getOrCreateSession('list-2', 0);
    vault.addEntry('list-2', makeEntry('[EMAIL_0]', 'a@b.com'));
    vault.save('list-2');

    const sessions = vault.listSessions();
    expect(sessions).toHaveLength(2);
  });

  test('TTL expiry on file vault', () => {
    vault.getOrCreateSession('file-ttl', 1);
    vault.save('file-ttl');

    const start = Date.now();
    while (Date.now() - start < 10) {
      // busy wait
    }

    const vault2 = new FileVault(testDir);
    expect(vault2.getSession('file-ttl')).toBeNull();
  });

  test('cleanup removes expired files', () => {
    vault.getOrCreateSession('expired-file', 1);
    vault.save('expired-file');
    vault.getOrCreateSession('alive-file', 0);
    vault.save('alive-file');

    const start = Date.now();
    while (Date.now() - start < 10) {
      // busy wait
    }

    const removed = vault.cleanup();
    expect(removed).toBeGreaterThanOrEqual(1);
  });

  test('findByOriginal works with file vault', () => {
    vault.getOrCreateSession('find-test', 0);
    vault.addEntry('find-test', makeEntry('[EMAIL_0]', 'find@me.com'));

    const found = vault.findByOriginal('find-test', 'find@me.com');
    expect(found).toBeDefined();
    expect(found!.token).toBe('[EMAIL_0]');
  });

  test('handles corrupt JSON files gracefully', () => {
    // Write a corrupt file
    const corruptFile = path.join(testDir, 'vault_corrupt1234567.json');
    fs.writeFileSync(corruptFile, 'not valid json{{{', 'utf-8');

    const sessions = vault.listSessions();
    // Should not crash, just skip the corrupt file
    expect(Array.isArray(sessions)).toBe(true);
  });
});

// ═══════════════════════════════════════════════════════
// createVault FACTORY
// ═══════════════════════════════════════════════════════
describe('createVault factory', () => {
  test('returns MemoryVault for "memory"', () => {
    const v = createVault('memory');
    expect(v).toBeInstanceOf(MemoryVault);
  });

  test('returns FileVault for "file"', () => {
    const testDir = fs.mkdtempSync(path.join(os.tmpdir(), 'factory-test-'));
    const v = createVault('file', testDir);
    expect(v).toBeInstanceOf(FileVault);
    fs.rmSync(testDir, { recursive: true, force: true });
  });

  test('defaults to MemoryVault for unknown type', () => {
    const v = createVault('unknown');
    expect(v).toBeInstanceOf(MemoryVault);
  });
});
