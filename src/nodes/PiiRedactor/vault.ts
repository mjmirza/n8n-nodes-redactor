import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { VaultEntry, VaultSession, PiiCategory } from './types';
import { encryptVaultData, decryptVaultData, isEncryptedVault, isPlaintextVault } from './encryption';

/**
 * Abstract vault interface — storage backend for token ↔ original mappings.
 */
export interface IVault {
  getOrCreateSession(sessionId: string, ttl: number): VaultSession;
  getSession(sessionId: string): VaultSession | null;
  addEntry(sessionId: string, entry: VaultEntry): void;
  findByOriginal(sessionId: string, original: string): VaultEntry | undefined;
  deleteSession(sessionId: string): void;
  listSessions(): Array<{ sessionId: string; entryCount: number; createdAt: string; ttl: number }>;
  save(sessionId: string): void;
  cleanup(): number; // returns number of expired sessions removed
}

// ═══════════════════════════════════════════════════════════
// In-memory vault
// ═══════════════════════════════════════════════════════════

const memoryStore: Map<string, VaultSession> = new Map();
const reverseIndex: Map<string, Map<string, VaultEntry>> = new Map();
const MAX_SESSIONS = 1000; // Prevent unbounded memory growth

export class MemoryVault implements IVault {
  getOrCreateSession(sessionId: string, ttl: number): VaultSession {
    // Auto-cleanup expired sessions on every create to prevent memory leak
    this.cleanup();
    // Enforce max session limit
    if (memoryStore.size >= MAX_SESSIONS && !memoryStore.has(sessionId)) {
      // Evict oldest session
      const oldest = memoryStore.keys().next().value;
      if (oldest !== undefined) {
        memoryStore.delete(oldest);
        reverseIndex.delete(oldest);
      }
    }
    if (!memoryStore.has(sessionId)) {
      memoryStore.set(sessionId, {
        sessionId,
        entries: {},
        createdAt: new Date().toISOString(),
        ttl,
      });
    }
    return memoryStore.get(sessionId)!;
  }

  getSession(sessionId: string): VaultSession | null {
    const session = memoryStore.get(sessionId);
    if (!session) return null;
    // Check expiry
    if (session.ttl > 0) {
      const created = new Date(session.createdAt).getTime();
      if (Date.now() - created > session.ttl) {
        memoryStore.delete(sessionId);
        return null;
      }
    }
    return session;
  }

  addEntry(sessionId: string, entry: VaultEntry): void {
    const session = memoryStore.get(sessionId);
    if (session) {
      session.entries[entry.token] = entry;
      // Maintain reverse lookup index for O(1) dedup
      if (!reverseIndex.has(sessionId)) reverseIndex.set(sessionId, new Map());
      reverseIndex.get(sessionId)!.set(entry.original, entry);
    }
  }

  findByOriginal(sessionId: string, original: string): VaultEntry | undefined {
    // O(1) lookup via reverse index instead of O(n) scan
    const index = reverseIndex.get(sessionId);
    if (index) {
      const entry = index.get(original);
      if (entry) return entry;
    }
    // Fallback to linear scan (for sessions loaded without index)
    const session = memoryStore.get(sessionId);
    if (!session) return undefined;
    return Object.values(session.entries).find((e) => e.original === original);
  }

  deleteSession(sessionId: string): void {
    memoryStore.delete(sessionId);
    reverseIndex.delete(sessionId);
  }

  listSessions(): Array<{ sessionId: string; entryCount: number; createdAt: string; ttl: number }> {
    return Array.from(memoryStore.values()).map((s) => ({
      sessionId: s.sessionId,
      entryCount: Object.keys(s.entries).length,
      createdAt: s.createdAt,
      ttl: s.ttl,
    }));
  }

  save(): void {
    // No-op for memory vault
  }

  cleanup(): number {
    let removed = 0;
    const now = Date.now();
    for (const [id, session] of memoryStore.entries()) {
      if (session.ttl > 0) {
        const created = new Date(session.createdAt).getTime();
        if (now - created > session.ttl) {
          memoryStore.delete(id);
          reverseIndex.delete(id);
          removed++;
        }
      }
    }
    return removed;
  }
}

// ═══════════════════════════════════════════════════════════
// File-based vault (JSON files in a directory)
// ═══════════════════════════════════════════════════════════

export class FileVault implements IVault {
  private dir: string;
  private cache: Map<string, VaultSession> = new Map();
  private passphrase: string;

  constructor(dir?: string, passphrase?: string) {
    this.passphrase = passphrase || '';
    this.dir = dir || path.join(process.env.HOME || '/tmp', '.n8n', 'pii-vault');
    if (!fs.existsSync(this.dir)) {
      fs.mkdirSync(this.dir, { recursive: true });
    }
    // Auto-cleanup expired files on every instantiation
    this.cleanup();
  }

  private filePath(sessionId: string): string {
    // Hash session ID for safe filenames — use 32 hex chars (128 bits) to avoid collisions
    const hash = crypto.createHash('sha256').update(sessionId).digest('hex').slice(0, 32);
    return path.join(this.dir, `vault_${hash}.json`);
  }

  private load(sessionId: string): VaultSession | null {
    if (this.cache.has(sessionId)) {
      return this.cache.get(sessionId)!;
    }
    const fp = this.filePath(sessionId);
    if (!fs.existsSync(fp)) return null;
    try {
      const raw = fs.readFileSync(fp);
      let jsonStr: string;

      if (isEncryptedVault(raw)) {
        // Encrypted file — decrypt with passphrase
        if (!this.passphrase) {
          // Encrypted but no passphrase — cannot read
          return null;
        }
        jsonStr = decryptVaultData(raw, this.passphrase);
      } else if (isPlaintextVault(raw)) {
        // Plaintext JSON — read directly
        jsonStr = raw.toString('utf-8');
      } else {
        // Unknown format
        return null;
      }

      const data = JSON.parse(jsonStr) as VaultSession;
      // Check expiry
      if (data.ttl > 0) {
        const created = new Date(data.createdAt).getTime();
        if (Date.now() - created > data.ttl) {
          try { fs.unlinkSync(fp); } catch { /* ignore */ }
          return null;
        }
      }
      this.cache.set(sessionId, data);
      return data;
    } catch {
      return null;
    }
  }

  getOrCreateSession(sessionId: string, ttl: number): VaultSession {
    // Auto-cleanup expired files before creating new sessions
    this.cleanup();
    const existing = this.load(sessionId);
    if (existing) return existing;
    const session: VaultSession = {
      sessionId,
      entries: {},
      createdAt: new Date().toISOString(),
      ttl,
    };
    this.cache.set(sessionId, session);
    return session;
  }

  getSession(sessionId: string): VaultSession | null {
    return this.load(sessionId);
  }

  addEntry(sessionId: string, entry: VaultEntry): void {
    const session = this.cache.get(sessionId);
    if (session) {
      session.entries[entry.token] = entry;
    }
  }

  findByOriginal(sessionId: string, original: string): VaultEntry | undefined {
    const session = this.cache.get(sessionId);
    if (!session) return undefined;
    return Object.values(session.entries).find((e) => e.original === original);
  }

  deleteSession(sessionId: string): void {
    this.cache.delete(sessionId);
    try {
      const fp = this.filePath(sessionId);
      if (fs.existsSync(fp)) {
        fs.unlinkSync(fp);
      }
    } catch {
      // Ignore file deletion errors (read-only FS, already deleted, etc.)
    }
  }

  listSessions(): Array<{ sessionId: string; entryCount: number; createdAt: string; ttl: number }> {
    // List all vault files
    const files = fs.readdirSync(this.dir).filter((f) => f.startsWith('vault_') && f.endsWith('.json'));
    const sessions: Array<{ sessionId: string; entryCount: number; createdAt: string; ttl: number }> = [];
    for (const file of files) {
      try {
        const fp = path.join(this.dir, file);
        const raw = fs.readFileSync(fp);
        let jsonStr: string;

        if (isEncryptedVault(raw)) {
          if (!this.passphrase) continue; // Can't read without passphrase
          try {
            jsonStr = decryptVaultData(raw, this.passphrase);
          } catch {
            continue; // Wrong passphrase or corrupted
          }
        } else if (isPlaintextVault(raw)) {
          jsonStr = raw.toString('utf-8');
        } else {
          continue;
        }

        const data = JSON.parse(jsonStr) as VaultSession;
        sessions.push({
          sessionId: data.sessionId,
          entryCount: Object.keys(data.entries).length,
          createdAt: data.createdAt,
          ttl: data.ttl,
        });
      } catch {
        // Skip corrupt files
      }
    }
    return sessions;
  }

  save(sessionId: string): void {
    const session = this.cache.get(sessionId);
    if (session) {
      try {
        const fp = this.filePath(sessionId);
        const tmpFp = fp + '.tmp';
        const jsonData = JSON.stringify(session, null, 2);

        if (this.passphrase) {
          // Encrypt vault data before writing
          const encrypted = encryptVaultData(jsonData, this.passphrase);
          fs.writeFileSync(tmpFp, encrypted);
        } else {
          // Write plaintext JSON
          fs.writeFileSync(tmpFp, jsonData, 'utf-8');
        }
        fs.renameSync(tmpFp, fp);
      } catch {
        // Write failed (read-only FS, permissions, disk full).
        // Session stays in memory cache — restore will still work
        // for this execution, just won't persist across restarts.
      }
    }
  }

  cleanup(): number {
    let removed = 0;
    const now = Date.now();
    const files = fs.readdirSync(this.dir).filter((f) => f.startsWith('vault_') && f.endsWith('.json'));
    for (const file of files) {
      try {
        const fp = path.join(this.dir, file);
        const data = JSON.parse(fs.readFileSync(fp, 'utf-8')) as VaultSession;
        if (data.ttl > 0) {
          const created = new Date(data.createdAt).getTime();
          if (now - created > data.ttl) {
            fs.unlinkSync(fp);
            this.cache.delete(data.sessionId);
            removed++;
          }
        }
      } catch {
        // Skip
      }
    }
    return removed;
  }
}

/**
 * Factory to get the right vault implementation.
 * If file vault fails (read-only filesystem, no permissions, Docker, cloud),
 * automatically falls back to memory vault so the node never crashes.
 */
export function createVault(storage: string, vaultDir?: string, passphrase?: string): IVault {
  if (storage === 'file') {
    try {
      return new FileVault(vaultDir, passphrase);
    } catch {
      // Filesystem not writable — fall back to memory vault silently
      return new MemoryVault();
    }
  }
  return new MemoryVault();
}
