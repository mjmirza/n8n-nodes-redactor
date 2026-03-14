import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { VaultEntry, VaultSession, PiiCategory } from './types';

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

export class MemoryVault implements IVault {
  getOrCreateSession(sessionId: string, ttl: number): VaultSession {
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
    }
  }

  findByOriginal(sessionId: string, original: string): VaultEntry | undefined {
    const session = memoryStore.get(sessionId);
    if (!session) return undefined;
    return Object.values(session.entries).find((e) => e.original === original);
  }

  deleteSession(sessionId: string): void {
    memoryStore.delete(sessionId);
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

  constructor(dir?: string) {
    this.dir = dir || path.join(process.env.HOME || '/tmp', '.n8n', 'pii-vault');
    if (!fs.existsSync(this.dir)) {
      fs.mkdirSync(this.dir, { recursive: true });
    }
  }

  private filePath(sessionId: string): string {
    // Hash session ID for safe filenames
    const hash = crypto.createHash('sha256').update(sessionId).digest('hex').slice(0, 16);
    return path.join(this.dir, `vault_${hash}.json`);
  }

  private load(sessionId: string): VaultSession | null {
    if (this.cache.has(sessionId)) {
      return this.cache.get(sessionId)!;
    }
    const fp = this.filePath(sessionId);
    if (!fs.existsSync(fp)) return null;
    try {
      const data = JSON.parse(fs.readFileSync(fp, 'utf-8')) as VaultSession;
      // Check expiry
      if (data.ttl > 0) {
        const created = new Date(data.createdAt).getTime();
        if (Date.now() - created > data.ttl) {
          fs.unlinkSync(fp);
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
    const fp = this.filePath(sessionId);
    if (fs.existsSync(fp)) {
      fs.unlinkSync(fp);
    }
  }

  listSessions(): Array<{ sessionId: string; entryCount: number; createdAt: string; ttl: number }> {
    // List all vault files
    const files = fs.readdirSync(this.dir).filter((f) => f.startsWith('vault_') && f.endsWith('.json'));
    const sessions: Array<{ sessionId: string; entryCount: number; createdAt: string; ttl: number }> = [];
    for (const file of files) {
      try {
        const data = JSON.parse(
          fs.readFileSync(path.join(this.dir, file), 'utf-8'),
        ) as VaultSession;
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
      fs.writeFileSync(this.filePath(sessionId), JSON.stringify(session, null, 2), 'utf-8');
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
 */
export function createVault(storage: string, vaultDir?: string): IVault {
  if (storage === 'file') {
    return new FileVault(vaultDir);
  }
  return new MemoryVault();
}
