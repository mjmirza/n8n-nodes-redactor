// CODE_DELETE_OK: FileVault removed in 2.0 because n8n verification bans fs; it stays on release/1.x.
import * as crypto from 'crypto';
import { VaultEntry, VaultSession } from './types';
import { encryptVaultData, decryptVaultData } from './encryption';

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

function isExpired(createdAt: string, ttl: number, now = Date.now()): boolean {
  if (!(ttl > 0)) return false;
  return now - new Date(createdAt).getTime() > ttl;
}

// ── In-memory vault ──

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
    if (isExpired(session.createdAt, session.ttl)) {
      memoryStore.delete(sessionId);
      reverseIndex.delete(sessionId);
      return null;
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

  // Required by IVault (called through the interface), so it is not dead code.
  // fallow-ignore-next-line unused-class-member
  save(): void {
    // No-op for memory vault
  }

  cleanup(): number {
    let removed = 0;
    const now = Date.now();
    for (const [id, session] of memoryStore.entries()) {
      if (isExpired(session.createdAt, session.ttl, now)) {
        memoryStore.delete(id);
        reverseIndex.delete(id);
        removed++;
      }
    }
    return removed;
  }
}

// ── Workflow vault (n8n workflow static data) ──

/** createdAt and ttl stay readable so expired sessions go without the passphrase. */
interface StoredSession {
  createdAt: string;
  ttl: number;
  session?: VaultSession;
  cipher?: string; // base64 of the encrypted vault format
}

/** The JSON-serializable object the vault reads and writes, normally workflow static data. */
export type VaultStore = Record<string, unknown>;

const STORE_KEY = 'redactorVault';
const MAX_STORED_SESSIONS = 500;

/** Persists in workflow static data. n8n saves it after production executions only. */
export class WorkflowVault implements IVault {
  private cache: Map<string, VaultSession> = new Map();

  constructor(
    private store: VaultStore,
    private passphrase = '',
  ) {
    const existing = store[STORE_KEY];
    if (!existing || typeof existing !== 'object' || Array.isArray(existing)) {
      store[STORE_KEY] = {};
    }
    this.cleanup();
  }

  private get sessions(): Record<string, StoredSession> {
    return this.store[STORE_KEY] as Record<string, StoredSession>;
  }

  private key(sessionId: string): string {
    return crypto.createHash('sha256').update(sessionId).digest('hex').slice(0, 32);
  }

  private decode(stored: StoredSession): VaultSession | null {
    try {
      if (stored.session) return stored.session;
      if (stored.cipher) {
        if (!this.passphrase) return null;
        return JSON.parse(decryptVaultData(Buffer.from(stored.cipher, 'base64'), this.passphrase)) as VaultSession;
      }
    } catch {
      // Wrong passphrase or tampered data. Treated as not found.
    }
    return null;
  }

  private load(sessionId: string): VaultSession | null {
    const cached = this.cache.get(sessionId);
    if (cached) {
      if (isExpired(cached.createdAt, cached.ttl)) {
        this.deleteSession(sessionId);
        return null;
      }
      return cached;
    }
    const k = this.key(sessionId);
    const stored = this.sessions[k];
    if (!stored) return null;
    if (isExpired(stored.createdAt, stored.ttl)) {
      delete this.sessions[k];
      return null;
    }
    const session = this.decode(stored);
    if (!session || session.sessionId !== sessionId) return null;
    this.cache.set(sessionId, session);
    return session;
  }

  getOrCreateSession(sessionId: string, ttl: number): VaultSession {
    this.cleanup();
    const existing = this.load(sessionId);
    if (existing) return existing;
    const session: VaultSession = { sessionId, entries: {}, createdAt: new Date().toISOString(), ttl };
    this.cache.set(sessionId, session);
    return session;
  }

  getSession(sessionId: string): VaultSession | null {
    return this.load(sessionId);
  }

  addEntry(sessionId: string, entry: VaultEntry): void {
    const session = this.cache.get(sessionId);
    if (session) session.entries[entry.token] = entry;
  }

  findByOriginal(sessionId: string, original: string): VaultEntry | undefined {
    const session = this.cache.get(sessionId);
    if (!session) return undefined;
    return Object.values(session.entries).find((e) => e.original === original);
  }

  deleteSession(sessionId: string): void {
    this.cache.delete(sessionId);
    delete this.sessions[this.key(sessionId)];
  }

  listSessions(): Array<{ sessionId: string; entryCount: number; createdAt: string; ttl: number }> {
    const out: Array<{ sessionId: string; entryCount: number; createdAt: string; ttl: number }> = [];
    for (const stored of Object.values(this.sessions)) {
      const session = this.decode(stored);
      if (!session) continue; // Encrypted with another passphrase, or corrupt
      out.push({
        sessionId: session.sessionId,
        entryCount: Object.keys(session.entries).length,
        createdAt: session.createdAt,
        ttl: session.ttl,
      });
    }
    return out;
  }

  save(sessionId: string): void {
    const session = this.cache.get(sessionId);
    if (!session) return;
    const k = this.key(sessionId);
    if (!this.sessions[k]) this.evictIfFull();
    const stored: StoredSession = { createdAt: session.createdAt, ttl: session.ttl };
    if (this.passphrase) {
      stored.cipher = encryptVaultData(JSON.stringify(session), this.passphrase).toString('base64');
    } else {
      stored.session = session;
    }
    this.sessions[k] = stored;
  }

  private evictIfFull(): void {
    const keys = Object.keys(this.sessions);
    if (keys.length < MAX_STORED_SESSIONS) return;
    keys
      .sort((a, b) => new Date(this.sessions[a].createdAt).getTime() - new Date(this.sessions[b].createdAt).getTime())
      .slice(0, keys.length - MAX_STORED_SESSIONS + 1)
      .forEach((k) => delete this.sessions[k]);
  }

  cleanup(): number {
    let removed = 0;
    const now = Date.now();
    for (const [k, stored] of Object.entries(this.sessions)) {
      if (!stored || typeof stored !== 'object' || isExpired(stored.createdAt, stored.ttl, now)) {
        delete this.sessions[k];
        removed++;
      }
    }
    for (const [id, session] of this.cache.entries()) {
      if (isExpired(session.createdAt, session.ttl, now)) this.cache.delete(id);
    }
    return removed;
  }
}

/** 'workflow' and the 1.x value 'file' persist in the store; anything else is in memory. */
export function createVault(storage: string, store?: VaultStore, passphrase?: string): IVault {
  if ((storage === 'workflow' || storage === 'file') && store) {
    return new WorkflowVault(store, passphrase || '');
  }
  return new MemoryVault();
}
