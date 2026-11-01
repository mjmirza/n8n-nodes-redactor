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
  // Erasure removes every record, expired or unreadable included, never only the live ones.
  purgeAll(): PurgeResult;
  purgeSession(sessionId: string): { found: boolean; entries: number | null };
}

export interface PurgeResult {
  sessions: number;
  entries: number;
}

function isExpired(createdAt: string, ttl: number, now = Date.now()): boolean {
  if (!(ttl > 0)) return false;
  return now - new Date(createdAt).getTime() > ttl;
}

// ── In-memory vault ──

const memoryStore: Map<string, VaultSession> = new Map();
const reverseIndex: Map<string, Map<string, VaultEntry>> = new Map();
const MAX_SESSIONS = 1000; // Per workflow, so one workflow cannot evict another
const MAX_TOTAL_SESSIONS = 20000; // Hard memory ceiling across all workflows

/** Refuses a token that already maps to a different original. */
function assertNoConflict(session: VaultSession, entry: VaultEntry): void {
  const existing = session.entries[entry.token];
  if (existing && existing.original !== entry.original) {
    throw new Error('Vault token already maps to a different value in this session');
  }
}

/** Process-wide memory store, scoped per workflow so sessions never cross workflows. */
export class MemoryVault implements IVault {
  constructor(private namespace = '') {}

  private key(sessionId: string): string {
    return `${this.namespace}\u0000${sessionId}`;
  }

  private ownKeys(): string[] {
    const prefix = `${this.namespace}\u0000`;
    return Array.from(memoryStore.keys()).filter((k) => k.startsWith(prefix));
  }

  private drop(key: string): void {
    memoryStore.delete(key);
    reverseIndex.delete(key);
  }

  private evictIfFull(key: string): void {
    if (memoryStore.has(key)) return;
    const own = this.ownKeys();
    if (own.length >= MAX_SESSIONS) this.drop(own[0]);
    if (memoryStore.size >= MAX_TOTAL_SESSIONS) {
      const oldest = memoryStore.keys().next().value;
      if (oldest !== undefined) this.drop(oldest);
    }
  }

  getOrCreateSession(sessionId: string, ttl: number): VaultSession {
    this.cleanup();
    const key = this.key(sessionId);
    this.evictIfFull(key);
    if (!memoryStore.has(key)) {
      memoryStore.set(key, { sessionId, entries: {}, createdAt: new Date().toISOString(), ttl });
    }
    return memoryStore.get(key)!;
  }

  getSession(sessionId: string): VaultSession | null {
    const key = this.key(sessionId);
    const session = memoryStore.get(key);
    if (!session) return null;
    if (isExpired(session.createdAt, session.ttl)) {
      this.drop(key);
      return null;
    }
    return session;
  }

  addEntry(sessionId: string, entry: VaultEntry): void {
    const key = this.key(sessionId);
    const session = memoryStore.get(key);
    if (!session) return;
    assertNoConflict(session, entry);
    session.entries[entry.token] = entry;
    const index = this.index(key, session);
    const first = index.get(entry.original);
    if (!first || first.token === entry.token) index.set(entry.original, entry);
  }

  findByOriginal(sessionId: string, original: string): VaultEntry | undefined {
    const key = this.key(sessionId);
    const session = memoryStore.get(key);
    return session ? this.index(key, session).get(original) : undefined;
  }

  /** The first entry per original. Built once per session and kept current, so a miss never scans every entry. */
  private index(key: string, session: VaultSession): Map<string, VaultEntry> {
    let index = reverseIndex.get(key);
    if (!index) {
      index = new Map();
      for (const e of Object.values(session.entries)) if (!index.has(e.original)) index.set(e.original, e);
      reverseIndex.set(key, index);
    }
    return index;
  }

  deleteSession(sessionId: string): void {
    this.drop(this.key(sessionId));
  }

  // Called through IVault from the Purge operation, so it is not dead code.
  // fallow-ignore-next-line unused-class-member
  purgeAll(): PurgeResult {
    const keys = this.ownKeys();
    const entries = keys.reduce((n, k) => n + Object.keys(memoryStore.get(k)?.entries ?? {}).length, 0);
    keys.forEach((k) => this.drop(k));
    return { sessions: keys.length, entries };
  }

  // Called through IVault from the Purge operation, so it is not dead code.
  // fallow-ignore-next-line unused-class-member
  purgeSession(sessionId: string): { found: boolean; entries: number | null } {
    const session = memoryStore.get(this.key(sessionId));
    this.deleteSession(sessionId);
    return { found: !!session, entries: session ? Object.keys(session.entries).length : null };
  }

  listSessions(): Array<{ sessionId: string; entryCount: number; createdAt: string; ttl: number }> {
    return this.ownKeys()
      .map((k) => memoryStore.get(k)!)
      .filter((s) => !isExpired(s.createdAt, s.ttl))
      .map((s) => ({
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
    for (const [key, session] of memoryStore.entries()) {
      if (isExpired(session.createdAt, session.ttl, now)) {
        this.drop(key);
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
  private readonly originals = new WeakMap<VaultSession, Map<string, VaultEntry>>();

  private cache: Map<string, VaultSession> = new Map();

  // Reads never write the store, so read-only runs cannot persist a stale snapshot.
  constructor(
    private store: VaultStore,
    private passphrase = '',
  ) {}

  private get sessions(): Record<string, StoredSession> {
    const existing = this.store[STORE_KEY];
    if (existing && typeof existing === 'object' && !Array.isArray(existing)) {
      return existing as Record<string, StoredSession>;
    }
    return {};
  }

  private writableSessions(): Record<string, StoredSession> {
    const existing = this.store[STORE_KEY];
    if (!existing || typeof existing !== 'object' || Array.isArray(existing)) this.store[STORE_KEY] = {};
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
      // Wrong passphrase or tampered data. Callers decide whether that is fatal.
    }
    return null;
  }

  /** A live record exists for this ID but this passphrase cannot open it. */
  private isUnreadable(sessionId: string): boolean {
    const stored = this.sessions[this.key(sessionId)];
    if (!stored || typeof stored !== 'object' || isExpired(stored.createdAt, stored.ttl)) return false;
    const session = this.decode(stored);
    return !session || session.sessionId !== sessionId;
  }

  private load(sessionId: string): VaultSession | null {
    const cached = this.cache.get(sessionId);
    if (cached) return isExpired(cached.createdAt, cached.ttl) ? null : cached;
    const stored = this.sessions[this.key(sessionId)];
    if (!stored || isExpired(stored.createdAt, stored.ttl)) return null;
    const session = this.decode(stored);
    if (!session || session.sessionId !== sessionId) return null;
    this.cache.set(sessionId, session);
    return session;
  }

  getOrCreateSession(sessionId: string, ttl: number): VaultSession {
    this.cleanup();
    const existing = this.load(sessionId);
    if (existing) return existing;
    if (this.isUnreadable(sessionId)) {
      throw new Error(
        'Session exists but cannot be decrypted with this passphrase. Use the passphrase it was written with, or a different Session ID.',
      );
    }
    const session: VaultSession = { sessionId, entries: {}, createdAt: new Date().toISOString(), ttl };
    this.cache.set(sessionId, session);
    return session;
  }

  getSession(sessionId: string): VaultSession | null {
    return this.load(sessionId);
  }

  addEntry(sessionId: string, entry: VaultEntry): void {
    const session = this.cache.get(sessionId);
    if (!session) return;
    assertNoConflict(session, entry);
    session.entries[entry.token] = entry;
    const index = this.originals.get(session);
    const first = index?.get(entry.original);
    if (index && (!first || first.token === entry.token)) index.set(entry.original, entry);
  }

  findByOriginal(sessionId: string, original: string): VaultEntry | undefined {
    const session = this.cache.get(sessionId);
    if (!session) return undefined;
    return this.originalIndex(session).get(original);
  }

  /** First entry per original, built once per session, so lookups never scan every entry. */
  private originalIndex(session: VaultSession): Map<string, VaultEntry> {
    let index = this.originals.get(session);
    if (!index) {
      index = new Map();
      for (const entry of Object.values(session.entries)) if (!index.has(entry.original)) index.set(entry.original, entry);
      this.originals.set(session, index);
    }
    return index;
  }

  deleteSession(sessionId: string): void {
    this.cache.delete(sessionId);
    const k = this.key(sessionId);
    if (k in this.sessions) delete this.writableSessions()[k];
  }

  // Called through IVault from the Purge operation, so it is not dead code.
  // fallow-ignore-next-line unused-class-member
  purgeAll(): PurgeResult {
    const stored = Object.values(this.sessions);
    const entries = stored.reduce((n, rec) => {
      const session = rec && typeof rec === 'object' ? this.decode(rec) : null;
      return n + (session ? Object.keys(session.entries).length : 0);
    }, 0);
    this.cache.clear();
    if (stored.length) this.store[STORE_KEY] = {};
    return { sessions: stored.length, entries };
  }

  /** Deletes by stored key, so expired or unreadable records go too. Called through IVault. */
  // fallow-ignore-next-line unused-class-member
  purgeSession(sessionId: string): { found: boolean; entries: number | null } {
    const stored = this.sessions[this.key(sessionId)];
    const live = this.cache.get(sessionId) ?? (stored && typeof stored === 'object' ? this.decode(stored) : null);
    const found = !!stored || this.cache.has(sessionId);
    this.deleteSession(sessionId);
    return { found, entries: live && live.sessionId === sessionId ? Object.keys(live.entries).length : null };
  }

  listSessions(): Array<{ sessionId: string; entryCount: number; createdAt: string; ttl: number }> {
    const out: Array<{ sessionId: string; entryCount: number; createdAt: string; ttl: number }> = [];
    for (const stored of Object.values(this.sessions)) {
      if (!stored || typeof stored !== 'object' || isExpired(stored.createdAt, stored.ttl)) continue;
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
    if (this.isUnreadable(sessionId)) {
      throw new Error('Refusing to overwrite session: it cannot be decrypted with this passphrase.');
    }
    const sessions = this.writableSessions();
    const k = this.key(sessionId);
    if (!sessions[k]) this.evictIfFull();
    const stored: StoredSession = { createdAt: session.createdAt, ttl: session.ttl };
    if (this.passphrase) {
      stored.cipher = encryptVaultData(JSON.stringify(session), this.passphrase).toString('base64');
    } else {
      stored.session = session;
    }
    sessions[k] = stored;
  }

  private evictIfFull(): void {
    const sessions = this.writableSessions();
    const keys = Object.keys(sessions);
    if (keys.length < MAX_STORED_SESSIONS) return;
    keys
      .sort((a, b) => new Date(sessions[a].createdAt).getTime() - new Date(sessions[b].createdAt).getTime())
      .slice(0, keys.length - MAX_STORED_SESSIONS + 1)
      .forEach((k) => delete sessions[k]);
  }

  cleanup(): number {
    let removed = 0;
    const now = Date.now();
    const stale = Object.entries(this.sessions)
      .filter(([, stored]) => !stored || typeof stored !== 'object' || isExpired(stored.createdAt, stored.ttl, now))
      .map(([k]) => k);
    if (stale.length) {
      const sessions = this.writableSessions();
      for (const k of stale) {
        delete sessions[k];
        removed++;
      }
    }
    for (const [id, session] of this.cache.entries()) {
      if (isExpired(session.createdAt, session.ttl, now)) this.cache.delete(id);
    }
    return removed;
  }
}

/** 'workflow' and the 1.x value 'file' persist in the store; memory is scoped by namespace. */
export function createVault(storage: string, store?: VaultStore, passphrase?: string, namespace = ''): IVault {
  if ((storage === 'workflow' || storage === 'file') && store) {
    return new WorkflowVault(store, passphrase || '');
  }
  return new MemoryVault(namespace);
}
