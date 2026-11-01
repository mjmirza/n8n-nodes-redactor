import { MemoryVault, WorkflowVault, VaultStore, createVault } from '../nodes/Redactor/vault';
import { VaultEntry } from '../nodes/Redactor/types';

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
// WORKFLOW VAULT (n8n workflow static data)
// ═══════════════════════════════════════════════════════
/** n8n persists static data as JSON, so a round trip models a later execution. */
const persist = (store: VaultStore): VaultStore => JSON.parse(JSON.stringify(store));
const busyWait = (ms: number) => {
  const start = Date.now();
  while (Date.now() - start < ms) {
    // busy wait
  }
};

describe('WorkflowVault', () => {
  let store: VaultStore;
  let vault: WorkflowVault;

  beforeEach(() => {
    store = {};
    vault = new WorkflowVault(store);
  });

  test('initialises its namespace in the store on first write, never on read', () => {
    expect(store.redactorVault).toBeUndefined();
    vault.getOrCreateSession('init', 0);
    vault.save('init');
    expect(Object.keys(store.redactorVault as object)).toHaveLength(1);
  });

  test('recovers from a non-object namespace', () => {
    const bad: VaultStore = { redactorVault: 'garbage' };
    const v = new WorkflowVault(bad);
    expect(v.listSessions()).toEqual([]);
    v.getOrCreateSession('fresh', 0);
    v.save('fresh');
    expect(Object.keys(bad.redactorVault as object)).toHaveLength(1);
  });

  test('save writes the session into the store', () => {
    vault.getOrCreateSession('wf-1', 0);
    vault.addEntry('wf-1', makeEntry('[EMAIL_0]', 'test@wf.com'));
    vault.save('wf-1');
    expect(Object.keys(store.redactorVault as object)).toHaveLength(1);
  });

  test('a later execution reads the persisted session', () => {
    vault.getOrCreateSession('persist-test', 0);
    vault.addEntry('persist-test', makeEntry('[EMAIL_0]', 'persisted@test.com'));
    vault.save('persist-test');

    const vault2 = new WorkflowVault(persist(store));
    const session = vault2.getSession('persist-test');
    expect(session).not.toBeNull();
    expect(session!.entries['[EMAIL_0]'].original).toBe('persisted@test.com');
  });

  test('unsaved sessions are not persisted', () => {
    vault.getOrCreateSession('unsaved', 0);
    expect(new WorkflowVault(persist(store)).getSession('unsaved')).toBeNull();
  });

  test('deleteSession removes it from the store (purge)', () => {
    vault.getOrCreateSession('delete-test', 0);
    vault.addEntry('delete-test', makeEntry('[EMAIL_0]', 'x@y.com'));
    vault.save('delete-test');

    vault.deleteSession('delete-test');
    expect(Object.keys(store.redactorVault as object)).toHaveLength(0);
    expect(new WorkflowVault(persist(store)).getSession('delete-test')).toBeNull();
  });

  test('listSessions reads all stored sessions', () => {
    vault.getOrCreateSession('list-1', 0);
    vault.save('list-1');
    vault.getOrCreateSession('list-2', 0);
    vault.addEntry('list-2', makeEntry('[EMAIL_0]', 'a@b.com'));
    vault.save('list-2');

    const sessions = new WorkflowVault(persist(store)).listSessions();
    expect(sessions).toHaveLength(2);
    expect(sessions.find((s) => s.sessionId === 'list-2')!.entryCount).toBe(1);
  });

  test('TTL expiry on workflow vault', () => {
    vault.getOrCreateSession('wf-ttl', 1);
    vault.save('wf-ttl');
    busyWait(10);
    expect(new WorkflowVault(persist(store)).getSession('wf-ttl')).toBeNull();
  });

  test('cleanup removes expired sessions without the passphrase', () => {
    const enc = new WorkflowVault(store, 'pw');
    enc.getOrCreateSession('expired-enc', 1);
    enc.save('expired-enc');
    enc.getOrCreateSession('alive-enc', 0);
    enc.save('alive-enc');
    busyWait(10);

    const noKey = new WorkflowVault(store);
    expect(Object.keys(store.redactorVault as object)).toHaveLength(1);
    expect(noKey.listSessions()).toHaveLength(0); // still encrypted, so not listed
    expect(new WorkflowVault(store, 'pw').getSession('alive-enc')).not.toBeNull();
  });

  test('findByOriginal works with workflow vault', () => {
    vault.getOrCreateSession('find-test', 0);
    vault.addEntry('find-test', makeEntry('[EMAIL_0]', 'find@me.com'));
    const found = vault.findByOriginal('find-test', 'find@me.com');
    expect(found).toBeDefined();
    expect(found!.token).toBe('[EMAIL_0]');
  });

  test('handles corrupt stored entries gracefully', () => {
    store.redactorVault = { broken: 'not an object' };
    const v = new WorkflowVault(store);
    expect(Array.isArray(v.listSessions())).toBe(true);
    v.cleanup();
    expect((store.redactorVault as Record<string, unknown>).broken).toBeUndefined();
  });

  test('a hash collision on the key never returns another session', () => {
    vault.getOrCreateSession('real', 0);
    vault.save('real');
    const sessions = store.redactorVault as Record<string, { session?: { sessionId: string } }>;
    const k = Object.keys(sessions)[0];
    sessions[k].session!.sessionId = 'someone-else';
    expect(new WorkflowVault(persist(store)).getSession('real')).toBeNull();
  });
});

// ═══════════════════════════════════════════════════════
// createVault FACTORY
// ═══════════════════════════════════════════════════════
describe('createVault factory', () => {
  test('returns MemoryVault for "memory"', () => {
    expect(createVault('memory', {})).toBeInstanceOf(MemoryVault);
  });

  test('returns WorkflowVault for "workflow" with a store', () => {
    expect(createVault('workflow', {})).toBeInstanceOf(WorkflowVault);
  });

  test('maps the 1.x value "file" to WorkflowVault', () => {
    expect(createVault('file', {})).toBeInstanceOf(WorkflowVault);
  });

  test('falls back to MemoryVault when no store is given', () => {
    expect(createVault('workflow')).toBeInstanceOf(MemoryVault);
  });

  test('defaults to MemoryVault for unknown type', () => {
    expect(createVault('unknown', {})).toBeInstanceOf(MemoryVault);
  });
});
