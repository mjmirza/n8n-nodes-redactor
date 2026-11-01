/**
 * Regression tests for the sixth Codex review of the 7.0.0 branch, one block per finding, using the review's inputs.
 */
import { MemoryVault } from '../nodes/Redactor/vault';

import { run } from './harness';

async function redactNote(note: string): Promise<string> {
  const [out] = await run({ operation: 'redact', sessionId: 'r75' }, [{ note }]);
  return out[0].json.note as string;
}

async function verifyStatus(note: string): Promise<unknown> {
  const [out] = await run({ operation: 'verify' }, [{ note }], { typeVersion: 2 });
  return out[0].json.status;
}

describe('re-review 75-1: quoted environment secrets', () => {
  it.each([
    ["DB_PASS='azure zebra'", 'zebra'],
    ['MASTER_KEY="alpha bravo charlie"', 'charlie'],
    ['MASTER_KEY="line one\nline two"', 'line two'],
  ])('%j is redacted whole and fails Verify', async (text, tail) => {
    expect(await redactNote(text)).not.toContain(tail);
    expect(await verifyStatus(text)).toBe('FAIL');
  });
});

describe('re-review 75-2: international email addresses', () => {
  it.each([
    ['alice@उदाहरण.भारत'],
    ['alice@café.example'],
  ])('%s is redacted and fails Verify', async (address) => {
    expect(await redactNote(`mail ${address} now`)).not.toContain('alice@');
    expect(await verifyStatus(`mail ${address} now`)).toBe('FAIL');
  });
});

describe('re-review 75-3: a profile that changes only the field mode', () => {
  it('re-targets the node rules instead of excluding every field', async () => {
    const [out] = await run(
      {
        operation: 'redact', sessionId: 'r75p', fieldMode: 'denylist', fieldRules: { rules: [{ field: 'note' }] },
        useTenantProfile: true, tenantProfile: { fieldMode: 'allowlist' },
      },
      [{ note: 'mail bob@example.com', other: 'x' }],
    );
    expect(out[0].json.note).not.toContain('bob@example.com');
  });
});

describe('re-review 75-4: Restore uses one session for the whole batch', () => {
  it('restores every item even when the session expires mid-batch', async () => {
    const [redacted] = await run({ operation: 'redact', sessionId: 'r75r', sessionTtl: 60, vaultStorage: 'memory' }, [{ e: 'a@example.com' }, { e: 'b@example.com' }]);
    const realNow = Date.now.bind(Date);
    let offset = 0;
    const clock = jest.spyOn(Date, 'now').mockImplementation(() => realNow() + offset);
    const realGet = MemoryVault.prototype.getSession;
    // The session check passes, then the clock moves past the 60-minute TTL.
    const get = jest.spyOn(MemoryVault.prototype, 'getSession').mockImplementation(function (this: MemoryVault, id: string) {
      const session = realGet.call(this, id);
      offset = 3 * 60 * 60 * 1000;
      return session;
    });
    try {
      const [out] = await run({ operation: 'restore', sessionId: 'r75r', vaultStorage: 'memory' }, redacted.map((r) => r.json));
      expect(out.map((r) => r.json.e)).toEqual(['a@example.com', 'b@example.com']);
    } finally {
      get.mockRestore();
      clock.mockRestore();
    }
  });
});

describe('re-review 75-5: a negative Session TTL is refused', () => {
  it('stops the run instead of keeping the vault forever', async () => {
    await expect(run({ operation: 'redact', sessionId: 'r75t', sessionTtl: -1 }, [{ note: 'a@example.com' }])).rejects.toThrow(
      /Session TTL must be 0 or more minutes/,
    );
  });
});
