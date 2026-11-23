/** Token Style: sequential stays the default, random ids hide the session count and still restore. */
import type { IDataObject } from 'n8n-workflow';
import { redactValue, restoreValue } from '../nodes/Redactor/engine';
import { parseTenantProfile } from '../nodes/Redactor/profiles';
import { engineSetup, persist, run } from './harness';

const TOKEN = /\[EMAIL_\d{9}\]/;

describe('Token Style', () => {
  it('keeps numbering from zero when the style is left unset', async () => {
    const [out] = await run({ operation: 'redact', sessionId: 'seq' }, [{ note: 'mail a@example.com' }]);
    expect(out[0].json.note).toBe('mail [EMAIL_0]');
  });

  it('writes a nine-digit id, deduplicates it, and restores both copies', async () => {
    const store: IDataObject = {};
    const input = { note: 'mail a@example.com', copy: 'again a@example.com', other: 'mail b@example.com' };
    const [out] = await run(
      { operation: 'redact', sessionId: 'rand', tokenStyle: 'random' },
      [input],
      { staticData: store },
    );
    const note = out[0].json.note as string;
    const copy = out[0].json.copy as string;
    const other = out[0].json.other as string;
    const first = note.match(TOKEN)?.[0];
    const second = other.match(TOKEN)?.[0];
    expect(first).toBeDefined();
    expect(copy).toBe(`again ${first}`);
    expect(second).toBeDefined();
    expect(second).not.toBe(first);
    expect(note).not.toMatch(/\[EMAIL_\d{1,8}\]/);

    const [back] = await run({ operation: 'restore', sessionId: 'rand' }, [out[0].json], { staticData: persist(store) });
    expect(back[0].json).toEqual(input);
  });

  it('keeps an earlier sequential token and gives the next value a random id', async () => {
    const store: IDataObject = {};
    const [first] = await run({ operation: 'redact', sessionId: 'mix', tokenStyle: 'sequential' }, [{ note: 'mail a@example.com' }], {
      staticData: store,
    });
    expect(first[0].json.note).toBe('mail [EMAIL_0]');

    const [second] = await run(
      { operation: 'redact', sessionId: 'mix', tokenStyle: 'random' },
      [{ note: 'mail a@example.com', other: 'mail b@example.com' }],
      { staticData: store },
    );
    expect(second[0].json.note).toBe('mail [EMAIL_0]');
    expect(second[0].json.other).toMatch(/^mail \[EMAIL_\d{9}\]$/);
  });

  it('a tenant profile can select random ids', async () => {
    const [out] = await run(
      {
        operation: 'redact',
        sessionId: 'prof',
        useTenantProfile: true,
        tenantProfile: { tokenStyle: 'random', enabledPatterns: ['email'] },
      },
      [{ note: 'mail a@example.com' }],
    );
    expect(out[0].json.note).toMatch(/^mail \[EMAIL_\d{9}\]$/);
  });

  it('refuses an unknown token style', async () => {
    await expect(
      run({ operation: 'redact', sessionId: 'bad', tokenStyle: 'shuffle' }, [{ note: 'mail a@example.com' }]),
    ).rejects.toThrow(/Token Style must be sequential or random/);
  });

  it('parses tokenStyle from a profile and rejects anything else', () => {
    expect(parseTenantProfile({ tokenStyle: 'random' }).tokenStyle).toBe('random');
    expect(() => parseTenantProfile({ tokenStyle: 'shuffle' })).toThrow(/tokenStyle must be one of/);
  });

  it('skips a random id that is already reserved or stored, then restores', () => {
    const draws = [42, 99, 7];
    const sessionId = 'token-style-collision';
    const { vault, ctx, hits } = engineSetup({
      enabledPatterns: ['email'],
      tokenStyle: 'random',
      reservedTokens: new Set(['[EMAIL_000000042]']),
      tokenRandom: (span) => {
        expect(span).toBe(1_000_000_000);
        return draws.shift() ?? 7;
      },
    });
    vault.getOrCreateSession(sessionId, 0);
    vault.addEntry(sessionId, {
      token: '[EMAIL_000000099]',
      original: 'taken@example.com',
      patternLabel: 'EMAIL',
      category: 'contact',
      createdAt: '',
    });
    try {
      const out = redactValue({ note: 'mail collision-case@example.com' }, ctx, vault, sessionId, hits, 0) as { note: string };
      expect(out.note).toBe('mail [EMAIL_000000007]');
      expect(restoreValue(out, vault, sessionId)).toEqual({ note: 'mail collision-case@example.com' });
      expect(draws).toEqual([]);
    } finally {
      vault.deleteSession(sessionId);
    }
  });

  it('stops when every draw is already taken', () => {
    const sessionId = 'token-style-exhaust';
    const { vault, ctx, hits } = engineSetup({
      enabledPatterns: ['email'],
      tokenStyle: 'random',
      reservedTokens: new Set(['[EMAIL_000000042]']),
      tokenRandom: () => 42,
    });
    vault.getOrCreateSession(sessionId, 0);
    try {
      expect(() => redactValue({ note: 'mail exhaust-case@example.com' }, ctx, vault, sessionId, hits, 0)).toThrow(
        /Could not allocate a random token/,
      );
    } finally {
      vault.deleteSession(sessionId);
    }
  });
});
