/** Regression coverage for all three findings in re-review 80. */
import type { IDataObject } from 'n8n-workflow';
import { getPatternsByNames } from '../nodes/Redactor/patterns';
import { cpuNow, fast, persist, redactNote, run, verifyStatus } from './harness';

const connScan = getPatternsByNames(['connStringKV'])[0].scan!;

describe('re-review 80-4: connection-string credentials in arbitrary segment order', () => {
  it.each([
    ['Pwd', 'Server', 'Uid', 'Secret'],
    ['Uid', 'Pwd', 'Secret', 'Server'],
    ['Secret', 'Uid', 'Server', 'Pwd'],
    ['Server', 'Pwd', 'Secret', 'Uid'],
  ])('covers credentials in %j order', async (...keys) => {
    const username = ['acct', '0', 'alpha'].join('');
    const password = ['p4ss', '0', 'alpha'].join('');
    const secret = ['s3cr', '0', 'alpha'].join('');
    const values: Record<string, string> = { Server: 'db', Uid: username, Pwd: password, Secret: secret };
    const note = `Deployment note: ${keys.map((key) => `${key}=${values[key]}`).join(';')}; ready.`;
    const output = await redactNote(note, 'r80order');
    for (const value of [username, password, secret]) expect(output).not.toContain(value);
    expect(await verifyStatus(note)).toBe('FAIL');
  });
});

describe('re-review 80-5: authenticated connection URLs', () => {
  it.each(['postgres', 'mysql', 'mongodb', 'redis', 'amqp', 'mssql'])('covers %s credentials containing an apostrophe', async (scheme) => {
    const username = ['acct', '0', 'alpha'].join('');
    const password = ['p4ss', '0', "'", 'alpha'].join('');
    const secret = ['s3cr', '0', "'", 'alpha'].join('');
    const url = `${scheme}://${username}:${encodeURIComponent(password)}@db.example/db?token=${encodeURIComponent(secret)}`;
    const note = `Deployment note: ${url}; ready.`;
    const output = await redactNote(note, 'r80url');
    for (const value of [username, password, secret, 'alpha']) expect(output).not.toContain(value);
    expect(await verifyStatus(note)).toBe('FAIL');
  });
});

describe('re-review 80-1: leading Unicode whitespace in connection-string keywords', () => {
  it.each(['\u00a0', '\u0085', '\u1680', '\u2003', '\u202f', '\u205f', '\u3000'])('covers the complete credentials with keyword whitespace %j', async (space) => {
    const connection = ['Server=db;Uid=alice;', space, 'Pass', 'word', '=alpha bravo;'].join('');
    expect(await redactNote(connection, 'r80space')).toMatch(/^\[CONN_STRING_\d+\];$/);
    expect(connScan(connection)).toEqual([{ start: 0, end: connection.length - 1 }]);
    expect(await verifyStatus(connection)).toBe('FAIL');

    const spaced = ['Server', space, '=', space, 'db;Uid=alice;', space, 'Pwd', space, '=', space, 'alpha bravo;'].join('');
    expect(await redactNote(spaced, 'r80equals')).toMatch(/^\[CONN_STRING_\d+\];$/);
    for (const newline of ['\n', '\r', '\r\n']) {
      const separate = ['Server=db;Uid=alice;', newline, space, 'Pass', 'word', '=alpha bravo;'].join('');
      expect(connScan(separate)).toEqual([]);
    }
  });
});

describe('re-review 80-2: distinguish ADO.NET literal braces from ODBC delimiters', () => {
  it('finds later passwords under both grammars without truncating braced values or rescanning suffixes', async () => {
    const connection = ['Server=db;Application Name={worker;User ID=alice;', 'Pass', 'word', '=alpha bravo;'].join('');
    expect(await redactNote(connection, 'r80literal')).toMatch(/^\[CONN_STRING_\d+\];$/);
    expect(await verifyStatus(connection)).toBe('FAIL');
    const cases = [
      ['Server=db;Application Name={worker;User ID=alice;', 'Pass', 'word', '=alpha bravo;Ignored=x};'],
      ['Server=db;Application Name=worker{;User ID=alice;', 'Pass', 'word', '=alpha bravo;'],
      ['Server=db;Application Name= {worker};User ID=alice;', 'Pass', 'word', '=alpha bravo;'],
      ['Server=db;Uid=alice;', 'Pwd', '= {alpha;bravo charlie};'],
      ['Server=db;Uid=alice;', 'Pwd', '= {alpha;bra}}vo charlie};'],
      ['Server=db;Uid=alice;', 'Pwd', '= {alpha;bravo charlie};', 'Pass', 'word', '=delta echo;'],
      ['Server=db;Application Name="{worker;still worker}";Uid=alice;', 'Pass', 'word', ' = "alpha""bravo;charlie";'],
    ];
    for (const [index, parts] of cases.entries()) {
      const note = parts.join('');
      const [data] = await run({ operation: 'redact', vaultStorage: 'memory', sessionId: `r80grammar${index}` }, [{ note }]);
      // The first variant ends its sensitive value before an unrelated property.
      const suffix = index === 0 ? ';Ignored=x};' : ';';
      expect(data[0].json.note).toMatch(new RegExp(`^\\[CONN_STRING_\\d+\\]${suffix}$`));
      const [restored] = await run({ operation: 'restore', vaultStorage: 'memory', sessionId: `r80grammar${index}` }, [data[0].json]);
      expect(restored[0].json.note).toBe(note);
    }

    const repeated = ['Server=db;', 'Application Name={worker;'.repeat(40000), 'Pass', 'word', '=alpha bravo;'].join('');
    fast(() => {
      const spans = connScan(repeated);
      expect(spans.length).toBeGreaterThan(0);
      expect(spans.every((span) => span.start === 0 && span.end === repeated.length - 1)).toBe(true);
    }, 1000);
    const acrossLines = ['Server=db;Application Name={worker;Uid=alice;', 'Pwd', '=alpha bravo;\nIgnored=};'].join('');
    expect(await redactNote(acrossLines, 'r80braceLine')).toMatch(/^\[CONN_STRING_\d+\];\nIgnored=};$/);
  });
});

describe('re-review 80-3: normalize numeric Session IDs for Purge', () => {
  it.each([false, true])('purges workflow mappings after numeric Redact and Restore with encryption=%s', async (encrypted) => {
    const store: IDataObject = {};
    const settings = { vaultStorage: 'workflow', ...(encrypted ? { vaultPassphrase: ['test', 'vault', 'passphrase'].join('-') } : {}) };
    const input = { note: ['alice', '@', 'example.com'].join('') };
    const [data] = await run({ ...settings, operation: 'redact', sessionId: 123456789 }, [input], { staticData: store });
    expect(data[0].json.note).toMatch(/^\[EMAIL_\d+\]$/);
    const [restored] = await run({ ...settings, operation: 'restore', sessionId: 123456789, deleteAfterRestore: false }, [data[0].json], { staticData: persist(store) });
    expect(restored[0].json).toEqual(input);

    const saved = persist(store);
    const [purged] = await run({ ...settings, operation: 'purge', purgeScope: 'specific', purgeSessionId: 123456789 }, [{}], { staticData: saved });
    expect(purged[0].json).toMatchObject({ purged: true, entriesDeleted: 1 });
    const [stats] = await run({ ...settings, operation: 'stats' }, [{}], { staticData: persist(saved) });
    expect(stats[0].json.totalSessions).toBe(0);
    await expect(run({ ...settings, operation: 'restore', sessionId: 123456789 }, [data[0].json], { staticData: persist(saved) }))
      .rejects.toThrow(/^No vault found for this session/);
    for (const operation of ['redact', 'restore', 'purge']) {
      const params = { ...settings, operation, sessionId: null, purgeScope: 'specific', purgeSessionId: null };
      await expect(run(params, [input], { staticData: saved })).rejects.toThrow(/^Session ID is required$/);
    }
  });
});

describe('re-review 80-session-growth: a long-lived session keeps each run cheap', () => {
  it('a small note costs about the same in a session with 15,000 earlier tokens as in a new one', async () => {
    const many = Array.from({ length: 15_000 }, (_, i) => `user${i}@example.com`).join(' ');
    const [first] = await run({ operation: 'redact', sessionId: 'growth-big', vaultStorage: 'memory' }, [{ note: many }]);
    const earlier = (first[0].json.note as string).match(/\[EMAIL_\d+\]/g) ?? [];
    expect(earlier.length).toBe(15_000);
    const small = (sessionId: string, note: string) => run({ operation: 'redact', sessionId, vaultStorage: 'memory' }, [{ note }]);
    const time = async (sessionId: string) => {
      const started = cpuNow();
      for (let i = 0; i < 20; i++) await small(sessionId, `mail fresh${i}@example.com today`);
      return cpuNow() - started;
    };
    await time('growth-warm');
    const empty = await time('growth-empty');
    const big = await time('growth-big');
    // Scanning the whole session history on every run made this about thirty times slower.
    expect(big).toBeLessThan(5 * Math.max(empty, 20));
  });

  it('still protects input text that equals an earlier token', async () => {
    const [first] = await run({ operation: 'redact', sessionId: 'growth-literal', vaultStorage: 'memory' }, [{ note: 'a@example.com' }]);
    const token = first[0].json.note as string;
    const [second] = await run({ operation: 'redact', sessionId: 'growth-literal', vaultStorage: 'memory' }, [{ note: `see ${token}` }]);
    expect(second[0].json.note).not.toContain(token);
    const [restored] = await run(
      { operation: 'restore', sessionId: 'growth-literal', vaultStorage: 'memory', deleteAfterRestore: false }, [second[0].json],
    );
    expect(restored[0].json.note).toBe(`see ${token}`);
  });
});
