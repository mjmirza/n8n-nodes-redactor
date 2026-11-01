/** Regression coverage for re-review 81 against 7.0.1. */
import { priorTokensInInput } from '../nodes/Redactor/engine';
import { cpuNow, engineSetup, redactNote, run, verifyStatus } from './harness';

describe('re-review 81-1: embedded equals and quotes in unquoted connection values', () => {
  it('redacts the complete username and password from the exact review input', async () => {
    const note = "Server=db;Uid=alice='x;Pwd=alpha bravo;";
    const output = await redactNote(note, 'r81equals');
    expect(output).toMatch(/^\[CONN_STRING_\d+\];$/);
    for (const credential of ["alice='x", 'alpha', 'bravo']) expect(output).not.toContain(credential);
    expect(await verifyStatus(note)).toBe('FAIL');
    expect(await verifyStatus(output)).toBe('PASS');
  });

  it.each(['alice=x', 'alice"x', "alice'x", 'alice{x', 'alice}x', "alice=Pwd='x"])(
    'treats interior punctuation in %s as literal and leaves unrelated trailing properties intact', async (username) => {
      const note = `Server=db;Uid=${username};Pwd=alpha bravo;Ignored=visible;`;
      expect(await redactNote(note, 'r81interior')).toMatch(/^\[CONN_STRING_\d+\];Ignored=visible;$/);
    },
  );
});

describe('re-review 81-property-1: an interior equals and quote cannot truncate a later quoted username', () => {
  it('covers the shrunk counterexample from the extended generator', async () => {
    const note = 'Deployment note: access token=s3cfr0aflphfa;server=db;password=p4sfs0{f="aflphfa;user id="accft0;falpfha"; ready.';
    const output = await redactNote(note, 'r81property1');
    expect(output).toMatch(/^Deployment note: \[CONN_STRING_\d+\]; ready\.$/);
    for (const fragment of ['s3cfr0aflphfa', 'p4sfs0{f="aflphfa', 'accft0;falpfha', ';fal']) expect(output).not.toContain(fragment);
    expect(await verifyStatus(note)).toBe('FAIL');
  });
});

describe('re-review 81-2: prior-token filtering with matching first characters and varied lengths', () => {
  it('finds suffix, overlapping and UTF-16 tokens through failure and output links', () => {
    const entries = Object.fromEntries(['he', 'she', 'hers', 'his', 'a', 'aa', 'aaa', '😀'].map((token) => [token, {}]));
    const { ctx } = engineSetup({ inputText: 'ushers aaaa 😀' });
    const matcher = priorTokensInInput(ctx, entries)!;
    for (const token of ['he', 'she', 'hers', 'a', 'aa', 'aaa', '😀']) expect(token.match(matcher)).toEqual([token]);
    expect('his'.match(matcher)).toBeNull();
    expect('aaaa'.match(matcher)).toEqual(['aaa', 'a']);
  });

  it('protects literals for tokens added after the session matcher was cached', async () => {
    const settings = {
      operation: 'redact', vaultStorage: 'memory', sessionId: 'r81cached-growth', useTenantProfile: true,
      tenantProfile: { enabledPatterns: [], customPatterns: [{ label: 'A', regex: 'ID[0-9]{4}' }] },
    };
    const [first] = await run(settings, [{ note: 'ID0000' }]);
    const firstToken = first[0].json.note as string;
    // The earlier literal builds the matcher, and ID0001 then extends the same entry table.
    const [second] = await run(settings, [{ note: `${firstToken} ID0001` }]);
    const addedToken = (second[0].json.note as string).split(' ')[1];
    const input = { note: `${firstToken} ${addedToken}` };
    const [third] = await run({ ...settings, tenantProfile: {
      enabledPatterns: [], fieldMode: 'allowlist', fieldRules: [{ field: 'selected', mode: 'include' }],
    } }, [input]);
    expect(third[0].json.note).not.toContain(firstToken);
    expect(third[0].json.note).not.toContain(addedToken);
    const [restored] = await run({ ...settings, operation: 'restore', deleteAfterRestore: false }, [third[0].json]);
    expect(restored[0].json.note).toBe(input.note);
  });

  it('uses under 16 times the CPU for an input eight times longer', async () => {
    const time = async (k: number) => {
      const sessionId = `r81lengths-${k}`;
      const customPatterns = Array.from({ length: k }, (_, i) => ({
        label: 'A'.repeat(i + 1), regex: 'ID' + String(i).padStart(4, '0'),
      }));
      const settings = { operation: 'redact', vaultStorage: 'memory', sessionId, useTenantProfile: true };
      const [seeded] = await run({ ...settings, tenantProfile: { enabledPatterns: [], customPatterns } }, [
        { note: customPatterns.map((pattern) => pattern.regex).join(' ') },
      ]);
      expect((seeded[0].json.note as string).match(/\[A+_\d+\]/g)).toHaveLength(k);
      const input = { note: '['.repeat(4000 * k) };
      const params = { ...settings, tenantProfile: {
        enabledPatterns: [], fieldMode: 'allowlist', fieldRules: [{ field: 'selected', mode: 'include' }],
      } };
      // Warm the cached matcher before measuring repeated full-node runs.
      await run(params, [input]);
      const started = cpuNow();
      for (let i = 0; i < 3; i++) {
        const [out] = await run(params, [input]);
        expect(out[0].json.note).toBe(input.note);
      }
      return (cpuNow() - started) / 3;
    };
    const small = await time(16);
    const large = await time(128);
    expect(large).toBeLessThan(16 * Math.max(small, 5));
  }, 60000);
});
