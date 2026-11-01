/** Regression coverage for re-review 82 against 7.0.2. */
import { cpuNow, run } from './harness';

async function timeBracketedNotes(sessionId: string): Promise<number> {
  const started = cpuNow();
  for (let i = 0; i < 200; i++) {
    const [out] = await run({ operation: 'redact', vaultStorage: 'memory', sessionId }, [
      { note: `[mail fresh${i}@example.com today]` },
    ]);
    expect(out[0].json.note).toMatch(/^\[mail \[EMAIL_\d+\] today\]$/);
  }
  return cpuNow() - started;
}

describe('re-review 82-1: growing sessions amortize prior-token matcher rebuilds', () => {
  it('keeps 200 bracketed Redact runs near the CPU cost of a fresh session after 15,000 emails', async () => {
    const sessionId = 'r82-bracketed-big';
    const note = Array.from({ length: 15_000 }, (_, i) => `user${i}@example.com`).join(' ');
    const [seeded] = await run({ operation: 'redact', vaultStorage: 'memory', sessionId }, [{ note }]);
    expect((seeded[0].json.note as string).match(/\[EMAIL_\d+\]/g)).toHaveLength(15_000);

    await timeBracketedNotes('r82-bracketed-warm');
    const fresh = await timeBracketedNotes('r82-bracketed-fresh');
    const grown = await timeBracketedNotes(sessionId);
    expect(grown / Math.max(fresh, 20)).toBeLessThan(5);
  });

  it('protects every earlier literal through delta updates and repeated base merges', async () => {
    const settings = { operation: 'redact', vaultStorage: 'memory', sessionId: 'r82-literal-growth' };
    const [seeded] = await run(settings, [{ note: 'seed@example.com' }]);
    const tokens = [seeded[0].json.note as string];
    // Build the base before adding tokens in notes with no possible token start.
    await run(settings, [{ note: '[warm]' }]);
    for (const count of [16, 80, 100]) {
      const note = Array.from({ length: count }, (_, i) => `batch${count}user${i}@example.com`).join(' ');
      const [added] = await run(settings, [{ note }]);
      tokens.push(...(added[0].json.note as string).split(' '));
      const input = { note: tokens.join(' ') };
      // Even excluded fields must protect every base and delta literal for a lossless restore.
      const [protectedItems] = await run({ ...settings, fieldMode: 'allowlist',
        fieldRules: { rules: [{ field: 'selected' }] },
      }, [input]);
      const protectedTokens = (protectedItems[0].json.note as string).split(' ');
      expect(protectedTokens).toHaveLength(tokens.length);
      for (const token of protectedTokens) expect(tokens).not.toContain(token);
      const [restored] = await run({ ...settings, operation: 'restore', deleteAfterRestore: false }, [protectedItems[0].json]);
      expect(restored[0].json).toEqual(input);
      tokens.push(...protectedTokens);
    }
  });
});

describe('re-review 82-2: the delta matcher rebuilds in amortized time', () => {
  it('keeps the median run of the last 500 of 3,000 growing runs below three times the median of the first 500', async () => {
    const settings = { operation: 'redact', vaultStorage: 'memory', sessionId: 'r82-amortized-delta' };
    const note = Array.from({ length: 15_000 }, (_, i) => `user${i}@example.com`).join(' ');
    const [seeded] = await run(settings, [{ note }]);
    expect((seeded[0].json.note as string).match(/\[EMAIL_\d+\]/g)).toHaveLength(15_000);
    // Cache the base before measuring delta growth so its initial build cannot hide the slowdown.
    await run(settings, [{ note: '[warm]' }]);
    // The median per run ignores garbage-collection pauses and the occasional large level merge.
    const medianBatch = async (offset: number): Promise<number> => {
      const costs: number[] = [];
      for (let i = offset; i < offset + 500; i++) {
        const started = cpuNow();
        const [out] = await run(settings, [{ note: `[mail fresh${i}@example.com today]` }]);
        costs.push(cpuNow() - started);
        expect(out[0].json.note).toBe(`[mail [EMAIL_${15_000 + i}] today]`);
      }
      costs.sort((a, b) => a - b);
      return costs[250];
    };
    const first = await medianBatch(0);
    for (let offset = 500; offset < 2_500; offset += 500) await medianBatch(offset);
    const last = await medianBatch(2_500);
    expect(last).toBeLessThan(3 * first);
  });
});
