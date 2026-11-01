/** Regression coverage for re-review 83 against 7.0.3. */
import { run } from './harness';

const bulk = (tag: string) =>
  Array.from({ length: 16_384 }, (_, i) => `${tag}${i}@example.com`).join(' ');

/** Counts Map insertions during one bulk run. Matcher states are Maps, so eager delta builds show up here. */
async function bulkMapWrites(sessionId: string, warm: boolean): Promise<number> {
  const settings = { operation: 'redact', vaultStorage: 'memory', sessionId };
  await run(settings, [{ note: 'seed@example.com' }]);
  // A bracketed note caches the prior-token matcher, which is the state the review reproduced.
  if (warm) await run(settings, [{ note: '[warm]' }]);
  const spy = jest.spyOn(Map.prototype, 'set');
  try {
    const [out] = await run(settings, [{ note: bulk(`${sessionId}x`) }]);
    expect((out[0].json.note as string).match(/\[EMAIL_\d+\]/g)).toHaveLength(16_384);
    return spy.mock.calls.length;
  } finally {
    spy.mockRestore();
  }
}

describe('re-review 83-1: bracket-free runs do not build delta matchers eagerly', () => {
  it('does no more matcher work on a session with a cached matcher than on an uncached one', async () => {
    const cold = await bulkMapWrites('r83-cold', false);
    const cached = await bulkMapWrites('r83-cached', true);
    expect(cached).toBeLessThan(cold + 1_000);
  });
});
