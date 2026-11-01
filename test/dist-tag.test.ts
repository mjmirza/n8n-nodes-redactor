import { spawnSync } from 'child_process';

const run = (tag: string) => {
  const r = spawnSync('bash', ['tools/npm-dist-tag.sh', tag], { encoding: 'utf8' });
  return { code: r.status, out: r.stdout.trim() };
};

describe('tools/npm-dist-tag.sh', () => {
  it.each([
    ['v1.11.2', 'v1-legacy'],
    ['v1.0.0', 'v1-legacy'],
    ['v0.9.1', 'v1-legacy'],
    ['v2.0.0', 'latest'],
    ['v10.3.4', 'latest'],
  ])('%s publishes as %s', (tag, expected) => {
    expect(run(tag)).toEqual({ code: 0, out: expected });
  });

  it.each(['', 'v2', 'v2.0', '2.0.0', 'v2.0.0-beta.1', 'v1.2.3; rm -rf /', 'refs/tags/v2.0.0'])('rejects %p', (tag) => {
    const r = run(tag);
    expect(r.code).toBe(1);
    expect(r.out).toBe('');
  });
});
