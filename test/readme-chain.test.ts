/**
 * Pins the documented production chain (re-review 70-6 and 72-8), so the README never again recommends a chain
 * that discards the model reply or feeds Detect's summary item into Verify.
 */
import { readFileSync } from 'fs';
import { join } from 'path';

const readme = readFileSync(join(__dirname, '..', 'README.md'), 'utf8');

describe('re-review 70-6 and 72-8: the documented production chain', () => {
  it('verifies before the LLM and restores the model reply after it', () => {
    expect(readme).toContain('Data source > Redact > Verify > LLM > Restore > Output > Purge');
    expect(readme).not.toMatch(/LLM > Verify > Restore/);
  });

  it('keeps Detect out of the chain and sets Verify to pass items on', () => {
    expect(readme).toMatch(/Detect is for a dry run[^\n]*keep it out of this chain/);
    expect(readme).toContain('Items, Stop on FAIL');
  });
});
