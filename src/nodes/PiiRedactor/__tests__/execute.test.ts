/**
 * End-to-end tests that run the node's real execute() with a mocked n8n context.
 */
import type { IDataObject, IExecuteFunctions, INodeExecutionData } from 'n8n-workflow';
import { PiiRedactor } from '../PiiRedactor.node';
import { createVault } from '../vault';

function run(
  params: Record<string, unknown>,
  items: IDataObject[],
): Promise<INodeExecutionData[][]> {
  const input: INodeExecutionData[] = items.map((json) => ({ json }));
  const ctx = {
    getInputData: () => input,
    getNode: () => ({ name: 'Redactor', type: 'n8n-nodes-redactor.redactor', typeVersion: 1 }),
    getNodeParameter: (name: string, _i: number, fallback?: unknown) => {
      if (name in params) return params[name];
      if (fallback !== undefined) return fallback;
      throw new Error(`Could not get parameter: ${name}`);
    },
  } as unknown as IExecuteFunctions;
  return new PiiRedactor().execute.call(ctx);
}

const mem = { vaultStorage: 'memory' };

beforeEach(() => {
  const v = createVault('memory');
  for (const s of v.listSessions()) v.deleteSession(s.sessionId);
});

describe('execute: restore isolation', () => {
  it('never restores from a different session when the requested one is missing', async () => {
    await run({ ...mem, operation: 'redact', sessionId: 'tenant-a' }, [{ email: 'alice@example.com' }]);
    await expect(
      run({ ...mem, operation: 'restore', sessionId: 'tenant-b' }, [{ text: 'Mail [EMAIL_0] please' }]),
    ).rejects.toThrow(/No vault found/);
  });

  it('restores within the same session', async () => {
    const [out] = await run({ ...mem, operation: 'redact', sessionId: 's1' }, [{ email: 'bob@example.com' }]);
    const [back] = await run({ ...mem, operation: 'restore', sessionId: 's1' }, [out[0].json]);
    expect(back[0].json.email).toBe('bob@example.com');
  });
});

describe('execute: purge', () => {
  it('purges without a sessionId parameter', async () => {
    await run({ ...mem, operation: 'redact', sessionId: 's1' }, [{ email: 'c@example.com' }]);
    const [out] = await run({ ...mem, operation: 'purge', purgeScope: 'all' }, [{}]);
    expect(out[0].json.purged).toBe(true);
    expect(out[0].json.sessionsPurged).toBe(1);
  });
});

describe('execute: numbers', () => {
  it('honours field exclusion for numeric fields', async () => {
    const [out] = await run(
      {
        ...mem,
        operation: 'redact',
        sessionId: 'n2',
        fieldMode: 'denylist',
        fieldRules: { rules: [{ field: 'salary' }] },
      },
      [{ salary: 85000 }],
    );
    expect(out[0].json.salary).toBe(85000);
  });
});

describe('execute: item linking', () => {
  it.each(['redact', 'detect', 'verify', 'classify'])('%s sets pairedItem on every output item', async (op) => {
    const [out] = await run({ ...mem, operation: op, sessionId: 'p1' }, [
      { email: 'd@example.com' },
      { email: 'e@example.com' },
    ]);
    // EXPECTATION_OK: new test, summary items link to all inputs per n8n paired-item spec.
    const all = [{ item: 0 }, { item: 1 }];
    out.forEach((item, i) => {
      const isSummary = op === 'verify' || op === 'classify' || i >= 2;
      expect(item.pairedItem).toEqual(isSummary ? all : { item: i });
    });
  });

  it('restore sets pairedItem', async () => {
    const [out] = await run({ ...mem, operation: 'redact', sessionId: 'p2' }, [{ a: 'f@example.com' }, { a: 'g@example.com' }]);
    const [back] = await run({ ...mem, operation: 'restore', sessionId: 'p2' }, out.map((o) => o.json));
    back.forEach((item, i) => expect(item.pairedItem).toEqual({ item: i }));
  });
});
