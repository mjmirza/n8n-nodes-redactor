/** Shared execute() harness for the node tests. Mirrors how n8n hands a node its context. */
import type { IDataObject, IExecuteFunctions, INodeExecutionData } from 'n8n-workflow';
import { MemoryVault } from '../nodes/Redactor/vault';
import type { RedactionContext, RedactionHit } from '../nodes/Redactor/types';
import { Redactor } from '../nodes/Redactor/Redactor.node';
import { checkRegex } from '../nodes/Redactor/regexSafety';
import { parseTenantProfile } from '../nodes/Redactor/profiles';

export interface RunOptions {
  staticData?: IDataObject;
  httpRequest?: jest.Mock;
  workflowId?: string;
  credential?: IDataObject;
  credentialAttached?: boolean;
  credentialError?: Error;
  typeVersion?: number;
  /** Binary data per item, as n8n attaches files. */
  binary?: Array<IDataObject | undefined>;
  /** Parameters whose expression fails to evaluate. */
  failingParams?: string[];
  /** Parameters whose expression gives a different value per item, by item index. */
  perItem?: Record<string, unknown[]>;
}

export function run(params: Record<string, unknown>, items: IDataObject[], opts: RunOptions = {}): Promise<INodeExecutionData[][]> {
  const input: INodeExecutionData[] = items.map((json, i) => {
    const binary = opts.binary?.[i];
    return binary ? ({ json, binary } as INodeExecutionData) : { json };
  });
  const staticData = opts.staticData ?? {};
  const attached = opts.credentialAttached ?? !!opts.credential;
  const node = {
    name: 'Redactor',
    type: 'n8n-nodes-redactor.redactor',
    typeVersion: opts.typeVersion ?? 1,
    ...(attached ? { credentials: { redactorVaultApi: { id: 'c1', name: 'Vault' } } } : {}),
  };
  const ctx = {
    getInputData: () => input,
    getNode: () => node,
    getWorkflow: () => ({ id: opts.workflowId ?? 'wf-default', active: true }),
    getCredentials: jest.fn(async () => {
      if (opts.credentialError) throw opts.credentialError;
      if (!opts.credential) throw new Error('Node does not have any credentials set');
      return opts.credential;
    }),
    getNodeParameter: (name: string, _i: number, fallback?: unknown) => {
      if (opts.failingParams?.includes(name)) throw new Error('Could not evaluate expression: missing node');
      if (opts.perItem && name in opts.perItem) return opts.perItem[name][_i];
      if (name in params) return params[name];
      if (fallback !== undefined) return fallback;
      throw new Error(`Could not get parameter: ${name}`);
    },
    getWorkflowStaticData: (type: string) => {
      if (type !== 'global') throw new Error(`unexpected static data scope ${type}`);
      return staticData;
    },
    helpers: { httpRequest: opts.httpRequest ?? jest.fn() },
  } as unknown as IExecuteFunctions;
  return new Redactor().execute.call(ctx);
}

/** n8n saves static data as JSON after a production run. */
export const persist = (data: IDataObject): IDataObject => JSON.parse(JSON.stringify(data));

/** The safety check and profile parsing must both refuse the regex. */
export function expectRegexRefused(re: string): void {
  expect(checkRegex(re)).not.toBeNull();
  expect(() => parseTenantProfile({ customPatterns: [{ label: 'x', regex: re }] })).toThrow();
}

/** A fresh memory vault with session "s" and an engine context for direct engine tests. */
export function engineSetup(overrides: Partial<RedactionContext>): { vault: MemoryVault; ctx: RedactionContext; hits: RedactionHit[] } {
  const vault = new MemoryVault();
  vault.getOrCreateSession('s', 0);
  const ctx: RedactionContext = {
    enabledPatterns: [], customPatterns: [], mode: 'token', dedup: true, fieldRules: [], fieldMode: 'all',
    skipSemantic: true, scanNumbers: true, lockedSpans: new WeakMap(), keyLocks: new WeakMap(), keyOrigins: new WeakMap(),
    ...overrides,
  };
  return { vault, ctx, hits: [] };
}

/** Runs fn and fails when it takes ms or longer. */
export function fast(fn: () => void, ms: number): void {
  const started = Date.now();
  fn();
  expect(Date.now() - started).toBeLessThan(ms);
}

/** Redacts one note with default settings and returns the redacted text. */
export async function redactNote(note: string, sessionId: string): Promise<string> {
  const [out] = await run({ operation: 'redact', sessionId }, [{ note }]);
  return out[0].json.note as string;
}

/** Runs version 2 Verify on one note and returns its status. */
export async function verifyStatus(note: string): Promise<unknown> {
  const [out] = await run({ operation: 'verify' }, [{ note }], { typeVersion: 2 });
  return out[0].json.status;
}
