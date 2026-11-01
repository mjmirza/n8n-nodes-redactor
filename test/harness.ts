/** Shared execute() harness for the node tests. Mirrors how n8n hands a node its context. */
import type { IDataObject, IExecuteFunctions, INodeExecutionData } from 'n8n-workflow';
import { Redactor } from '../nodes/Redactor/Redactor.node';

export interface RunOptions {
  staticData?: IDataObject;
  httpRequest?: jest.Mock;
  workflowId?: string;
  credential?: IDataObject;
  credentialAttached?: boolean;
  credentialError?: Error;
}

export function run(params: Record<string, unknown>, items: IDataObject[], opts: RunOptions = {}): Promise<INodeExecutionData[][]> {
  const input: INodeExecutionData[] = items.map((json) => ({ json }));
  const staticData = opts.staticData ?? {};
  const attached = opts.credentialAttached ?? !!opts.credential;
  const node = {
    name: 'Redactor',
    type: 'n8n-nodes-redactor.redactor',
    typeVersion: 1,
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
