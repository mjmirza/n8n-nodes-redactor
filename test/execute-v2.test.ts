/**
 * 2.0 behaviour through the real execute(): workflow-storage vault, audit records on the
 * Report output, JSON tenant profiles, and Presidio over n8n's HTTP helper.
 */
import type { IDataObject } from 'n8n-workflow';
import { Redactor } from '../nodes/Redactor/Redactor.node';
import { resetCircuitBreaker } from '../nodes/Redactor/presidio';

import { run, persist } from './harness';

describe('execute v2: workflow storage vault', () => {
  it('defaults to workflow storage and restores in a later execution', async () => {
    const store: IDataObject = {};
    const [out] = await run({ operation: 'redact', sessionId: 'wf-1' }, [{ email: 'anna@example.com' }], { staticData: store });
    expect(out[0].json.email).not.toBe('anna@example.com');
    expect(Object.keys(store.redactorVault as object)).toHaveLength(1);

    const [back] = await run({ operation: 'restore', sessionId: 'wf-1' }, [out[0].json], { staticData: persist(store) });
    expect(back[0].json.email).toBe('anna@example.com');
  });

  it('uses global static data so Redact and Restore nodes share sessions', async () => {
    const store: IDataObject = {};
    await run({ operation: 'redact', sessionId: 'g' }, [{ email: 'x@example.com' }], { staticData: store });
    expect(store.redactorVault).toBeDefined();
  });

  it('treats the 1.x value "file" as workflow storage', async () => {
    const store: IDataObject = {};
    const [out] = await run({ vaultStorage: 'file', operation: 'redact', sessionId: 'legacy' }, [{ email: 'l@example.com' }], { staticData: store });
    const [back] = await run({ vaultStorage: 'file', operation: 'restore', sessionId: 'legacy' }, [out[0].json], { staticData: persist(store) });
    expect(back[0].json.email).toBe('l@example.com');
  });

  it('encrypts stored sessions with the passphrase', async () => {
    const store: IDataObject = {};
    const [out] = await run(
      { operation: 'redact', sessionId: 'enc', vaultPassphrase: 'pw' },
      [{ email: 'secret@example.com' }],
      { staticData: store },
    );
    expect(JSON.stringify(store)).not.toContain('secret@example.com');
    await expect(
      run({ operation: 'restore', sessionId: 'enc', vaultPassphrase: 'wrong' }, [out[0].json], { staticData: persist(store) }),
    ).rejects.toThrow(/No vault found/);
    const [back] = await run({ operation: 'restore', sessionId: 'enc', vaultPassphrase: 'pw' }, [out[0].json], { staticData: persist(store) });
    expect(back[0].json.email).toBe('secret@example.com');
  });

  it('memory storage never touches workflow static data', async () => {
    const store: IDataObject = {};
    await run({ vaultStorage: 'memory', operation: 'redact', sessionId: 'm' }, [{ email: 'm@example.com' }], { staticData: store });
    expect(store).toEqual({});
  });

  it('stats and purge work on workflow storage', async () => {
    const store: IDataObject = {};
    await run({ operation: 'redact', sessionId: 'a' }, [{ email: 'a@example.com' }], { staticData: store });
    await run({ operation: 'redact', sessionId: 'b' }, [{ email: 'b@example.com' }], { staticData: store });
    const [stats] = await run({ operation: 'stats' }, [{}], { staticData: store });
    expect(stats[0].json.totalSessions).toBe(2);
    const [purged] = await run({ operation: 'purge', purgeScope: 'specific', purgeSessionId: 'a' }, [{}], { staticData: store });
    expect(purged[0].json.purged).toBe(true);
    const [after] = await run({ operation: 'stats' }, [{}], { staticData: store });
    expect(after[0].json.totalSessions).toBe(1);
  });
});

describe('execute v2: audit records on the Report output', () => {
  it('redact emits an audit record without values when Audit Log is on', async () => {
    const result = await run({ operation: 'redact', sessionId: 'au', auditLog: true }, [{ email: 'audit@example.com' }]);
    expect(result).toHaveLength(2);
    const audit = result[1][0].json.audit as IDataObject;
    expect(audit.action).toBe('REDACT');
    expect(audit.totalHits).toBe(1);
    expect(typeof audit.processingTimeMs).toBe('number');
    expect(JSON.stringify(result[1])).not.toContain('audit@example.com');
  });

  it('includes the audit record next to the full report', async () => {
    const result = await run({ operation: 'redact', sessionId: 'au2', auditLog: true, includeReport: true }, [{ email: 'r@example.com' }]);
    expect(result[1][0].json.audit).toBeDefined();
    expect(result[1][0].json.totalHits).toBe(1);
  });

  it('detect emits an audit record and keeps the summary on the data output', async () => {
    const result = await run({ operation: 'detect', auditLog: true }, [{ email: 'd@example.com' }]);
    expect(result).toHaveLength(2);
    expect((result[1][0].json.audit as IDataObject).action).toBe('DETECT');
    expect(result[0][result[0].length - 1].json._redactorScan).toBe(true);
  });

  it('has one output when neither report nor audit log is on', async () => {
    const result = await run({ operation: 'redact', sessionId: 'one' }, [{ email: 'o@example.com' }]);
    expect(result).toHaveLength(1);
  });

  it('declares the Report output when only Audit Log is on', () => {
    const outputs = new Redactor().description.outputs as string;
    expect(outputs).toContain('parameters["auditLog"]');
  });
});

describe('execute v2: tenant profile JSON', () => {
  it('overrides redaction mode and enabled patterns', async () => {
    const [out] = await run(
      {
        operation: 'redact',
        sessionId: 'tp',
        detectionScope: 'all',
        useTenantProfile: true,
        tenantProfile: JSON.stringify({ redactionMode: 'redact', enabledPatterns: ['email'] }),
      },
      // 'zq' carries no field-name meaning, so only the enabled patterns decide.
      [{ email: 'p@example.com', zq: 'host 10.0.0.1' }],
    );
    expect(out[0].json.email).toBe('[REDACTED]');
    expect(out[0].json.zq).toBe('host 10.0.0.1');
  });

  it('allow list from the profile keeps listed values', async () => {
    const [out] = await run(
      { operation: 'redact', sessionId: 'tp2', useTenantProfile: true, tenantProfile: { allowList: [{ value: 'support@acme.com', type: 'exact' }] } },
      [{ email: 'support@acme.com' }],
    );
    expect(out[0].json.email).toBe('support@acme.com');
  });

  it('rejects an invalid profile with a NodeOperationError', async () => {
    await expect(
      run({ operation: 'redact', sessionId: 'tp3', useTenantProfile: true, tenantProfile: '{"redactionMode":"shred"}' }, [{ email: 'q@example.com' }]),
    ).rejects.toThrow(/Invalid tenant profile: redactionMode/);
  });

  it('an empty profile changes nothing', async () => {
    const [out] = await run({ operation: 'redact', sessionId: 'tp4', useTenantProfile: true, tenantProfile: '{}' }, [{ email: 'e@example.com' }]);
    expect(out[0].json.email).toMatch(/^\[EMAIL_\d+\]$/);
  });

  it('ignores a leftover profile while the toggle is off', async () => {
    const [out] = await run(
      { operation: 'redact', sessionId: 'tp5', useTenantProfile: false, tenantProfile: '{"redactionMode":"shred"}' },
      [{ email: 'f@example.com' }],
    );
    expect(out[0].json.email).toMatch(/^\[EMAIL_\d+\]$/);
  });
});

describe('execute v2: Presidio over n8n httpRequest', () => {
  beforeEach(() => resetCircuitBreaker());

  it('calls Presidio through this.helpers.httpRequest and redacts its entities', async () => {
    const httpRequest = jest.fn(async () => ({ statusCode: 200, body: [{ entity_type: 'PERSON', start: 6, end: 12, score: 0.9 }] }));
    const [out] = await run(
      { operation: 'redact', sessionId: 'pr', enablePresidio: true, presidioUrl: 'http://presidio:3000' },
      [{ note: 'Hello Wilma and good bye' }],
      { httpRequest },
    );
    expect(httpRequest).toHaveBeenCalledWith(
      expect.objectContaining({ method: 'POST', url: 'http://presidio:3000/analyze', json: true, returnFullResponse: true, ignoreHttpStatusErrors: true }),
    );
    expect(out[0].json.note).not.toContain('Wilma');
  });

  // From 7.0 a Presidio outage stops the run unless If Presidio Fails is set to continue (see codex-review-76).
  it('falls back to built-in patterns when Presidio is down and fallback is chosen', async () => {
    const httpRequest = jest.fn(async () => {
      throw new Error('ECONNREFUSED');
    });
    const [out] = await run(
      { operation: 'redact', sessionId: 'pr2', enablePresidio: true, presidioUrl: 'http://presidio:3000', presidioOnFailure: 'continue' },
      [{ email: 'down@example.com' }],
      { httpRequest },
    );
    expect(out[0].json.email).toMatch(/^\[EMAIL_\d+\]$/);
  });
});

describe('execute v2: resource parameter', () => {
  it('declares a single resource whose default keeps 1.x workflows valid', () => {
    const props = new Redactor().description.properties;
    const resource = props.find((p) => p.name === 'resource')!;
    expect(resource.type).toBe('options');
    expect(resource.default).toBe('data');
    expect(resource.options).toHaveLength(1);
    const operation = props.find((p) => p.name === 'operation')!;
    expect(operation.displayOptions).toBeUndefined();
  });
});
