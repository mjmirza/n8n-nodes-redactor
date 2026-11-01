import { IExecuteFunctions, NodeOperationError } from 'n8n-workflow';
import { checkRegex } from './regexSafety';
import { AllowDenyEntry, CustomPattern, isPiiCategory, PII_CATEGORIES } from './types';
import { INJECTION_DESCRIPTIONS, PromptInjectionResult } from './injection';

const VAULT_CREDENTIAL = 'redactorVaultApi';

/** Direct settings get the same fail-closed pattern selection as tenant profiles. */
export function selectedPatterns(fns: IExecuteFunctions, known: string[], recommended: string[]): string[] {
  const scope = runSetting(fns, 'detectionScope', 'recommended');
  if (scope === 'all') return known;
  if (scope === 'recommended') return recommended;
  if (scope !== 'select') throw new NodeOperationError(fns.getNode(), 'Detection Scope must be recommended, all or select');
  const names = runSetting(fns, 'piiTypes');
  const allowed = new Set(known);
  if (!Array.isArray(names) || names.some((name) => typeof name !== 'string' || !allowed.has(name))) {
    throw new NodeOperationError(fns.getNode(), 'PII Types must be an array of known pattern names');
  }
  return names;
}

/** Whether a saved parameter value holds an n8n expression anywhere inside it. */
function hasExpression(value: unknown): boolean {
  if (typeof value === 'string') return value.startsWith('=');
  if (Array.isArray(value)) return value.some(hasExpression);
  if (value !== null && typeof value === 'object') return Object.values(value).some(hasExpression);
  return false;
}

/**
 * A setting the whole run uses, such as the session or the tenant profile. An expression is evaluated for every item,
 * and the run stops when items disagree, so a mixed batch never silently runs with the first item's settings.
 */
export function runSetting(fx: IExecuteFunctions, name: string, fallback?: unknown): unknown {
  const read = (i: number) => (fallback === undefined ? fx.getNodeParameter(name, i) : fx.getNodeParameter(name, i, fallback));
  const first = read(0);
  const saved = (fx.getNode().parameters as Record<string, unknown> | undefined)?.[name];
  if (saved !== undefined && !hasExpression(saved)) return first;
  const expected = JSON.stringify(first);
  const count = fx.getInputData().length;
  for (let i = 1; i < count; i++) {
    if (JSON.stringify(read(i)) !== expected) {
      throw new NodeOperationError(fx.getNode(), `The setting "${name}" has a different value for item ${i} than for item 0`, {
        description: 'One run uses one session and one set of settings. Split the batch first, for example with Loop Over Items, so each run sees one tenant or session.',
      });
    }
  }
  return first;
}


/** The credential wins. The legacy plain-text parameter is read only when no credential is attached. */
export async function resolvePassphrase(fns: IExecuteFunctions): Promise<string> {
  if (fns.getNode().credentials?.[VAULT_CREDENTIAL]) {
    let cred: Record<string, unknown>;
    try {
      cred = (await fns.getCredentials(VAULT_CREDENTIAL)) as Record<string, unknown>;
    } catch (error) {
      throw new NodeOperationError(fns.getNode(), 'The Redactor Vault credential could not be read, so the vault stays locked.', {
        description: `Nothing was stored. Re-enter the passphrase in the credential. Cause: ${(error as Error).message}`,
      });
    }
    if (typeof cred.passphrase !== 'string' || cred.passphrase === '') {
      throw new NodeOperationError(fns.getNode(), 'The Redactor Vault credential has an empty passphrase.', {
        description: 'Nothing was stored. Set a passphrase in the credential, or remove the credential from the node.',
      });
    }
    return cred.passphrase;
  }
  return legacyPassphrase(fns);
}

/** Only an absent or empty legacy setting means no encryption. A failed evaluation stops the run. */
function legacyPassphrase(fns: IExecuteFunctions): string {
  let raw: unknown;
  try {
    raw = runSetting(fns, 'vaultPassphrase', '');
  } catch (error) {
    // Items that disagree already carry a clear error. Only a failed expression is explained here.
    if (error instanceof NodeOperationError) {
      throw new NodeOperationError(fns.getNode(), error.message, { description: error.description ?? undefined });
    }
    throw new NodeOperationError(fns.getNode(), 'The legacy vault passphrase could not be evaluated, so the vault stays locked.', {
      description: `Nothing was stored. Fix the expression, or move the passphrase into a Redactor Vault credential. Cause: ${(error as Error).message}`,
    });
  }
  if (raw === undefined || raw === null || raw === '') return '';
  if (typeof raw !== 'string') {
    throw new NodeOperationError(fns.getNode(), 'The legacy vault passphrase is not text, so the vault stays locked.', {
      description: 'Nothing was stored. Set the passphrase to a text value, or use a Redactor Vault credential.',
    });
  }
  return raw;
}

/** Memory sessions are keyed by workflow, so one workflow never sees another's sessions. */
export function workflowNamespace(fns: IExecuteFunctions): string {
  try {
    const id = fns.getWorkflow().id;
    if (id !== undefined && id !== null && String(id) !== '') return `wf:${String(id)}`;
  } catch {
    // getWorkflow is unavailable in some test harnesses.
  }
  return 'wf:unsaved';
}

/** Refuses unsafe or invalid user regexes explicitly instead of skipping them silently. */
/** Node version 2 refuses an unknown category. Version 1 files it under other, so saved workflows keep running. */
function assertCategory(fns: IExecuteFunctions, cp: CustomPattern): void {
  if (fns.getNode().typeVersion < 2 || !cp.category || isPiiCategory(cp.category)) return;
  throw new NodeOperationError(fns.getNode(), `Custom pattern "${cp.label}" has an unknown category "${cp.category}"`, {
    description: `Use one of ${PII_CATEGORIES.join(', ')}.`,
  });
}

export function assertUserRegexes(
  fns: IExecuteFunctions,
  customPatterns: CustomPattern[],
  lists: Array<{ name: string; entries: AllowDenyEntry[] }>,
): void {
  const refuse = (what: string, problem: string): never => {
    throw new NodeOperationError(fns.getNode(), `${what} regex ${problem}`, {
      description: 'Rewrite the pattern without nested or alternated repetition, for example [ab]+ instead of (a|b)+, and without two repetitions in a row that can match the same characters, for example \\d+ instead of \\d+\\d+. Put a fixed separator such as - or @ between repeated parts.',
    });
  };
  for (const cp of customPatterns) {
    if (!cp.label || !cp.regex) continue;
    assertCategory(fns, cp);
    const problem = checkRegex(cp.regex);
    if (problem) refuse(`Custom pattern "${cp.label}"`, problem);
  }
  for (const list of lists) {
    for (const [index, entry] of list.entries.entries()) {
      const problem = entry.type === 'regex' ? checkRegex(entry.value) : null;
      if (problem) refuse(`${list.name} entry ${index + 1}`, problem);
    }
  }
}

/** Diagnostics leave the node on the Data output, so they carry detector metadata only, never content or paths. */
export function sanitizeInjection(result: PromptInjectionResult): PromptInjectionResult {
  const matchedPatterns = result.matchedPatterns.map((m) => ({
    category: m.category,
    pattern: INJECTION_DESCRIPTIONS.find((d) => m.pattern === d || m.pattern.endsWith(` ${d}`)) ?? 'Prompt injection detector',
    matchedText: '(withheld)',
    severity: m.severity,
    score: m.score,
  }));
  return { ...result, matchedPatterns };
}
