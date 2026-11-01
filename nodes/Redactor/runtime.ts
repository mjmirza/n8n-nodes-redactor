import { IExecuteFunctions, NodeOperationError } from 'n8n-workflow';
import { checkRegex } from './regexSafety';
import { AllowDenyEntry, CustomPattern, isPiiCategory, PII_CATEGORIES } from './types';
import { INJECTION_DESCRIPTIONS, PromptInjectionResult } from './injection';

const VAULT_CREDENTIAL = 'redactorVaultApi';

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
    raw = fns.getNodeParameter('vaultPassphrase', 0, '');
  } catch (error) {
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
    for (const entry of list.entries) {
      const problem = entry.type === 'regex' ? checkRegex(entry.value) : null;
      if (problem) refuse(`${list.name} entry "${entry.value}"`, problem);
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
