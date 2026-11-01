import { IExecuteFunctions, NodeOperationError } from 'n8n-workflow';
import { checkRegex } from './regexSafety';
import { AllowDenyEntry, CustomPattern } from './types';
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
  try {
    return (fns.getNodeParameter('vaultPassphrase', 0, '') as string) || '';
  } catch {
    return '';
  }
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
export function assertUserRegexes(
  fns: IExecuteFunctions,
  customPatterns: CustomPattern[],
  lists: Array<{ name: string; entries: AllowDenyEntry[] }>,
): void {
  const refuse = (what: string, problem: string): never => {
    throw new NodeOperationError(fns.getNode(), `${what} regex ${problem}`, {
      description: 'Rewrite the pattern without nested or alternated repetition, for example [ab]+ instead of (a|b)+.',
    });
  };
  for (const cp of customPatterns) {
    if (!cp.label || !cp.regex) continue;
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
