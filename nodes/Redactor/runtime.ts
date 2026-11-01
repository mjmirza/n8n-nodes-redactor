import { IExecuteFunctions, NodeOperationError } from 'n8n-workflow';
import { getPatternOptions } from './patterns';
import { createVault } from './vault';
import { redactValue } from './engine';
import { checkRegex } from './regexSafety';
import { AllowDenyEntry, CustomPattern, RedactionContext } from './types';
import { PromptInjectionResult } from './injection';

const VAULT_CREDENTIAL = 'redactorVaultApi';

/** The credential wins. The legacy plain-text parameter is read only when no credential is attached. */
export async function resolvePassphrase(fns: IExecuteFunctions): Promise<string> {
  try {
    const cred = await fns.getCredentials(VAULT_CREDENTIAL);
    if (cred && typeof cred.passphrase === 'string' && cred.passphrase) return cred.passphrase;
  } catch {
    // No credential attached. Fall back to the deprecated parameter.
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

/** Diagnostics leave the node on the Data output, so every excerpt is redacted first. */
export function sanitizeInjection(result: PromptInjectionResult): PromptInjectionResult {
  const vault = createVault('memory', undefined, undefined, 'injection-scrub');
  const sessionId = 'scrub';
  vault.getOrCreateSession(sessionId, 60000);
  const ctx: RedactionContext = {
    enabledPatterns: getPatternOptions().map((p) => p.value),
    customPatterns: [],
    mode: 'redact',
    dedup: false,
    fieldRules: [],
    fieldMode: 'all',
  };
  const scrub = (text: string): string => redactValue(text, ctx, vault, sessionId, [], 0) as string;
  const matchedPatterns = result.matchedPatterns.map((m) => ({ ...m, pattern: scrub(m.pattern), matchedText: scrub(m.matchedText) }));
  vault.deleteSession(sessionId);
  return { ...result, matchedPatterns };
}
