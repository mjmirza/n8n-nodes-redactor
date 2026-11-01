/**
 * Prompt Injection Detection Engine
 *
 * Detects prompt injection attempts in text before it reaches an LLM.
 * Based on OWASP LLM Top 10 (2025), LLM Guard, Rebuff, and Lakera Guard.
 *
 * Categories:
 *   1. Direct instruction override ("ignore previous instructions")
 *   2. Role manipulation / jailbreak ("you are now DAN")
 *   3. System prompt extraction ("reveal your system prompt")
 *   4. Delimiter / context escape ([SYSTEM], <<SYS>>)
 *   5. Encoded payloads (base64, URL-encoded, Unicode)
 *   6. Zero-width character injection
 *
 * Response actions:
 *   BLOCK (score >= 0.7) - High confidence injection
 *   FLAG (score >= 0.3) - Suspicious, review recommended
 *   LOG_ONLY (score < 0.3) - Low-confidence match
 */

export type InjectionAction = 'BLOCK' | 'FLAG' | 'LOG_ONLY' | 'CLEAN';
export type InjectionSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface InjectionMatch {
  category: string;
  pattern: string;
  matchedText: string;
  severity: InjectionSeverity;
  score: number;
}

export interface PromptInjectionResult {
  detected: boolean;
  score: number;
  action: InjectionAction;
  matchedPatterns: InjectionMatch[];
  encodedPayloadsFound: boolean;
  zeroWidthCharsFound: boolean;
  message: string;
}

interface InjectionPattern {
  category: string;
  regex: RegExp;
  severity: InjectionSeverity;
  score: number;
  description: string;
}

const INJECTION_PATTERNS: InjectionPattern[] = [
  // ═══════════════════════════════════════
  // Category 1: Direct Instruction Override
  // ═══════════════════════════════════════
  {
    category: 'instruction_override',
    regex: /ignore\s+(all\s+)?previous\s+(instructions?|prompts?|rules?|guidelines?|context)/i,
    severity: 'CRITICAL',
    score: 0.45,
    description: 'Attempt to override previous instructions',
  },
  {
    category: 'instruction_override',
    regex: /disregard\s+(all\s+)?(previous|above|prior|earlier)\s+(instructions?|context|prompts?|rules?)/i,
    severity: 'CRITICAL',
    score: 0.45,
    description: 'Attempt to disregard prior context',
  },
  {
    category: 'instruction_override',
    regex: /forget\s+(all\s+)?(previous|above|prior|everything)\s*(you|instructions?|prompts?|said)?/i,
    severity: 'HIGH',
    score: 0.40,
    description: 'Attempt to make model forget instructions',
  },
  {
    category: 'instruction_override',
    regex: /override\s+(all\s+)?(previous|system|safety)\s*(instructions?|settings?|rules?|filters?)?/i,
    severity: 'CRITICAL',
    score: 0.45,
    description: 'Direct override attempt',
  },
  {
    category: 'instruction_override',
    regex: /new\s+instructions?\s*:/i,
    severity: 'HIGH',
    score: 0.35,
    description: 'Injecting new instructions',
  },
  {
    category: 'instruction_override',
    regex: /you\s+must\s+(now\s+)?follow\s+(these|my|new)\s+instructions?/i,
    severity: 'HIGH',
    score: 0.40,
    description: 'Commanding model to follow new instructions',
  },

  // ═══════════════════════════════════════
  // Category 2: Role Manipulation / Jailbreak
  // ═══════════════════════════════════════
  {
    category: 'role_manipulation',
    regex: /you\s+are\s+now\s+(in\s+)?(developer|debug|admin|god|unrestricted|DAN|evil)\s*(mode)?/i,
    severity: 'CRITICAL',
    score: 0.45,
    description: 'Role manipulation - DAN/developer mode',
  },
  {
    category: 'role_manipulation',
    regex: /act\s+as\s+(a\s+)?(different|new|unrestricted|unfiltered|evil)\s*(AI|assistant|model|system)?/i,
    severity: 'HIGH',
    score: 0.35,
    description: 'Role manipulation - act as different entity',
  },
  {
    category: 'role_manipulation',
    regex: /pretend\s+(you\s+are|to\s+be)\s+(a\s+)?(hacker|evil|unrestricted|jailbroken|unfiltered)/i,
    severity: 'HIGH',
    score: 0.40,
    description: 'Role manipulation - pretend to be jailbroken',
  },
  {
    category: 'role_manipulation',
    regex: /enter\s+(developer|debug|admin|sudo|root|maintenance|god)\s*mode/i,
    severity: 'CRITICAL',
    score: 0.45,
    description: 'Attempt to enter privileged mode',
  },
  {
    category: 'role_manipulation',
    regex: /switch\s+to\s+(unrestricted|unfiltered|uncensored|raw)\s*mode/i,
    severity: 'HIGH',
    score: 0.40,
    description: 'Attempt to switch to unrestricted mode',
  },
  {
    category: 'role_manipulation',
    regex: /you\s+have\s+no\s+(restrictions?|limitations?|rules?|boundaries|filters?|guardrails?)/i,
    severity: 'HIGH',
    score: 0.35,
    description: 'Claiming model has no restrictions',
  },
  {
    category: 'role_manipulation',
    regex: /do\s+anything\s+now/i,
    severity: 'HIGH',
    score: 0.40,
    description: 'DAN (Do Anything Now) jailbreak',
  },
  {
    category: 'role_manipulation',
    regex: /jailbreak/i,
    severity: 'HIGH',
    score: 0.35,
    description: 'Explicit jailbreak mention',
  },

  // ═══════════════════════════════════════
  // Category 3: System Prompt Extraction
  // ═══════════════════════════════════════
  {
    category: 'prompt_extraction',
    regex: /reveal\s+(your\s+)?(system\s+)?prompt/i,
    severity: 'HIGH',
    score: 0.35,
    description: 'Attempt to reveal system prompt',
  },
  {
    category: 'prompt_extraction',
    regex: /show\s+(me\s+)?(your\s+)?(system\s+)?(prompt|instructions?|rules?|guidelines?|configuration)/i,
    severity: 'MEDIUM',
    score: 0.30,
    description: 'Attempt to show system instructions',
  },
  {
    category: 'prompt_extraction',
    regex: /what\s+(are|is)\s+your\s+(system\s+)?(prompt|instructions?|rules?|guidelines?|initial\s+instructions?)/i,
    severity: 'MEDIUM',
    score: 0.25,
    description: 'Asking for system prompt contents',
  },
  {
    category: 'prompt_extraction',
    regex: /repeat\s+(your\s+)?(system\s+)?(prompt|instructions?|initial\s+instructions?)\s*(verbatim|exactly|word\s+for\s+word)?/i,
    severity: 'HIGH',
    score: 0.35,
    description: 'Asking to repeat system prompt verbatim',
  },
  {
    category: 'prompt_extraction',
    regex: /output\s+(your\s+)?(system\s+)?(prompt|instructions?|configuration)\s*(verbatim|exactly|in\s+full)?/i,
    severity: 'HIGH',
    score: 0.35,
    description: 'Asking to output system configuration',
  },

  // ═══════════════════════════════════════
  // Category 4: Delimiter / Context Escape
  // ═══════════════════════════════════════
  {
    category: 'delimiter_escape',
    regex: /\[SYSTEM\]/i,
    severity: 'CRITICAL',
    score: 0.50,
    description: 'System delimiter injection [SYSTEM]',
  },
  {
    category: 'delimiter_escape',
    regex: /\[INST\]/i,
    severity: 'CRITICAL',
    score: 0.50,
    description: 'Instruction delimiter injection [INST]',
  },
  {
    category: 'delimiter_escape',
    regex: /<<SYS>>/i,
    severity: 'CRITICAL',
    score: 0.50,
    description: 'Llama system delimiter <<SYS>>',
  },
  {
    category: 'delimiter_escape',
    regex: /<\|im_start\|>system/i,
    severity: 'CRITICAL',
    score: 0.50,
    description: 'ChatML system delimiter injection',
  },
  {
    category: 'delimiter_escape',
    regex: /```system\b/i,
    severity: 'HIGH',
    score: 0.40,
    description: 'Code block system injection',
  },
  {
    category: 'delimiter_escape',
    regex: /###\s*(SYSTEM|INSTRUCTION|END|OVERRIDE)/i,
    severity: 'HIGH',
    score: 0.40,
    description: 'Markdown heading delimiter injection',
  },
  {
    category: 'delimiter_escape',
    regex: /---\s*(new|system|override)\s*(context|instructions?|prompt)?\s*---/i,
    severity: 'HIGH',
    score: 0.40,
    description: 'Horizontal rule context break',
  },
  {
    category: 'delimiter_escape',
    regex: /BEGINNING\s+OF\s+(NEW\s+)?CONVERSATION/i,
    severity: 'HIGH',
    score: 0.35,
    description: 'Fake conversation reset',
  },
  {
    category: 'delimiter_escape',
    regex: /END\s+OF\s+(SYSTEM\s+)?(PROMPT|INSTRUCTIONS?|CONTEXT)/i,
    severity: 'HIGH',
    score: 0.40,
    description: 'Fake end-of-prompt marker',
  },
];

/** Zero-width and invisible Unicode characters used for evasion */
/** Every static detector description, so diagnostics can be reduced to these and nothing else. */
export const INJECTION_DESCRIPTIONS: readonly string[] = [
  ...INJECTION_PATTERNS.map((p) => p.description),
  'Invisible Unicode characters detected',
  'Base64-encoded injection payload detected',
];

const ZERO_WIDTH_RE = /(?:\u200B|\u200C|\u200D|\uFEFF|\u00AD|\u2060|\u2061|\u2062|\u2063|\u2064|\u2066|\u2067|\u2068|\u2069|\u206A|\u206B|\u206C|\u206D|\u206E|\u206F)/g;

/** Detect Base64-encoded strings that might contain injection payloads */
const BASE64_SUSPICIOUS_RE = /[A-Za-z0-9+/]{40,}={0,2}/g;

/** Common injection seeds for Base64 decoding check */
const INJECTION_SEEDS = [
  'ignore', 'override', 'system', 'prompt', 'instruction', 'jailbreak',
  'developer mode', 'DAN', 'bypass', 'unrestricted',
];

/**
 * Detect prompt injection attempts in text.
 */
export function detectPromptInjection(text: string): PromptInjectionResult {
  if (!text || text.trim().length === 0) {
    return {
      detected: false,
      score: 0,
      action: 'CLEAN',
      matchedPatterns: [],
      encodedPayloadsFound: false,
      zeroWidthCharsFound: false,
      message: 'No text to analyze.',
    };
  }

  const matches: InjectionMatch[] = [];
  let totalScore = 0;

  // Check regex patterns
  for (const pattern of INJECTION_PATTERNS) {
    const re = new RegExp(pattern.regex.source, pattern.regex.flags);
    const match = re.exec(text);
    if (match) {
      matches.push({
        category: pattern.category,
        pattern: pattern.description,
        matchedText: match[0].slice(0, 100), // Truncate long matches
        severity: pattern.severity,
        score: pattern.score,
      });
      totalScore += pattern.score;
    }
  }

  // Check for zero-width characters
  const zeroWidthCharsFound = ZERO_WIDTH_RE.test(text);
  if (zeroWidthCharsFound) {
    totalScore += 0.20;
    matches.push({
      category: 'zero_width_chars',
      pattern: 'Invisible Unicode characters detected',
      matchedText: '(hidden characters)',
      severity: 'MEDIUM',
      score: 0.20,
    });
  }

  // Check for suspicious Base64 payloads
  let encodedPayloadsFound = false;
  const base64Matches = text.match(BASE64_SUSPICIOUS_RE);
  if (base64Matches) {
    for (const b64 of base64Matches.slice(0, 5)) { // Check max 5 to avoid perf issues
      try {
        const decoded = Buffer.from(b64, 'base64').toString('utf-8');
        const decodedLower = decoded.toLowerCase();
        if (INJECTION_SEEDS.some((seed) => decodedLower.includes(seed))) {
          encodedPayloadsFound = true;
          totalScore += 0.35;
          matches.push({
            category: 'encoded_payload',
            pattern: 'Base64-encoded injection payload detected',
            matchedText: `(decoded payload of ${decoded.length} characters withheld)`,
            severity: 'HIGH',
            score: 0.35,
          });
          break;
        }
      } catch {
        // Not valid base64, skip
      }
    }
  }

  // Cap score at 1.0
  totalScore = Math.min(1.0, totalScore);
  totalScore = Math.round(totalScore * 100) / 100;

  // Determine action
  let action: InjectionAction = 'CLEAN';
  if (totalScore >= 0.7) action = 'BLOCK';
  else if (totalScore >= 0.3) action = 'FLAG';
  else if (matches.length > 0) action = 'LOG_ONLY';

  // Build message
  let message: string;
  if (!matches.length) {
    message = 'No prompt injection detected.';
  } else if (action === 'BLOCK') {
    message = `BLOCKED: High-confidence prompt injection detected (score: ${totalScore}). ${matches.length} suspicious pattern(s) found.`;
  } else if (action === 'FLAG') {
    message = `FLAGGED: Potential prompt injection detected (score: ${totalScore}). Review recommended.`;
  } else {
    message = `Low-confidence match (score: ${totalScore}). Likely safe but logged for review.`;
  }

  return {
    detected: matches.length > 0,
    score: totalScore,
    action,
    matchedPatterns: matches,
    encodedPayloadsFound,
    zeroWidthCharsFound,
    message,
  };
}

/**
 * Scan all string values in a data object for prompt injection.
 * Returns the highest-severity result across all fields.
 */
export function scanForInjection(
  data: Record<string, unknown>,
  currentPath: string = '',
): PromptInjectionResult {
  let worstResult: PromptInjectionResult = {
    detected: false,
    score: 0,
    action: 'CLEAN',
    matchedPatterns: [],
    encodedPayloadsFound: false,
    zeroWidthCharsFound: false,
    message: 'No prompt injection detected.',
  };

  for (const [key, value] of Object.entries(data)) {
    const fieldPath = currentPath ? `${currentPath}.${key}` : key;

    if (typeof value === 'string' && value.trim().length > 0) {
      const result = detectPromptInjection(value);
      if (result.score > worstResult.score) {
        // Add field path to each match
        worstResult = {
          ...result,
          matchedPatterns: result.matchedPatterns.map((m) => ({
            ...m,
            pattern: `[${fieldPath}] ${m.pattern}`,
          })),
        };
      } else if (result.detected) {
        // Merge matches from lower-scoring fields
        worstResult.matchedPatterns.push(
          ...result.matchedPatterns.map((m) => ({
            ...m,
            pattern: `[${fieldPath}] ${m.pattern}`,
          })),
        );
        worstResult.score = Math.min(1.0, worstResult.score + result.score * 0.3);
        worstResult.detected = true;
        if (result.encodedPayloadsFound) worstResult.encodedPayloadsFound = true;
        if (result.zeroWidthCharsFound) worstResult.zeroWidthCharsFound = true;
      }
    }

    // Recurse into nested objects
    if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
      const nested = scanForInjection(value as Record<string, unknown>, fieldPath);
      if (nested.score > worstResult.score) {
        worstResult = nested;
      } else if (nested.detected) {
        worstResult.matchedPatterns.push(...nested.matchedPatterns);
        worstResult.score = Math.min(1.0, worstResult.score + nested.score * 0.3);
        worstResult.detected = true;
      }
    }

    // Recurse into arrays
    if (Array.isArray(value)) {
      for (let i = 0; i < value.length; i++) {
        const item = value[i];
        if (item !== null && typeof item === 'object') {
          const nested = scanForInjection(item as Record<string, unknown>, `${fieldPath}[${i}]`);
          if (nested.detected) {
            worstResult.matchedPatterns.push(...nested.matchedPatterns);
            worstResult.score = Math.min(1.0, worstResult.score + nested.score * 0.3);
            worstResult.detected = true;
          }
        }
      }
    }
  }

  // Recalculate action based on final merged score
  if (worstResult.score >= 0.7) worstResult.action = 'BLOCK';
  else if (worstResult.score >= 0.3) worstResult.action = 'FLAG';
  else if (worstResult.detected) worstResult.action = 'LOG_ONLY';

  return worstResult;
}
