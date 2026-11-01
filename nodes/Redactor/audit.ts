// CODE_DELETE_OK: JSONL file writer/reader removed in 2.0 (n8n bans fs); records now go to the report output.
/**
 * Audit records for compliance logging (GDPR Art.30, HIPAA, SOX, PCI DSS record-keeping).
 * Emitted on the node's report output. Store them with any node (database, file, SIEM).
 */

import * as crypto from 'crypto';
import { RedactionHit, RedactionMode } from './types';
import { ClassificationLabel } from './classification';

/**
 * Counts hits by a field. Counting in a Map and building own properties keeps labels such as constructor or
 * __proto__ as ordinary counters.
 */
export function countHits(hits: RedactionHit[], field: 'category' | 'patternLabel'): Record<string, number> {
  const counts = new Map<string, number>();
  for (const hit of hits) counts.set(hit[field], (counts.get(hit[field]) ?? 0) + 1);
  return Object.fromEntries(counts);
}

export interface AuditLogEntry {
  version: string;
  timestamp: string;
  eventId: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

  // Action details
  action: string;
  mode: RedactionMode | string;
  status: 'SUCCESS' | 'PARTIAL' | 'FAILED';

  // Detection summary
  totalHits: number;
  hitsByCategory: Record<string, number>;
  hitsByPattern: Record<string, number>;
  classificationLevel?: string;

  // Metadata
  inputItemCount: number;
  processingTimeMs: number;
  patternsUsed: number;
  presidioEnabled: boolean;
  /** Texts Presidio could not scan in this run. Present only when above zero. */
  presidioUnscannedTexts?: number;
  sessionId?: string;
}

/**
 * Determine severity from classification level and hit count.
 */
function determineSeverity(
  classificationLevel?: string,
  totalHits: number = 0,
): 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' {
  if (classificationLevel === 'RESTRICTED' || totalHits >= 50) return 'CRITICAL';
  if (classificationLevel === 'CONFIDENTIAL' || totalHits >= 20) return 'HIGH';
  if (classificationLevel === 'INTERNAL' || totalHits >= 5) return 'MEDIUM';
  return 'LOW';
}

/**
 * Build one audit record. Pure: no I/O, never throws on valid input.
 * Contains counts and labels only, never the redacted values.
 */
export function buildAuditEntry(
  action: string,
  mode: RedactionMode | string,
  hits: RedactionHit[],
  inputItemCount: number,
  processingTimeMs: number,
  patternsUsed: number,
  presidioEnabled: boolean,
  classification?: ClassificationLabel,
  sessionId?: string,
  presidioUnscannedTexts = 0,
): AuditLogEntry {
  const hitsByCategory = countHits(hits, 'category');
  const hitsByPattern = countHits(hits, 'patternLabel');

  return {
    version: '2.0',
    timestamp: new Date().toISOString(),
    eventId: crypto.randomUUID(),
    severity: determineSeverity(classification?.level, hits.length),
    action,
    mode,
    // Text Presidio never scanned makes the run partial, so an audit consumer can tell it from a full scan.
    status: presidioUnscannedTexts > 0 ? 'PARTIAL' : 'SUCCESS',
    totalHits: hits.length,
    hitsByCategory,
    hitsByPattern,
    classificationLevel: classification?.level,
    inputItemCount,
    processingTimeMs,
    patternsUsed,
    presidioEnabled,
    ...(presidioUnscannedTexts > 0 ? { presidioUnscannedTexts } : {}),
    sessionId,
  };
}
