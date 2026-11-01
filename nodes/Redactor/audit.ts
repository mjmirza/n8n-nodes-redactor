// CODE_DELETE_OK: JSONL file writer/reader removed in 2.0 (n8n bans fs); records now go to the report output.
/**
 * Audit records for compliance logging (GDPR Art.30, HIPAA, SOX, PCI DSS record-keeping).
 * Emitted on the node's report output. Store them with any node (database, file, SIEM).
 */

import * as crypto from 'crypto';
import { RedactionHit, RedactionMode } from './types';
import { ClassificationLabel } from './classification';

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
): AuditLogEntry {
  const hitsByCategory: Record<string, number> = {};
  const hitsByPattern: Record<string, number> = {};
  for (const hit of hits) {
    hitsByCategory[hit.category] = (hitsByCategory[hit.category] || 0) + 1;
    hitsByPattern[hit.patternLabel] = (hitsByPattern[hit.patternLabel] || 0) + 1;
  }

  return {
    version: '2.0',
    timestamp: new Date().toISOString(),
    eventId: crypto.randomUUID(),
    severity: determineSeverity(classification?.level, hits.length),
    action,
    mode,
    status: 'SUCCESS',
    totalHits: hits.length,
    hitsByCategory,
    hitsByPattern,
    classificationLevel: classification?.level,
    inputItemCount,
    processingTimeMs,
    patternsUsed,
    presidioEnabled,
    sessionId,
  };
}
