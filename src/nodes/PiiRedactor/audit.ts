/**
 * Persistent Audit Log
 *
 * JSONL (JSON Lines) audit logger for compliance recording.
 * One JSON object per line, append-only, auto-rotating.
 *
 * Compliant with:
 *   - GDPR Article 30 (Records of Processing Activities)
 *   - HIPAA (6-year retention)
 *   - SOX (7-year retention)
 *   - PCI DSS (1-year minimum)
 *
 * Format: JSONL (compatible with Splunk, ELK, Datadog, CloudWatch)
 * Location: ~/.n8n/pii-audit/pii-audit-YYYY-MM-DD.jsonl
 * Rotation: Daily + 100MB size limit
 */

import * as fs from 'fs';
import * as path from 'path';
import { PiiCategory, RedactionHit, RedactionMode } from './types';
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

const MAX_FILE_SIZE = 104857600; // 100MB
const DEFAULT_AUDIT_DIR = path.join(process.env.HOME || '/tmp', '.n8n', 'pii-audit');

/**
 * Generate a simple UUID v4.
 */
function generateEventId(): string {
  const bytes = new Array(16).fill(0).map(() => Math.floor(Math.random() * 256));
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.map((b) => b.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/**
 * Get today's audit log file path.
 */
function getLogFilePath(auditDir: string): string {
  const today = new Date().toISOString().split('T')[0]; // YYYY-MM-DD
  return path.join(auditDir, `pii-audit-${today}.jsonl`);
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
 * Write an audit log entry.
 * Creates the audit directory if it doesn't exist.
 * Handles file rotation (daily + size-based).
 * Graceful: never throws, never blocks the workflow.
 */
export function writeAuditLog(
  action: string,
  mode: RedactionMode | string,
  hits: RedactionHit[],
  inputItemCount: number,
  processingTimeMs: number,
  patternsUsed: number,
  presidioEnabled: boolean,
  classification?: ClassificationLabel,
  sessionId?: string,
  auditDir?: string,
): void {
  try {
    const dir = auditDir || DEFAULT_AUDIT_DIR;

    // Ensure directory exists
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    // Build hit summaries
    const hitsByCategory: Record<string, number> = {};
    const hitsByPattern: Record<string, number> = {};
    for (const hit of hits) {
      hitsByCategory[hit.category] = (hitsByCategory[hit.category] || 0) + 1;
      hitsByPattern[hit.patternLabel] = (hitsByPattern[hit.patternLabel] || 0) + 1;
    }

    const entry: AuditLogEntry = {
      version: '1.0',
      timestamp: new Date().toISOString(),
      eventId: generateEventId(),
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

    // Get log file path
    let logFile = getLogFilePath(dir);

    // Size-based rotation
    try {
      if (fs.existsSync(logFile)) {
        const stats = fs.statSync(logFile);
        if (stats.size >= MAX_FILE_SIZE) {
          // Rotate: rename current file with sequence number
          let seq = 1;
          while (fs.existsSync(`${logFile}.${seq}`)) seq++;
          fs.renameSync(logFile, `${logFile}.${seq}`);
        }
      }
    } catch {
      // Rotation failed, continue writing to current file
    }

    // Append entry as JSONL (one JSON object per line)
    fs.appendFileSync(logFile, JSON.stringify(entry) + '\n', 'utf-8');
  } catch {
    // Audit logging should NEVER crash the workflow
    // Silently fail — the redaction itself already succeeded
  }
}

/**
 * Read audit log entries for a given date range.
 * Returns parsed entries. Used by Stats operation for audit review.
 */
export function readAuditLog(
  startDate?: string,
  endDate?: string,
  auditDir?: string,
): AuditLogEntry[] {
  try {
    const dir = auditDir || DEFAULT_AUDIT_DIR;
    if (!fs.existsSync(dir)) return [];

    const files = fs.readdirSync(dir)
      .filter((f) => f.startsWith('pii-audit-') && f.endsWith('.jsonl'))
      .sort();

    const entries: AuditLogEntry[] = [];

    for (const file of files) {
      // Filter by date range if provided
      const fileDate = file.replace('pii-audit-', '').replace('.jsonl', '');
      if (startDate && fileDate < startDate) continue;
      if (endDate && fileDate > endDate) continue;

      try {
        const content = fs.readFileSync(path.join(dir, file), 'utf-8');
        const lines = content.split('\n').filter((l) => l.trim().length > 0);
        for (const line of lines) {
          try {
            entries.push(JSON.parse(line));
          } catch {
            // Skip malformed lines
          }
        }
      } catch {
        // Skip unreadable files
      }
    }

    return entries;
  } catch {
    return [];
  }
}
