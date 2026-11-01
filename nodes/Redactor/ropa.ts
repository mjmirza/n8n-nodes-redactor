/**
 * GDPR Article 30 ROPA (Records of Processing Activities) Report Generator
 *
 * Generates structured compliance reports as required by GDPR Art.30(1).
 * Auto-populates technical fields from redaction results.
 * User provides business context (controller name, purposes, legal basis).
 *
 * Output: JSON conforming to Art.30(1)(a)-(h) requirements.
 */

import { RedactionHit } from './types';
import { ClassificationLabel } from './classification';

export interface RopaController {
  name: string;
  contactEmail: string;
  representative?: string;
  dpo?: string;
}

export interface RopaThirdCountryTransfer {
  country: string;
  organization: string;
  safeguards: string;
}

export interface RopaRecord {
  // Meta
  recordId: string;
  version: string;
  generatedAt: string;
  generatedBy: string;

  // Art.30(1)(a) - Controller
  controller: RopaController;

  // Art.30(1)(b) - Purposes
  processingPurposes: string[];
  legalBasis: string;

  // Art.30(1)(c) - Data subjects
  dataSubjectCategories: string[];

  // Art.30(1)(d) - Personal data categories
  personalDataCategories: Array<{
    category: string;
    count: number;
    patternLabels: string[];
  }>;

  // Art.30(1)(e) - Recipients
  recipientCategories: string[];

  // Art.30(1)(f) - Third country transfers
  thirdCountryTransfers: RopaThirdCountryTransfer[];

  // Art.30(1)(g) - Retention
  retentionPolicy: {
    vaultTtlMinutes: number;
    // Null, because the node writes audit entries to its output and enforces no retention itself.
    auditLogRetentionDays: number | null;
    description: string;
  };

  // Art.30(1)(h) - Security measures
  securityMeasures: {
    encryptionAtRest: boolean;
    encryptionAlgorithm: string;
    pseudonymization: boolean;
    accessControl: string;
    auditLogging: boolean;
  };

  // Processing summary (auto-generated)
  processingSummary: {
    totalItemsProcessed: number;
    totalPiiDetected: number;
    redactionMode: string;
    patternsUsed: number;
    classificationLevel: string;
    hitsByCategory: Record<string, number>;
  };
}

/**
 * Generate a ROPA record from redaction results and user-provided context.
 */
/** States only what the node enforces. A TTL of 0 means sessions never expire on their own. */
function retentionDescription(vaultTtlMinutes: number, auditLogEnabled: boolean): string {
  const vault = vaultTtlMinutes > 0
    ? `Vault sessions expire after ${vaultTtlMinutes} minutes.`
    : 'Vault sessions do not expire automatically. Purge them when they are no longer needed.';
  const audit = auditLogEnabled
    ? 'Audit entries go to the Report output. Their retention depends on where the workflow stores them.'
    : 'No audit log is written.';
  return `${vault} ${audit}`;
}

/** Hits counted per PII category, never per sensitivity level. */
function countByCategory(hits: RedactionHit[]): Record<string, number> {
  const counts = new Map<string, number>();
  for (const hit of hits) counts.set(hit.category, (counts.get(hit.category) ?? 0) + 1);
  return Object.fromEntries(counts);
}

export function generateRopaRecord(
  // Auto-populated from redaction
  hits: RedactionHit[],
  classification: ClassificationLabel,
  itemCount: number,
  patternsUsed: number,
  redactionMode: string,
  vaultTtlMinutes: number,
  encryptionEnabled: boolean,
  auditLogEnabled: boolean,

  // User-provided context
  controller: RopaController,
  processingPurposes: string[],
  legalBasis: string,
  dataSubjectCategories: string[],
  recipientCategories: string[],
  thirdCountryTransfers: RopaThirdCountryTransfer[],
): RopaRecord {
  // Auto-derive personal data categories from hits
  const categoryMap: Record<string, { count: number; labels: Set<string> }> = {};
  for (const hit of hits) {
    if (!categoryMap[hit.category]) {
      categoryMap[hit.category] = { count: 0, labels: new Set() };
    }
    categoryMap[hit.category].count++;
    categoryMap[hit.category].labels.add(hit.patternLabel);
  }

  const personalDataCategories = Object.entries(categoryMap).map(([cat, data]) => ({
    category: cat,
    count: data.count,
    patternLabels: Array.from(data.labels),
  }));

  // Generate record ID
  const recordId = `ropa-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;

  return {
    recordId,
    version: '1.0',
    generatedAt: new Date().toISOString(),
    generatedBy: 'n8n-nodes-redactor',

    controller,
    processingPurposes,
    legalBasis,
    dataSubjectCategories,
    recipientCategories,
    thirdCountryTransfers,

    personalDataCategories,

    retentionPolicy: {
      vaultTtlMinutes,
      auditLogRetentionDays: null,
      description: retentionDescription(vaultTtlMinutes, auditLogEnabled),
    },

    securityMeasures: {
      encryptionAtRest: encryptionEnabled,
      encryptionAlgorithm: encryptionEnabled ? 'AES-256-GCM' : 'none',
      pseudonymization: redactionMode === 'pseudonymize',
      accessControl: 'n8n workflow execution context with optional vault passphrase',
      auditLogging: auditLogEnabled,
    },

    processingSummary: {
      totalItemsProcessed: itemCount,
      totalPiiDetected: hits.length,
      redactionMode,
      patternsUsed,
      classificationLevel: classification.level,
      hitsByCategory: countByCategory(hits),
    },
  };
}
