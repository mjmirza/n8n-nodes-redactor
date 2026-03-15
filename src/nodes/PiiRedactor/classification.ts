/**
 * Data Classification Engine
 *
 * Assigns sensitivity labels to data based on what PII categories were found.
 * Modeled on Microsoft Purview and Google Cloud DLP classification taxonomy.
 *
 * Levels:
 *   PUBLIC (0)     - No PII detected
 *   INTERNAL (1)   - Low-sensitivity PII (network, location, vehicle, temporal)
 *   CONFIDENTIAL (2) - Personal PII (names, emails, phones, addresses, identity docs)
 *   RESTRICTED (3) - High-sensitivity PII (financial, medical, biometric, enterprise secrets)
 *
 * Escalation rules (based on Purview instance-count thresholds):
 *   - Any RESTRICTED-category hit -> RESTRICTED
 *   - 10+ CONFIDENTIAL hits -> escalate to RESTRICTED
 *   - 5+ INTERNAL hits -> escalate to CONFIDENTIAL
 */

import { PiiCategory, RedactionHit } from './types';

export type SensitivityLevel = 'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL' | 'RESTRICTED';

export interface ClassificationLabel {
  level: SensitivityLevel;
  numericLevel: 0 | 1 | 2 | 3;
  reason: string;
  topCategory: PiiCategory | 'none';
  hitCountByLevel: Record<SensitivityLevel, number>;
  escalated: boolean;
  totalHits: number;
  averageConfidence: number;
}

/** Map PII categories to base sensitivity levels */
const CATEGORY_SENSITIVITY: Record<string, SensitivityLevel> = {
  // RESTRICTED (3) - highest sensitivity
  financial: 'RESTRICTED',
  medical: 'RESTRICTED',
  biometric: 'RESTRICTED',
  enterprise: 'RESTRICTED',
  crypto: 'RESTRICTED',

  // CONFIDENTIAL (2) - personal data
  identity: 'CONFIDENTIAL',
  contact: 'CONFIDENTIAL',

  // INTERNAL (1) - low sensitivity
  network: 'INTERNAL',
  location: 'INTERNAL',
  vehicle: 'INTERNAL',
  temporal: 'INTERNAL',
  other: 'INTERNAL',
};

const LEVEL_NUMERIC: Record<SensitivityLevel, number> = {
  PUBLIC: 0,
  INTERNAL: 1,
  CONFIDENTIAL: 2,
  RESTRICTED: 3,
};

/**
 * Classify data sensitivity based on detected PII hits.
 */
export function classifyData(hits: RedactionHit[]): ClassificationLabel {
  if (hits.length === 0) {
    return {
      level: 'PUBLIC',
      numericLevel: 0,
      reason: 'No sensitive data detected.',
      topCategory: 'none',
      hitCountByLevel: { PUBLIC: 0, INTERNAL: 0, CONFIDENTIAL: 0, RESTRICTED: 0 },
      escalated: false,
      totalHits: 0,
      averageConfidence: 0,
    };
  }

  // Count hits by sensitivity level
  const hitCountByLevel: Record<SensitivityLevel, number> = {
    PUBLIC: 0,
    INTERNAL: 0,
    CONFIDENTIAL: 0,
    RESTRICTED: 0,
  };

  const categoryCounts: Record<string, number> = {};
  let totalConfidence = 0;

  for (const hit of hits) {
    const catLevel = CATEGORY_SENSITIVITY[hit.category] || 'INTERNAL';
    hitCountByLevel[catLevel]++;
    categoryCounts[hit.category] = (categoryCounts[hit.category] || 0) + 1;
    totalConfidence += hit.confidence || 0.65;
  }

  // Determine base level from highest-sensitivity hit
  let level: SensitivityLevel = 'PUBLIC';
  if (hitCountByLevel.RESTRICTED > 0) level = 'RESTRICTED';
  else if (hitCountByLevel.CONFIDENTIAL > 0) level = 'CONFIDENTIAL';
  else if (hitCountByLevel.INTERNAL > 0) level = 'INTERNAL';

  // Escalation rules
  let escalated = false;

  // 10+ CONFIDENTIAL hits -> RESTRICTED
  if (level === 'CONFIDENTIAL' && hitCountByLevel.CONFIDENTIAL >= 10) {
    level = 'RESTRICTED';
    escalated = true;
  }

  // 5+ INTERNAL hits -> CONFIDENTIAL
  if (level === 'INTERNAL' && hitCountByLevel.INTERNAL >= 5) {
    level = 'CONFIDENTIAL';
    escalated = true;
  }

  // Find top category
  const topCategory = Object.entries(categoryCounts)
    .sort((a, b) => b[1] - a[1])[0][0] as PiiCategory;

  // Build reason string
  const reasonParts: string[] = [];
  for (const [cat, count] of Object.entries(categoryCounts).sort((a, b) => b[1] - a[1])) {
    reasonParts.push(`${count} ${cat}`);
  }
  let reason = `Contains: ${reasonParts.join(', ')}.`;
  if (escalated) {
    reason += ` Escalated due to high volume of detections.`;
  }

  return {
    level,
    numericLevel: LEVEL_NUMERIC[level] as 0 | 1 | 2 | 3,
    reason,
    topCategory,
    hitCountByLevel,
    escalated,
    totalHits: hits.length,
    averageConfidence: Math.round((totalConfidence / hits.length) * 100) / 100,
  };
}
