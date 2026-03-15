/**
 * Per-Tenant Profile Management
 *
 * Profiles allow agencies to define different redaction rules per client/tenant.
 * Each profile is a JSON config containing: enabled patterns, allow/deny lists,
 * redaction mode, field rules, confidence threshold, and compliance settings.
 *
 * Storage: ~/.n8n/pii-profiles/profile_{profileId}.json
 * Loading: By profileId parameter in node settings
 * Isolation: Each profile has its own vault passphrase recommendation
 */

import * as fs from 'fs';
import * as path from 'path';
import {
  RedactionMode,
  CustomPattern,
  AllowDenyEntry,
  FieldRule,
} from './types';

export interface TenantProfile {
  profileId: string;
  displayName: string;

  // Detection config
  enabledPatterns?: string[];
  customPatterns?: CustomPattern[];
  confidenceThreshold?: number;

  // Redaction behavior
  redactionMode?: RedactionMode;
  dedup?: boolean;

  // Field targeting
  fieldMode?: 'all' | 'allowlist' | 'denylist';
  fieldRules?: FieldRule[];

  // Allow/Deny lists
  allowList?: AllowDenyEntry[];
  denyList?: AllowDenyEntry[];

  // Compliance
  region?: string;
  retentionMinutes?: number;
  auditLog?: boolean;

  // Metadata
  createdAt: string;
  updatedAt: string;
}

const DEFAULT_PROFILE_DIR = path.join(process.env.HOME || '/tmp', '.n8n', 'pii-profiles');

/**
 * Load a tenant profile by ID.
 * Returns null if not found.
 */
export function loadProfile(profileId: string, profileDir?: string): TenantProfile | null {
  if (!profileId || profileId.trim().length === 0) return null;

  try {
    const dir = profileDir || DEFAULT_PROFILE_DIR;
    // Sanitize profileId to prevent path traversal
    const safeId = profileId.replace(/[^a-zA-Z0-9_\-]/g, '_');
    const fp = path.join(dir, `profile_${safeId}.json`);

    if (!fs.existsSync(fp)) return null;

    const data = JSON.parse(fs.readFileSync(fp, 'utf-8')) as TenantProfile;
    return data;
  } catch {
    return null;
  }
}

/**
 * Save a tenant profile.
 */
export function saveProfile(profile: TenantProfile, profileDir?: string): boolean {
  try {
    const dir = profileDir || DEFAULT_PROFILE_DIR;
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    const safeId = profile.profileId.replace(/[^a-zA-Z0-9_\-]/g, '_');
    const fp = path.join(dir, `profile_${safeId}.json`);
    const tmpFp = fp + '.tmp';

    profile.updatedAt = new Date().toISOString();
    fs.writeFileSync(tmpFp, JSON.stringify(profile, null, 2), 'utf-8');
    fs.renameSync(tmpFp, fp);
    return true;
  } catch {
    return false;
  }
}

/**
 * List all available profiles.
 */
export function listProfiles(profileDir?: string): TenantProfile[] {
  try {
    const dir = profileDir || DEFAULT_PROFILE_DIR;
    if (!fs.existsSync(dir)) return [];

    const files = fs.readdirSync(dir)
      .filter((f) => f.startsWith('profile_') && f.endsWith('.json'));

    const profiles: TenantProfile[] = [];
    for (const file of files) {
      try {
        const data = JSON.parse(
          fs.readFileSync(path.join(dir, file), 'utf-8'),
        ) as TenantProfile;
        profiles.push(data);
      } catch {
        // Skip corrupt profiles
      }
    }
    return profiles;
  } catch {
    return [];
  }
}

/**
 * Delete a tenant profile.
 */
export function deleteProfile(profileId: string, profileDir?: string): boolean {
  try {
    const dir = profileDir || DEFAULT_PROFILE_DIR;
    const safeId = profileId.replace(/[^a-zA-Z0-9_\-]/g, '_');
    const fp = path.join(dir, `profile_${safeId}.json`);

    if (fs.existsSync(fp)) {
      fs.unlinkSync(fp);
      return true;
    }
    return false;
  } catch {
    return false;
  }
}
