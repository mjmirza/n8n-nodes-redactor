/**
 * Vault Encryption Engine (AES-256-GCM)
 *
 * Encrypts vault files at rest so that even if someone accesses the
 * filesystem, they cannot read the PII mapping data without the passphrase.
 *
 * Security properties:
 *   - AES-256-GCM: Authenticated encryption (confidentiality + integrity)
 *   - scrypt key derivation: Memory-hard, resists GPU/ASIC brute-force
 *   - Unique salt per file: Same passphrase produces different keys per file
 *   - Unique IV per encryption: Same data produces different ciphertext
 *   - Auth tag: Detects tampering or wrong passphrase
 *
 * File format:
 *   [1 byte: version 0x01]
 *   [16 bytes: salt]
 *   [12 bytes: IV]
 *   [16 bytes: GCM auth tag]
 *   [N bytes: ciphertext]
 *
 * Backward compatible:
 *   - Files starting with '{' (0x7B) are read as plaintext JSON
 *   - Files starting with 0x01 are decrypted
 *   - Unencrypted files are auto-migrated to encrypted on next save
 */

import * as crypto from 'crypto';

const VERSION_BYTE = 0x01;
const SALT_LENGTH = 16;
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;
const KEY_LENGTH = 32; // AES-256
const SCRYPT_N = 2 ** 14; // 16384 — fast and secure for file encryption
const SCRYPT_R = 8;
const SCRYPT_P = 1;

/**
 * Derive a 256-bit encryption key from a passphrase using scrypt.
 */
function deriveKey(passphrase: string, salt: Buffer): Buffer {
  return crypto.scryptSync(passphrase, salt, KEY_LENGTH, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
  });
}

/**
 * Encrypt a JSON string using AES-256-GCM.
 * Returns a Buffer in the encrypted file format.
 */
export function encryptVaultData(jsonData: string, passphrase: string): Buffer {
  const salt = crypto.randomBytes(SALT_LENGTH);
  const iv = crypto.randomBytes(IV_LENGTH);
  const key = deriveKey(passphrase, salt);

  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([
    cipher.update(jsonData, 'utf-8'),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();

  // Assemble: [version][salt][iv][authTag][ciphertext]
  return Buffer.concat([
    Buffer.from([VERSION_BYTE]),
    salt,
    iv,
    authTag,
    encrypted,
  ]);
}

/**
 * Decrypt vault data from the encrypted file format.
 * Returns the decrypted JSON string.
 * Throws on wrong passphrase, corrupted data, or tampered file.
 */
export function decryptVaultData(data: Buffer, passphrase: string): string {
  if (data.length < 1 + SALT_LENGTH + IV_LENGTH + AUTH_TAG_LENGTH + 1) {
    throw new Error('Encrypted vault file is too short or corrupted.');
  }

  const version = data[0];
  if (version !== VERSION_BYTE) {
    throw new Error(`Unsupported vault encryption version: ${version}`);
  }

  let offset = 1;
  const salt = data.subarray(offset, offset + SALT_LENGTH);
  offset += SALT_LENGTH;
  const iv = data.subarray(offset, offset + IV_LENGTH);
  offset += IV_LENGTH;
  const authTag = data.subarray(offset, offset + AUTH_TAG_LENGTH);
  offset += AUTH_TAG_LENGTH;
  const ciphertext = data.subarray(offset);

  const key = deriveKey(passphrase, salt);

  let decrypted: Buffer | undefined;
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);
    decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    // GCM auth failure: wrong passphrase or tampered data. Reported below.
  }
  if (!decrypted) {
    throw new Error('Vault decryption failed: wrong passphrase or corrupted file.');
  }
  return decrypted.toString('utf-8');
}

/**
 * Check if a buffer contains encrypted vault data (starts with version byte).
 * If it starts with '{' (0x7B), it's plaintext JSON.
 */
export function isEncryptedVault(data: Buffer): boolean {
  if (data.length === 0) return false;
  return data[0] === VERSION_BYTE;
}

/**
 * Check if a buffer contains plaintext JSON vault data.
 */
export function isPlaintextVault(data: Buffer): boolean {
  if (data.length === 0) return false;
  return data[0] === 0x7B; // '{'
}
