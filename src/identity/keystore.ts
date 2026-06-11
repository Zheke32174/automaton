/**
 * Conway Automaton — Wallet Keystore (AES-256-GCM)
 *
 * Ported from cluster/quoroom/src/shared/wallet.ts (2026-06-11 sweep).
 *
 * Closes a real security gap: the wallet at ~/.automaton/wallet.json was
 * previously plaintext on disk. With this module the privateKey / secretKey
 * field can be stored as an iv:tag:ciphertext hex envelope, decryptable
 * only with the operator's master password.
 *
 * Format: `${iv_hex}:${authTag_hex}:${ciphertext_hex}` — same format Quoroom
 * uses, so a future fusion of the two wallets can share the same payload.
 *
 * Master-password unlock paths:
 *   1. AUTOMATON_MASTER_PASSWORD env var (for systemd / cron / non-interactive).
 *   2. (deferred) interactive prompt — not yet wired so we never block a
 *      headless start without an env var being present.
 *
 * Migration is opt-in via `migrateWalletToEncrypted()` in wallet.ts. Existing
 * unencrypted wallets continue to work unchanged.
 */

import crypto from "node:crypto";

export const ENCRYPTION_ALGORITHM = "aes-256-gcm" as const;
export const IV_LENGTH = 12;
export const KEYSTORE_VERSION = 1;

/**
 * Encrypt arbitrary UTF-8 plaintext with AES-256-GCM.
 * The encryption key is a passphrase (any length) — we hash it with SHA-256
 * down to the required 32-byte key. A fresh random 96-bit IV is generated for
 * every encryption.
 */
export function encryptString(plaintext: string, passphrase: string): string {
  const key = crypto.createHash("sha256").update(passphrase).digest();
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ENCRYPTION_ALGORITHM, key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${iv.toString("hex")}:${tag.toString("hex")}:${ciphertext.toString("hex")}`;
}

/**
 * Decrypt an envelope produced by encryptString. Throws if the auth tag fails
 * (wrong password OR tampered ciphertext).
 */
export function decryptString(envelope: string, passphrase: string): string {
  const key = crypto.createHash("sha256").update(passphrase).digest();
  const parts = envelope.split(":");
  if (parts.length !== 3) {
    throw new Error("invalid encrypted envelope: expected iv:tag:ciphertext");
  }
  const iv = Buffer.from(parts[0], "hex");
  const tag = Buffer.from(parts[1], "hex");
  const ciphertext = Buffer.from(parts[2], "hex");
  if (iv.length !== IV_LENGTH) {
    throw new Error(`invalid IV length: expected ${IV_LENGTH}, got ${iv.length}`);
  }
  const decipher = crypto.createDecipheriv(ENCRYPTION_ALGORITHM, key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
}

/**
 * Resolve the master password from the environment.
 * Throws if not set so a misconfigured headless start fails fast and loud
 * rather than silently writing a plaintext wallet.
 */
export function getMasterPassword(): string {
  const p = process.env.AUTOMATON_MASTER_PASSWORD;
  if (!p) {
    throw new Error(
      "AUTOMATON_MASTER_PASSWORD env var is required when loading or " +
      "encrypting an encrypted wallet. Set it in the systemd unit, the " +
      "shell, or your secret manager — never commit it.",
    );
  }
  return p;
}

/**
 * Cheap test that an envelope LOOKS like an encrypted blob (does not verify).
 * Used to distinguish a legacy plaintext private key from a v1 envelope.
 */
export function looksEncrypted(value: string | undefined): boolean {
  if (!value) return false;
  // Plaintext EVM private keys are `0x` + 64 hex chars.
  // Solana secret keys are base58 of 64 bytes (~88 base58 chars, no colons).
  // Envelopes always have exactly two colons separating three hex blobs.
  if (value.startsWith("0x")) return false;
  const parts = value.split(":");
  return parts.length === 3 && parts.every((p) => /^[0-9a-f]+$/i.test(p));
}
