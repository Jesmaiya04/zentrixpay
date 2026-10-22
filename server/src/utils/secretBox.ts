import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

// AES-256-GCM for small secrets stored at rest (providers' upstream API keys).
//
// Single-key encoding (legacy, still readable):
//   "v1:<iv>:<tag>:<ciphertext>"   — each part base64.
//
// Key-ring encoding (#53):
//   "v2:<keyId>:<iv>:<tag>:<ciphertext>"  — keyId is the id of the key used.
//
// When UPSTREAM_SECRET_KEYS is set, new secrets are always written in v2 format
// using the first (active) key.  Old v1 ciphertexts are decrypted with the
// single UPSTREAM_SECRET_KEY fallback and returned as-is; call the re-encryption
// script (server/scripts/reencrypt-secrets.ts) to migrate them.

const V1 = "v1";
const V2 = "v2";

function keyFromHex(hexKey: string): Buffer {
  const key = Buffer.from(hexKey, "hex");
  if (key.length !== 32) throw new Error("secret key must be 32 bytes (64 hex chars)");
  return key;
}

// ── Key ring ──────────────────────────────────────────────────────────────────

export interface KeyRingEntry {
  id: string;
  hex: string;
}

/**
 * Parse UPSTREAM_SECRET_KEYS value: a comma-separated list of "id:hex" pairs.
 * The first entry is the *active* key used for all new encryptions.
 *
 * Example:
 *   UPSTREAM_SECRET_KEYS=k2:aabbcc...64hex,k1:112233...64hex
 *
 * Returns an empty array if the value is empty/undefined.
 */
export function parseKeyRing(raw: string | undefined): KeyRingEntry[] {
  if (!raw) return [];
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
    .map((entry) => {
      const idx = entry.indexOf(":");
      if (idx === -1) throw new Error(`Invalid UPSTREAM_SECRET_KEYS entry: "${entry}" (expected id:hex)`);
      const id = entry.slice(0, idx).trim();
      const hex = entry.slice(idx + 1).trim();
      if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
        throw new Error(`Key "${id}" in UPSTREAM_SECRET_KEYS must be 64 hex characters`);
      }
      if (!id) throw new Error(`Key id must not be empty in UPSTREAM_SECRET_KEYS`);
      return { id, hex };
    });
}

/**
 * Build a lookup map from key id to key bytes.
 * Duplicate ids are rejected at parse time.
 */
export function buildKeyMap(ring: KeyRingEntry[]): Map<string, Buffer> {
  const map = new Map<string, Buffer>();
  for (const entry of ring) {
    if (map.has(entry.id)) throw new Error(`Duplicate key id "${entry.id}" in key ring`);
    map.set(entry.id, keyFromHex(entry.hex));
  }
  return map;
}

// ── Encryption ────────────────────────────────────────────────────────────────

/**
 * Encrypt `plaintext` with the active (first) key in the ring.
 * Falls back to the legacy single-key path when no ring is provided.
 */
export function encryptSecret(plaintext: string, hexKeyOrRing: string | KeyRingEntry[]): string {
  if (typeof hexKeyOrRing === "string") {
    // Legacy single-key path — produces v1 ciphertext.
    return encryptV1(plaintext, hexKeyOrRing);
  }
  if (hexKeyOrRing.length === 0) {
    throw new Error("Key ring is empty; cannot encrypt");
  }
  const active = hexKeyOrRing[0];
  return encryptV2(plaintext, active.id, active.hex);
}

function encryptV1(plaintext: string, hexKey: string): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", keyFromHex(hexKey), iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [V1, iv, tag, ciphertext]
    .map((p) => (typeof p === "string" ? p : p.toString("base64")))
    .join(":");
}

function encryptV2(plaintext: string, keyId: string, hexKey: string): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", keyFromHex(hexKey), iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [V2, keyId, iv.toString("base64"), tag.toString("base64"), ciphertext.toString("base64")].join(":");
}

// ── Decryption ────────────────────────────────────────────────────────────────

/**
 * Decrypt a ciphertext produced by `encryptSecret`.
 *
 * For v1 ciphertexts:  `hexKeyOrRing` must be the plain hex key string.
 * For v2 ciphertexts:  `hexKeyOrRing` can be a key ring (Map or array); the key
 *                       id embedded in the ciphertext is used to select the key.
 *
 * Passing a key ring (array/Map) transparently handles both v1 and v2 when
 * `fallbackHexKey` is also provided.
 */
export function decryptSecret(
  encoded: string,
  hexKeyOrRing: string | KeyRingEntry[] | Map<string, Buffer>,
  fallbackHexKey?: string,
): string {
  const parts = encoded.split(":");
  const version = parts[0];

  if (version === V1) {
    // v1: "v1:<iv>:<tag>:<ciphertext>"
    const [, iv, tag, ciphertext] = parts;
    if (!iv || !tag || ciphertext === undefined) {
      throw new Error("unrecognised v1 secret encoding");
    }
    // Accept a bare hex key, a key ring (use fallback), or a Map (use fallback).
    const hexKey =
      typeof hexKeyOrRing === "string"
        ? hexKeyOrRing
        : (fallbackHexKey ?? (() => { throw new Error("v1 ciphertext requires a fallback hex key"); })());
    return decryptV1(iv, tag, ciphertext, hexKey);
  }

  if (version === V2) {
    // v2: "v2:<keyId>:<iv>:<tag>:<ciphertext>"
    const [, keyId, iv, tag, ciphertext] = parts;
    if (!keyId || !iv || !tag || ciphertext === undefined) {
      throw new Error("unrecognised v2 secret encoding");
    }
    let keyBuf: Buffer | undefined;
    if (hexKeyOrRing instanceof Map) {
      keyBuf = hexKeyOrRing.get(keyId);
    } else if (Array.isArray(hexKeyOrRing)) {
      const entry = hexKeyOrRing.find((e) => e.id === keyId);
      keyBuf = entry ? keyFromHex(entry.hex) : undefined;
    } else {
      // Legacy caller passing a plain hex key — only works if that is the right key.
      keyBuf = keyFromHex(hexKeyOrRing);
    }
    if (!keyBuf) throw new Error(`Key "${keyId}" not found in key ring`);
    return decryptV2(keyId, iv, tag, ciphertext, keyBuf);
  }

  throw new Error(`unrecognised secret encoding version: "${version}"`);
}

function decryptV1(iv: string, tag: string, ciphertext: string, hexKey: string): string {
  const decipher = createDecipheriv("aes-256-gcm", keyFromHex(hexKey), Buffer.from(iv, "base64"));
  decipher.setAuthTag(Buffer.from(tag, "base64"));
  return Buffer.concat([
    decipher.update(Buffer.from(ciphertext, "base64")),
    decipher.final(),
  ]).toString("utf8");
}

function decryptV2(_keyId: string, iv: string, tag: string, ciphertext: string, key: Buffer): string {
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(iv, "base64"));
  decipher.setAuthTag(Buffer.from(tag, "base64"));
  return Buffer.concat([
    decipher.update(Buffer.from(ciphertext, "base64")),
    decipher.final(),
  ]).toString("utf8");
}

// ── Re-encryption helper ──────────────────────────────────────────────────────

/**
 * Re-encrypt `encoded` under the active key in `ring`.
 * No-op (returns the input unchanged) if it is already encrypted under the
 * active key.  The `fallbackHexKey` is used to decrypt legacy v1 ciphertexts.
 */
export function reencryptSecret(
  encoded: string,
  ring: KeyRingEntry[],
  fallbackHexKey?: string,
): string {
  if (ring.length === 0) throw new Error("Key ring is empty");
  const activeId = ring[0].id;

  // Already encrypted under the active key?
  const parts = encoded.split(":");
  if (parts[0] === V2 && parts[1] === activeId) return encoded;

  const plaintext = decryptSecret(encoded, ring, fallbackHexKey);
  return encryptSecret(plaintext, ring);
}
