/**
 * Tests for the secretBox key-ring implementation (#53).
 *
 * Covers:
 *  - parseKeyRing / buildKeyMap validation
 *  - v2 encrypt → decrypt with the correct key from a ring
 *  - v1 (legacy) ciphertext decryption still works via fallbackHexKey
 *  - Old-key ciphertexts decrypt through the ring
 *  - reencryptSecret migrates to the active key
 *  - Re-encryption is idempotent (no change when already on active key)
 */

import { describe, it, expect } from "vitest";
import {
  encryptSecret,
  decryptSecret,
  parseKeyRing,
  buildKeyMap,
  reencryptSecret,
  type KeyRingEntry,
} from "./secretBox.js";

// ── Helpers ───────────────────────────────────────────────────────────────────

const KEY1_HEX = "a1".repeat(32); // 64 hex chars
const KEY2_HEX = "b2".repeat(32);
const KEY3_HEX = "c3".repeat(32);

const ring2: KeyRingEntry[] = [
  { id: "k2", hex: KEY2_HEX }, // active
  { id: "k1", hex: KEY1_HEX }, // old
];

// ── parseKeyRing ──────────────────────────────────────────────────────────────

describe("parseKeyRing", () => {
  it("parses a single entry", () => {
    const ring = parseKeyRing(`k1:${KEY1_HEX}`);
    expect(ring).toHaveLength(1);
    expect(ring[0]).toEqual({ id: "k1", hex: KEY1_HEX });
  });

  it("parses multiple entries", () => {
    const ring = parseKeyRing(`k2:${KEY2_HEX},k1:${KEY1_HEX}`);
    expect(ring).toHaveLength(2);
    expect(ring[0].id).toBe("k2");
    expect(ring[1].id).toBe("k1");
  });

  it("returns empty array for undefined", () => {
    expect(parseKeyRing(undefined)).toEqual([]);
  });

  it("throws on a non-hex key", () => {
    expect(() => parseKeyRing("k1:notahexstring")).toThrow(/64 hex/);
  });

  it("throws on a key that is too short", () => {
    expect(() => parseKeyRing("k1:aabb")).toThrow(/64 hex/);
  });

  it("throws on a missing id", () => {
    expect(() => parseKeyRing(`:${KEY1_HEX}`)).toThrow(/empty/);
  });
});

// ── buildKeyMap ───────────────────────────────────────────────────────────────

describe("buildKeyMap", () => {
  it("builds a map from the ring", () => {
    const map = buildKeyMap(ring2);
    expect(map.size).toBe(2);
    expect(map.has("k1")).toBe(true);
    expect(map.has("k2")).toBe(true);
  });

  it("throws on duplicate ids", () => {
    const dup: KeyRingEntry[] = [
      { id: "k1", hex: KEY1_HEX },
      { id: "k1", hex: KEY2_HEX },
    ];
    expect(() => buildKeyMap(dup)).toThrow(/Duplicate/);
  });
});

// ── v2 encrypt / decrypt ──────────────────────────────────────────────────────

describe("encryptSecret / decryptSecret — v2 key ring", () => {
  it("encrypts with the active (first) key", () => {
    const enc = encryptSecret("my-secret", ring2);
    expect(enc.startsWith("v2:k2:")).toBe(true);
  });

  it("decrypts with the full ring (active key)", () => {
    const enc = encryptSecret("hello ring", ring2);
    expect(decryptSecret(enc, ring2)).toBe("hello ring");
  });

  it("decrypts a ciphertext encrypted under an old key using the ring", () => {
    // Encrypt under key k1 (simulating an old ciphertext)
    const oldRing: KeyRingEntry[] = [{ id: "k1", hex: KEY1_HEX }];
    const enc = encryptSecret("old secret", oldRing);
    expect(enc.startsWith("v2:k1:")).toBe(true);

    // Decrypt with ring2 that still has k1
    expect(decryptSecret(enc, ring2)).toBe("old secret");
  });

  it("throws when the key id is not in the ring", () => {
    const enc = encryptSecret("x", [{ id: "k3", hex: KEY3_HEX }]);
    expect(() => decryptSecret(enc, ring2)).toThrow(/k3.*not found/i);
  });

  it("decrypts with a Map-based key ring", () => {
    const enc = encryptSecret("map test", ring2);
    const map = buildKeyMap(ring2);
    expect(decryptSecret(enc, map)).toBe("map test");
  });

  it("produces different ciphertexts each call (random IV)", () => {
    const a = encryptSecret("same", ring2);
    const b = encryptSecret("same", ring2);
    expect(a).not.toBe(b);
    // But both decrypt correctly
    expect(decryptSecret(a, ring2)).toBe("same");
    expect(decryptSecret(b, ring2)).toBe("same");
  });
});

// ── v1 backward compatibility ─────────────────────────────────────────────────

describe("decryptSecret — v1 backward compatibility", () => {
  it("decrypts a v1 ciphertext using the fallback hex key", () => {
    // Simulate a legacy single-key encrypt (v1 format)
    const enc = encryptSecret("legacy secret", KEY1_HEX);
    expect(enc.startsWith("v1:")).toBe(true);

    // The new API: pass ring + fallback
    expect(decryptSecret(enc, ring2, KEY1_HEX)).toBe("legacy secret");
  });

  it("decrypts v1 ciphertext with a plain hex key string", () => {
    const enc = encryptSecret("plain key", KEY1_HEX);
    expect(decryptSecret(enc, KEY1_HEX)).toBe("plain key");
  });

  it("throws when decrypting v1 without a fallback key", () => {
    const enc = encryptSecret("need fallback", KEY1_HEX);
    expect(() => decryptSecret(enc, ring2 /*, no fallback */)).toThrow(/fallback/i);
  });
});

// ── reencryptSecret ───────────────────────────────────────────────────────────

describe("reencryptSecret", () => {
  it("re-encrypts a v1 ciphertext under the active key", () => {
    const enc = encryptSecret("rotate me", KEY1_HEX);
    expect(enc.startsWith("v1:")).toBe(true);

    const migrated = reencryptSecret(enc, ring2, KEY1_HEX);
    expect(migrated.startsWith("v2:k2:")).toBe(true);
    expect(decryptSecret(migrated, ring2)).toBe("rotate me");
  });

  it("re-encrypts an old-key v2 ciphertext under the active key", () => {
    const oldRing: KeyRingEntry[] = [{ id: "k1", hex: KEY1_HEX }];
    const enc = encryptSecret("old v2", oldRing);
    expect(enc.startsWith("v2:k1:")).toBe(true);

    const migrated = reencryptSecret(enc, ring2);
    expect(migrated.startsWith("v2:k2:")).toBe(true);
    expect(decryptSecret(migrated, ring2)).toBe("old v2");
  });

  it("returns the input unchanged when already on the active key", () => {
    const enc = encryptSecret("already current", ring2);
    const result = reencryptSecret(enc, ring2);
    // The encoded key id is k2 (active) — no re-encryption needed.
    expect(result).toBe(enc);
  });

  it("throws when the ring is empty", () => {
    const enc = encryptSecret("x", ring2);
    expect(() => reencryptSecret(enc, [])).toThrow(/empty/i);
  });
});
