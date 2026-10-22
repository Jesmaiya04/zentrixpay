#!/usr/bin/env tsx
/**
 * scripts/reencrypt-secrets.ts
 *
 * Re-encrypt all stored upstream secrets (header values, query params, webhook
 * secrets) under the active key in UPSTREAM_SECRET_KEYS.
 *
 * Usage:
 *
 *   # 1. Add the NEW key as the first entry and keep the OLD key(s) as fallbacks:
 *   export UPSTREAM_SECRET_KEYS="newKeyId:newhex64...,oldKeyId:oldhex64..."
 *   # (If you only have the legacy UPSTREAM_SECRET_KEY, still set it so v1
 *   #  ciphertexts can be decrypted during migration.)
 *   export UPSTREAM_SECRET_KEY="oldhex64..."   # legacy fallback for v1 blobs
 *   export DATABASE_URL="postgres://..."
 *
 *   # 2. Run the script (dry-run by default):
 *   pnpm tsx server/scripts/reencrypt-secrets.ts
 *
 *   # 3. Apply when you are satisfied:
 *   pnpm tsx server/scripts/reencrypt-secrets.ts --apply
 *
 *   # 4. Once all rows are migrated, remove old key ids from UPSTREAM_SECRET_KEYS.
 *
 * The script is idempotent: rows already encrypted under the active key are
 * skipped.  It commits each row individually so a crash mid-run can be retried.
 */

import "dotenv/config";
import { eq, isNotNull, or } from "drizzle-orm";
import { drizzle } from "drizzle-orm/postgres-js";
import postgres from "postgres";
import { apis } from "../src/db/schema.js";
import { parseKeyRing, reencryptSecret, buildKeyMap } from "../src/utils/secretBox.js";

// ── Configuration ─────────────────────────────────────────────────────────────

const DRY_RUN = !process.argv.includes("--apply");
const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) {
  console.error("ERROR: DATABASE_URL is required");
  process.exit(1);
}

const UPSTREAM_SECRET_KEYS = process.env.UPSTREAM_SECRET_KEYS;
if (!UPSTREAM_SECRET_KEYS) {
  console.error(
    "ERROR: UPSTREAM_SECRET_KEYS must be set with at least one entry.\n" +
      "Format: id:hex64[,id:hex64,...] — first entry is the target (active) key.",
  );
  process.exit(1);
}

let ring;
try {
  ring = parseKeyRing(UPSTREAM_SECRET_KEYS);
} catch (err) {
  console.error("ERROR: Invalid UPSTREAM_SECRET_KEYS:", (err as Error).message);
  process.exit(1);
}

if (ring.length === 0) {
  console.error("ERROR: UPSTREAM_SECRET_KEYS is empty");
  process.exit(1);
}

const keyMap = buildKeyMap(ring);
const LEGACY_KEY = process.env.UPSTREAM_SECRET_KEY; // v1 fallback
const activeKeyId = ring[0].id;

console.log(`Active key: ${activeKeyId}`);
console.log(`Key ring size: ${ring.length}`);
console.log(`Mode: ${DRY_RUN ? "DRY RUN (add --apply to write changes)" : "APPLY"}`);
console.log("");

// ── Database ──────────────────────────────────────────────────────────────────

const pg = postgres(DATABASE_URL);
const db = drizzle(pg);

// ── Re-encryption ─────────────────────────────────────────────────────────────

interface Stats {
  scanned: number;
  alreadyCurrent: number;
  reencrypted: number;
  errors: number;
}

async function reencryptColumn(
  apiId: string,
  col: "upstreamHeaderValueEnc" | "upstreamQueryValueEnc" | "webhookSecretEnc",
  encoded: string | null,
  stats: Stats,
): Promise<string | null> {
  if (!encoded) return null;
  stats.scanned++;

  try {
    const reencoded = reencryptSecret(encoded, ring, LEGACY_KEY);
    if (reencoded === encoded) {
      stats.alreadyCurrent++;
      return null; // no change
    }

    if (!DRY_RUN) {
      await db.update(apis).set({ [col]: reencoded }).where(eq(apis.id, apiId));
    }
    stats.reencrypted++;
    console.log(`  [${DRY_RUN ? "dry" : "done"}] ${apiId}.${col}`);
    return reencoded;
  } catch (err) {
    stats.errors++;
    console.error(`  [error] ${apiId}.${col}: ${(err as Error).message}`);
    return null;
  }
}

async function run(): Promise<void> {
  const stats: Stats = { scanned: 0, alreadyCurrent: 0, reencrypted: 0, errors: 0 };

  // Only fetch rows that have at least one encrypted column.
  const rows = await db
    .select()
    .from(apis)
    .where(
      or(
        isNotNull(apis.upstreamHeaderValueEnc),
        isNotNull(apis.upstreamQueryValueEnc),
        isNotNull(apis.webhookSecretEnc),
      ),
    );

  console.log(`Found ${rows.length} API row(s) with encrypted columns.\n`);

  for (const api of rows) {
    console.log(`API ${api.id} (${api.name})`);
    await reencryptColumn(api.id, "upstreamHeaderValueEnc", api.upstreamHeaderValueEnc, stats);
    await reencryptColumn(api.id, "upstreamQueryValueEnc", api.upstreamQueryValueEnc, stats);
    await reencryptColumn(api.id, "webhookSecretEnc", api.webhookSecretEnc, stats);
  }

  console.log("");
  console.log("── Summary ──────────────────────────────────────────────────");
  console.log(`  Scanned:         ${stats.scanned}`);
  console.log(`  Already current: ${stats.alreadyCurrent}`);
  console.log(`  Re-encrypted:    ${stats.reencrypted}`);
  console.log(`  Errors:          ${stats.errors}`);
  if (DRY_RUN && stats.reencrypted > 0) {
    console.log("");
    console.log("  Run with --apply to write these changes to the database.");
  }

  await pg.end();
  process.exit(stats.errors > 0 ? 1 : 0);
}

run().catch((err) => {
  console.error("Unexpected error:", err);
  process.exit(1);
});
