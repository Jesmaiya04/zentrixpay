/**
 * /.well-known/x402 — Bazaar discovery index for listed ZentrixPay APIs.
 *
 * x402 clients and agent marketplaces can GET this endpoint to discover every
 * paid API the server exposes through the pay-per-call proxy.  The response
 * shape follows the x402 Bazaar discovery extension:
 *
 *   {
 *     "version": "1",
 *     "provider": "ZentrixPay",
 *     "baseUrl": "https://example.com",
 *     "apis": [
 *       {
 *         "id": "<cuid>",
 *         "name": "...",
 *         "description": "...",
 *         "proxyUrl": "https://example.com/api/<id>",
 *         "price": "0.01",
 *         "currency": "USDC",
 *         "network": "base-sepolia",
 *         "payTo": "<wallet>",
 *         "allowedMethods": ["GET"],
 *         "tags": [],
 *         "inputSchema": null,   // JSON Schema or null
 *         "outputSchema": null,  // JSON Schema or null
 *         "category": null
 *       }
 *     ]
 *   }
 *
 * Responses are cached for 30 s to cut DB load on discovery crawlers.
 */

import { Router } from 'express';
import { and, eq, isNull } from 'drizzle-orm';
import { db } from '../db/index.js';
import { apis } from '../db/schema.js';
import { config } from '../config.js';

const router = Router();

// Simple in-process cache so discovery crawlers don't hammer the DB.
let cachedIndex: string | null = null;
let cacheExpiresAt = 0;
const CACHE_TTL_MS = 30_000;

async function buildIndex(): Promise<object> {
  const rows = await db
    .select()
    .from(apis)
    .where(and(eq(apis.listed, true), isNull(apis.archivedAt)));

  const apiEntries = rows.map((api) => ({
    id: api.id,
    name: api.name,
    description: api.description ?? null,
    proxyUrl: `${config.BASE_URL}/api/${api.id}`,
    openapiUrl: api.openapiSpec ? `${config.BASE_URL}/apis/${api.id}/openapi.json` : null,
    price: api.price,
    currency: 'USDC',
    network: api.network ?? config.NETWORK,
    payTo: api.walletAddress,
    allowedMethods: api.allowedMethods,
    tags: api.tags,
    // Discovery-specific fields — populated when the provider uploads an
    // OpenAPI spec with x-input-schema / x-output-schema extensions or
    // explicitly sets these via the management API.
    inputSchema: (api.openapiSpec as Record<string, unknown> | null)?.['x-input-schema'] ?? null,
    outputSchema:
      (api.openapiSpec as Record<string, unknown> | null)?.['x-output-schema'] ?? null,
    category: (api.openapiSpec as Record<string, unknown> | null)?.['x-category'] ?? null,
  }));

  return {
    version: '1',
    provider: 'ZentrixPay',
    baseUrl: config.BASE_URL,
    apis: apiEntries,
  };
}

// GET /.well-known/x402
router.get('/.well-known/x402', async (_req, res) => {
  const now = Date.now();
  if (!cachedIndex || now > cacheExpiresAt) {
    try {
      cachedIndex = JSON.stringify(await buildIndex());
      cacheExpiresAt = now + CACHE_TTL_MS;
    } catch (err) {
      res.status(500).json({ error: 'Failed to build discovery index' });
      return;
    }
  }

  res
    .setHeader('Content-Type', 'application/json')
    .setHeader('Cache-Control', 'public, max-age=30')
    .end(cachedIndex);
});

/** Exported so tests and other routes can invalidate the cache after a write. */
export function invalidateDiscoveryCache(): void {
  cachedIndex = null;
  cacheExpiresAt = 0;
}

export default router;
