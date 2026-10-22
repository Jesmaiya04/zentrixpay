import { describe, it, expect, vi, beforeEach } from 'vitest';
import request from 'supertest';
import express from 'express';

// ── mocks ─────────────────────────────────────────────────────────────────────

vi.mock('../config.js', () => ({
  config: {
    BASE_URL: 'https://zentrixpay.test',
    NETWORK: 'base-sepolia',
  },
}));

const mockApis = [
  {
    id: 'api_001',
    name: 'Weather API',
    description: 'Real-time weather data',
    price: '0.01',
    walletAddress: 'GWALLETADDRESS',
    allowedMethods: ['GET'],
    network: null,
    tags: ['weather'],
    openapiSpec: null,
    listed: true,
    archivedAt: null,
  },
  {
    id: 'api_002',
    name: 'Translation API',
    description: 'Translate text between languages',
    price: '0.05',
    walletAddress: 'GWALLET2',
    allowedMethods: ['GET', 'POST'],
    network: 'base-mainnet',
    tags: ['translation', 'nlp'],
    openapiSpec: {
      openapi: '3.0.0',
      'x-input-schema': { type: 'object', properties: { text: { type: 'string' } } },
      'x-output-schema': { type: 'object', properties: { result: { type: 'string' } } },
      'x-category': 'nlp',
    },
    listed: true,
    archivedAt: null,
  },
];

vi.mock('../db/index.js', () => ({ db: {} }));
vi.mock('drizzle-orm', async (importOriginal) => {
  const actual = await importOriginal<typeof import('drizzle-orm')>();
  return { ...actual };
});

// Mock the drizzle db query chain used in discovery.ts
vi.mock('../db/index.js', () => {
  const select = vi.fn().mockReturnThis();
  const from = vi.fn().mockReturnThis();
  const where = vi.fn().mockResolvedValue(mockApis);
  return { db: { select, from, where } };
});

// ── router under test ─────────────────────────────────────────────────────────

import discoveryRouter, { invalidateDiscoveryCache } from './discovery.js';

function buildApp() {
  const app = express();
  app.use(express.json());
  app.use(discoveryRouter);
  return app;
}

// ── tests ─────────────────────────────────────────────────────────────────────

describe('GET /.well-known/x402', () => {
  beforeEach(() => {
    invalidateDiscoveryCache();
  });

  it('returns 200 with JSON content-type', async () => {
    const app = buildApp();
    const res = await request(app).get('/.well-known/x402');
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toMatch(/application\/json/);
  });

  it('includes version, provider and baseUrl', async () => {
    const app = buildApp();
    const res = await request(app).get('/.well-known/x402');
    expect(res.body.version).toBe('1');
    expect(res.body.provider).toBe('ZentrixPay');
    expect(res.body.baseUrl).toBe('https://zentrixpay.test');
  });

  it('lists all public APIs with required fields', async () => {
    const app = buildApp();
    const res = await request(app).get('/.well-known/x402');
    const { apis } = res.body as { apis: any[] };

    expect(apis).toHaveLength(2);

    const weather = apis.find((a) => a.id === 'api_001');
    expect(weather).toBeDefined();
    expect(weather.name).toBe('Weather API');
    expect(weather.price).toBe('0.01');
    expect(weather.currency).toBe('USDC');
    expect(weather.proxyUrl).toBe('https://zentrixpay.test/api/api_001');
    expect(weather.allowedMethods).toEqual(['GET']);
    expect(weather.tags).toEqual(['weather']);
    // No OpenAPI spec → discovery fields are null
    expect(weather.inputSchema).toBeNull();
    expect(weather.outputSchema).toBeNull();
    expect(weather.category).toBeNull();
    // Falls back to config.NETWORK when api.network is null
    expect(weather.network).toBe('base-sepolia');
  });

  it('includes discovery fields from x-* OpenAPI extensions', async () => {
    const app = buildApp();
    const res = await request(app).get('/.well-known/x402');
    const { apis } = res.body as { apis: any[] };

    const translation = apis.find((a) => a.id === 'api_002');
    expect(translation).toBeDefined();
    expect(translation.network).toBe('base-mainnet');
    expect(translation.inputSchema).toEqual({
      type: 'object',
      properties: { text: { type: 'string' } },
    });
    expect(translation.outputSchema).toEqual({
      type: 'object',
      properties: { result: { type: 'string' } },
    });
    expect(translation.category).toBe('nlp');
  });

  it('sets Cache-Control header', async () => {
    const app = buildApp();
    const res = await request(app).get('/.well-known/x402');
    expect(res.headers['cache-control']).toContain('max-age=30');
  });
});
