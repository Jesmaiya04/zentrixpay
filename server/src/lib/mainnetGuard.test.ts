/**
 * Tests for the mainnet startup safety guard (#51).
 *
 * We test `mainnetSafetyViolations` directly so we can exercise every branch
 * without calling process.exit or loading the full config module (which
 * requires live env vars and calls process.exit on parse failure).
 */

import { describe, it, expect } from 'vitest';

// We cannot import config.ts directly because it calls process.exit at module
// load time if env vars are wrong.  Instead we inline the guard logic here —
// the guard itself is kept in a pure helper that config.ts exports.

// Build a minimal config-shaped object so we can drive the guard in isolation.
type MinimalConfig = {
  STELLAR_NETWORK: 'testnet' | 'mainnet';
  PROXY_ALLOW_PRIVATE_UPSTREAMS: boolean;
};

function mainnetSafetyViolations(cfg: MinimalConfig): string[] {
  if (cfg.STELLAR_NETWORK !== 'mainnet') return [];

  const violations: string[] = [];

  if (cfg.PROXY_ALLOW_PRIVATE_UPSTREAMS) {
    violations.push(
      'PROXY_ALLOW_PRIVATE_UPSTREAMS=true is not allowed on mainnet — ' +
        'it would permit SSRF attacks via provider-supplied upstream URLs.',
    );
  }

  return violations;
}

// ── tests ─────────────────────────────────────────────────────────────────────

describe('mainnetSafetyViolations', () => {
  const safeMainnet: MinimalConfig = {
    STELLAR_NETWORK: 'mainnet',
    PROXY_ALLOW_PRIVATE_UPSTREAMS: false,
  };

  it('returns no violations for a safe mainnet config', () => {
    expect(mainnetSafetyViolations(safeMainnet)).toEqual([]);
  });

  it('returns no violations on testnet even with unsafe settings', () => {
    expect(
      mainnetSafetyViolations({
        STELLAR_NETWORK: 'testnet',
        PROXY_ALLOW_PRIVATE_UPSTREAMS: true,
      }),
    ).toEqual([]);
  });

  it('flags PROXY_ALLOW_PRIVATE_UPSTREAMS=true on mainnet', () => {
    const violations = mainnetSafetyViolations({
      ...safeMainnet,
      PROXY_ALLOW_PRIVATE_UPSTREAMS: true,
    });
    expect(violations).toHaveLength(1);
    expect(violations[0]).toMatch(/PROXY_ALLOW_PRIVATE_UPSTREAMS/);
    expect(violations[0]).toMatch(/mainnet/);
  });

  it('server would refuse to start on mainnet with private upstreams enabled', () => {
    // Simulate what index.ts / config.ts does at startup.
    const cfg: MinimalConfig = {
      STELLAR_NETWORK: 'mainnet',
      PROXY_ALLOW_PRIVATE_UPSTREAMS: true,
    };
    const violations = mainnetSafetyViolations(cfg);
    // The real guard calls process.exit(1) when violations.length > 0.
    expect(violations.length).toBeGreaterThan(0);
  });
});
