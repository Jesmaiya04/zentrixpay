import "dotenv/config";
import { z } from "zod/v4";
import {
  applyNetworkEnvDefaults,
  resolveStellarNetwork,
  validateNetworkConfig,
} from "@zentrixpay/registry-client";
import { rootLogger } from "./lib/logger.js";

const envWithDefaults = applyNetworkEnvDefaults(process.env);

const envSchema = z.object({
  NODE_ENV: z.enum(["development", "production", "test"]).default("development"),
  PORT: z.coerce.number().default(4021),
  BASE_URL: z.string().default("http://localhost:4021"),
  WEB_APP_URL: z.string().url().default("http://localhost:5173"),
  ALLOWED_ORIGINS: z.string().optional(),

  // Stellar / x402 — STELLAR_NETWORK selects preset defaults; individual vars may override.
  STELLAR_NETWORK: z.enum(["testnet", "mainnet"]).default("testnet"),
  NETWORK: z.string().min(1),
  FACILITATOR_URL: z.string().default("https://www.x402.org/facilitator"),
  PAY_TO: z.string().min(1, "PAY_TO (platform wallet address) is required"),
  AGENT_SECRET_KEY: z.string().min(1, "AGENT_SECRET_KEY (platform agent secret) is required"),
  USDC_CONTRACT_ID: z.string().min(1),

  // Soroban / vault-registry
  SOROBAN_RPC_URL: z.string().url("SOROBAN_RPC_URL must be a valid URL"),
  VAULT_REGISTRY_CONTRACT_ID: z.string().min(1, "VAULT_REGISTRY_CONTRACT_ID is required"),

  // OpenRouter
  OPENROUTER_API_KEY: z.string().min(1, "OPENROUTER_API_KEY is required"),
  OPENROUTER_MODEL: z.string().default("anthropic/claude-sonnet-4"),

  // Supabase
  DATABASE_URL: z.string().min(1, "DATABASE_URL (Supabase Postgres connection string) is required"),
  SUPABASE_URL: z.string().url("SUPABASE_URL must be a valid URL"),
  SUPABASE_SERVICE_KEY: z.string().min(1, "SUPABASE_SERVICE_KEY is required"),
  SUPABASE_STORAGE_BUCKET: z.string().default("resources"),

  // Limits
  MAX_FILE_SIZE_MB: z.coerce.number().default(50),
  // Explicit JSON body limit for express.json() (e.g. "1mb", "512kb").
  MAX_JSON_BODY_SIZE: z.string().default("1mb"),
  // Comma-separated allowlist of accepted upload content types (#87).
  ALLOWED_UPLOAD_MIME_TYPES: z
    .string()
    .default(
      "application/pdf,image/png,image/jpeg,image/gif,image/webp,text/plain,text/markdown,application/json,application/zip,video/mp4,audio/mpeg",
    ),

  // Soroban registry
  REGISTRY_CONTRACT_ID: z.string().min(1, "REGISTRY_CONTRACT_ID is required"),
  REGISTRY_SECRET_KEY: z
    .string()
    .min(1, "REGISTRY_SECRET_KEY (deployer / owner secret) is required"),

  // Metrics endpoint token — if set, requests to /metrics must supply it via
  // Bearer auth or ?token=. If unset, the endpoint is disabled.
  METRICS_TOKEN: z.string().optional(),

  // Sentry error tracking — when DSN is set, unhandled errors are reported.
  SENTRY_DSN: z.string().url().optional(),

  // Verification
  VERIFICATION_PRICE: z.string().default("0.10"),
  // OpenRouter token pricing (USD per 1M tokens) used to estimate the cost of
  // each verification (#283). Defaults track anthropic/claude-sonnet-4 list
  // pricing; override per model if you change OPENROUTER_MODEL.
  VERIFICATION_PROMPT_COST_PER_1M: z.coerce.number().nonnegative().default(3),
  VERIFICATION_COMPLETION_COST_PER_1M: z.coerce.number().nonnegative().default(15),

  // Rate limiting (verify-content + publish)
  RATE_LIMIT_VERIFY_IP_MAX: z.coerce.number().default(10),
  RATE_LIMIT_VERIFY_IP_WINDOW_MS: z.coerce.number().default(60_000),
  RATE_LIMIT_VERIFY_WALLET_MAX: z.coerce.number().default(5),
  RATE_LIMIT_VERIFY_WALLET_WINDOW_MS: z.coerce.number().default(3_600_000),
  RATE_LIMIT_PUBLISH_IP_MAX: z.coerce.number().default(20),
  RATE_LIMIT_PUBLISH_IP_WINDOW_MS: z.coerce.number().default(60_000),
  RATE_LIMIT_PUBLISH_WALLET_MAX: z.coerce.number().default(10),
  RATE_LIMIT_PUBLISH_WALLET_WINDOW_MS: z.coerce.number().default(3_600_000),

  // Optional Redis URL for a shared sliding-window rate-limit store (multi-instance).
  REDIS_URL: z.string().url().optional(),

  // Optional HMAC-SHA256 request signatures for publisher mutations (off by default).
  REQUIRE_REQUEST_SIGNATURE: z.coerce.boolean().default(false),
  // Max clock skew for X-Timestamp when signatures are required (default 5 minutes).
  SIGNATURE_MAX_SKEW_MS: z.coerce.number().default(300_000),

  // Per-request timeout — slow upstreams (RPC, facilitator) return 503 instead
  // of hanging the connection.
  REQUEST_TIMEOUT_MS: z.coerce.number().default(30_000),
  // Max time to drain in-flight requests on SIGTERM/SIGINT before forcing exit.
  GRACEFUL_SHUTDOWN_TIMEOUT_MS: z.coerce.number().default(10_000),
  // How long a publish Idempotency-Key is remembered so retries return the
  // original result instead of creating a duplicate (default 24h).
  IDEMPOTENCY_TTL_MS: z.coerce.number().default(86_400_000),
  // Short-lived cache for catalog/preview reads to cut DB load. Kept low so
  // newly published/delisted resources surface quickly.
  CATALOG_CACHE_TTL_MS: z.coerce.number().default(10_000),
  // Max distinct filter/sort/pagination combinations cached for the catalog
  // (#316). Bounds key cardinality; oldest entries are evicted (FIFO).
  CATALOG_CACHE_MAX_KEYS: z.coerce.number().int().min(1).default(200),

  // API proxy (pay-per-call gateway)
  // 32-byte key (64 hex chars) used to encrypt providers' upstream secret
  // headers at rest. Without it, APIs cannot be registered with a secret.
  // Kept for backwards-compatibility; prefer UPSTREAM_SECRET_KEYS for new
  // deployments (see #53).
  UPSTREAM_SECRET_KEY: z
    .string()
    .regex(/^[0-9a-fA-F]{64}$/, "UPSTREAM_SECRET_KEY must be 64 hex characters")
    .optional(),
  // Key ring for secret rotation (#53): comma-separated "id:hex64" pairs.
  // The FIRST entry is the active key used for all new encryptions; older
  // entries remain so existing ciphertexts can still be decrypted.
  // Example: UPSTREAM_SECRET_KEYS=k2:aabbcc...64hex,k1:112233...64hex
  // When set, this takes precedence over UPSTREAM_SECRET_KEY.
  UPSTREAM_SECRET_KEYS: z.string().optional(),
  // Largest request body forwarded to an upstream API (express size string).
  PROXY_MAX_REQUEST_BODY: z.string().default("5mb"),
  // Upstream responses are held in memory until payment settles, so they are capped.
  PROXY_MAX_RESPONSE_BYTES: z.coerce
    .number()
    .int()
    .positive()
    .default(10 * 1024 * 1024),
  // Default and ceiling for a single upstream call. Kept under REQUEST_TIMEOUT_MS.
  PROXY_DEFAULT_TIMEOUT_MS: z.coerce.number().int().positive().default(15_000),
  PROXY_MAX_TIMEOUT_MS: z.coerce.number().int().positive().default(25_000),
  // Idempotency-Key replay for paid calls: how long a charged response is kept,
  // how many are kept (oldest evicted first) and the largest body kept.
  PROXY_IDEMPOTENCY_TTL_MS: z.coerce.number().int().positive().default(3_600_000),
  PROXY_IDEMPOTENCY_MAX_ENTRIES: z.coerce.number().int().positive().default(1000),
  PROXY_IDEMPOTENCY_MAX_BODY_BYTES: z.coerce
    .number()
    .int()
    .positive()
    .default(256 * 1024),
  // Local development only: allow upstreams on loopback/private networks.
  PROXY_ALLOW_PRIVATE_UPSTREAMS: z
    .enum(["true", "false"])
    .default("false")
    .transform((v) => v === "true"),

  // Issue #33: IP rate limiter on /api/:id — rejects 402-spam before DB is touched.
  // Max unpaid requests per IP per window; set to 0 to disable.
  PROXY_402_RATE_LIMIT_MAX: z.coerce.number().int().min(0).default(60),
  PROXY_402_RATE_LIMIT_WINDOW_MS: z.coerce.number().int().positive().default(60_000),
  // How long a proxied API's row is cached between DB lookups (#34). Edits
  // invalidate the entry, so this only bounds staleness across replicas.
  PROXY_API_CACHE_TTL_MS: z.coerce.number().int().min(0).default(5_000),

  // Upstream health checks (#35): APIs with a healthPath are pinged on this
  // interval and hidden from the catalog after this many consecutive failures.
  HEALTH_CHECK_INTERVAL_MS: z.coerce.number().int().min(0).default(60_000),
  HEALTH_CHECK_TIMEOUT_MS: z.coerce.number().int().positive().default(5_000),
  HEALTH_CHECK_FAILURE_THRESHOLD: z.coerce.number().int().min(1).default(3),

  // Provider webhooks for charged calls (#36). Delays between attempts grow
  // as WEBHOOK_RETRY_BASE_MS * 4^n.
  WEBHOOK_TIMEOUT_MS: z.coerce.number().int().positive().default(5_000),
  WEBHOOK_MAX_ATTEMPTS: z.coerce.number().int().min(1).default(5),
  WEBHOOK_RETRY_BASE_MS: z.coerce.number().int().positive().default(1_000),
});

const parsed = envSchema.safeParse(envWithDefaults);

if (!parsed.success) {
  rootLogger.error(
    { event: "config_invalid", issues: parsed.error.format() },
    "invalid environment variables",
  );
  process.exit(1);
}

const stellarNetwork = resolveStellarNetwork(parsed.data.STELLAR_NETWORK);
const networkIssues = validateNetworkConfig({
  stellarNetwork,
  x402Network: parsed.data.NETWORK,
  sorobanRpcUrl: parsed.data.SOROBAN_RPC_URL,
  usdcSacContractId: parsed.data.USDC_CONTRACT_ID,
  registryContractId: parsed.data.VAULT_REGISTRY_CONTRACT_ID,
});

if (networkIssues.length > 0) {
  rootLogger.error(
    { event: "config_network_mismatch", issues: networkIssues },
    "inconsistent Stellar network configuration",
  );
  for (const issue of networkIssues) {
    rootLogger.error({ field: issue.field }, issue.message);
  }
  process.exit(1);
}

// ── Mainnet safety guard (#51) ────────────────────────────────────────────────
// Refuse to start if the server is configured for mainnet but has settings that
// are only safe on a local/testnet environment.  This prevents a misconfigured
// production deployment from silently accepting SSRF or leaking funds.

/**
 * Returns a list of human-readable violation messages for mainnet-unsafe
 * settings.  An empty array means the config is safe to run on mainnet.
 * Exported so tests can exercise the logic without calling process.exit.
 */
export function mainnetSafetyViolations(cfg: typeof parsed.data): string[] {
  if (cfg.STELLAR_NETWORK !== "mainnet") return [];

  const violations: string[] = [];

  if (cfg.PROXY_ALLOW_PRIVATE_UPSTREAMS) {
    violations.push(
      "PROXY_ALLOW_PRIVATE_UPSTREAMS=true is not allowed on mainnet — " +
        "it would permit SSRF attacks via provider-supplied upstream URLs.",
    );
  }

  return violations;
}

if (parsed.data.STELLAR_NETWORK === "mainnet") {
  const violations = mainnetSafetyViolations(parsed.data);
  if (violations.length > 0) {
    rootLogger.error(
      { event: "mainnet_unsafe_config", violations },
      "refusing to start: unsafe settings detected for mainnet deployment",
    );
    for (const v of violations) {
      rootLogger.error(v);
    }
    process.exit(1);
  }
}

export const config = parsed.data;

// ── Key ring (#53) ────────────────────────────────────────────────────────────
// Parse UPSTREAM_SECRET_KEYS into an ordered list of {id, hex} entries.
// The first entry is the active key.  When only UPSTREAM_SECRET_KEY is set we
// wrap it in a single-entry ring so the rest of the codebase can always use the
// ring API.

import { parseKeyRing, type KeyRingEntry } from "./utils/secretBox.js";

function buildEffectiveKeyRing(): KeyRingEntry[] {
  if (config.UPSTREAM_SECRET_KEYS) {
    try {
      return parseKeyRing(config.UPSTREAM_SECRET_KEYS);
    } catch (err) {
      rootLogger.error(
        { event: "config_invalid_key_ring", err },
        "UPSTREAM_SECRET_KEYS is invalid",
      );
      process.exit(1);
    }
  }
  if (config.UPSTREAM_SECRET_KEY) {
    return [{ id: "default", hex: config.UPSTREAM_SECRET_KEY }];
  }
  return [];
}

/**
 * Parsed key ring for encrypting / decrypting upstream secrets.
 * Empty when neither UPSTREAM_SECRET_KEY nor UPSTREAM_SECRET_KEYS is set.
 */
export const upstreamKeyRing: KeyRingEntry[] = buildEffectiveKeyRing();
