import { createHash } from "node:crypto";
import express, {
  Router,
  type NextFunction,
  type Router as RouterType,
  type Request,
  type Response,
} from "express";
import { apiKeyAuth } from "../middleware/apiKeyAuth.js";
import { requestSignatureAuth } from "../middleware/requestSignatureAuth.js";
import { payeeSignatureAuth } from "../middleware/payeeSignatureAuth.js";
import { validate } from "../middleware/validate.js";
import { publishIpRateLimit, publishWalletRateLimit } from "../middleware/rateLimiters.js";
import { apiPaywall, checkPayerAccess, loadProxiedApi } from "../middleware/apiPaywall.js";
import {
  apiCatalogQuerySchema,
  apiStatsQuerySchema,
  createApiSchema,
  payerCallsQuerySchema,
  updateApiSchema,
} from "../schemas/requests.js";
import {
  ApiServiceError,
  archiveApi,
  createApi,
  effectiveMaxResponseBytes,
  getApiById,
  getApiStats,
  getApiTimeSeries,
  getOwnedApi,
  listPublicApis,
  listPayerCalls,
  listPublisherApis,
  listRecentCalls,
  recordApiCall,
  toOwnerApi,
  toPublicApi,
  toPublicOpenApi,
  updateApi,
  verifyOwnership,
  type ApiRow,
} from "../services/apiService.js";
import {
  confirmApiPrice,
  confirmApiRegistration,
  prepareApiPrice,
  prepareApiRegistration,
} from "../services/apiOnchain.js";
import { confirmCallRefund, prepareCallRefund } from "../services/apiRefunds.js";
import { sendUpstream, streamUpstream, UpstreamError } from "../lib/upstreamClient.js";
import { filterRequestHeaders, filterResponseHeaders } from "../lib/proxyHeaders.js";
import { paymentHeader, paymentHeaderHash, payerFromPayment } from "../lib/payer.js";
import {
  getProxyIdempotencyStore,
  proxyIdempotencyCacheKey,
  type StoredProxyResponse,
} from "../lib/idempotency.js";
import { decryptSecret } from "../utils/secretBox.js";
import { getLogger } from "../lib/logger.js";
import { config } from "../config.js";

const router: RouterType = Router();

function sendServiceError(res: Response, err: unknown): void {
  if (err instanceof ApiServiceError) {
    res.status(err.status).json({ error: err.message });
    return;
  }
  throw err;
}

// ── Management ────────────────────────────────────────────────────────────────

// POST /apis — register an API to sell per call (authenticated)
router.post(
  "/apis",
  apiKeyAuth,
  publishIpRateLimit,
  publishWalletRateLimit,
  requestSignatureAuth,
  validate(createApiSchema),
  async (req, res) => {
    const publisher = req.publisher!;
    try {
      const api = await createApi({
        ...req.body,
        publisherId: publisher.id,
        walletAddress: req.body.walletAddress ?? publisher.walletAddress,
      });
      const owner = toOwnerApi(api);
      res.status(201).json({
        ...owner,
        nextStep:
          `Serve "${owner.ownershipVerification.expectedContent}" at ` +
          `${owner.ownershipVerification.url}, then POST /apis/${api.id}/verify-ownership. ` +
          `Register it on-chain with GET /apis/${api.id}/register/prepare and ` +
          `POST /apis/${api.id}/register to list the API.`,
      });
    } catch (err) {
      sendServiceError(res, err);
    }
  },
);

// GET /apis — public catalog of listed APIs
router.get("/apis", async (req, res) => {
  const parsed = apiCatalogQuerySchema.safeParse(req.query);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.format() });
    return;
  }
  res.json(await listPublicApis(parsed.data));
});

// GET /publishers/me/apis — the caller's own APIs, listed or not
router.get("/publishers/me/apis", apiKeyAuth, async (req, res) => {
  res.json(await listPublisherApis(req.publisher!.id));
});

// GET /apis/:id — public details of a listed API
router.get("/apis/:id", async (req, res) => {
  const api = await getApiById(req.params.id);
  if (!api || !api.listed) {
    res.status(404).json({ error: "API not found" });
    return;
  }
  res.json(toPublicApi(api));
});

// GET /apis/:id/openapi.json — the API's OpenAPI document, pointed at the proxy
router.get("/apis/:id/openapi.json", async (req, res) => {
  const api = await getApiById(req.params.id);
  const spec = api?.listed ? toPublicOpenApi(api) : null;
  if (!spec) {
    res.status(404).json({ error: "No OpenAPI document for this API" });
    return;
  }
  res.json(spec);
});

// PATCH /apis/:id — update price, upstream, methods, secret header, listing (owner)
// Changing walletAddress additionally requires a signature from the current payee wallet
// (X-Payee-Timestamp + X-Payee-Signature headers) to prevent a compromised API key
// from silently redirecting all revenue to an attacker-controlled address.
router.patch(
  "/apis/:id",
  apiKeyAuth,
  requestSignatureAuth,
  // Load the API and stash it in res.locals.api so payeeSignatureAuth can read
  // the current walletAddress without a second DB round-trip in the handler.
  async (req, res, next) => {
    try {
      const api = await getOwnedApi(req.params.id as string, req.publisher!.id);
      res.locals.api = api;
      next();
    } catch (err) {
      sendServiceError(res, err);
    }
  },
  validate(updateApiSchema),
  payeeSignatureAuth,
  async (req, res) => {
    try {
      const api = res.locals.api as ApiRow;
      res.json(toOwnerApi(await updateApi(api, req.body)));
    } catch (err) {
      sendServiceError(res, err);
    }
  },
);

// DELETE /apis/:id — archive (soft-delete): unlist and hide the API, keep its call history (owner)
router.delete("/apis/:id", apiKeyAuth, requestSignatureAuth, async (req, res) => {
  try {
    const api = await getOwnedApi(req.params.id as string, req.publisher!.id);
    const archived = await archiveApi(api);
    res.json({ id: archived.id, archived: true, archivedAt: archived.archivedAt });
  } catch (err) {
    sendServiceError(res, err);
  }
});

// POST /apis/:id/verify-ownership — check /.well-known/zentrixpay.txt, then list (owner)
router.post("/apis/:id/verify-ownership", apiKeyAuth, requestSignatureAuth, async (req, res) => {
  try {
    const api = await getOwnedApi(req.params.id as string, req.publisher!.id);
    res.json(toOwnerApi(await verifyOwnership(api)));
  } catch (err) {
    sendServiceError(res, err);
  }
});

// GET /apis/:id/stats — call counts, revenue and recent calls (owner; archived APIs included)
router.get("/apis/:id/stats", apiKeyAuth, async (req, res) => {
  const query = apiStatsQuerySchema.safeParse(req.query);
  if (!query.success) {
    res.status(400).json({ error: query.error.format() });
    return;
  }
  try {
    const api = await getOwnedApi(req.params.id as string, req.publisher!.id, {
      includeArchived: true,
    });
    const [totals, recentCalls] = await Promise.all([
      getApiStats(api.id),
      listRecentCalls(api.id, 50),
      q.interval ? getApiTimeSeries(api.id, q) : undefined,
    ]);
    res.json({ apiId: api.id, archivedAt: api.archivedAt, ...totals, recentCalls });
  } catch (err) {
    sendServiceError(res, err);
  }
});

// GET /apis/:id/stats/time-series?days=7|30|90 — per-day calls and revenue (owner)
router.get("/apis/:id/stats/time-series", apiKeyAuth, async (req, res) => {
  try {
    const api = await getOwnedApi(req.params.id as string, req.publisher!.id);
    const rawDays = Number(req.query.days);
    const days = [7, 30, 90].includes(rawDays) ? (rawDays as 7 | 30 | 90) : 30;
    const series = await getApiTimeSeries(api.id, days);
    res.json({ apiId: api.id, days, series });
  } catch (err) {
    sendServiceError(res, err);
  }
});

// GET /payers/:address/calls — receipts for the calls a wallet paid for (paged)
router.get("/payers/:address/calls", async (req, res) => {
  const address = req.params.address as string;
  if (!/^G[A-Z2-7]{55}$/.test(address)) {
    res.status(400).json({ error: "address must be a Stellar public key (G...)" });
    return;
  }
  const query = payerCallsQuerySchema.safeParse(req.query);
  if (!query.success) {
    res.status(400).json({ error: query.error.format() });
    return;
  }
  const { limit, offset } = query.data;
  const { calls, hasMore } = await listPayerCalls(address, { limit, offset });
  res.json({
    payer: address,
    calls,
    limit,
    offset,
    nextOffset: hasMore ? offset + limit : null,
  });
});

// ── Paid proxy ────────────────────────────────────────────────────────────────

/** Map /api/:id/<segments>?<query> onto the API's upstream URL. */
export function buildUpstreamUrl(
  upstreamUrl: string,
  segments: string[],
  originalUrl: string,
): URL | null {
  // Segments arrive decoded. Refuse anything that could climb out of the
  // upstream base path or smuggle a separator.
  if (segments.some((s) => s === "." || s === ".." || /[/\\]/.test(s))) return null;

  const base = new URL(upstreamUrl);
  const basePath = base.pathname.replace(/\/+$/, "");
  const subPath = segments.map(encodeURIComponent).join("/");
  const target = new URL(base.origin);
  target.pathname = subPath ? `${basePath}/${subPath}` : basePath || "/";

  const queryStart = originalUrl.indexOf("?");
  const requestQuery = queryStart === -1 ? "" : originalUrl.slice(queryStart + 1);
  target.search = [base.search.slice(1), requestQuery].filter(Boolean).join("&");
  return target;
}

function decodeQueryPart(part: string): string {
  try {
    return decodeURIComponent(part.replace(/\+/g, " "));
  } catch {
    return part;
  }
}

/**
 * Set the provider's secret query parameter on the upstream URL. Any value the
 * caller sent under the same name is dropped so it cannot override the
 * provider's key. The rest of the query string is left byte-for-byte as sent.
 */
export function withSecretQueryParam(target: URL, name: string, value: string): URL {
  const kept = target.search
    .slice(1)
    .split("&")
    .filter((pair) => pair && decodeQueryPart(pair.split("=")[0]) !== name);
  kept.push(`${encodeURIComponent(name)}=${encodeURIComponent(value)}`);
  target.search = kept.join("&");
  return target;
}

export interface UpstreamSecrets {
  queryName?: string;
  values: string[];
}

/** Remove a secret query parameter (by name or by value) from a URL-ish string. */
function stripSecretParam(value: string, secrets: UpstreamSecrets): string {
  const queryStart = value.indexOf("?");
  if (queryStart === -1) return value;
  const hashStart = value.indexOf("#", queryStart);
  const query = value.slice(queryStart + 1, hashStart === -1 ? undefined : hashStart);
  const kept = query.split("&").filter((pair) => {
    if (!pair) return false;
    const [rawKey, ...rest] = pair.split("=");
    const key = decodeQueryPart(rawKey);
    return key !== secrets.queryName && !secrets.values.includes(decodeQueryPart(rest.join("=")));
  });
  return (
    value.slice(0, queryStart) +
    (kept.length ? `?${kept.join("&")}` : "") +
    (hashStart === -1 ? "" : value.slice(hashStart))
  );
}

/** Replace any literal (or URL-encoded) occurrence of a secret value. */
function redactSecrets(value: string, secrets: UpstreamSecrets): string {
  let out = value;
  for (const secret of secrets.values) {
    if (secret.length < 4) continue;
    for (const form of new Set([secret, encodeURIComponent(secret)])) {
      out = out.split(form).join("[redacted]");
    }
  }
  return out;
}

// Response headers that carry URLs; secret query parameters are removed from these.
const URL_HEADERS = new Set(["location", "content-location", "link", "refresh"]);

/**
 * Prepare an upstream response header for the caller: point upstream URLs at
 * the proxy and make sure no provider secret is echoed back.
 */
export function rewriteResponseHeader(
  name: string,
  value: string,
  api: ApiRow,
  secrets: UpstreamSecrets,
): string {
  let out = value;
  if (name === "location") {
    const base = api.upstreamUrl.replace(/\/+$/, "");
    if (out.startsWith(base)) out = `${config.BASE_URL}/api/${api.id}${out.slice(base.length)}`;
  }
  if (URL_HEADERS.has(name)) out = stripSecretParam(out, secrets);
  return redactSecrets(out, secrets);
}

interface SettlementInfo {
  payer?: string;
  transaction?: string;
}

/** The settlement the x402 middleware reported on the response, if any. */
function settlementFrom(res: Response): SettlementInfo {
  const header = res.getHeader("payment-response") ?? res.getHeader("x-payment-response");
  if (typeof header !== "string") return {};
  try {
    const decoded = JSON.parse(Buffer.from(header, "base64").toString("utf8"));
    return {
      payer: typeof decoded?.payer === "string" ? decoded.payer : undefined,
      transaction:
        typeof decoded?.transaction === "string" && decoded.transaction
          ? decoded.transaction
          : undefined,
    };
  } catch {
    return {};
  }
}

function payerFrom(req: Request, settlement: SettlementInfo): string {
  return settlement.payer ?? payerFromPayment(paymentHeader(req)).address ?? "unknown";
}

// A paid call holding its idempotency key cannot outlive the request timeout;
// this only matters if the finish/close hooks never run.
const IN_PROGRESS_TTL_MS = config.REQUEST_TIMEOUT_MS * 2;

interface IdempotencyContext {
  scopedKey: string;
  fingerprint: string;
  paymentHash: string;
}

function requestFingerprint(req: Request): string {
  const hash = createHash("sha256").update(`${req.method}\n${req.originalUrl}\n`);
  if (Buffer.isBuffer(req.body)) hash.update(req.body);
  return hash.digest("hex");
}

/**
 * Idempotency-Key for paid calls (scoped per API and payer wallet). A retry
 * with the key of a charged call replays the stored response instead of
 * paying again; the replay requires proof the caller is that wallet: either
 * the identical payment header or a fresh payment signed by the wallet.
 */
function proxyIdempotency(req: Request, res: Response, next: NextFunction) {
  const key = req.header("Idempotency-Key");
  const header = paymentHeader(req);
  // Without a payment the caller just gets the 402 challenge; nothing to dedupe.
  if (!key || !header) return next();
  if (key.length > 255) {
    res.status(400).json({ error: "Idempotency-Key must be at most 255 characters" });
    return;
  }
  const payer = payerFromPayment(header);
  if (!payer.address) return next();

  const api = res.locals.api as ApiRow;
  const store = getProxyIdempotencyStore();
  const scopedKey = proxyIdempotencyCacheKey(api.id, payer.address, key);
  const fingerprint = requestFingerprint(req);
  const paymentHash = paymentHeaderHash(header);

  const existing = store.get(scopedKey);
  if (existing) {
    if (existing.fingerprint !== fingerprint) {
      res.status(422).json({ error: "Idempotency-Key was already used for a different request" });
      return;
    }
    if (existing.inProgress) {
      res.status(409).json({ error: "A call with this Idempotency-Key is already in progress" });
      return;
    }
    if (!payer.signed && existing.paymentHash !== paymentHash) {
      res.status(409).json({
        error: "Idempotency-Key already used; resend the original payment to replay the response",
      });
      return;
    }
    if (!existing.response) {
      res.status(409).json({
        error: "This call was already paid for, but its response was too large to keep for replay",
        txHash: existing.txHash,
      });
      return;
    }
    const { status, headers, body } = existing.response;
    res.status(status);
    for (const [name, value] of Object.entries(headers)) res.setHeader(name, value);
    res.setHeader("Idempotent-Replayed", "true");
    res.setHeader("Content-Length", String(body.length));
    res.end(body);
    return;
  }

  store.set(scopedKey, { inProgress: true, fingerprint }, IN_PROGRESS_TTL_MS);
  const ctx: IdempotencyContext = { scopedKey, fingerprint, paymentHash };

  // Keep the response only once it is final and charged (status < 400 means the
  // x402 middleware settled); otherwise release the key so a retry can pay.
  const finalize = () => {
    const stored = res.locals.proxyResponse as StoredProxyResponse | undefined;
    if (!res.writableFinished || res.statusCode >= 400 || !stored) {
      store.delete(ctx.scopedKey);
      return;
    }
    const settlement = settlementFrom(res);
    const paymentResponse = res.getHeader("payment-response");
    const keep = stored.body.length <= config.PROXY_IDEMPOTENCY_MAX_BODY_BYTES;
    store.set(ctx.scopedKey, {
      inProgress: false,
      fingerprint: ctx.fingerprint,
      paymentHash: ctx.paymentHash,
      txHash: settlement.transaction ?? null,
      response: keep
        ? {
            ...stored,
            headers:
              typeof paymentResponse === "string"
                ? { ...stored.headers, "payment-response": paymentResponse }
                : stored.headers,
          }
        : null,
    });
  };
  res.once("finish", finalize);
  res.once("close", () => {
    if (!res.writableFinished) store.delete(ctx.scopedKey);
  });
  next();
}

const UPSTREAM_ERROR_STATUS = { blocked: 502, network: 502, too_large: 502, timeout: 504 } as const;

/** Build and inject upstream secrets into headers/url, returning the secrets manifest. */
function prepareUpstreamRequest(
  api: ApiRow,
  target: URL,
  reqHeaders: ReturnType<typeof filterRequestHeaders>,
): UpstreamSecrets {
  const secrets: UpstreamSecrets = { values: [] };
  if (api.upstreamHeaderName && api.upstreamHeaderValueEnc && config.UPSTREAM_SECRET_KEY) {
    const value = decryptSecret(api.upstreamHeaderValueEnc, config.UPSTREAM_SECRET_KEY);
    reqHeaders[api.upstreamHeaderName] = value;
    secrets.values.push(value);
  }
  if (api.upstreamQueryName && api.upstreamQueryValueEnc && config.UPSTREAM_SECRET_KEY) {
    const value = decryptSecret(api.upstreamQueryValueEnc, config.UPSTREAM_SECRET_KEY);
    withSecretQueryParam(target, api.upstreamQueryName, value);
    secrets.queryName = api.upstreamQueryName;
    secrets.values.push(value);
  }
  return secrets;
}

async function proxyHandler(req: Request, res: Response) {
  const api = res.locals.api as ApiRow;
  const segments = (req.params.path as unknown as string[] | undefined) ?? [];
  const target = buildUpstreamUrl(api.upstreamUrl, segments, req.originalUrl);
  if (!target) {
    res.status(400).json({ error: "Invalid path" });
    return;
  }

  const headers = filterRequestHeaders(req.headers);
  const secrets = prepareUpstreamRequest(api, target, headers);
  const body = Buffer.isBuffer(req.body) && req.body.length > 0 ? req.body : undefined;

  const started = Date.now();

  // Recorded once the response (and settlement) is complete: a final status
  // below 400 means the x402 middleware settled the payment.
  res.on("finish", () => {
    const settlement = settlementFrom(res);
    const charged = res.statusCode < 400;
    recordApiCall({
      apiId: api.id,
      payerAddress: payerFrom(req, settlement),
      amount: api.price,
      charged,
      txHash: charged ? (settlement.transaction ?? null) : null,
      method: req.method,
      path:
        target.pathname.slice(new URL(api.upstreamUrl).pathname.replace(/\/+$/, "").length) || "/",
      responseStatus: res.statusCode,
      durationMs: Date.now() - started,
    }).catch((err) =>
      getLogger().error(
        { event: "api_call_record_failed", apiId: api.id, err },
        "failed to record API call",
      ),
    );
  });

  const upstreamOpts = {
    url: target,
    method: req.method,
    headers,
    body,
    timeoutMs: api.timeoutMs ?? config.PROXY_DEFAULT_TIMEOUT_MS,
    maxResponseBytes: effectiveMaxResponseBytes(api),
    allowPrivate: config.PROXY_ALLOW_PRIVATE_UPSTREAMS,
  };

  // ── Streaming path (SSE / chunked) ─────────────────────────────────────────
  // settle-before-stream: the x402 middleware already collected payment before
  // this handler runs. If the upstream fails before the first byte we never
  // write a 2xx status to the caller, so the caller is not charged
  // (see the "finish" listener above — charged = statusCode < 400).
  if (api.streamingEnabled) {
    let upstream;
    try {
      upstream = await streamUpstream(upstreamOpts);
    } catch (err) {
      if (err instanceof UpstreamError) {
        getLogger().warn(
          { event: "api_upstream_stream_failed", apiId: api.id, kind: err.kind, error: err.message },
          "upstream stream failed before first byte; caller not charged",
        );
        res
          .status(UPSTREAM_ERROR_STATUS[err.kind])
          .json({ error: "upstream_failed", reason: err.kind });
        return;
      }
      throw err;
    }

    // Mirror useful response headers (no buffering, no content-length).
    const responseHeaders = filterResponseHeaders(upstream.headers);
    res.status(upstream.status);
    for (const [name, value] of Object.entries(responseHeaders)) {
      const rewritten =
        typeof value === "string"
          ? rewriteResponseHeader(name, value, api, secrets)
          : value;
      res.setHeader(name, rewritten);
    }

    // For SSE: disable compression / buffering on the Express response so
    // events reach the caller immediately.
    res.setHeader("X-Accel-Buffering", "no");
    res.flushHeaders();

    upstream.stream.pipe(res);

    upstream.stream.on("error", (err) => {
      getLogger().warn(
        { event: "api_upstream_stream_error", apiId: api.id, error: err.message },
        "upstream stream error mid-flight",
      );
      if (!res.writableEnded) res.end();
    });

    req.on("close", () => {
      // Client disconnected early — destroy the upstream socket too.
      upstream.stream.destroy();
    });

    return;
  }

  // ── Buffered path (default) ─────────────────────────────────────────────────
  let upstream;
  try {
    upstream = await sendUpstream(upstreamOpts);
  } catch (err) {
    if (err instanceof UpstreamError) {
      getLogger().warn(
        { event: "api_upstream_failed", apiId: api.id, kind: err.kind, error: err.message },
        "upstream call failed; caller not charged",
      );
      res
        .status(UPSTREAM_ERROR_STATUS[err.kind])
        .json({ error: "upstream_failed", reason: err.kind });
      return;
    }
    throw err;
  }

  const responseHeaders: StoredProxyResponse["headers"] = {};
  for (const [name, value] of Object.entries(filterResponseHeaders(upstream.headers))) {
    responseHeaders[name] =
      typeof value === "string"
        ? rewriteResponseHeader(name, value, api, secrets)
        : value;
  }
  // Kept for Idempotency-Key replay once the call is known to be charged.
  res.locals.proxyResponse = {
    status: upstream.status,
    headers: responseHeaders,
    body: upstream.body,
  } satisfies StoredProxyResponse;

  res.status(upstream.status);
  for (const [name, value] of Object.entries(responseHeaders)) res.setHeader(name, value);
  // res.end, not res.send: send() would add an ETag and could turn the reply
  // into a bodiless 304 that still counts as a successful (charged) call.
  res.setHeader("Content-Length", String(upstream.body.length));
  res.end(upstream.body);
}

// ANY /api/:id[/*path] — one paid call to the provider's API
router.all(
  "/api/:id{/*path}",
  loadProxiedApi,
  express.raw({ type: () => true, limit: config.PROXY_MAX_REQUEST_BODY }),
  checkPayerAccess,
  proxyIdempotency,
  apiPaywall,
  proxyHandler,
);

export default router;
