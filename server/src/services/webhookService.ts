import { createHmac } from "node:crypto";
import { config, upstreamKeyRing } from "../config.js";
import { getLogger } from "../lib/logger.js";
import { sendUpstream } from "../lib/upstreamClient.js";
import { decryptSecret } from "../utils/secretBox.js";
import type { ApiRow } from "./apiService.js";

// Provider webhooks for charged calls (#36). After each call that settles, the
// provider's webhook URL receives a signed JSON event:
//
//   POST <webhookUrl>
//   X-ZentrixPay-Event: api.call.charged
//   X-ZentrixPay-Delivery: <event id, stable across retries>
//   X-ZentrixPay-Signature: t=<unix seconds>,v1=<hex HMAC-SHA256>
//
// v1 is HMAC-SHA256(secret, `${t}.${rawBody}`). Receivers should recompute it,
// compare in constant time, and reject stale timestamps. A non-2xx answer or a
// network error is retried with exponential backoff. Deliveries are in-memory:
// retries still pending when the process stops are dropped.
//
// Delivery goes through sendUpstream, so the SSRF guard applies at connect
// time (DNS rebinding included), not only when the URL is registered.

export const WEBHOOK_EVENT_CHARGED = "api.call.charged";

export interface ChargedCallEvent {
  callId: string;
  payerAddress: string;
  amount: string;
  method: string;
  path: string;
  responseStatus: number;
  durationMs: number;
}

export function signWebhookPayload(secret: string, timestamp: number, body: string): string {
  return createHmac("sha256", secret).update(`${timestamp}.${body}`).digest("hex");
}

export function webhookSignatureHeader(secret: string, timestamp: number, body: string): string {
  return `t=${timestamp},v1=${signWebhookPayload(secret, timestamp, body)}`;
}

/** Delay before retry `attempt` (1-based count of failed attempts so far). */
export function webhookRetryDelayMs(attempt: number): number {
  return config.WEBHOOK_RETRY_BASE_MS * 4 ** (attempt - 1);
}

async function attemptDelivery(url: string, secret: string, eventId: string, body: string) {
  const timestamp = Math.floor(Date.now() / 1000);
  const res = await sendUpstream({
    url: new URL(url),
    method: "POST",
    headers: {
      "content-type": "application/json",
      "user-agent": "ZentrixPay-Webhooks/1",
      "x-zentrixpay-event": WEBHOOK_EVENT_CHARGED,
      "x-zentrixpay-delivery": eventId,
      "x-zentrixpay-signature": webhookSignatureHeader(secret, timestamp, body),
    },
    body: Buffer.from(body, "utf8"),
    timeoutMs: config.WEBHOOK_TIMEOUT_MS,
    maxResponseBytes: 64 * 1024,
    allowPrivate: config.PROXY_ALLOW_PRIVATE_UPSTREAMS,
  });
  if (res.status < 200 || res.status >= 300) {
    throw new Error(`webhook answered HTTP ${res.status}`);
  }
}

/** Fire-and-forget delivery of a charged-call event, retried with backoff. */
export function deliverChargedCallWebhook(api: ApiRow, call: ChargedCallEvent): void {
  if (!api.webhookUrl || !api.webhookSecretEnc) return;
  const log = getLogger();
  if (upstreamKeyRing.length === 0) {
    log.warn(
      { event: "webhook_skipped", apiId: api.id, reason: "no_secret_key" },
      "webhook configured but UPSTREAM_SECRET_KEY / UPSTREAM_SECRET_KEYS is missing",
    );
    return;
  }

  const url = api.webhookUrl;
  const secret = decryptSecret(api.webhookSecretEnc, upstreamKeyRing, config.UPSTREAM_SECRET_KEY);
  const eventId = `evt_${call.callId}`;
  const body = JSON.stringify({
    id: eventId,
    type: WEBHOOK_EVENT_CHARGED,
    createdAt: new Date().toISOString(),
    data: { apiId: api.id, currency: "USDC", ...call },
  });

  const attempt = async (n: number): Promise<void> => {
    try {
      await attemptDelivery(url, secret, eventId, body);
      log.info(
        { event: "webhook_delivered", apiId: api.id, eventId, attempt: n },
        "webhook delivered",
      );
    } catch (err) {
      const error = (err as Error).message;
      if (n >= config.WEBHOOK_MAX_ATTEMPTS) {
        log.error(
          { event: "webhook_failed", apiId: api.id, eventId, attempts: n, error },
          "webhook delivery failed; giving up",
        );
        return;
      }
      const delayMs = webhookRetryDelayMs(n);
      log.warn(
        { event: "webhook_retry", apiId: api.id, eventId, attempt: n, delayMs, error },
        "webhook delivery failed; retrying",
      );
      setTimeout(() => void attempt(n + 1), delayMs).unref();
    }
  };
  void attempt(1);
}
