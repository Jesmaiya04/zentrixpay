import type { NextFunction, Request, Response } from "express";
import { config } from "../config.js";
import { apiCreditRequestBodyHash, verifyApiCreditSpendSignature } from "../lib/apiCreditSignature.js";
import { resolveApiPrice } from "./apiPaywall.js";
import type { ApiRow } from "../db/schema.js";
import { ApiCreditError, spendApiCredit } from "../services/apiCredits.js";

const CREDIT_HEADERS = [
  "x-credit-wallet",
  "x-credit-timestamp",
  "x-credit-nonce",
  "x-credit-signature",
] as const;

export async function spendSignedApiCredit(req: Request, res: Response, next: NextFunction) {
  const present = CREDIT_HEADERS.some((name) => req.headers[name] !== undefined);
  if (!present) return next();

  const values = CREDIT_HEADERS.map((name) => req.headers[name]);
  if (values.some((value) => typeof value !== "string")) {
    return res.status(401).json({ error: "All X-Credit-* headers are required" });
  }
  const [walletAddress, timestamp, nonce, signature] = values as string[];
  const api = res.locals.api as ApiRow | undefined;
  if (!api) return res.status(500).json({ error: "Credit spending requires a loaded API" });

  const result = verifyApiCreditSpendSignature({
    walletAddress,
    apiId: api.id,
    method: req.method,
    path: req.originalUrl,
    timestamp,
    nonce,
    bodyHash: apiCreditRequestBodyHash(Buffer.isBuffer(req.body) ? req.body : undefined),
    signature,
    nowMs: Date.now(),
    maxSkewMs: config.SIGNATURE_MAX_SKEW_MS,
  });
  if (!result.ok) {
    return res.status(401).json({ error: `Invalid credit signature: ${result.error}` });
  }

  if (api.payerDenylist?.includes(walletAddress)) {
    return res.status(403).json({ error: "This wallet is not allowed to call this API" });
  }
  if (api.payerAllowlist?.length && !api.payerAllowlist.includes(walletAddress)) {
    return res.status(403).json({ error: "This API is restricted to approved wallets" });
  }

  try {
    const balance = await spendApiCredit({ apiId: api.id, walletAddress, nonce });
    res.locals.creditPayer = walletAddress;
    res.locals.apiCreditBalance = balance;
    res.locals.apiCallPrice = resolveApiPrice(
      api,
      req.method,
      Array.isArray(req.params.path)
        ? (req.params.path as string[]).length
          ? `/${(req.params.path as string[]).join("/")}`
          : "/"
        : typeof req.params.path === "string" && req.params.path
          ? `/${req.params.path}`
          : "/",
    );
    return next();
  } catch (err) {
    if (err instanceof ApiCreditError) {
      return res.status(err.status).json({ error: err.message });
    }
    return next(err);
  }
}
