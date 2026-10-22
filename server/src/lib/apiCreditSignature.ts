import { createHash } from "node:crypto";
import { Keypair } from "@stellar/stellar-sdk";
import {
  EMPTY_BODY_HASH,
  hashRequestBody,
  isTimestampWithinSkew,
} from "../utils/requestSignature.js";

export function apiCreditRequestBodyHash(body: Buffer | undefined): string {
  return body ? hashRequestBody(body) : EMPTY_BODY_HASH;
}

export function buildApiCreditSpendMessage(input: {
  walletAddress: string;
  apiId: string;
  method: string;
  path: string;
  timestamp: string;
  nonce: string;
  bodyHash: string;
}): string {
  return [
    "zentrixpay:api-credit-spend",
    input.walletAddress,
    input.apiId,
    input.method.toUpperCase(),
    input.path,
    input.timestamp,
    input.nonce,
    input.bodyHash,
  ].join("\n");
}

export type ApiCreditSignatureError =
  | "invalid_wallet"
  | "invalid_timestamp"
  | "expired_timestamp"
  | "invalid_nonce"
  | "invalid_signature"
  | "signature_mismatch";

export function verifyApiCreditSpendSignature(input: {
  walletAddress: string;
  apiId: string;
  method: string;
  path: string;
  timestamp: string;
  nonce: string;
  bodyHash: string;
  signature: string;
  nowMs: number;
  maxSkewMs: number;
}): { ok: true } | { ok: false; error: ApiCreditSignatureError } {
  let keypair: Keypair;
  try {
    keypair = Keypair.fromPublicKey(input.walletAddress);
  } catch {
    return { ok: false, error: "invalid_wallet" };
  }

  const timestamp = Number(input.timestamp);
  if (!Number.isFinite(timestamp) || timestamp <= 0) {
    return { ok: false, error: "invalid_timestamp" };
  }
  if (!isTimestampWithinSkew(timestamp, input.nowMs, input.maxSkewMs)) {
    return { ok: false, error: "expired_timestamp" };
  }
  if (!/^[A-Za-z0-9._~-]{16,128}$/.test(input.nonce)) {
    return { ok: false, error: "invalid_nonce" };
  }

  const signature = Buffer.from(input.signature, "base64");
  if (
    signature.length !== 64 ||
    signature.toString("base64").replace(/=+$/, "") !== input.signature.replace(/=+$/, "")
  ) {
    return { ok: false, error: "invalid_signature" };
  }

  const message = buildApiCreditSpendMessage(input);
  try {
    return keypair.verify(Buffer.from(message, "utf8"), signature)
      ? { ok: true }
      : { ok: false, error: "signature_mismatch" };
  } catch {
    return { ok: false, error: "signature_mismatch" };
  }
}

export function apiCreditPurchaseReference(transaction: string | undefined, paymentHeader: string) {
  if (transaction) return transaction;
  return `payment:${createHash("sha256").update(paymentHeader).digest("hex")}`;
}
