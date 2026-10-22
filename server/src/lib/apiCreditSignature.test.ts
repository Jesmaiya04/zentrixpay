import { describe, expect, it } from "vitest";
import { Keypair } from "@stellar/stellar-sdk";
import {
  apiCreditRequestBodyHash,
  buildApiCreditSpendMessage,
  verifyApiCreditSpendSignature,
} from "./apiCreditSignature.js";

describe("API credit spend signatures", () => {
  it("verifies a wallet signature bound to the request and rejects a changed path", () => {
    const keypair = Keypair.random();
    const nowMs = Date.now();
    const input = {
      walletAddress: keypair.publicKey(),
      apiId: "api1",
      method: "POST",
      path: "/api/api1/generate",
      timestamp: String(Math.floor(nowMs / 1000)),
      nonce: "nonce-request-0001",
      bodyHash: apiCreditRequestBodyHash(Buffer.from('{"prompt":"hello"}')),
    };
    const signature = keypair.sign(Buffer.from(buildApiCreditSpendMessage(input))).toString("base64");
    const request = { ...input, signature, nowMs, maxSkewMs: 300_000 };

    expect(verifyApiCreditSpendSignature(request)).toEqual({ ok: true });
    expect(
      verifyApiCreditSpendSignature({ ...request, path: "/api/api1/other" }),
    ).toEqual({ ok: false, error: "signature_mismatch" });
  });
});
