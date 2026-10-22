import { describe, expect, it, vi } from "vitest";

vi.mock("../config.js", () => ({ config: { NETWORK: "stellar:testnet" } }));
vi.mock("../db/client.js", () => ({ db: {} }));
vi.mock("../lib/payer.js", () => ({
  paymentHeader: vi.fn(),
  payerFromPayment: vi.fn(),
}));
vi.mock("../lib/x402.js", () => ({ sharedX402ResourceServer: vi.fn() }));

import { resolveApiPrice } from "./apiPaywall.js";

describe("resolveApiPrice", () => {
  const api = {
    price: "0.01",
    priceRules: [
      { method: "GET", pathPattern: "/items/*", price: "0.02" },
      { method: "GET", pathPattern: "/items/featured/*", price: "0.05" },
      { method: "GET", pathPattern: "/items/featured/today", price: "0.08" },
      { method: "POST", pathPattern: "/items/featured/today", price: "0.10" },
    ],
  };

  it("prefers exact paths over matching wildcards, then the most specific wildcard", () => {
    expect(resolveApiPrice(api, "GET", "/items/featured/today")).toBe("0.08");
    expect(resolveApiPrice(api, "GET", "/items/featured/tomorrow")).toBe("0.05");
    expect(resolveApiPrice(api, "GET", "/items/other")).toBe("0.02");
  });

  it("falls back to the API default when no method and path rule matches", () => {
    expect(resolveApiPrice(api, "DELETE", "/items/featured/today")).toBe("0.01");
  });
});
