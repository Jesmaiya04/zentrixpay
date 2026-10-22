import { describe, expect, it } from "vitest";
import { createApiSchema, updateApiSchema } from "./requests.js";

const createInput = {
  name: "Example API",
  upstreamUrl: "https://api.example.test",
  price: "0.01",
};

describe("API price rule validation", () => {
  it("accepts method/path price overrides on create and update", () => {
    const priceRules = [{ method: "POST", pathPattern: "/generate/*", price: "0.10" }];
    expect(createApiSchema.safeParse({ ...createInput, priceRules }).success).toBe(true);
    expect(updateApiSchema.safeParse({ priceRules }).success).toBe(true);
  });

  it("rejects invalid methods, paths, prices, duplicate rules, and too many rules", () => {
    expect(
      createApiSchema.safeParse({
        ...createInput,
        priceRules: [{ method: "OPTIONS", pathPattern: "/generate", price: "0.10" }],
      }).success,
    ).toBe(false);
    expect(
      createApiSchema.safeParse({
        ...createInput,
        priceRules: [{ method: "POST", pathPattern: "generate", price: "0.10" }],
      }).success,
    ).toBe(false);
    expect(
      updateApiSchema.safeParse({
        priceRules: [
          { method: "POST", pathPattern: "/generate", price: "0.10" },
          { method: "POST", pathPattern: "/generate", price: "0.20" },
        ],
      }).success,
    ).toBe(false);
    expect(
      updateApiSchema.safeParse({
        priceRules: Array.from({ length: 101 }, (_, index) => ({
          method: "POST",
          pathPattern: `/generate/${index}`,
          price: "0.10",
        })),
      }).success,
    ).toBe(false);
  });
});
