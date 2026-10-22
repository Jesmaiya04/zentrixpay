import { beforeEach, describe, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({
  balance: 1,
  nonces: new Set<string>(),
  transactionLock: Promise.resolve(),
}));

vi.mock("../db/client.js", () => ({
  db: {
    transaction: async (run: (tx: unknown) => Promise<unknown>) => {
      const previous = state.transactionLock;
      let release!: () => void;
      state.transactionLock = new Promise<void>((resolve) => {
        release = resolve;
      });
      await previous;
      const balanceBefore = state.balance;
      const noncesBefore = new Set(state.nonces);
      const tx = {
        insert: () => {
          let entry: { requestNonce?: string } | undefined;
          const query = {
            values: (value: { requestNonce?: string }) => {
              entry = value;
              return query;
            },
            onConflictDoNothing: () => query,
            returning: async () => {
              const nonce = entry?.requestNonce;
              if (nonce && state.nonces.has(nonce)) return [];
              if (nonce) state.nonces.add(nonce);
              return [{ id: "ledger-entry" }];
            },
          };
          return query;
        },
        update: () => {
          const query = {
            set: () => query,
            where: () => query,
            returning: async () => {
              if (state.balance === 0) return [];
              state.balance -= 1;
              return [{ balance: state.balance }];
            },
          };
          return query;
        },
      };
      try {
        return await run(tx);
      } catch (error) {
        state.balance = balanceBefore;
        state.nonces = noncesBefore;
        throw error;
      } finally {
        release();
      }
    },
  },
}));

import { ApiCreditError, spendApiCredit } from "./apiCredits.js";

describe("spendApiCredit", () => {
  beforeEach(() => {
    state.balance = 1;
    state.nonces.clear();
    state.transactionLock = Promise.resolve();
  });

  it("allows only one of two concurrent requests to spend the last credit", async () => {
    const results = await Promise.allSettled([
      spendApiCredit({ apiId: "api1", walletAddress: "wallet", nonce: "nonce-request-0001" }),
      spendApiCredit({ apiId: "api1", walletAddress: "wallet", nonce: "nonce-request-0002" }),
    ]);

    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    const rejected = results.find((result) => result.status === "rejected");
    expect(rejected).toMatchObject({ reason: expect.any(ApiCreditError) });
    expect(state.balance).toBe(0);
  });
});
