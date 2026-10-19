import { and, eq, sql } from "drizzle-orm";
import { db } from "../db/client.js";
import { apiCreditBalances, apiCreditLedger } from "../db/schema.js";

export class ApiCreditError extends Error {
  constructor(
    public readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

export async function getApiCreditBalance(apiId: string, walletAddress: string): Promise<number> {
  const [row] = await db
    .select({ balance: apiCreditBalances.balance })
    .from(apiCreditBalances)
    .where(
      and(
        eq(apiCreditBalances.apiId, apiId),
        eq(apiCreditBalances.walletAddress, walletAddress),
      ),
    )
    .limit(1);
  return row?.balance ?? 0;
}

export async function purchaseApiCredits(input: {
  apiId: string;
  walletAddress: string;
  calls: number;
  reference: string;
}): Promise<{ balance: number; duplicate: boolean }> {
  return db.transaction(async (tx) => {
    const [entry] = await tx
      .insert(apiCreditLedger)
      .values({
        apiId: input.apiId,
        walletAddress: input.walletAddress,
        delta: input.calls,
        entryType: "purchase",
        reference: input.reference,
      })
      .onConflictDoNothing()
      .returning({ id: apiCreditLedger.id });

    if (!entry) {
      const [existing] = await tx
        .select({ balance: apiCreditBalances.balance })
        .from(apiCreditBalances)
        .where(
          and(
            eq(apiCreditBalances.apiId, input.apiId),
            eq(apiCreditBalances.walletAddress, input.walletAddress),
          ),
        )
        .limit(1);
      return { balance: existing?.balance ?? 0, duplicate: true };
    }

    const [balance] = await tx
      .insert(apiCreditBalances)
      .values({
        apiId: input.apiId,
        walletAddress: input.walletAddress,
        balance: input.calls,
        updatedAt: new Date(),
      })
      .onConflictDoUpdate({
        target: [apiCreditBalances.apiId, apiCreditBalances.walletAddress],
        set: {
          balance: sql`${apiCreditBalances.balance} + ${input.calls}`,
          updatedAt: new Date(),
        },
      })
      .returning({ balance: apiCreditBalances.balance });

    return { balance: balance.balance, duplicate: false };
  });
}

export async function spendApiCredit(input: {
  apiId: string;
  walletAddress: string;
  nonce: string;
}): Promise<number> {
  return db.transaction(async (tx) => {
    const [entry] = await tx
      .insert(apiCreditLedger)
      .values({
        apiId: input.apiId,
        walletAddress: input.walletAddress,
        delta: -1,
        entryType: "spend",
        requestNonce: input.nonce,
      })
      .onConflictDoNothing()
      .returning({ id: apiCreditLedger.id });

    if (!entry) {
      throw new ApiCreditError(409, "This signed credit request has already been used");
    }

    const [balance] = await tx
      .update(apiCreditBalances)
      .set({
        balance: sql`${apiCreditBalances.balance} - 1`,
        updatedAt: new Date(),
      })
      .where(
        and(
          eq(apiCreditBalances.apiId, input.apiId),
          eq(apiCreditBalances.walletAddress, input.walletAddress),
          sql`${apiCreditBalances.balance} > 0`,
        ),
      )
      .returning({ balance: apiCreditBalances.balance });

    if (!balance) throw new ApiCreditError(402, "No prepaid call credits are available");
    return balance.balance;
  });
}
