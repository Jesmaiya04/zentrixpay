import {
  pgTable,
  text,
  real,
  integer,
  boolean,
  timestamp,
  pgEnum,
  jsonb,
  index,
  uniqueIndex,
} from "drizzle-orm/pg-core";
import { createId } from "@paralleldrive/cuid2";

export const resourceTypeEnum = pgEnum("resource_type", ["file", "link"]);

export const verificationStatusEnum = pgEnum("verification_status", [
  "pending",
  "verified",
  "rejected",
  "skipped",
]);

export const onchainStatusEnum = pgEnum("onchain_status_enum", [
  "none",
  "pending",
  "registered",
  "failed",
]);

// Publishers — humans or AI agents that publish resources
export const publishers = pgTable("publishers", {
  id: text("id")
    .primaryKey()
    .$defaultFn(() => createId()),
  name: text("name").notNull(),
  email: text("email").notNull().unique(),
  walletAddress: text("wallet_address").notNull(),
  apiKeyHash: text("api_key_hash").notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

// Resources — digital assets published on the marketplace
export const resources = pgTable(
  "resources",
  {
    id: text("id")
      .primaryKey()
      .$defaultFn(() => createId()),
    publisherId: text("publisher_id")
      .notNull()
      .references(() => publishers.id),
    title: text("title").notNull(),
    description: text("description"),
    price: text("price").notNull(),
    walletAddress: text("wallet_address").notNull(),
    resourceType: resourceTypeEnum("resource_type").notNull(),
    storagePath: text("storage_path"),
    thumbnailPath: text("thumbnail_path"),
    contentHash: text("content_hash"),
    externalUrl: text("external_url"),
    mimeType: text("mime_type"),
    verificationStatus: verificationStatusEnum("verification_status").notNull().default("pending"),
    verificationId: text("verification_id"),
    listed: boolean("listed").notNull().default(false),
    onchainStatus: onchainStatusEnum("onchain_status").notNull().default("none"),
    onchainTxHash: text("onchain_tx_hash"),
    tags: jsonb("tags").$type<string[]>().notNull().default([]),
    createdAt: timestamp("created_at").defaultNow().notNull(),
  },
  (table) => ({
    catalogFilterSortIdx: index("idx_resources_catalog_filter_sort").on(
      table.listed,
      table.verificationStatus,
      table.createdAt,
    ),
    // Publisher dashboards list a single publisher's resources (#285).
    publisherIdx: index("idx_resources_publisher_id").on(table.publisherId),
    // Verification-status filters that aren't anchored to `listed` can't use the
    // composite catalog index, so they get their own (#285).
    verificationStatusIdx: index("idx_resources_verification_status").on(table.verificationStatus),
  }),
);

// Verifications — AI originality check results
export const verifications = pgTable("verifications", {
  id: text("id")
    .primaryKey()
    .$defaultFn(() => createId()),
  resourceId: text("resource_id")
    .notNull()
    .references(() => resources.id),
  isOriginal: boolean("is_original").notNull(),
  confidence: real("confidence").notNull(), // 0.0 - 1.0
  flags: text("flags"), // JSON stringified array of issues
  // Token usage + estimated spend for the verification model call (#283).
  // Nullable so historical rows predating usage tracking remain valid.
  promptTokens: integer("prompt_tokens"),
  completionTokens: integer("completion_tokens"),
  totalTokens: integer("total_tokens"),
  estimatedCost: text("estimated_cost"), // USD, stringified for precision
  checkedAt: timestamp("checked_at").defaultNow().notNull(),
});

// Payments — tracks x402 payments for resources
export const payments = pgTable(
  "payments",
  {
    id: text("id")
      .primaryKey()
      .$defaultFn(() => createId()),
    resourceId: text("resource_id")
      .notNull()
      .references(() => resources.id),
    payerAddress: text("payer_address").notNull(),
    recipientAddress: text("recipient_address").notNull(),
    amount: text("amount").notNull(), // USDC amount
    paidAt: timestamp("paid_at").defaultNow().notNull(),
  },
  (table) => ({
    // Payment history is queried per payer wallet (#285).
    payerAddressIdx: index("idx_payments_payer_address").on(table.payerAddress),
  }),
);

// APIs — upstream HTTP APIs that providers sell per call through the proxy
export const apis = pgTable(
  "apis",
  {
    id: text("id")
      .primaryKey()
      .$defaultFn(() => createId()),
    publisherId: text("publisher_id")
      .notNull()
      .references(() => publishers.id),
    name: text("name").notNull(),
    description: text("description"),
    // Never exposed publicly: callers must go through the paid proxy.
    upstreamUrl: text("upstream_url").notNull(),
    price: text("price").notNull(), // USDC per call
    walletAddress: text("wallet_address").notNull(),
    allowedMethods: jsonb("allowed_methods").$type<string[]>().notNull().default(["GET"]),
    // Header the proxy adds to every upstream request, e.g. the provider's own
    // API key. The value is AES-256-GCM encrypted (see utils/secretBox.ts).
    upstreamHeaderName: text("upstream_header_name"),
    upstreamHeaderValueEnc: text("upstream_header_value_enc"),
    // Query parameter the proxy adds to every upstream URL, for APIs that take
    // their key as ?api_key=…. Encrypted like the header value.
    upstreamQueryName: text("upstream_query_name"),
    upstreamQueryValueEnc: text("upstream_query_value_enc"),
    // Provider-supplied OpenAPI 3 document, stored as uploaded (it may name the
    // upstream; the public copy is rewritten, see services/openApiSpec.ts).
    openapiSpec: jsonb("openapi_spec").$type<Record<string, unknown>>(),
    timeoutMs: integer("timeout_ms"),
    // Per-API response cap; never above PROXY_MAX_RESPONSE_BYTES (#37).
    maxResponseBytes: integer("max_response_bytes"),
    // Signed event POSTed after each charged call (#36). The secret is
    // AES-256-GCM encrypted like the upstream header value.
    webhookUrl: text("webhook_url"),
    webhookSecretEnc: text("webhook_secret_enc"),
    // Upstream health (#35): healthPath is pinged relative to upstreamUrl;
    // unhealthy APIs are hidden from the catalog until a check succeeds.
    healthPath: text("health_path"),
    healthy: boolean("healthy").notNull().default(true),
    healthFailures: integer("health_failures").notNull().default(0),
    lastHealthCheckAt: timestamp("last_health_check_at"),
    ownershipToken: text("ownership_token").notNull(),
    ownershipVerifiedAt: timestamp("ownership_verified_at"),
    listed: boolean("listed").notNull().default(false),
    tags: jsonb("tags").$type<string[]>().notNull().default([]),
    // When true the proxy streams the upstream response body directly to the
    // caller instead of buffering it. Required for SSE / chunked APIs. The
    // payment is settled before streaming begins; a stream that fails before
    // the first data byte is never charged (see proxyHandler in routes/apis.ts).
    streamingEnabled: boolean("streaming_enabled").notNull().default(false),
    // Soft delete: archived APIs are hidden everywhere but keep their call history.
    archivedAt: timestamp("archived_at"),
    createdAt: timestamp("created_at").defaultNow().notNull(),
  },
  (table) => ({
    publisherIdx: index("idx_apis_publisher_id").on(table.publisherId),
    catalogIdx: index("idx_apis_listed_created_at").on(table.listed, table.createdAt),
    tagsIdx: index("idx_apis_tags").using("gin", table.tags),
  }),
);

// API calls — one row per proxied call, charged or not
export const apiCalls = pgTable(
  "api_calls",
  {
    id: text("id")
      .primaryKey()
      .$defaultFn(() => createId()),
    apiId: text("api_id")
      .notNull()
      .references(() => apis.id),
    payerAddress: text("payer_address").notNull(),
    amount: text("amount").notNull(), // USDC; only collected when charged
    charged: boolean("charged").notNull(),
    method: text("method").notNull(),
    path: text("path").notNull(),
    responseStatus: integer("response_status").notNull(),
    durationMs: integer("duration_ms").notNull(),
    // Settlement transaction, from the x402 PAYMENT-RESPONSE header; null when not charged.
    txHash: text("tx_hash"),
    createdAt: timestamp("created_at").defaultNow().notNull(),
  },
  (table) => ({
    refundTxIdx: uniqueIndex("idx_api_calls_refund_tx_hash").on(table.refundTxHash),
    apiCreatedIdx: index("idx_api_calls_api_id_created_at").on(table.apiId, table.createdAt),
    payerCreatedIdx: index("idx_api_calls_payer_address_created_at").on(
      table.payerAddress,
      table.createdAt,
    ),
  }),
);
