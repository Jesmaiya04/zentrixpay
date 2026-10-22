import { describe, it, expect, vi, beforeEach } from "vitest";
import express from "express";
import request from "supertest";
import {
  corsMiddleware,
  parseAllowedOrigins,
  X402_ALLOWED_HEADERS,
  X402_EXPOSED_HEADERS,
} from "./cors.js";

vi.mock("./config.js", () => ({
  config: {
    NODE_ENV: "production",
    WEB_APP_URL: "https://app.example.com",
    ALLOWED_ORIGINS: undefined,
  },
}));

describe("parseAllowedOrigins", () => {
  it("splits a comma-separated list", () => {
    expect(
      parseAllowedOrigins("https://app.example.com, http://localhost:5173", "fallback"),
    ).toEqual(["https://app.example.com", "http://localhost:5173"]);
  });

  it("falls back when unset or blank", () => {
    expect(parseAllowedOrigins(undefined, "https://app.example.com")).toEqual([
      "https://app.example.com",
    ]);
    expect(parseAllowedOrigins("  ", "https://app.example.com")).toEqual([
      "https://app.example.com",
    ]);
  });
});

describe("createCorsOptions", () => {
  beforeEach(() => {
    vi.resetModules();
  });

  it("keeps the production allowlist on non-proxy routes", async () => {
    const app = express();
    app.use(corsMiddleware());
    const response = await request(app)
      .options("/apis")
      .set("Origin", "https://app.example.com")
      .set("Access-Control-Request-Method", "GET");
    const allowed = response.headers["access-control-allow-headers"].toLowerCase();
    for (const header of X402_ALLOWED_HEADERS) {
      expect(allowed).toContain(header.toLowerCase());
    }
    expect(response.headers["access-control-expose-headers"]).toContain(
      X402_EXPOSED_HEADERS[0],
    );
  });

  it("reflects requested headers only for API proxy paths", async () => {
    const app = express();
    app.use(corsMiddleware());
    const response = await request(app)
      .options("/api/weather/v1/forecast")
      .set("Origin", "https://app.example.com")
      .set("Access-Control-Request-Method", "POST")
      .set("Access-Control-Request-Headers", "content-type, x-tenant-key");
    expect(response.headers["access-control-allow-headers"]).toBe("content-type,x-tenant-key");
  });

  it("rejects unlisted origins in production", async () => {
    const { createCorsOptions } = await import("./cors.js");
    const options = createCorsOptions();
    const origin = options.origin as (
      origin: string | undefined,
      callback: (err: Error | null, allow?: boolean) => void,
    ) => void;

    await new Promise<void>((resolve) => {
      origin("https://app.example.com", (err, allow) => {
        expect(err).toBeNull();
        expect(allow).toBe(true);
        resolve();
      });
    });

    await new Promise<void>((resolve) => {
      origin("https://evil.example.com", (err) => {
        expect(err).toBeInstanceOf(Error);
        resolve();
      });
    });
  });
});
