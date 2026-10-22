/**
 * Tests for the SSRF guard additions (#52): 6to4 (2002::/16) and Teredo
 * (2001::/32) IPv6 address blocking.
 */

import { describe, it, expect } from "vitest";
import { isPublicAddress, validateUpstreamUrl } from "./upstreamGuard.js";

// ── 6to4 (2002::/16) ─────────────────────────────────────────────────────────

describe("isPublicAddress — 6to4 (2002::/16)", () => {
  it("blocks 2002:7f00:0001:: (embeds 127.0.0.1 — loopback)", () => {
    // 127.0.0.1 → 0x7f000001 → groups 7f00 : 0001
    expect(isPublicAddress("2002:7f00:0001::")).toBe(false);
  });

  it("blocks 2002:0a00:0001:: (embeds 10.0.0.1 — private)", () => {
    // 10.0.0.1 → 0x0a000001 → 0a00 : 0001
    expect(isPublicAddress("2002:0a00:0001::")).toBe(false);
  });

  it("blocks 2002:c0a8:0101:: (embeds 192.168.1.1 — private)", () => {
    // 192.168.1.1 → 0xc0a80101 → c0a8 : 0101
    expect(isPublicAddress("2002:c0a8:0101::")).toBe(false);
  });

  it("blocks 2002:a9fe:0101:: (embeds 169.254.1.1 — link-local)", () => {
    // 169.254.1.1 → 0xa9fe0101 → a9fe : 0101
    expect(isPublicAddress("2002:a9fe:0101::")).toBe(false);
  });

  it("allows 2002:0808:0808:: (embeds 8.8.8.8 — public)", () => {
    // 8.8.8.8 → 0x08080808 → 0808 : 0808
    expect(isPublicAddress("2002:0808:0808::")).toBe(true);
  });
});

// ── Teredo (2001::/32) ────────────────────────────────────────────────────────

describe("isPublicAddress — Teredo (2001::/32)", () => {
  it("blocks a Teredo address whose server is 127.0.0.1", () => {
    // Teredo format: 2001:0000:<server_hi>:<server_lo>:flags:<client_hi_xor>:<client_lo_xor>
    // Server = 127.0.0.1 → 0x7f000001 → groups 7f00:0001
    // Client = 1.2.3.4 XOR 0xfffe → 0xfefe : 0xfcfb (dummy)
    const addr = "2001:0000:7f00:0001:0000:ffff:fefe:fcfb";
    expect(isPublicAddress(addr)).toBe(false);
  });

  it("blocks a Teredo address whose server is 10.0.0.1 (private)", () => {
    // Server = 10.0.0.1 → 0x0a000001 → 0a00:0001
    const addr = "2001:0000:0a00:0001:0000:ffff:fefe:fcfb";
    expect(isPublicAddress(addr)).toBe(false);
  });

  it("blocks a Teredo address whose mapped client IP is 192.168.1.1", () => {
    // Client IPv4 192.168.1.1 → XOR 0xffff each group:
    // 192.168 → 0xc0a8 XOR 0xffff = 0x3f57
    // 1.1     → 0x0101 XOR 0xffff = 0xfefe
    // Server = 1.1.1.1 (public) → 0x01010101 → 0101:0101
    const addr = "2001:0000:0101:0101:0000:ffff:3f57:fefe";
    expect(isPublicAddress(addr)).toBe(false);
  });

  it("allows a Teredo address with only public IPs embedded", () => {
    // Server = 8.8.8.8 → 0x08080808 → 0808:0808
    // Client = 8.8.4.4 → XOR each word: 0x0808 XOR 0xffff = 0xf7f7; 0x0404 XOR 0xffff = 0xfbfb
    const addr = "2001:0000:0808:0808:0000:ffff:f7f7:fbfb";
    expect(isPublicAddress(addr)).toBe(true);
  });
});

// ── Pre-existing ranges (regression) ─────────────────────────────────────────

describe("isPublicAddress — pre-existing ranges still blocked", () => {
  it("blocks ::1 (loopback)", () => {
    expect(isPublicAddress("::1")).toBe(false);
  });

  it("blocks ::ffff:127.0.0.1 (IPv4-mapped loopback)", () => {
    expect(isPublicAddress("::ffff:127.0.0.1")).toBe(false);
  });

  it("blocks fc00::1 (unique local)", () => {
    expect(isPublicAddress("fc00::1")).toBe(false);
  });

  it("blocks 10.0.0.1 (IPv4 private)", () => {
    expect(isPublicAddress("10.0.0.1")).toBe(false);
  });

  it("allows 8.8.8.8 (public IPv4)", () => {
    expect(isPublicAddress("8.8.8.8")).toBe(true);
  });

  it("allows 2600::1 (public IPv6)", () => {
    expect(isPublicAddress("2600::1")).toBe(true);
  });
});

// ── validateUpstreamUrl integration ──────────────────────────────────────────

describe("validateUpstreamUrl — 6to4 and Teredo blocked", () => {
  it("rejects a URL with a 6to4 address embedding 127.0.0.1", () => {
    expect(() =>
      validateUpstreamUrl("http://[2002:7f00:0001::]/api", { allowPrivate: false }),
    ).toThrow(/public address/);
  });

  it("rejects a URL with a Teredo address embedding a private server IP", () => {
    expect(() =>
      validateUpstreamUrl("http://[2001:0000:7f00:0001:0000:ffff:fefe:fcfb]/api", {
        allowPrivate: false,
      }),
    ).toThrow(/public address/);
  });

  it("accepts a URL with a 6to4 address embedding a public IPv4", () => {
    // 8.8.8.8 → 2002:0808:0808::
    expect(() =>
      validateUpstreamUrl("https://[2002:0808:0808::]/api", { allowPrivate: false }),
    ).not.toThrow();
  });
});
