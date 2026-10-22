import { isIP, BlockList } from "node:net";

// SSRF protection for the API proxy. Providers choose the upstream URL, so
// without these checks anyone could register an "API" that points at the
// server's own network (localhost, cloud metadata, private ranges) and have
// ZentrixPay fetch it for them.

const blocked = new BlockList();
// IPv4
blocked.addSubnet("0.0.0.0", 8, "ipv4"); // "this" network
blocked.addSubnet("10.0.0.0", 8, "ipv4"); // private
blocked.addSubnet("100.64.0.0", 10, "ipv4"); // carrier-grade NAT
blocked.addSubnet("127.0.0.0", 8, "ipv4"); // loopback
blocked.addSubnet("169.254.0.0", 16, "ipv4"); // link-local, cloud metadata
blocked.addSubnet("172.16.0.0", 12, "ipv4"); // private
blocked.addSubnet("192.0.0.0", 24, "ipv4"); // IETF protocol assignments
blocked.addSubnet("192.0.2.0", 24, "ipv4"); // TEST-NET-1
blocked.addSubnet("192.168.0.0", 16, "ipv4"); // private
blocked.addSubnet("198.18.0.0", 15, "ipv4"); // benchmarking
blocked.addSubnet("198.51.100.0", 24, "ipv4"); // TEST-NET-2
blocked.addSubnet("203.0.113.0", 24, "ipv4"); // TEST-NET-3
blocked.addSubnet("224.0.0.0", 4, "ipv4"); // multicast
blocked.addSubnet("240.0.0.0", 4, "ipv4"); // reserved + broadcast
// IPv6
blocked.addAddress("::", "ipv6"); // unspecified
blocked.addAddress("::1", "ipv6"); // loopback
blocked.addSubnet("64:ff9b::", 96, "ipv6"); // NAT64 (embeds IPv4)
blocked.addSubnet("100::", 64, "ipv6"); // discard
blocked.addSubnet("2001::", 32, "ipv6"); // Teredo (#52) — embeds server IPv4 (bits 96-127 inverted)
blocked.addSubnet("2002::", 16, "ipv6"); // 6to4 (#52) — bits 16-47 are the embedded IPv4 address
blocked.addSubnet("2001:db8::", 32, "ipv6"); // documentation
blocked.addSubnet("fc00::", 7, "ipv6"); // unique local
blocked.addSubnet("fe80::", 10, "ipv6"); // link-local
blocked.addSubnet("ff00::", 8, "ipv6"); // multicast

/** IPv4-mapped / -compatible IPv6 forms are judged by the embedded IPv4 address. */
function embeddedIpv4(address: string): string | null {
  // ::ffff:a.b.c.d  or  ::a.b.c.d
  const dotted = /^::(?:ffff:)?(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(address);
  if (dotted) return dotted[1];

  // ::ffff:hhhh:hhhh  (hex-encoded IPv4)
  const hex = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i.exec(address);
  if (hex) {
    const hi = parseInt(hex[1], 16);
    const lo = parseInt(hex[2], 16);
    return `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
  }

  return null;
}

/**
 * Extract the embedded IPv4 address from a 6to4 address (2002::/16).
 * The IPv4 address occupies bits 16-47, i.e. the second and third groups.
 * Example: 2002:7f00:0001:: → 127.0.0.1
 */
function extract6to4Ipv4(address: string): string | null {
  // Expand the address enough to read groups 2 and 3.
  // Node.js normalises IPv6 addresses, but we may receive un-normalised ones.
  const match = /^2002:([0-9a-f]{1,4}):([0-9a-f]{1,4}):/i.exec(address);
  if (!match) return null;
  const hi = parseInt(match[1], 16); // upper 16 bits of IPv4
  const lo = parseInt(match[2], 16); // lower 16 bits of IPv4
  return `${hi >> 8}.${hi & 0xff}.${lo >> 8}.${lo & 0xff}`;
}

/**
 * Extract the embedded server IPv4 address from a Teredo address (2001::/32).
 * RFC 4380 §4: bits 96-127 are the server IPv4 XOR 0xffffffff (bitwise NOT).
 * Example: 2001:0000:....:<hi_xor>:<lo_xor>  → server IP
 *
 * The Teredo client IPv4 is in bits 80-95 (XOR 0xffff) but the SSRF-relevant
 * address is the *server* address (bits 32-63 — the Teredo server that forwarded
 * the packet).  We check both the server address (bits 32-63) and the mapped
 * server IPv4 (bits 96-127 XOR 0xffffffff) to be thorough.
 */
function extractTeredoIpv4(address: string): string[] {
  // Fully expand the address to reliably index into it.
  const expanded = expandIpv6(address);
  if (!expanded) return [];

  const groups = expanded.split(":").map((g) => parseInt(g, 16));
  if (groups.length !== 8) return [];

  // Teredo server IPv4: groups[2] and groups[3] (bits 32-63)
  const serverHi = groups[2];
  const serverLo = groups[3];
  const serverIp = `${serverHi >> 8}.${serverHi & 0xff}.${serverLo >> 8}.${serverLo & 0xff}`;

  // Mapped client IPv4: groups[6] and groups[7] XOR 0xffff each (bits 96-127)
  const clientHi = groups[6] ^ 0xffff;
  const clientLo = groups[7] ^ 0xffff;
  const clientIp = `${clientHi >> 8}.${clientHi & 0xff}.${clientLo >> 8}.${clientLo & 0xff}`;

  return [serverIp, clientIp];
}

/** Fully expand a compressed IPv6 address to 8 colon-separated hex groups. */
function expandIpv6(address: string): string | null {
  // Strip zone ID (e.g. %eth0)
  const clean = address.split("%")[0];

  if (!clean.includes(":")) return null;

  const halves = clean.split("::");
  if (halves.length > 2) return null;

  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves[1] ? halves[1].split(":") : [];
  const missing = 8 - left.length - right.length;
  if (missing < 0) return null;

  const middle = Array<string>(missing).fill("0");
  const all = [...left, ...middle, ...right];
  if (all.length !== 8) return null;

  return all.map((g) => g.padStart(4, "0")).join(":");
}

export function isPublicAddress(address: string): boolean {
  const family = isIP(address);
  if (family === 0) return false;

  if (family === 6) {
    // 1. IPv4-mapped / IPv4-compatible forms — judge by embedded IPv4
    const v4 = embeddedIpv4(address);
    if (v4) return !blocked.check(v4, "ipv4");

    // 2. 6to4 (2002::/16) — decode the embedded IPv4 in bits 16-47 (#52)
    if (/^2002:/i.test(address)) {
      const v4from6to4 = extract6to4Ipv4(address);
      if (v4from6to4 && blocked.check(v4from6to4, "ipv4")) return false;
      // Also block the prefix itself via the BlockList entry above.
      return !blocked.check(address, "ipv6");
    }

    // 3. Teredo (2001::/32) — check the embedded server & client IPv4s (#52)
    if (/^2001:/i.test(address)) {
      const teredoV4s = extractTeredoIpv4(address);
      if (teredoV4s.some((ip) => blocked.check(ip, "ipv4"))) return false;
      return !blocked.check(address, "ipv6");
    }

    return !blocked.check(address, "ipv6");
  }

  return !blocked.check(address, "ipv4");
}

export class UpstreamUrlError extends Error {}

/**
 * Static checks on a provider-supplied upstream (or webhook) URL. Address
 * checks on the resolved host happen at connect time (see upstreamClient.ts),
 * so a hostname that later re-resolves to a private address is still refused.
 */
export function validateUpstreamUrl(
  raw: string,
  opts: { allowPrivate: boolean; field?: string },
): URL {
  const field = opts.field ?? "upstreamUrl";
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new UpstreamUrlError(`${field} is not a valid URL`);
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new UpstreamUrlError(`${field} must use http or https`);
  }
  if (url.username || url.password) {
    const hint = field === "upstreamUrl" ? "; use upstreamHeader" : "";
    throw new UpstreamUrlError(`${field} must not contain credentials${hint}`);
  }
  if (url.hash) {
    throw new UpstreamUrlError(`${field} must not contain a fragment`);
  }
  if (!opts.allowPrivate) {
    const host = url.hostname.replace(/^\[|\]$/g, "");
    if (isIP(host) && !isPublicAddress(host)) {
      throw new UpstreamUrlError(`${field} must point at a public address`);
    }
    if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".internal")) {
      throw new UpstreamUrlError(`${field} must point at a public address`);
    }
  }
  return url;
}
