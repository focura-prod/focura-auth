import { describe, it, expect } from "vitest";
import {
  looksLikeServerToServerUA,
  looksLikeServerToServerRequest,
  normalizeUserAgent,
  generateDeviceFingerprint,
  getClientIp,
  createSessionMetadata,
  isPrivateIp,
  validateSessionBinding,
} from "../src/session/sessionBinding.js";
import type { SessionMetadata } from "../src/types.js";

describe("looksLikeServerToServerUA", () => {
  it("should return true for server UAs", () => {
    expect(looksLikeServerToServerUA("node")).toBe(true);
    expect(looksLikeServerToServerUA("curl/7.68")).toBe(true);
    expect(looksLikeServerToServerUA("axios/1.0")).toBe(true);
    expect(looksLikeServerToServerUA("python-requests/2.28")).toBe(true);
    expect(looksLikeServerToServerUA("go-http-client/1.1")).toBe(true);
    expect(looksLikeServerToServerUA("okhttp/4.9")).toBe(true);
    expect(looksLikeServerToServerUA("")).toBe(true);
    expect(looksLikeServerToServerUA("undici")).toBe(true);
  });
  it("should return false for browser UAs", () => {
    expect(looksLikeServerToServerUA("Mozilla/5.0 Chrome/120")).toBe(false);
    expect(looksLikeServerToServerUA("Mozilla/5.0 Firefox/121")).toBe(false);
    expect(looksLikeServerToServerUA("Mozilla/5.0 Safari/17")).toBe(false);
  });
});

describe("looksLikeServerToServerRequest", () => {
  it("should return true for server-like UA", () => {
    expect(looksLikeServerToServerRequest({ headers: { "user-agent": "node" } })).toBe(true);
  });
  it("should return true when no accept-language AND no accept-encoding", () => {
    expect(looksLikeServerToServerRequest({ headers: {} })).toBe(true);
  });
  it("should return false for browser request", () => {
    expect(looksLikeServerToServerRequest({
      headers: { "user-agent": "Mozilla/5.0 Chrome", "accept-language": "en", "accept-encoding": "gzip" },
    })).toBe(false);
  });
});

describe("normalizeUserAgent", () => {
  it("should detect Chrome on Windows", () => {
    expect(normalizeUserAgent("Mozilla/5.0 Chrome/120 Windows")).toBe("Chrome|Windows|desktop");
  });
  it("should detect Firefox on macOS", () => {
    expect(normalizeUserAgent("Mozilla/5.0 Firefox/121 Macintosh")).toBe("Firefox|macOS|desktop");
  });
  it("should detect Safari on iOS mobile", () => {
    expect(normalizeUserAgent("Mozilla/5.0 Safari/17 iPhone")).toBe("Safari|iOS|mobile");
  });
  it("should detect Edge on Windows", () => {
    expect(normalizeUserAgent("Mozilla/5.0 Edg/120 Windows")).toBe("Edge|Windows|desktop");
  });
  it("should detect Opera on Linux", () => {
    expect(normalizeUserAgent("Mozilla/5.0 OPR/100 Linux")).toBe("Opera|Linux|desktop");
  });
  it("should detect Brave on Windows", () => {
    expect(normalizeUserAgent("Mozilla/5.0 Chrome/120 Brave/1.60 Windows")).toBe("Brave|Windows|desktop");
  });
  it("should detect Vivaldi on macOS", () => {
    expect(normalizeUserAgent("Mozilla/5.0 Vivaldi/6.5 Chrome/120 Macintosh")).toBe("Vivaldi|macOS|desktop");
  });
  it("should detect Android mobile", () => {
    expect(normalizeUserAgent("Mozilla/5.0 Chrome/120 Android Mobile")).toBe("Chrome|Android|mobile");
  });
  it("should default to Other for unknown", () => {
    expect(normalizeUserAgent("custom-agent")).toBe("Other|Other|desktop");
  });
  it("should handle empty string", () => {
    expect(normalizeUserAgent("")).toBe("Other|Other|desktop");
  });
});

describe("generateDeviceFingerprint", () => {
  it("should produce a 64-char hex string", () => {
    const fp = generateDeviceFingerprint({ headers: { "user-agent": "Chrome/120", "accept-language": "en" } });
    expect(fp).toMatch(/^[a-f0-9]{64}$/);
  });
  it("should be deterministic", () => {
    const a = generateDeviceFingerprint({ headers: { "user-agent": "Chrome/120", "accept-language": "en" } });
    const b = generateDeviceFingerprint({ headers: { "user-agent": "Chrome/120", "accept-language": "en" } });
    expect(a).toBe(b);
  });
  it("should differ for different inputs", () => {
    const a = generateDeviceFingerprint({ headers: { "user-agent": "Mozilla/5.0 Chrome/120", "accept-language": "en-US" } });
    const b = generateDeviceFingerprint({ headers: { "user-agent": "Mozilla/5.0 Firefox/121", "accept-language": "fr-FR" } });
    expect(a).not.toBe(b);
  });
});

describe("getClientIp", () => {
  it("should return req.ip if set", () => {
    expect(getClientIp({ ip: "1.2.3.4", headers: {} })).toBe("1.2.3.4");
  });
  it("should strip ::ffff: prefix", () => {
    expect(getClientIp({ ip: "::ffff:10.0.0.1", headers: {} })).toBe("10.0.0.1");
  });
  it("should use x-forwarded-for", () => {
    expect(getClientIp({ headers: { "x-forwarded-for": "5.6.7.8, 9.10.11.12" } })).toBe("5.6.7.8");
  });
  it("should fall back to socket.remoteAddress", () => {
    expect(getClientIp({ headers: {}, socket: { remoteAddress: "::ffff:192.168.1.1" } })).toBe("192.168.1.1");
  });
  it("should use plain socket.remoteAddress without prefix", () => {
    expect(getClientIp({ headers: {}, socket: { remoteAddress: "9.9.9.9" } })).toBe("9.9.9.9");
  });
  it("should ignore empty req.ip and fall through", () => {
    expect(getClientIp({ ip: "", headers: { "x-forwarded-for": "4.4.4.4" } })).toBe("4.4.4.4");
  });
  it("should skip non-string x-forwarded-for headers", () => {
    expect(getClientIp({ headers: { "x-forwarded-for": ["a", "b"] }, socket: { remoteAddress: "6.6.6.6" } })).toBe("6.6.6.6");
  });
  it("should return unknown when nothing available", () => {
    expect(getClientIp({ headers: {} })).toBe("unknown");
  });
  it("should use XFF from trusted proxy", () => {
    expect(getClientIp({ ip: "10.0.0.1", headers: { "x-forwarded-for": "203.0.113.1, 7.8.9.10" } }, ["10.0.0.1"])).toBe("7.8.9.10");
  });
  it("should ignore XFF from untrusted proxy", () => {
    expect(getClientIp({ ip: "8.8.8.8", headers: { "x-forwarded-for": "203.0.113.1" } }, ["10.0.0.1"])).toBe("8.8.8.8");
  });
  it("should use XFF from CIDR-matched proxy", () => {
    expect(getClientIp({ ip: "10.0.0.5", headers: { "x-forwarded-for": "203.0.113.1" } }, ["10.0.0.0/8"])).toBe("203.0.113.1");
  });
  it("should return directIp when XFF is empty string from trusted proxy", () => {
    expect(getClientIp({ ip: "10.0.0.1", headers: { "x-forwarded-for": "" } }, ["10.0.0.1"])).toBe("10.0.0.1");
  });
  it("should use socket.remoteAddress when req.ip is missing", () => {
    expect(getClientIp({ headers: {}, socket: { remoteAddress: "192.168.1.1" } })).toBe("192.168.1.1");
  });
  it("should strip ::ffff: from socket.remoteAddress", () => {
    expect(getClientIp({ headers: {}, socket: { remoteAddress: "::ffff:172.16.0.1" } })).toBe("172.16.0.1");
  });
});

describe("ipMatchesCidr / ipInList (via getClientIp trustedProxies)", () => {
  it("should match exact IP in trusted list", () => {
    expect(getClientIp({ ip: "10.0.0.1", headers: { "x-forwarded-for": "1.2.3.4" } }, ["10.0.0.1"])).toBe("1.2.3.4");
  });
  it("should match /24 CIDR", () => {
    expect(getClientIp({ ip: "10.0.0.50", headers: { "x-forwarded-for": "1.2.3.4" } }, ["10.0.0.0/24"])).toBe("1.2.3.4");
  });
  it("should match /16 CIDR", () => {
    expect(getClientIp({ ip: "172.16.5.5", headers: { "x-forwarded-for": "1.2.3.4" } }, ["172.16.0.0/16"])).toBe("1.2.3.4");
  });
  it("should match /8 CIDR", () => {
    expect(getClientIp({ ip: "10.255.255.255", headers: { "x-forwarded-for": "1.2.3.4" } }, ["10.0.0.0/8"])).toBe("1.2.3.4");
  });
  it("should not match different subnet", () => {
    expect(getClientIp({ ip: "192.168.1.1", headers: { "x-forwarded-for": "1.2.3.4" } }, ["10.0.0.0/8"])).toBe("192.168.1.1");
  });
  it("should handle mixed exact and CIDR entries", () => {
    expect(getClientIp({ ip: "172.16.0.1", headers: { "x-forwarded-for": "1.2.3.4" } }, ["10.0.0.1", "172.16.0.0/12"])).toBe("1.2.3.4");
  });
  it("should handle /0 CIDR (matches all)", () => {
    expect(getClientIp({ ip: "8.8.8.8", headers: { "x-forwarded-for": "1.2.3.4" } }, ["0.0.0.0/0"])).toBe("1.2.3.4");
  });
  it("should handle invalid CIDR prefix > 32 (falls back to exact match, no match)", () => {
    // Invalid CIDR → ipMatchesCidr falls back to exact string compare → "10.0.0.1" !== "10.0.0.1/33" → no match
    expect(getClientIp({ ip: "10.0.0.1", headers: { "x-forwarded-for": "1.2.3.4" } }, ["10.0.0.1/33"])).toBe("10.0.0.1");
  });
  it("should handle non-numeric CIDR prefix (falls back to exact match, no match)", () => {
    expect(getClientIp({ ip: "10.0.0.1", headers: { "x-forwarded-for": "1.2.3.4" } }, ["10.0.0.1/abc"])).toBe("10.0.0.1");
  });
  it("should handle empty CIDR subnet (falls back to exact match, matches)", () => {
    // "/24" includes "/" → goes to ipMatchesCidr → subnet="" → !subnet → falls back to ip===cidr → "/24"==="/24" → match
    expect(getClientIp({ ip: "/24", headers: { "x-forwarded-for": "1.2.3.4" } }, ["/24"])).toBe("1.2.3.4");
  });
});

describe("createSessionMetadata", () => {
  it("should create metadata from request", () => {
    const m = createSessionMetadata({ ip: "1.2.3.4", headers: { "user-agent": "Chrome" } });
    expect(m.deviceId).toBeNull();
    expect(m.ipAddress).toBe("1.2.3.4");
    expect(m.userAgent).toBe("Chrome");
    expect(typeof m.lastActivity).toBe("number");
  });
});

describe("isPrivateIp", () => {
  it("should detect private IPs", () => {
    expect(isPrivateIp("10.0.0.1")).toBe(true);
    expect(isPrivateIp("192.168.1.1")).toBe(true);
    expect(isPrivateIp("172.16.0.1")).toBe(true);
    expect(isPrivateIp("127.0.0.1")).toBe(true);
    expect(isPrivateIp("0.0.0.0")).toBe(true);
    expect(isPrivateIp("169.254.1.1")).toBe(true);
    expect(isPrivateIp("::1")).toBe(true);
    expect(isPrivateIp("fe80::1")).toBe(true);
    expect(isPrivateIp("fc00::1")).toBe(true);
    expect(isPrivateIp("fd00::1")).toBe(true);
    expect(isPrivateIp("::ffff:10.0.0.1")).toBe(true);
  });
  it("should return false for unknown/empty", () => {
    expect(isPrivateIp("")).toBe(false);
    expect(isPrivateIp("unknown")).toBe(false);
  });
  it("should detect public IPs", () => {
    expect(isPrivateIp("8.8.8.8")).toBe(false);
    expect(isPrivateIp("1.1.1.1")).toBe(false);
    expect(isPrivateIp("203.0.113.1")).toBe(false);
  });
});

describe("validateSessionBinding", () => {
  const meta: SessionMetadata = {
    deviceId: generateDeviceFingerprint({ headers: { "user-agent": "Chrome/120", "accept-language": "en" } }),
    ipAddress: "1.2.3.4",
    userAgent: "Chrome/120",
    lastActivity: Date.now() - 10_000,
  };

  it("should pass with matching device and IP", () => {
    const req = { headers: { "user-agent": "Chrome/120", "accept-language": "en" }, ip: "1.2.3.4" };
    expect(validateSessionBinding(req, meta).valid).toBe(true);
  });
  it("should fail on device mismatch", () => {
    const req = { headers: { "user-agent": "Firefox/120", "accept-language": "en" }, ip: "1.2.3.4" };
    const r = validateSessionBinding(req, meta);
    expect(r.valid).toBe(false);
    expect(r.reason).toBe("DEVICE_MISMATCH");
  });
  it("should allow IP change if stored IP is private", () => {
    const privateMeta = { ...meta, ipAddress: "192.168.1.1" };
    const req = { headers: { "user-agent": "Chrome/120", "accept-language": "en" }, ip: "5.6.7.8" };
    expect(validateSessionBinding(req, privateMeta).valid).toBe(true);
  });
  it("should allow IP change if current IP is private", () => {
    const req = { headers: { "user-agent": "Chrome/120", "accept-language": "en" }, ip: "10.0.0.1" };
    expect(validateSessionBinding(req, meta).valid).toBe(true);
  });
  it("should detect suspicious IP change when recent activity", () => {
    const recentMeta = { ...meta, lastActivity: Date.now() - 1000 };
    const req = { headers: { "user-agent": "Chrome/120", "accept-language": "en" }, ip: "5.6.7.8" };
    const r = validateSessionBinding(req, recentMeta);
    expect(r.valid).toBe(false);
    expect(r.reason).toBe("SUSPICIOUS_IP_CHANGE");
  });
  it("should allow IP change after long gap", () => {
    const oldMeta = { ...meta, lastActivity: Date.now() - 600_000 };
    const req = { headers: { "user-agent": "Chrome/120", "accept-language": "en" }, ip: "5.6.7.8" };
    expect(validateSessionBinding(req, oldMeta).valid).toBe(true);
  });
  it("should accept request when stored IP is unknown", () => {
    const unknownMeta = { ...meta, ipAddress: "unknown" };
    const req = { headers: { "user-agent": "Chrome/120", "accept-language": "en" }, ip: "5.6.7.8" };
    expect(validateSessionBinding(req, unknownMeta).valid).toBe(true);
  });
  it("should accept request when current IP is unknown", () => {
    const req = { headers: { "user-agent": "Chrome/120", "accept-language": "en" } };
    expect(validateSessionBinding(req, meta).valid).toBe(true);
  });
});
