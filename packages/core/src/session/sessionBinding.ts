import crypto from "crypto";
import type { SessionMetadata } from "../types.js";

const SERVER_TO_SERVER_UA =
  /^(node|undici|axios|curl|go-http-client|python-requests|java\/|okhttp|superagent)/i;

export function looksLikeServerToServerUA(userAgent: string): boolean {
  return !userAgent || SERVER_TO_SERVER_UA.test(userAgent);
}

export function looksLikeServerToServerRequest(req: {
  headers: Record<string, string | string[] | undefined>;
}): boolean {
  const ua = (req.headers["user-agent"] as string | undefined) ?? "";
  if (looksLikeServerToServerUA(ua)) return true;
  return !req.headers["accept-language"] && !req.headers["accept-encoding"];
}

export function normalizeUserAgent(userAgent: string): string {
  const ua = userAgent || "";
  const mobile = /Mobile|Android|iPhone|iPad|iPod/i.test(ua);
  const browser = /Edg\//i.test(ua)
    ? "Edge"
    : /OPR\/|Opera/i.test(ua)
      ? "Opera"
      : /Firefox\/|FxiOS/i.test(ua)
        ? "Firefox"
        : /CriOS\/|Chrome\//i.test(ua)
          ? "Chrome"
          : /Safari\//i.test(ua)
            ? "Safari"
            : "Other";
  const os = /Android/i.test(ua)
    ? "Android"
    : /iPhone|iPad|iPod/i.test(ua)
      ? "iOS"
      : /Windows/i.test(ua)
        ? "Windows"
        : /Macintosh|Mac OS X/i.test(ua)
          ? "macOS"
          : /Linux/i.test(ua)
            ? "Linux"
            : "Other";
  return `${browser}|${os}|${mobile ? "mobile" : "desktop"}`;
}

function primaryLanguage(acceptLanguage: string): string {
  const first = (acceptLanguage || "").split(",")[0]?.trim() ?? "";
  return first ? first.split("-")[0]!.toLowerCase() : "";
}

export function generateDeviceFingerprint(req: {
  headers: Record<string, string | string[] | undefined>;
}): string {
  const components = [
    normalizeUserAgent((req.headers["user-agent"] as string) || ""),
    primaryLanguage((req.headers["accept-language"] as string) || ""),
  ].join("|");

  return crypto.createHash("sha256").update(components).digest("hex").substring(0, 32);
}

export function getClientIp(req: {
  ip?: string;
  headers: Record<string, string | string[] | undefined>;
  socket?: { remoteAddress?: string };
}): string {
  if (typeof req.ip === "string" && req.ip.length > 0) {
    return req.ip.startsWith("::ffff:") ? req.ip.slice(7) : req.ip;
  }
  const forwarded = req.headers["x-forwarded-for"];
  if (typeof forwarded === "string") return forwarded.split(",")[0]!.trim();
  const ip = req.socket?.remoteAddress || "unknown";
  return ip.startsWith("::ffff:") ? ip.slice(7) : ip;
}

export function createSessionMetadata(req: {
  ip?: string;
  headers: Record<string, string | string[] | undefined>;
  socket?: { remoteAddress?: string };
}): SessionMetadata {
  return {
    deviceId: null,
    ipAddress: getClientIp(req),
    userAgent: (req.headers["user-agent"] as string) || "unknown",
    lastActivity: Date.now(),
  };
}

export function isPrivateIp(ip: string): boolean {
  if (!ip || ip === "unknown") return true;
  const normalized = ip.startsWith("::ffff:") ? ip.slice(7) : ip;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(normalized)) {
    const [a, b] = normalized.split(".").map(Number);
    return (
      a === 10 ||
      (a === 172 && b! >= 16 && b! <= 31) ||
      (a === 192 && b === 168) ||
      (a === 169 && b === 254)
    );
  }
  return (
    normalized === "::1" ||
    /^fe80:/i.test(normalized) ||
    /^fc/i.test(normalized) ||
    /^fd/i.test(normalized)
  );
}

export function validateSessionBinding(
  req: { headers: Record<string, string | string[] | undefined>; ip?: string; socket?: { remoteAddress?: string } },
  storedMetadata: SessionMetadata,
): { valid: boolean; reason?: string } {
  const currentDeviceId = generateDeviceFingerprint(req);
  const currentIp = getClientIp(req);

  if (currentDeviceId !== storedMetadata.deviceId) {
    return { valid: false, reason: "DEVICE_MISMATCH" };
  }
  if (currentIp !== storedMetadata.ipAddress) {
    if (isPrivateIp(currentIp) || isPrivateIp(storedMetadata.ipAddress)) {
      return { valid: true };
    }
    const timeSinceLastActivity = Date.now() - storedMetadata.lastActivity;
    const maxIpChangeInterval = 5 * 60 * 1000;
    if (timeSinceLastActivity < maxIpChangeInterval) {
      return { valid: false, reason: "SUSPICIOUS_IP_CHANGE" };
    }
  }
  return { valid: true };
}
