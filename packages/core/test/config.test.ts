import { describe, it, expect } from "vitest";
import { DEFAULTS, resolveConfig, AUDIT_SEVERITY } from "../src/config.js";
import type { AuthCoreConfig, AuditEventType } from "../src/types.js";
import { MockRedis } from "./helpers/mockRedis.js";

function rawConfig(overrides?: Partial<AuthCoreConfig>): AuthCoreConfig {
  return {
    redis: new MockRedis(),
    userStore: { findById: async () => null, findByEmail: async () => null, update: async () => {}, updateEmailVerified: async () => {} },
    hmacSecret: "secret",
    jwt: { privateKey: "pk", publicKey: "pb", ...overrides?.jwt },
    ...overrides,
  };
}

describe("DEFAULTS", () => {
  it("should have expected values", () => {
    expect(DEFAULTS.keyPrefix).toBe("focura:");
    expect(DEFAULTS.issuer).toBe("focura-app");
    expect(DEFAULTS.audience).toBe("focura-backend");
    expect(DEFAULTS.accessTokenExpiry).toBe("15m");
    expect(DEFAULTS.refreshTokenExpiry).toBe("7d");
    expect(DEFAULTS.sseTokenExpiry).toBe("30s");
    expect(DEFAULTS.currentVersion).toBe(1);
    expect(DEFAULTS.maxConcurrentSessions).toBe(5);
    expect(DEFAULTS.lockoutMaxFailures).toBe(10);
    expect(DEFAULTS.lockoutSeconds).toBe(900);
    expect(DEFAULTS.lockoutWindowSeconds).toBe(3600);
    expect(DEFAULTS.refreshLockTtlSeconds).toBe(45);
    expect(DEFAULTS.refreshDedupeTtlSeconds).toBe(30);
  });
});

describe("resolveConfig", () => {
  it("should use all defaults when optional config is omitted", () => {
    const r = resolveConfig(rawConfig());
    expect(r.keyPrefix).toBe("focura:");
    expect(r.issuer).toBe("focura-app");
    expect(r.audience).toBe("focura-backend");
    expect(r.accessTokenExpiry).toBe("15m");
    expect(r.maxConcurrentSessions).toBe(5);
    expect(r.lockoutMaxFailures).toBe(10);
  });
  it("should honour custom keyPrefix", () => {
    expect(resolveConfig(rawConfig({ keyPrefix: "x:" })).keyPrefix).toBe("x:");
  });
  it("should honour jwt overrides", () => {
    const r = resolveConfig(rawConfig({ jwt: { privateKey: "k", publicKey: "p", issuer: "i", audience: "a", accessTokenExpiry: "1h", refreshTokenExpiry: "30d", sseTokenExpiry: "1m", currentVersion: 2 } }));
    expect(r.issuer).toBe("i");
    expect(r.audience).toBe("a");
    expect(r.accessTokenExpiry).toBe("1h");
    expect(r.currentVersion).toBe(2);
  });
  it("should honour session overrides", () => {
    const r = resolveConfig(rawConfig({ session: { maxConcurrent: 20, inactivityTimeout: 100, absoluteTimeout: 200 } }));
    expect(r.maxConcurrentSessions).toBe(20);
    expect(r.inactivityTimeout).toBe(100);
    expect(r.absoluteTimeout).toBe(200);
  });
  it("should honour lockout overrides", () => {
    const r = resolveConfig(rawConfig({ lockout: { maxFailures: 3, lockoutSeconds: 60, windowSeconds: 120 } }));
    expect(r.lockoutMaxFailures).toBe(3);
    expect(r.lockoutSeconds).toBe(60);
    expect(r.lockoutWindowSeconds).toBe(120);
  });
  it("should preserve adapter references", () => {
    const redis = new MockRedis();
    const r = resolveConfig(rawConfig({ redis }));
    expect(r.redis).toBe(redis);
  });
});

describe("AUDIT_SEVERITY", () => {
  const allEvents: AuditEventType[] = [
    "LOGIN_SUCCESS", "LOGIN_FAILED", "LOGIN_BLOCKED", "LOGOUT", "LOGOUT_ALL_DEVICES",
    "TOKEN_REFRESHED", "TOKEN_REVOKED", "TOKEN_EXPIRED", "TOKEN_VERSION_MISMATCH",
    "TOKEN_REPLAY_DETECTED", "EXCHANGE_SUCCESS", "EXCHANGE_FAILED", "SSE_CONNECTED",
    "SSE_DISCONNECTED", "ACCOUNT_LOCKED", "TOTP_VERIFIED", "TOTP_FAILED",
    "PERMISSION_DENIED", "EMAIL_NOT_VERIFIED", "SESSION_HIJACK_DETECTED",
    "SESSION_BOUND", "SESSION_REBOUND", "SESSION_TIMEOUT", "MAX_SESSIONS_REACHED",
    "SESSION_REVOKED", "SESSIONS_REVOKED", "DEVICE_MISMATCH", "SUSPICIOUS_IP_CHANGE",
    "CSRF_VALIDATION_FAILED", "UNAUTHORIZED_ACCESS", "RATE_LIMIT_EXCEEDED",
    "MALWARE_DETECTED", "SUSPICIOUS_ACTIVITY", "DATA_EXPORT", "DATA_DELETION",
    "SENSITIVE_DATA_ACCESS", "WORKSPACE_CREATED", "WORKSPACE_DELETED", "MEMBER_ADDED",
    "MEMBER_REMOVED", "ROLE_CHANGED", "SUBSCRIPTION_CREATED", "SUBSCRIPTION_CANCELLED",
    "PAYMENT_FAILED",
  ];

  it("should map every event to a valid severity", () => {
    for (const e of allEvents) {
      expect(["info", "warn", "critical"]).toContain(AUDIT_SEVERITY[e]);
    }
  });
  it("should mark critical events", () => {
    for (const e of ["TOKEN_REPLAY_DETECTED", "ACCOUNT_LOCKED", "SESSION_HIJACK_DETECTED", "MALWARE_DETECTED", "DATA_DELETION", "WORKSPACE_DELETED"] as AuditEventType[]) {
      expect(AUDIT_SEVERITY[e]).toBe("critical");
    }
  });
  it("should mark info events", () => {
    for (const e of ["LOGIN_SUCCESS", "LOGOUT", "TOKEN_REFRESHED", "EXCHANGE_SUCCESS"] as AuditEventType[]) {
      expect(AUDIT_SEVERITY[e]).toBe("info");
    }
  });
  it("should mark warn events", () => {
    for (const e of ["LOGIN_FAILED", "LOGIN_BLOCKED", "EXCHANGE_FAILED", "PERMISSION_DENIED"] as AuditEventType[]) {
      expect(AUDIT_SEVERITY[e]).toBe("warn");
    }
  });
});
