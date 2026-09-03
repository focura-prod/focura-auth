import { describe, it, expect, vi, beforeEach } from "vitest";
import crypto from "crypto";
import { AuthService } from "../src/auth/authService.js";
import { MockRedis } from "./helpers/mockRedis.js";
import { makeAuthConfig, TEST_USER, mockUserStore, privateKey, publicKey } from "./helpers/setup.js";

function makeService(redisOverrides?: MockRedis) {
  const redis = redisOverrides ?? new MockRedis();
  const userStore = mockUserStore([TEST_USER]);
  return { service: new AuthService(makeAuthConfig({ redis, userStore })), redis, userStore };
}

function validExchangeProof(userId: string, email: string, role: string, sessionId: string, hmacSecret: string) {
  const timestamp = Date.now();
  const payload = `${userId}${email}${role}${sessionId}${timestamp}`;
  const signature = crypto.createHmac("sha256", hmacSecret).update(payload).digest("hex");
  return { userId, email, role, sessionId, timestamp, signature };
}

describe("AuthService", () => {
  describe("getConfig / getRedis", () => {
    it("should expose config and redis", () => {
      const { service, redis } = makeService();
      expect(service.getConfig()).toBeDefined();
      expect(service.getRedis()).toBe(redis);
    });
  });

  describe("exchange", () => {
    it("should reject expired proof", async () => {
      const { service } = makeService();
      const proof = validExchangeProof("user-1", "test@example.com", "USER", "s1", "test-hmac-secret-32chars-long!!");
      proof.timestamp = Date.now() - 120_000;
      await expect(service.exchange(proof)).rejects.toThrow("expired");
    });

    it("should reject invalid signature", async () => {
      const { service } = makeService();
      const proof = validExchangeProof("user-1", "test@example.com", "USER", "s1", "test-hmac-secret-32chars-long!!");
      proof.signature = "deadbeef";
      await expect(service.exchange(proof)).rejects.toThrow("Invalid exchange proof");
    });

    it("should reject user not found", async () => {
      const { service } = makeService();
      const proof = validExchangeProof("unknown-user", "test@example.com", "USER", "s1", "test-hmac-secret-32chars-long!!");
      await expect(service.exchange(proof)).rejects.toThrow("User not found");
    });

    it("should reject email mismatch", async () => {
      const userStore = mockUserStore([{ ...TEST_USER, email: "other@example.com" }]);
      const service = new AuthService(makeAuthConfig({ userStore }));
      const proof = validExchangeProof("user-1", "test@example.com", "USER", "s1", "test-hmac-secret-32chars-long!!");
      await expect(service.exchange(proof)).rejects.toThrow("Email mismatch");
    });

    it("should reject unverified email", async () => {
      const userStore = mockUserStore([{ ...TEST_USER, emailVerified: null }]);
      const service = new AuthService(makeAuthConfig({ userStore }));
      const proof = validExchangeProof("user-1", "test@example.com", "USER", "s1", "test-hmac-secret-32chars-long!!");
      await expect(service.exchange(proof)).rejects.toThrow("Email not verified");
    });

    it("should return tokens on valid exchange", async () => {
      const { service } = makeService();
      const proof = validExchangeProof("user-1", "test@example.com", "USER", "s1", "test-hmac-secret-32chars-long!!");
      const result = await service.exchange(proof);
      expect(result.accessToken).toBeDefined();
      expect(result.refreshToken).toBeDefined();
      expect(result.sseToken).toBeDefined();
      expect(result.sessionId).toBe("s1");
    });

    it("should use provided sessionId or generate one", async () => {
      const { service } = makeService();
      const proof = validExchangeProof("user-1", "test@example.com", "USER", "", "test-hmac-secret-32chars-long!!");
      const result = await service.exchange(proof);
      expect(result.sessionId).toBeDefined();
      expect(result.sessionId.length).toBeGreaterThan(0);
    });

    it("should return cached result on idempotency hit", async () => {
      const { service, redis } = makeService();
      const proof = validExchangeProof("user-1", "test@example.com", "USER", "s1", "test-hmac-secret-32chars-long!!");
      const cached = { accessToken: "cached", refreshToken: "cached", sseToken: "cached", sessionId: "s1", accessTokenExpiry: 0, refreshTokenExpiry: 0 };
      await redis.setex(`exchange:idempotent:user-1:s1:${proof.timestamp}`, 90, JSON.stringify(cached));
      const result = await service.exchange(proof);
      expect(result.accessToken).toBe("cached");
    });
  });

  describe("verifyToken", () => {
    it("should reject invalid token", async () => {
      const { service } = makeService();
      await expect(service.verifyToken({ token: "garbage" })).rejects.toThrow();
    });

    it("should reject expired token", async () => {
      const { service } = makeService();
      const jwt = await import("jsonwebtoken");
      const token = jwt.default.sign(
        { sub: "user-1", email: "test@example.com", role: "USER", type: "access", version: 1, jti: "jti1", sessionId: "s1" },
        privateKey, { algorithm: "RS256", expiresIn: "0s", issuer: "test-issuer", audience: "test-audience" }
      );
      await new Promise(r => setTimeout(r, 100));
      await expect(service.verifyToken({ token })).rejects.toThrow();
    });

    it("should reject version mismatch", async () => {
      const { service } = makeService();
      const jwt = await import("jsonwebtoken");
      const token = jwt.default.sign(
        { sub: "user-1", email: "test@example.com", role: "USER", type: "access", version: 99, jti: "jti1", sessionId: "s1" },
        privateKey, { algorithm: "RS256", expiresIn: "15m", issuer: "test-issuer", audience: "test-audience" }
      );
      await expect(service.verifyToken({ token })).rejects.toThrow();
    });

    it("should reject non-access token", async () => {
      const { service } = makeService();
      const jwt = await import("jsonwebtoken");
      const token = jwt.default.sign(
        { sub: "user-1", email: "test@example.com", role: "USER", type: "refresh", version: 1, jti: "jti1", sessionId: "s1" },
        privateKey, { algorithm: "RS256", expiresIn: "15m", issuer: "test-issuer", audience: "test-audience" }
      );
      await expect(service.verifyToken({ token })).rejects.toThrow();
    });

    it("should reject revoked token", async () => {
      const { service, redis } = makeService();
      const jwt = await import("jsonwebtoken");
      const jti = "revoked-jti";
      // The default keyPrefix is "focura:", so the key is "focura:revoked:access:..."
      await redis.setex(`focura:revoked:access:${jti}`, 60, "1");
      const token = jwt.default.sign(
        { sub: "user-1", email: "test@example.com", role: "USER", type: "access", version: 1, jti, sessionId: "s1" },
        privateKey, { algorithm: "RS256", expiresIn: "15m", issuer: "test-issuer", audience: "test-audience" }
      );
      await expect(service.verifyToken({ token })).rejects.toThrow("revoked");
    });

    it("should return user and payload on success", async () => {
      const { service } = makeService();
      const jwt = await import("jsonwebtoken");
      const token = jwt.default.sign(
        { sub: "user-1", email: "test@example.com", role: "USER", type: "access", version: 1, jti: "jti1", sessionId: "s1" },
        privateKey, { algorithm: "RS256", expiresIn: "15m", issuer: "test-issuer", audience: "test-audience" }
      );
      const result = await service.verifyToken({ token });
      expect(result.user.id).toBe("user-1");
      expect(result.payload.id).toBe("user-1");
      expect(result.payload.jti).toBe("jti1");
    });

    it("should reject when user not found", async () => {
      const userStore = mockUserStore([]);
      const service = new AuthService(makeAuthConfig({ userStore }));
      const jwt = await import("jsonwebtoken");
      const token = jwt.default.sign(
        { sub: "nonexistent", email: "x@y.com", role: "USER", type: "access", version: 1, jti: "j1", sessionId: "s1" },
        privateKey, { algorithm: "RS256", expiresIn: "15m", issuer: "test-issuer", audience: "test-audience" }
      );
      await expect(service.verifyToken({ token })).rejects.toThrow("User not found");
    });

    it("should reject banned user", async () => {
      const userStore = mockUserStore([{ ...TEST_USER, bannedAt: new Date() }]);
      const service = new AuthService(makeAuthConfig({ userStore }));
      const jwt = await import("jsonwebtoken");
      const token = jwt.default.sign(
        { sub: "user-1", email: "test@example.com", role: "USER", type: "access", version: 1, jti: "j1", sessionId: "s1" },
        privateKey, { algorithm: "RS256", expiresIn: "15m", issuer: "test-issuer", audience: "test-audience" }
      );
      await expect(service.verifyToken({ token })).rejects.toThrow("banned");
    });

    it("should reject unverified email", async () => {
      const userStore = mockUserStore([{ ...TEST_USER, emailVerified: null }]);
      const service = new AuthService(makeAuthConfig({ userStore }));
      const jwt = await import("jsonwebtoken");
      const token = jwt.default.sign(
        { sub: "user-1", email: "test@example.com", role: "USER", type: "access", version: 1, jti: "j1", sessionId: "s1" },
        privateKey, { algorithm: "RS256", expiresIn: "15m", issuer: "test-issuer", audience: "test-audience" }
      );
      await expect(service.verifyToken({ token })).rejects.toThrow("Email not verified");
    });

    it("should skip binding when sessionId is missing", async () => {
      const { service } = makeService();
      const jwt = await import("jsonwebtoken");
      const token = jwt.default.sign(
        { sub: "user-1", email: "test@example.com", role: "USER", type: "access", version: 1, jti: "j1" },
        privateKey, { algorithm: "RS256", expiresIn: "15m", issuer: "test-issuer", audience: "test-audience" }
      );
      const result = await service.verifyToken({ token, ipAddress: "1.2.3.4", userAgent: "Chrome" });
      expect(result.user.id).toBe("user-1");
    });

    it("should bind device fingerprint on first visit", async () => {
      const { service, redis } = makeService();
      const jwt = await import("jsonwebtoken");
      const token = jwt.default.sign(
        { sub: "user-1", email: "test@example.com", role: "USER", type: "access", version: 1, jti: "j1", sessionId: "s1" },
        privateKey, { algorithm: "RS256", expiresIn: "15m", issuer: "test-issuer", audience: "test-audience" }
      );
      await redis.setex("focura:session:metadata:s1", 3600, JSON.stringify({
        deviceId: null, ipAddress: "1.2.3.4", userAgent: "Chrome", lastActivity: Date.now(),
      }));
      const result = await service.verifyToken({ token, ipAddress: "1.2.3.4", userAgent: "Chrome" });
      expect(result.user.id).toBe("user-1");
      const meta = JSON.parse((await redis.get("focura:session:metadata:s1"))!);
      expect(meta.deviceId).toMatch(/^[a-f0-9]{32}$/);
    });

    it("should recover from corrupt metadata during binding", async () => {
      const { service, redis } = makeService();
      const jwt = await import("jsonwebtoken");
      const token = jwt.default.sign(
        { sub: "user-1", email: "test@example.com", role: "USER", type: "access", version: 1, jti: "j1", sessionId: "s1" },
        privateKey, { algorithm: "RS256", expiresIn: "15m", issuer: "test-issuer", audience: "test-audience" }
      );
      await redis.setex("focura:session:metadata:s1", 3600, "not-json");
      const result = await service.verifyToken({ token, ipAddress: "1.2.3.4", userAgent: "Chrome" });
      expect(result.user.id).toBe("user-1");
    });

    it("should accept matching device binding", async () => {
      const { service, redis } = makeService();
      const jwt = await import("jsonwebtoken");
      const token = jwt.default.sign(
        { sub: "user-1", email: "test@example.com", role: "USER", type: "access", version: 1, jti: "j1", sessionId: "s1" },
        privateKey, { algorithm: "RS256", expiresIn: "15m", issuer: "test-issuer", audience: "test-audience" }
      );
      const fp = crypto.createHash("sha256").update("Other|Other|desktop|").digest("hex").substring(0, 32);
      await redis.setex("focura:session:metadata:s1", 3600, JSON.stringify({
        deviceId: fp, ipAddress: "1.2.3.4", userAgent: "Chrome", lastActivity: Date.now() - 10_000,
      }));
      const result = await service.verifyToken({ token, ipAddress: "1.2.3.4", userAgent: "Chrome" });
      expect(result.user.id).toBe("user-1");
    });

    it("should detect session hijack on device mismatch", async () => {
      const { service, redis } = makeService();
      const jwt = await import("jsonwebtoken");
      const token = jwt.default.sign(
        { sub: "user-1", email: "test@example.com", role: "USER", type: "access", version: 1, jti: "j1", sessionId: "s1" },
        privateKey, { algorithm: "RS256", expiresIn: "15m", issuer: "test-issuer", audience: "test-audience" }
      );
      await redis.setex("focura:session:metadata:s1", 3600, JSON.stringify({
        deviceId: "old-device", ipAddress: "8.8.8.8", userAgent: "OldBrowser", lastActivity: Date.now(),
      }));
      await expect(service.verifyToken({ token, ipAddress: "9.9.9.9", userAgent: "NewBrowser/120" })).rejects.toThrow();
    });
  });

  describe("refresh", () => {
    it("should reject invalid refresh token", async () => {
      const { service } = makeService();
      await expect(service.refresh({ refreshToken: "garbage" })).rejects.toThrow();
    });

    it("should rotate tokens on valid refresh", async () => {
      const { service } = makeService();
      const jwt = await import("jsonwebtoken");
      // First do an exchange to get a valid session
      const proof = validExchangeProof("user-1", "test@example.com", "USER", "s1", "test-hmac-secret-32chars-long!!");
      const exchangeResult = await service.exchange(proof);
      const refreshJti = crypto.randomUUID();
      const refreshToken = jwt.default.sign(
        { sub: "user-1", email: "test@example.com", role: "USER", type: "refresh", version: 1, jti: refreshJti, sessionId: "s1" },
        privateKey, { algorithm: "RS256", expiresIn: "7d", issuer: "test-issuer", audience: "test-audience" }
      );
      // Store the refresh token
      const { TokenManager } = await import("../src/tokens/backendToken.js");
      const parsedRefresh = TokenManager.parseExpiry("7d") / 1000;
      await service.tokenRevocation.storeRefreshToken("user-1", refreshJti, parsedRefresh);
      const result = await service.refresh({ refreshToken });
      expect(result.accessToken).toBeDefined();
      expect(result.refreshToken).toBeDefined();
      expect(result.sseToken).toBeDefined();
    });

    it("should reject refresh for revoked session", async () => {
      const { service, redis } = makeService();
      const jwt = await import("jsonwebtoken");
      // Default prefix is "focura:
      await redis.setex("focura:session:revoked:s1", 3600, "1");
      // Also need session:created key so the session isn't expired
      await redis.setex("focura:session:created:s1", 3600, Date.now().toString());
      const token = jwt.default.sign(
        { sub: "user-1", email: "test@example.com", role: "USER", type: "refresh", version: 1, jti: "j1", sessionId: "s1" },
        privateKey, { algorithm: "RS256", expiresIn: "7d", issuer: "test-issuer", audience: "test-audience" }
      );
      await expect(service.refresh({ refreshToken: token })).rejects.toThrow("Session revoked");
    });

    it("should reject refresh for expired session", async () => {
      const { service } = makeService();
      const jwt = await import("jsonwebtoken");
      const token = jwt.default.sign(
        { sub: "user-1", email: "test@example.com", role: "USER", type: "refresh", version: 1, jti: "j1", sessionId: "nonexistent" },
        privateKey, { algorithm: "RS256", expiresIn: "7d", issuer: "test-issuer", audience: "test-audience" }
      );
      await expect(service.refresh({ refreshToken: token })).rejects.toThrow("Session expired");
    });

    it("should return cached result on refresh dedupe hit", async () => {
      const { service, redis } = makeService();
      const jwt = await import("jsonwebtoken");
      const jti = "dedupe-jti";
      const token = jwt.default.sign(
        { sub: "user-1", email: "test@example.com", role: "USER", type: "refresh", version: 1, jti, sessionId: "s1" },
        privateKey, { algorithm: "RS256", expiresIn: "7d", issuer: "test-issuer", audience: "test-audience" }
      );
      const cached = { accessToken: "cached-at", refreshToken: "cached-rt", sseToken: "cached-sse", accessTokenExpiry: 0, refreshTokenExpiry: 0 };
      await redis.setex(`focura:refresh:dedupe:user-1:${jti}`, 30, JSON.stringify(cached));
      const result = await service.refresh({ refreshToken: token });
      expect(result.accessToken).toBe("cached-at");
    });

    it("should reject refresh already in progress (lock held)", async () => {
      const { service, redis } = makeService();
      const jwt = await import("jsonwebtoken");
      const token = jwt.default.sign(
        { sub: "user-1", email: "test@example.com", role: "USER", type: "refresh", version: 1, jti: "j-locked", sessionId: "s1" },
        privateKey, { algorithm: "RS256", expiresIn: "7d", issuer: "test-issuer", audience: "test-audience" }
      );
      await redis.set("focura:refresh:lock:s1", "1", "EX", 45, "NX");
      await expect(service.refresh({ refreshToken: token })).rejects.toThrow("Refresh already in progress");
    });
  });

  describe("sessions", () => {
    it("should list active sessions for a user", async () => {
      const { service, redis } = makeService();
      const proof = validExchangeProof("user-1", "test@example.com", "USER", "s1", "test-hmac-secret-32chars-long!!");
      await service.exchange(proof);
      // Sessions only appear once metadata exists
      await redis.setex("focura:session:metadata:s1", 3600, JSON.stringify({
        deviceId: "dev", ipAddress: "1.2.3.4", userAgent: "Chrome", lastActivity: Date.now(),
      }));
      const sessions = await service.getActiveSessions("user-1");
      expect(Array.isArray(sessions)).toBe(true);
      expect(sessions.some((s: { sessionId: string }) => s.sessionId === "s1")).toBe(true);
    });

    it("should revoke a session", async () => {
      const { service, redis } = makeService();
      const proof = validExchangeProof("user-1", "test@example.com", "USER", "s1", "test-hmac-secret-32chars-long!!");
      await service.exchange(proof);
      await service.revokeSession("user-1", "s1");
      expect(await redis.get("focura:session:revoked:s1")).toBe("1");
      const sessions = await service.getActiveSessions("user-1");
      expect(sessions.some((s: { sessionId: string }) => s.sessionId === "s1")).toBe(false);
    });
  });

  describe("logout", () => {
    it("should revoke access token jti", async () => {
      const { service, redis } = makeService();
      await service.logout({ accessTokenJti: "jti-1", accessToken: "token", userId: "u1", sessionId: "s1" });
      // Default prefix is "focura:
      expect(await redis.get("focura:revoked:access:jti-1")).toBe("1");
    });

    it("should revoke all on logoutAll", async () => {
      const { service } = makeService();
      await service.logout({ logoutAll: true, userId: "u1", sessionId: "s1" });
      // Should not throw
    });

    it("should revoke single session", async () => {
      const { service } = makeService();
      await service.logout({ userId: "u1", sessionId: "s1" });
    });
  });

  describe("2FA", () => {
    it("should generate 2FA setup", () => {
      const { service } = makeService();
      const result = service.generateTwoFactor();
      expect(result.secret).toBeDefined();
      expect(result.uri).toContain("otpauth://totp");
    });

    it("should create 2FA URI", () => {
      const { service } = makeService();
      const result = service.generateTwoFactor();
      const uri = service.createTwoFactorUri(result.secret, "user@example.com");
      expect(uri).toContain("otpauth://totp");
    });

    it("should verify a valid 2FA token", async () => {
      const { service } = makeService();
      const setup = service.generateTwoFactor();
      const { generate } = await import("otplib");
      const token = await generate({ secret: setup.secret });
      const result = await service.verifyTwoFactor({ token, secret: setup.secret });
      expect(result).toBe(true);
    });

    it("should return false for an invalid 2FA token", async () => {
      const { service } = makeService();
      const setup = service.generateTwoFactor();
      const result = await service.verifyTwoFactor({ token: "000000", secret: setup.secret });
      expect(result).toBe(false);
    });

    it("should return false for an invalid secret", async () => {
      const { service } = makeService();
      const result = await service.verifyTwoFactor({ token: "123456", secret: "INVALID_SECRET" });
      expect(result).toBe(false);
    });
  });

  describe("lockout helpers", () => {
    it("should record and check login failures", async () => {
      // AccountLockout uses DEFAULTS.keyPrefix ("focura:") + "lockout" as prefix
      // and maxFailures defaults to 10 from DEFAULTS
      const { service } = makeService();
      const config = service.getConfig();
      // Use the config's lockout settings
      const maxFailures = config.lockoutMaxFailures;
      for (let i = 0; i < maxFailures; i++) {
        await service.recordLoginFailure("a@b.com");
      }
      const locked = await service.isAccountLocked("a@b.com");
      expect(locked.locked).toBe(true);
    });

    it("should clear login failures", async () => {
      const { service } = makeService();
      await service.recordLoginFailure("a@b.com");
      await service.clearLoginFailures("a@b.com");
      const locked = await service.isAccountLocked("a@b.com");
      expect(locked.locked).toBe(false);
    });
  });

  describe("log", () => {
    it("should delegate to audit", () => {
      const { service } = makeService();
      expect(() => service.log("LOGIN_SUCCESS", { userId: "u1" })).not.toThrow();
    });
  });
});
