import { describe, it, expect, vi, beforeEach } from "vitest";
import crypto from "crypto";
import { MiddlewareFactory } from "../src/middleware/middlewareFactory.js";
import { MockRedis } from "./helpers/mockRedis.js";
import { makeAuthConfig, TEST_USER, mockUserStore, mockAuditLogger } from "./helpers/setup.js";
import jwt from "jsonwebtoken";
import { privateKey, publicKey } from "./helpers/setup.js";

function makeFactory(redisOverrides?: MockRedis) {
  const redis = redisOverrides ?? new MockRedis();
  const userStore = mockUserStore([TEST_USER]);
  return { factory: new MiddlewareFactory(makeAuthConfig({ redis, userStore })), redis, userStore };
}

function makeToken(overrides?: Record<string, unknown>) {
  return jwt.sign(
    { sub: "user-1", email: "test@example.com", role: "USER", type: "access", version: 1, jti: crypto.randomUUID(), sessionId: "s1", ...overrides },
    privateKey,
    { algorithm: "RS256", expiresIn: "15m", issuer: "test-issuer", audience: "test-audience" }
  );
}

function makeRefreshToken(overrides?: Record<string, unknown>) {
  return jwt.sign(
    { sub: "user-1", email: "test@example.com", role: "USER", type: "refresh", version: 1, jti: crypto.randomUUID(), sessionId: "s1", ...overrides },
    privateKey,
    { algorithm: "RS256", expiresIn: "7d", issuer: "test-issuer", audience: "test-audience" }
  );
}

function mockReq(authHeader?: string, extras?: Record<string, unknown>) {
  const headers: Record<string, string | string[]> = authHeader ? { authorization: authHeader } : {};
  // Extract headers from extras (e.g. "user-agent", "accept-language")
  const { headers: extraHeaders, ...rest } = extras ?? {};
  if (extraHeaders && typeof extraHeaders === "object") {
    Object.assign(headers, extraHeaders);
  }
  return { headers, ...rest } as any;
}

function mockCache() {
  const store = new Map<string, unknown>();
  return {
    store,
    get: async <T>(key: string) => (store.get(key) as T | undefined) ?? null,
    set: async (key: string, value: unknown) => { store.set(key, value); },
    delete: async (key: string) => { store.delete(key); },
  } as any;
}

// The middleware reads `decoded.sub` from the verified payload, so tests that
// need a resolved user provide a tokenManager returning a sub-shaped payload.
function mockTokenManager(overrides?: Record<string, unknown>) {
  return {
    verifyToken: () => ({
      sub: "user-1",
      email: "test@example.com",
      role: "USER",
      jti: crypto.randomUUID(),
      version: 1,
      type: "access",
      sessionId: "s1",
      ...overrides,
    }),
  } as any;
}

function mockRes() {
  const res: any = {};
  res.status = vi.fn(() => res);
  res.json = vi.fn(() => res);
  res.end = vi.fn();
  return res;
}

describe("MiddlewareFactory", () => {
  describe("getters", () => {
    it("should expose all managers", () => {
      const { factory, redis } = makeFactory();
      expect(factory.getTokenManager()).toBeDefined();
      expect(factory.getTokenRevocation()).toBeDefined();
      expect(factory.getAuditLog()).toBeDefined();
      expect(factory.getRedis()).toBe(redis);
      expect(factory.getConfig()).toBeDefined();
    });
  });

  describe("createAuthenticateMiddleware", () => {
    it("should reject missing Authorization header", async () => {
      const { factory } = makeFactory();
      const mw = factory.createAuthenticateMiddleware();
      const next = vi.fn();
      await mw(mockReq(), mockRes(), next);
      expect(next).toHaveBeenCalledWith(expect.objectContaining({ code: "NO_TOKEN" }));
    });

    it("should reject empty token", async () => {
      const { factory } = makeFactory();
      const mw = factory.createAuthenticateMiddleware();
      const next = vi.fn();
      await mw(mockReq("Bearer "), mockRes(), next);
      expect(next).toHaveBeenCalledWith(expect.objectContaining({ code: "NO_TOKEN" }));
    });

    it("should reject invalid token", async () => {
      const { factory } = makeFactory();
      const mw = factory.createAuthenticateMiddleware();
      const next = vi.fn();
      await mw(mockReq("Bearer garbage"), mockRes(), next);
      expect(next).toHaveBeenCalledWith(expect.objectContaining({ code: "INVALID_TOKEN" }));
    });

    it("should accept valid access token", async () => {
      const { factory } = makeFactory();
      const mw = factory.createAuthenticateMiddleware();
      const next = vi.fn();
      const res = mockRes();
      await mw(mockReq(`Bearer ${makeToken()}`), res, next);
      expect(next).toHaveBeenCalled();
    });

    it("should reject token with wrong version", async () => {
      const { factory } = makeFactory();
      const mw = factory.createAuthenticateMiddleware();
      const next = vi.fn();
      await mw(mockReq(`Bearer ${makeToken({ version: 99 })}`), mockRes(), next);
      expect(next).toHaveBeenCalledWith(expect.objectContaining({ code: "INVALID_TOKEN" }));
    });

    it("should reject non-access token type", async () => {
      const { factory } = makeFactory();
      const mw = factory.createAuthenticateMiddleware();
      const next = vi.fn();
      await mw(mockReq(`Bearer ${makeToken({ type: "refresh" })}`), mockRes(), next);
      expect(next).toHaveBeenCalledWith(expect.objectContaining({ code: "INVALID_TOKEN_TYPE" }));
    });

    it("should reject revoked access token", async () => {
      const jti = crypto.randomUUID();
      const { factory, redis } = makeFactory();
      await redis.setex(`focura:revoked:access:${jti}`, 60, "1");
      const mw = factory.createAuthenticateMiddleware();
      const next = vi.fn();
      await mw(mockReq(`Bearer ${makeToken({ jti })}`), mockRes(), next);
      expect(next).toHaveBeenCalledWith(expect.objectContaining({ code: "TOKEN_REVOKED" }));
    });

    it("should reject banned user", async () => {
      const bannedStore = mockUserStore([{ ...TEST_USER, bannedAt: new Date() }]);
      const redis = new MockRedis();
      const factory = new MiddlewareFactory(makeAuthConfig({ redis, userStore: bannedStore }));
      (factory as any).loadUser = async () => ({ ...TEST_USER, bannedAt: new Date() });
      const mw = factory.createAuthenticateMiddleware();
      const next = vi.fn();
      await mw(mockReq(`Bearer ${makeToken()}`), mockRes(), next);
      expect(next).toHaveBeenCalledWith(expect.objectContaining({ code: "ACCOUNT_BANNED" }));
    });

    it("should reject unverified email", async () => {
      const unverifiedStore = mockUserStore([{ ...TEST_USER, emailVerified: null }]);
      const redis = new MockRedis();
      const factory = new MiddlewareFactory(makeAuthConfig({ redis, userStore: unverifiedStore }));
      (factory as any).loadUser = async () => ({ ...TEST_USER, emailVerified: null });
      const mw = factory.createAuthenticateMiddleware();
      const next = vi.fn();
      await mw(mockReq(`Bearer ${makeToken()}`), mockRes(), next);
      expect(next).toHaveBeenCalledWith(expect.objectContaining({ code: "EMAIL_NOT_VERIFIED" }));
    });

    it("should handle enforceSessionBinding with stored metadata (first visit)", async () => {
      const { factory, redis } = makeFactory();
      await redis.setex("focura:session:metadata:s1", 3600, JSON.stringify({
        deviceId: null, ipAddress: "1.2.3.4", userAgent: "Chrome", lastActivity: Date.now(),
      }));
      (factory as any).loadUser = async () => TEST_USER;
      const mw = factory.createAuthenticateMiddleware();
      const next = vi.fn();
      await mw(mockReq(`Bearer ${makeToken()}`, { headers: { "user-agent": "Chrome", "accept-language": "en" } }), mockRes(), next);
      expect(next).toHaveBeenCalled();
    });

    it("should handle enforceSessionBinding with matching device", async () => {
      const { factory, redis } = makeFactory();
      const fp = crypto.createHash("sha256").update("Chrome|Other|desktop|").digest("hex").substring(0, 32);
      await redis.setex("focura:session:metadata:s1", 3600, JSON.stringify({
        deviceId: fp, ipAddress: "1.2.3.4", userAgent: "Chrome", lastActivity: Date.now(),
      }));
      (factory as any).loadUser = async () => TEST_USER;
      const mw = factory.createAuthenticateMiddleware();
      const next = vi.fn();
      await mw(mockReq(`Bearer ${makeToken()}`, { headers: { "user-agent": "Chrome" } }), mockRes(), next);
      expect(next).toHaveBeenCalled();
    });

    it("should handle corrupt session metadata", async () => {
      const { factory, redis } = makeFactory();
      await redis.setex("focura:session:metadata:s1", 3600, "not-json");
      const mw = factory.createAuthenticateMiddleware();
      const next = vi.fn();
      await mw(mockReq(`Bearer ${makeToken()}`), mockRes(), next);
      expect(next).toHaveBeenCalled();
    });

    it("should handle server-to-server request (skip binding)", async () => {
      const { factory, redis } = makeFactory();
      await redis.setex("focura:session:metadata:s1", 3600, JSON.stringify({
        deviceId: "abc", ipAddress: "1.2.3.4", userAgent: "node", lastActivity: Date.now(),
      }));
      (factory as any).loadUser = async () => TEST_USER;
      const mw = factory.createAuthenticateMiddleware();
      const next = vi.fn();
      await mw(mockReq(`Bearer ${makeToken()}`, { headers: { "user-agent": "node" } }), mockRes(), next);
      expect(next).toHaveBeenCalled();
    });

    it("should handle session hijack detection (device mismatch)", async () => {
      const { factory, redis } = makeFactory();
      await redis.setex("focura:session:metadata:s1", 3600, JSON.stringify({
        deviceId: "old-device", ipAddress: "1.2.3.4", userAgent: "OldBrowser", lastActivity: Date.now(),
      }));
      // Override loadUser so the hijack check is reached (decoded.sub is undefined from verifyToken)
      (factory as any).loadUser = async () => TEST_USER;
      const mw = factory.createAuthenticateMiddleware();
      const next = vi.fn();
      // Public IP + different device → not a same-IP rebound → hijack detected
      await mw(mockReq(`Bearer ${makeToken()}`, { headers: { "user-agent": "NewBrowser/120", "accept-language": "en" }, ip: "8.8.8.8" }), mockRes(), next);
      expect(next).toHaveBeenCalledWith(expect.objectContaining({ code: "SESSION_HIJACK_DETECTED" }));
    });

    it("should handle session rebound on same-IP device change", async () => {
      const { factory, redis } = makeFactory();
      await redis.setex("focura:session:metadata:s1", 3600, JSON.stringify({
        deviceId: "old-device", ipAddress: "127.0.0.1", userAgent: "OldBrowser", lastActivity: Date.now(),
      }));
      (factory as any).loadUser = async () => TEST_USER;
      const mw = factory.createAuthenticateMiddleware();
      const next = vi.fn();
      await mw(mockReq(`Bearer ${makeToken()}`, { headers: { "user-agent": "NewBrowser/120" }, ip: "127.0.0.1" }), mockRes(), next);
      // Same private IP → rebound, should succeed
      expect(next).toHaveBeenCalled();
    });

    it("should handle unexpected errors gracefully", async () => {
      const { factory } = makeFactory();
      const mw = factory.createAuthenticateMiddleware();
      const brokenReq = { headers: { authorization: "Bearer " + makeToken() } };
      // Make tokenManager.verifyToken throw in an unexpected way
      (factory as any).tokenManager = { verifyToken: () => { throw new Error("unexpected"); } };
      const next = vi.fn();
      await mw(brokenReq, mockRes(), next);
      expect(next).toHaveBeenCalledWith(expect.any(Error));
    });

    it("should treat userStore lookup failure as user not found", async () => {
      const redis = new MockRedis();
      const userStore = { findById: async () => { throw new Error("db down"); } } as any;
      const factory = new MiddlewareFactory(makeAuthConfig({ redis, userStore }));
      const mw = factory.createAuthenticateMiddleware();
      const next = vi.fn();
      await mw(mockReq(`Bearer ${makeToken()}`), mockRes(), next);
      expect(next).toHaveBeenCalledWith(expect.objectContaining({ code: "USER_NOT_FOUND" }));
    });

    it("should use cached auth result when valid", async () => {
      const cache = mockCache();
      const factory = new MiddlewareFactory(makeAuthConfig({ cache }));
      (factory as any).loadUser = async () => TEST_USER;
      const jti = crypto.randomUUID();
      cache.store.set(`auth:result:${jti}`, { userId: "user-1", valid: true });
      const mw = factory.createAuthenticateMiddleware();
      const next = vi.fn();
      await mw(mockReq(`Bearer ${makeToken({ jti })}`), mockRes(), next);
      expect(next).toHaveBeenCalled();
    });

    it("should reject cached invalid auth result", async () => {
      const cache = mockCache();
      const factory = new MiddlewareFactory(makeAuthConfig({ cache }));
      const jti = crypto.randomUUID();
      cache.store.set(`auth:result:${jti}`, { userId: "user-1", valid: false });
      const mw = factory.createAuthenticateMiddleware();
      const next = vi.fn();
      await mw(mockReq(`Bearer ${makeToken({ jti })}`), mockRes(), next);
      expect(next).toHaveBeenCalledWith(expect.objectContaining({ code: "INVALID_TOKEN_CACHED" }));
    });

    it("should use cached user and write auth:result cache entries", async () => {
      const cache = mockCache();
      const redis = new MockRedis();
      const userStore = mockUserStore([TEST_USER]);
      const findByIdSpy = vi.spyOn(userStore, "findById");
      const factory = new MiddlewareFactory(makeAuthConfig({ redis, userStore, cache }));
      const jti = crypto.randomUUID();
      (factory as any).tokenManager = mockTokenManager({ jti });
      cache.store.set(`auth:user:user-1`, TEST_USER);
      const mw = factory.createAuthenticateMiddleware();
      const next = vi.fn();
      await mw(mockReq(`Bearer ${makeToken()}`), mockRes(), next);
      expect(next).toHaveBeenCalled();
      expect(findByIdSpy).not.toHaveBeenCalled();
      expect(cache.store.has(`auth:result:${jti}`)).toBe(true);
    });

    it("should write auth:user cache entry on first lookup", async () => {
      const cache = mockCache();
      const factory = new MiddlewareFactory(makeAuthConfig({ cache }));
      (factory as any).tokenManager = mockTokenManager();
      const mw = factory.createAuthenticateMiddleware();
      const next = vi.fn();
      await mw(mockReq(`Bearer ${makeToken()}`), mockRes(), next);
      expect(next).toHaveBeenCalled();
      expect(cache.store.has(`auth:user:user-1`)).toBe(true);
    });

    it("should emit observability events on success", async () => {
      const observability = {
        setUserContext: vi.fn(),
        addBreadcrumb: vi.fn(),
        captureException: vi.fn(),
      };
      const factory = new MiddlewareFactory(makeAuthConfig({ observability }));
      (factory as any).tokenManager = mockTokenManager();
      const mw = factory.createAuthenticateMiddleware();
      const next = vi.fn();
      await mw(mockReq(`Bearer ${makeToken()}`), mockRes(), next);
      expect(next).toHaveBeenCalled();
      expect(observability.setUserContext).toHaveBeenCalledWith({ id: "user-1", email: "test@example.com" });
      expect(observability.addBreadcrumb).toHaveBeenCalled();
    });

    it("should emit captureException on unexpected errors", async () => {
      const observability = { captureException: vi.fn() };
      const cache = mockCache();
      const factory = new MiddlewareFactory(makeAuthConfig({ observability, cache }));
      (factory as any).tokenManager = mockTokenManager();
      // Fail after token verification so the outer catch runs
      cache.get = async () => { throw new Error("cache down"); };
      const mw = factory.createAuthenticateMiddleware();
      await mw(mockReq(`Bearer ${makeToken()}`), mockRes(), vi.fn());
      expect(observability.captureException).toHaveBeenCalled();
    });
  });

  describe("createAuthorizeMiddleware", () => {
    it("should reject when no user on request", () => {
      const { factory } = makeFactory();
      const mw = factory.createAuthorizeMiddleware("ADMIN");
      const next = vi.fn();
      mw({ headers: {} } as any, mockRes(), next);
      expect(next).toHaveBeenCalledWith(expect.objectContaining({ code: "NOT_AUTHENTICATED" }));
    });
    it("should reject when role not in allowed list", () => {
      const { factory } = makeFactory();
      const mw = factory.createAuthorizeMiddleware("ADMIN");
      const next = vi.fn();
      mw({ headers: {}, user: { role: "USER" } } as any, mockRes(), next);
      expect(next).toHaveBeenCalledWith(expect.objectContaining({ message: "Insufficient permissions" }));
    });
    it("should pass when role is allowed", () => {
      const { factory } = makeFactory();
      const mw = factory.createAuthorizeMiddleware("USER", "ADMIN");
      const next = vi.fn();
      mw({ headers: {}, user: { role: "USER" } } as any, mockRes(), next);
      expect(next).toHaveBeenCalledWith();
    });
  });

  describe("createCsrfMiddleware", () => {
    it("should generate and validate CSRF tokens", async () => {
      const { factory } = makeFactory();
      const csrf = factory.createCsrfMiddleware();
      const token = await csrf.generateToken("u1", "s1");
      expect(typeof token).toBe("string");
      expect(await csrf.validateToken("u1", "s1", token)).toBe(true);
      expect(await csrf.validateToken("u1", "s1", "bad")).toBe(false);
      expect(await csrf.validateToken("u1", "s1", "")).toBe(false);
    });
    it("should return false for missing stored token", async () => {
      const { factory } = makeFactory();
      const csrf = factory.createCsrfMiddleware();
      expect(await csrf.validateToken("u1", "s1", "sometoken")).toBe(false);
    });
    it("should skip GET/HEAD/OPTIONS in middleware", async () => {
      const { factory } = makeFactory();
      const csrf = factory.createCsrfMiddleware();
      const mw = csrf.middleware();
      const next = vi.fn();
      await mw({ method: "GET", headers: {} } as any, mockRes(), next);
      expect(next).toHaveBeenCalledWith();
      await mw({ method: "HEAD", headers: {} } as any, mockRes(), next);
      expect(next).toHaveBeenCalledTimes(2);
      await mw({ method: "OPTIONS", headers: {} } as any, mockRes(), next);
      expect(next).toHaveBeenCalledTimes(3);
    });
    it("should skip webhook paths", async () => {
      const { factory } = makeFactory();
      const csrf = factory.createCsrfMiddleware();
      const mw = csrf.middleware();
      const next = vi.fn();
      await mw({ method: "POST", path: "/webhooks/stripe", headers: {} } as any, mockRes(), next);
      expect(next).toHaveBeenCalledWith();
      await mw({ method: "POST", path: "/api/callback", headers: {} } as any, mockRes(), next);
      expect(next).toHaveBeenCalledTimes(2);
    });
    it("should return 401 for unauthenticated POST", async () => {
      const { factory } = makeFactory();
      const csrf = factory.createCsrfMiddleware();
      const mw = csrf.middleware();
      const res = mockRes();
      await mw({ method: "POST", path: "/api/data", headers: {}, user: undefined } as any, res, vi.fn());
      expect(res.status).toHaveBeenCalledWith(401);
    });
    it("should return 403 for missing CSRF token", async () => {
      const { factory } = makeFactory();
      const csrf = factory.createCsrfMiddleware();
      const mw = csrf.middleware();
      const res = mockRes();
      await mw({ method: "POST", path: "/api/data", headers: {}, user: { id: "u1", sessionId: "s1" } } as any, res, vi.fn());
      expect(res.status).toHaveBeenCalledWith(403);
    });
    it("should return 403 for invalid CSRF token", async () => {
      const { factory, redis } = makeFactory();
      const csrf = factory.createCsrfMiddleware();
      await csrf.generateToken("u1", "s1");
      const mw = csrf.middleware();
      const res = mockRes();
      await mw({ method: "POST", path: "/api/data", headers: { "x-csrf-token": "badtoken" }, user: { id: "u1", sessionId: "s1" } } as any, res, vi.fn());
      expect(res.status).toHaveBeenCalledWith(403);
    });
    it("should pass with a valid CSRF token", async () => {
      const { factory } = makeFactory();
      const csrf = factory.createCsrfMiddleware();
      const token = await csrf.generateToken("u1", "s1");
      const mw = csrf.middleware();
      const next = vi.fn();
      await mw({ method: "POST", path: "/api/data", headers: { "x-csrf-token": token }, user: { id: "u1", sessionId: "s1" } } as any, mockRes(), next);
      expect(next).toHaveBeenCalled();
    });
  });

  describe("createRateLimitMiddleware", () => {
    it("should allow requests within limit", async () => {
      const { factory } = makeFactory();
      const rl = factory.createRateLimitMiddleware()(2, 60);
      const next = vi.fn();
      await rl(mockReq(), mockRes(), next);
      expect(next).toHaveBeenCalled();
    });
    it("should block requests over limit", async () => {
      const { factory } = makeFactory();
      const rl = factory.createRateLimitMiddleware()(1, 60);
      const next = vi.fn();
      const res = mockRes();
      await rl(mockReq(), res, next);
      await rl(mockReq(), res, vi.fn());
      expect(res.status).toHaveBeenCalledWith(429);
    });
    it("should fail open when configured", async () => {
      const brokenRedis = { incr: async () => { throw new Error("fail"); } } as any;
      const factory = new MiddlewareFactory(makeAuthConfig({ redis: brokenRedis as any }));
      const rl = factory.createRateLimitMiddleware()(1, 60, undefined, { failOpen: true });
      const next = vi.fn();
      await rl(mockReq(), mockRes(), next);
      expect(next).toHaveBeenCalled();
    });
    it("should fail closed by default", async () => {
      const brokenRedis = { incr: async () => { throw new Error("fail"); } } as any;
      const factory = new MiddlewareFactory(makeAuthConfig({ redis: brokenRedis as any }));
      const rl = factory.createRateLimitMiddleware()(1, 60);
      const res = mockRes();
      await rl(mockReq(), res, vi.fn());
      expect(res.status).toHaveBeenCalledWith(429);
    });
    it("should use custom key function", async () => {
      const { factory } = makeFactory();
      const keyFn = (req: any) => req.user?.id;
      const rl = factory.createRateLimitMiddleware()(5, 60, keyFn);
      const next = vi.fn();
      await rl(mockReq(undefined, { user: { id: "u1" } } as any), mockRes(), next);
      expect(next).toHaveBeenCalled();
    });
  });

  describe("createSessionTimeoutMiddleware", () => {
    it("should pass if no session id", async () => {
      const { factory } = makeFactory();
      const mw = factory.createSessionTimeoutMiddleware();
      const next = vi.fn();
      await mw(mockReq(undefined, { user: {} } as any), mockRes(), next);
      expect(next).toHaveBeenCalled();
    });
    it("should pass if session not tracked", async () => {
      const { factory } = makeFactory();
      const mw = factory.createSessionTimeoutMiddleware();
      const next = vi.fn();
      await mw(mockReq(undefined, { user: { sessionId: "s1" } } as any), mockRes(), next);
      expect(next).toHaveBeenCalled();
    });
    it("should reject inactive session", async () => {
      const { factory, redis } = makeFactory();
      const mw = factory.createSessionTimeoutMiddleware();
      // Mark the session as created so it is tracked, but leave no activity key
      await redis.setex("focura:session:created:s1", 3600, Date.now().toString());
      const res = mockRes();
      await mw(mockReq(undefined, { user: { sessionId: "s1" } }), res, vi.fn());
      expect(res.status).toHaveBeenCalledWith(401);
    });
    it("should update activity for active session", async () => {
      const { factory, redis } = makeFactory();
      const mw = factory.createSessionTimeoutMiddleware();
      // Mark the session as created with an active activity key
      await redis.setex("focura:session:created:s1", 3600, Date.now().toString());
      await redis.setex("focura:session:activity:s1", 900, Date.now().toString());
      const next = vi.fn();
      await mw(mockReq(undefined, { user: { sessionId: "s1" } }), mockRes(), next);
      expect(next).toHaveBeenCalled();
      // Activity should be refreshed (still present with a new timestamp)
      expect(await redis.get("focura:session:activity:s1")).toBeDefined();
    });
  });

  describe("createExchangeHandler", () => {
    it("should reject expired proof", async () => {
      const { factory } = makeFactory();
      const handler = factory.createExchangeHandler();
      const req = mockReq(undefined, { body: { userId: "u1", email: "a@b.com", role: "USER", sessionId: "s1", timestamp: Date.now() - 120_000, signature: "x" } });
      await expect(handler(req, mockRes())).rejects.toThrow("expired");
    });

    it("should reject invalid signature", async () => {
      const { factory } = makeFactory();
      const handler = factory.createExchangeHandler();
      const req = mockReq(undefined, { body: { userId: "u1", email: "a@b.com", role: "USER", sessionId: "s1", timestamp: Date.now(), signature: "bad" } });
      await expect(handler(req, mockRes())).rejects.toThrow("Invalid exchange proof");
    });

    it("should accept valid exchange proof", async () => {
      const { factory } = makeFactory();
      const handler = factory.createExchangeHandler();
      const timestamp = Date.now();
      const payload = `user-1test@example.comUSERs1${timestamp}`;
      const signature = crypto.createHmac("sha256", "test-hmac-secret-32chars-long!!").update(payload).digest("hex");
      const req = mockReq(undefined, { body: { userId: "user-1", email: "test@example.com", role: "USER", sessionId: "s1", timestamp, signature } });
      const res = mockRes();
      await handler(req, res);
      expect(res.status).toHaveBeenCalledWith(200);
    });

    it("should return cached result on idempotency", async () => {
      const { factory, redis } = makeFactory();
      const handler = factory.createExchangeHandler();
      const timestamp = Date.now();
      const payload = `user-1test@example.comUSERs1${timestamp}`;
      const signature = crypto.createHmac("sha256", "test-hmac-secret-32chars-long!!").update(payload).digest("hex");
      await redis.setex(`exchange:idempotent:user-1:s1:${timestamp}`, 90, JSON.stringify({ accessToken: "cached" }));
      const req = mockReq(undefined, { body: { userId: "user-1", email: "test@example.com", role: "USER", sessionId: "s1", timestamp, signature } });
      const res = mockRes();
      await handler(req, res);
      expect(res.status).toHaveBeenCalledWith(200);
    });

    it("should reject user not found in exchange", async () => {
      const userStore = mockUserStore([]);
      const factory = new MiddlewareFactory(makeAuthConfig({ userStore }));
      const handler = factory.createExchangeHandler();
      const timestamp = Date.now();
      const payload = `unknowna@b.comUSERs1${timestamp}`;
      const signature = crypto.createHmac("sha256", "test-hmac-secret-32chars-long!!").update(payload).digest("hex");
      const req = mockReq(undefined, { body: { userId: "unknown", email: "a@b.com", role: "USER", sessionId: "s1", timestamp, signature } });
      await expect(handler(req, mockRes())).rejects.toThrow("User not found");
    });

    it("should reject email mismatch in exchange", async () => {
      const userStore = mockUserStore([{ ...TEST_USER, email: "other@example.com" }]);
      const factory = new MiddlewareFactory(makeAuthConfig({ userStore }));
      const handler = factory.createExchangeHandler();
      const timestamp = Date.now();
      const payload = `user-1test@example.comUSERs1${timestamp}`;
      const signature = crypto.createHmac("sha256", "test-hmac-secret-32chars-long!!").update(payload).digest("hex");
      const req = mockReq(undefined, { body: { userId: "user-1", email: "test@example.com", role: "USER", sessionId: "s1", timestamp, signature } });
      await expect(handler(req, mockRes())).rejects.toThrow("Email mismatch");
    });

    it("should reject unverified email in exchange", async () => {
      const userStore = mockUserStore([{ ...TEST_USER, emailVerified: null }]);
      const factory = new MiddlewareFactory(makeAuthConfig({ userStore }));
      const handler = factory.createExchangeHandler();
      const timestamp = Date.now();
      const payload = `user-1test@example.comUSERs1${timestamp}`;
      const signature = crypto.createHmac("sha256", "test-hmac-secret-32chars-long!!").update(payload).digest("hex");
      const req = mockReq(undefined, { body: { userId: "user-1", email: "test@example.com", role: "USER", sessionId: "s1", timestamp, signature } });
      await expect(handler(req, mockRes())).rejects.toThrow("Email not verified");
    });
  });

  describe("createRefreshHandler", () => {
    it("should reject missing refresh token", async () => {
      const { factory } = makeFactory();
      const handler = factory.createRefreshHandler();
      const req = mockReq(undefined, { body: {} });
      await expect(handler(req, mockRes())).rejects.toThrow("Refresh token required");
    });

    it("should reject invalid refresh token", async () => {
      const { factory } = makeFactory();
      const handler = factory.createRefreshHandler();
      const req = mockReq(undefined, { body: { refreshToken: "garbage" } });
      await expect(handler(req, mockRes())).rejects.toThrow("Invalid refresh token");
    });

    it("should reject refresh for revoked session", async () => {
      const { factory, redis } = makeFactory();
      const handler = factory.createRefreshHandler();
      await redis.setex("focura:session:revoked:s1", 3600, "1");
      await redis.setex("focura:session:created:s1", 3600, Date.now().toString());
      const req = mockReq(undefined, { body: { refreshToken: makeRefreshToken() } });
      await expect(handler(req, mockRes())).rejects.toThrow("Session revoked");
    });

    it("should reject refresh for expired session", async () => {
      const { factory } = makeFactory();
      const handler = factory.createRefreshHandler();
      const req = mockReq(undefined, { body: { refreshToken: makeRefreshToken({ sessionId: "nonexistent" }) } });
      await expect(handler(req, mockRes())).rejects.toThrow("Session expired");
    });

    it("should return deduplicated result", async () => {
      const { factory, redis } = makeFactory();
      const handler = factory.createRefreshHandler();
      const jti = crypto.randomUUID();
      const cached = { accessToken: "cached", refreshToken: "cached", sseToken: "cached", accessTokenExpiry: 0, refreshTokenExpiry: 0 };
      await redis.setex(`focura:refresh:dedupe:user-1:${jti}`, 30, JSON.stringify(cached));
      const req = mockReq(undefined, { body: { refreshToken: makeRefreshToken({ jti }) } });
      const res = mockRes();
      await handler(req, res);
      expect(res.status).toHaveBeenCalledWith(200);
    });

    it("should rotate tokens on valid refresh", async () => {
      const { factory, redis } = makeFactory();
      const handler = factory.createRefreshHandler();
      await redis.setex("focura:session:created:s1", 3600, Date.now().toString());
      const jti = crypto.randomUUID();
      await redis.setex(`focura:refresh:user-1:${jti}`, 3600, JSON.stringify({ jti, createdAt: Date.now() }));
      await redis.sadd(`focura:refresh:index:user-1`, `focura:refresh:user-1:${jti}`);
      const req = mockReq(undefined, { body: { refreshToken: makeRefreshToken({ jti }) } });
      const res = mockRes();
      await handler(req, res);
      expect(res.status).toHaveBeenCalledWith(200);
    });

    it("should handle lock already held", async () => {
      const { factory, redis } = makeFactory();
      const handler = factory.createRefreshHandler();
      // Pre-acquire the lock
      await redis.set("focura:refresh:lock:s1", "1", "EX", 45, "NX");
      const req = mockReq(undefined, { body: { refreshToken: makeRefreshToken() } });
      await expect(handler(req, mockRes())).rejects.toThrow("Refresh already in progress");
    });
  });

  describe("createLogoutHandler", () => {
    it("should return success with token revocation", async () => {
      const { factory } = makeFactory();
      const handler = factory.createLogoutHandler();
      const token = makeToken({ jti: "logout-jti" });
      const req = mockReq(`Bearer ${token}`, { user: { id: "user-1", tokenJti: "logout-jti", sessionId: "s1" }, body: {} });
      const res = mockRes();
      await handler(req, res);
      expect(res.status).toHaveBeenCalledWith(200);
    });

    it("should handle logoutAll", async () => {
      const { factory } = makeFactory();
      const handler = factory.createLogoutHandler();
      const req = mockReq(undefined, { user: { id: "user-1", sessionId: "s1" }, body: { logoutAll: true } });
      const res = mockRes();
      await handler(req, res);
      expect(res.status).toHaveBeenCalledWith(200);
    });

    it("should handle single session logout", async () => {
      const { factory } = makeFactory();
      const handler = factory.createLogoutHandler();
      const req = mockReq(undefined, { user: { id: "user-1", sessionId: "s1" }, body: {} });
      const res = mockRes();
      await handler(req, res);
      expect(res.status).toHaveBeenCalledWith(200);
    });

    it("should handle logout without user", async () => {
      const { factory } = makeFactory();
      const handler = factory.createLogoutHandler();
      const req = mockReq(undefined, { body: {} });
      const res = mockRes();
      await handler(req, res);
      expect(res.status).toHaveBeenCalledWith(200);
    });
  });
});
