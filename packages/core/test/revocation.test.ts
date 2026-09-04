import { describe, it, expect, beforeEach } from "vitest";
import { TokenRevocation } from "../src/revocation/tokenRevocation.js";
import { MockRedis } from "./helpers/mockRedis.js";

describe("TokenRevocation", () => {
  let redis: MockRedis;
  let rev: TokenRevocation;

  beforeEach(() => {
    redis = new MockRedis();
    rev = new TokenRevocation(redis, "test:");
  });

  describe("revokeAccessToken / isAccessTokenRevoked", () => {
    it("should revoke and detect access token", async () => {
      await rev.revokeAccessToken("jti-1", 60);
      expect(await rev.isAccessTokenRevoked("jti-1")).toBe(true);
      expect(await rev.isAccessTokenRevoked("jti-2")).toBe(false);
    });
    it("should handle redis errors gracefully", async () => {
      const broken = { get: async () => { throw new Error("fail"); } } as any;
      const r = new TokenRevocation(broken);
      // should not throw
      await r.revokeAccessToken("j", 10);
      expect(await r.isAccessTokenRevoked("j")).toBe(true);
    });
  });

  describe("storeRefreshToken / isRefreshTokenValid / revokeRefreshToken", () => {
    it("should store, validate and revoke a refresh token", async () => {
      await rev.storeRefreshToken("u1", "jti-r", 3600);
      expect(await rev.isRefreshTokenValid("u1", "jti-r")).toBe(true);
      await rev.revokeRefreshToken("u1", "jti-r");
      expect(await rev.isRefreshTokenValid("u1", "jti-r")).toBe(false);
    });
    it("should track tokens in the index set", async () => {
      await rev.storeRefreshToken("u1", "j1", 3600);
      await rev.storeRefreshToken("u1", "j2", 3600);
      const idxKey = "test:refresh:index:u1";
      const members = await redis.smembers(idxKey);
      expect(members.length).toBe(2);
    });
  });

  describe("revokeAllRefreshTokens", () => {
    it("should revoke all refresh tokens for a user (via index)", async () => {
      await rev.storeRefreshToken("u1", "j1", 3600);
      await rev.storeRefreshToken("u1", "j2", 3600);
      await rev.revokeAllRefreshTokens("u1");
      expect(await rev.isRefreshTokenValid("u1", "j1")).toBe(false);
      expect(await rev.isRefreshTokenValid("u1", "j2")).toBe(false);
    });
    it("should fall back to scan when index is empty", async () => {
      // manually set keys without using storeRefreshToken
      await redis.setex("test:refresh:u1:j1", 3600, "{}");
      await redis.setex("test:refresh:u1:j2", 3600, "{}");
      await rev.revokeAllRefreshTokens("u1");
      expect(await redis.get("test:refresh:u1:j1")).toBeNull();
    });
    it("should not throw when redis fails during revokeAll", async () => {
      const broken = { smembers: async () => { throw new Error("fail"); } } as any;
      const r = new TokenRevocation(broken);
      await expect(r.revokeAllRefreshTokens("u1")).resolves.toBeUndefined();
    });
  });

  describe("rotateRefreshToken", () => {
    it("should atomically rotate (old → new)", async () => {
      await rev.storeRefreshToken("u1", "old", 3600);
      const ok = await rev.rotateRefreshToken("u1", "old", "new", 3600);
      expect(ok).toBe(true);
      expect(await rev.isRefreshTokenValid("u1", "old")).toBe(false);
      expect(await rev.isRefreshTokenValid("u1", "new")).toBe(true);
    });
    it("should return false if old token doesn't exist", async () => {
      const ok = await rev.rotateRefreshToken("u1", "ghost", "new", 3600);
      expect(ok).toBe(false);
    });
    it("should propagate MaxRetriesPerRequestError", async () => {
      const brokenRedis = {
        eval: async () => { const e = new Error("fail"); e.name = "MaxRetriesPerRequestError"; throw e; },
      } as any;
      const r = new TokenRevocation(brokenRedis);
      await expect(r.rotateRefreshToken("u", "o", "n", 10)).rejects.toThrow("Redis service temporarily unavailable");
    });
    it("should rethrow generic eval errors", async () => {
      const brokenRedis = { eval: async () => { throw new Error("boom"); } } as any;
      const r = new TokenRevocation(brokenRedis);
      await expect(r.rotateRefreshToken("u", "o", "n", 10)).rejects.toThrow("boom");
    });
  });

  describe("SSE token store/consume", () => {
    it("should store and consume an SSE token", async () => {
      await rev.storeSseToken("sse-jti", "u1", 60);
      const userId = await rev.consumeSseToken("sse-jti");
      expect(userId).toBe("u1");
      // consumed — second call should be null
      expect(await rev.consumeSseToken("sse-jti")).toBeNull();
    });
    it("should propagate MaxRetriesPerRequestError on store", async () => {
      const brokenRedis = { setex: async () => { const e = new Error("fail"); e.name = "MaxRetriesPerRequestError"; throw e; } } as any;
      const r = new TokenRevocation(brokenRedis);
      await expect(r.storeSseToken("j", "u", 10)).rejects.toThrow("Redis service temporarily unavailable");
    });
    it("should rethrow generic errors on store", async () => {
      const brokenRedis = { setex: async () => { throw new Error("boom"); } } as any;
      const r = new TokenRevocation(brokenRedis);
      await expect(r.storeSseToken("j", "u", 10)).rejects.toThrow("boom");
    });
    it("should propagate MaxRetriesPerRequestError on consume", async () => {
      const brokenRedis = { eval: async () => { const e = new Error("fail"); e.name = "MaxRetriesPerRequestError"; throw e; } } as any;
      const r = new TokenRevocation(brokenRedis);
      await expect(r.consumeSseToken("j")).rejects.toThrow("Redis service temporarily unavailable");
    });
    it("should rethrow generic errors on consume", async () => {
      const brokenRedis = { eval: async () => { throw new Error("boom"); } } as any;
      const r = new TokenRevocation(brokenRedis);
      await expect(r.consumeSseToken("j")).rejects.toThrow("boom");
    });
  });

  describe("session revocation", () => {
    it("should mark and check session revoked", async () => {
      await rev.markSessionRevoked("sess-1");
      expect(await rev.isSessionRevoked("sess-1")).toBe(true);
      expect(await rev.isSessionRevoked("sess-2")).toBe(false);
    });
    it("should handle redis errors in markSessionRevoked", async () => {
      const broken = { setex: async () => { throw new Error("fail"); } } as any;
      const r = new TokenRevocation(broken);
      await r.markSessionRevoked("s"); // should not throw
    });
    it("should handle redis errors in isSessionRevoked", async () => {
      const broken = { get: async () => { throw new Error("fail"); } } as any;
      const r = new TokenRevocation(broken);
      expect(await r.isSessionRevoked("s")).toBe(true);
    });
  });
});
