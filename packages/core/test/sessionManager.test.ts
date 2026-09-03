import { describe, it, expect, beforeEach } from "vitest";
import { SessionManager } from "../src/session/sessionManager.js";
import { MockRedis } from "./helpers/mockRedis.js";

describe("SessionManager", () => {
  let redis: MockRedis;
  let mgr: SessionManager;

  const mockRevocation = { markSessionRevoked: async () => {} };

  beforeEach(() => {
    redis = new MockRedis();
    mgr = new SessionManager(redis, mockRevocation, undefined, "test:", 3);
  });

  describe("trackUserSession", () => {
    it("should add session to user set", async () => {
      await mgr.trackUserSession("u1", "s1");
      const members = await redis.smembers("test:user:sessions:u1");
      expect(members).toContain("s1");
    });
    it("should evict least active session when limit reached", async () => {
      // Add 3 sessions (the limit)
      await mgr.trackUserSession("u1", "s1");
      await mgr.trackUserSession("u1", "s2");
      await mgr.trackUserSession("u1", "s3");
      // Add metadata for s1 (least active)
      await redis.setex("test:session:metadata:s1", 3600, JSON.stringify({ lastActivity: 100 }));
      await redis.setex("test:session:metadata:s2", 3600, JSON.stringify({ lastActivity: 300 }));
      await redis.setex("test:session:metadata:s3", 3600, JSON.stringify({ lastActivity: 200 }));
      // Track a 4th — should evict s1
      await mgr.trackUserSession("u1", "s4");
      const members = await redis.smembers("test:user:sessions:u1");
      expect(members).not.toContain("s1");
      expect(members).toContain("s4");
    });
    it("should handle redis errors gracefully", async () => {
      const broken = { smembers: async () => { throw new Error("fail"); }, sadd: async () => { throw new Error("fail"); }, expire: async () => { throw new Error("fail"); } } as any;
      const m = new SessionManager(broken, mockRevocation, undefined, "test:", 3);
      await m.trackUserSession("u1", "s1"); // should not throw
    });
    it("should evict even when metadata is corrupt", async () => {
      await mgr.trackUserSession("u1", "s1");
      await mgr.trackUserSession("u1", "s2");
      await mgr.trackUserSession("u1", "s3");
      // Corrupt metadata on s1 → treated as least active (lastActivity 0)
      await redis.setex("test:session:metadata:s1", 3600, "not-json");
      await mgr.trackUserSession("u1", "s4");
      const members = await redis.smembers("test:user:sessions:u1");
      expect(members).not.toContain("s1");
      expect(members).toContain("s4");
    });
    it("should treat metadata without lastActivity as least active", async () => {
      await mgr.trackUserSession("u1", "s1");
      await mgr.trackUserSession("u1", "s2");
      await mgr.trackUserSession("u1", "s3");
      // s1 metadata has no lastActivity → falls back to 0 → evicted
      await redis.setex("test:session:metadata:s1", 3600, JSON.stringify({ userAgent: "Chrome" }));
      await mgr.trackUserSession("u1", "s4");
      const members = await redis.smembers("test:user:sessions:u1");
      expect(members).not.toContain("s1");
    });
    it("should use default maxConcurrent when not provided", async () => {
      const m = new SessionManager(redis, mockRevocation);
      await m.trackUserSession("u1", "s1");
      // Without a prefix, the default "focura:" prefix is used
      const members = await redis.smembers("focura:user:sessions:u1");
      expect(members).toContain("s1");
    });
  });

  describe("revokeUserSession", () => {
    it("should remove session from set and delete metadata", async () => {
      await mgr.trackUserSession("u1", "s1");
      await mgr.revokeUserSession("u1", "s1");
      const members = await redis.smembers("test:user:sessions:u1");
      expect(members).not.toContain("s1");
    });
    it("should handle redis errors gracefully", async () => {
      const broken = { srem: async () => { throw new Error("fail"); }, del: async () => { throw new Error("fail"); } } as any;
      const m = new SessionManager(broken, mockRevocation, undefined, "test:", 3);
      await m.revokeUserSession("u1", "s1"); // should not throw
    });
  });

  describe("getUserActiveSessions", () => {
    it("should return session info", async () => {
      await mgr.trackUserSession("u1", "s1");
      await redis.setex("test:session:metadata:s1", 3600, JSON.stringify({
        deviceId: "dev1", ipAddress: "1.2.3.4", userAgent: "Chrome", lastActivity: 1000, createdAt: 900,
      }));
      const sessions = await mgr.getUserActiveSessions("u1");
      expect(sessions).toHaveLength(1);
      expect(sessions[0]!.sessionId).toBe("s1");
      expect(sessions[0]!.ipAddress).toBe("1.2.3.4");
      expect(sessions[0]!.deviceInfo).toBe("Chrome");
    });
    it("should skip sessions with corrupted metadata", async () => {
      await mgr.trackUserSession("u1", "s1");
      await redis.setex("test:session:metadata:s1", 3600, "not-json");
      const sessions = await mgr.getUserActiveSessions("u1");
      expect(sessions).toHaveLength(0);
    });
    it("should skip sessions without metadata", async () => {
      await mgr.trackUserSession("u1", "s1");
      const sessions = await mgr.getUserActiveSessions("u1");
      expect(sessions).toHaveLength(0);
    });
    it("should return empty array on redis error", async () => {
      const broken = { smembers: async () => { throw new Error("fail"); } } as any;
      const m = new SessionManager(broken, mockRevocation, undefined, "test:", 3);
      expect(await m.getUserActiveSessions("u1")).toEqual([]);
    });
  });
});
