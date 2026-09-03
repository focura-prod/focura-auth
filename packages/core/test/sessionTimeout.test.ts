import { describe, it, expect, beforeEach } from "vitest";
import { SessionTimeoutManager } from "../src/middleware/sessionTimeout.js";
import { MockRedis } from "./helpers/mockRedis.js";

describe("SessionTimeoutManager", () => {
  let redis: MockRedis;
  let mgr: SessionTimeoutManager;

  beforeEach(() => {
    redis = new MockRedis();
    mgr = new SessionTimeoutManager(redis, { inactivityTimeout: 60, absoluteTimeout: 120, prefix: "test:" });
  });

  describe("recordCreation", () => {
    it("should create both created and activity keys", async () => {
      await mgr.recordCreation("s1");
      expect(await mgr.isTracked("s1")).toBe(true);
      expect(await mgr.isInactive("s1")).toBe(false);
    });
  });

  describe("invalidate", () => {
    it("should delete both keys", async () => {
      await mgr.recordCreation("s1");
      await mgr.invalidate("s1");
      expect(await mgr.isTracked("s1")).toBe(false);
    });
  });

  describe("isTracked", () => {
    it("should return false for unknown session", async () => {
      expect(await mgr.isTracked("unknown")).toBe(false);
    });
    it("should return true after recordCreation", async () => {
      await mgr.recordCreation("s1");
      expect(await mgr.isTracked("s1")).toBe(true);
    });
  });

  describe("isInactive", () => {
    it("should return true if activity key doesn't exist", async () => {
      expect(await mgr.isInactive("unknown")).toBe(true);
    });
    it("should return false if activity key exists", async () => {
      await mgr.recordCreation("s1");
      expect(await mgr.isInactive("s1")).toBe(false);
    });
  });

  describe("updateActivity", () => {
    it("should refresh activity key", async () => {
      await mgr.recordCreation("s1");
      const ok = await mgr.updateActivity("s1");
      expect(ok).toBe(true);
      expect(await mgr.isInactive("s1")).toBe(false);
    });
    it("should handle redis errors", async () => {
      const broken = { setex: async () => { throw new Error("fail"); } } as any;
      const m = new SessionTimeoutManager(broken);
      expect(await m.updateActivity("s1")).toBe(false);
    });
  });
});
