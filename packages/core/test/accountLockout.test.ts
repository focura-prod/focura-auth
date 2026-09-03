import { describe, it, expect, beforeEach } from "vitest";
import { AccountLockout } from "../src/lockout/accountLockout.js";
import { MockRedis } from "./helpers/mockRedis.js";

describe("AccountLockout", () => {
  let redis: MockRedis;
  let lockout: AccountLockout;

  beforeEach(() => {
    redis = new MockRedis();
    lockout = new AccountLockout(redis, { maxFailures: 3, lockoutSeconds: 60, windowSeconds: 120, prefix: "test:lockout" });
  });

  describe("recordFailedAttempt", () => {
    it("should track attempts", async () => {
      const r1 = await lockout.recordFailedAttempt("user@example.com");
      expect(r1.locked).toBe(false);
      expect(r1.attempts).toBe(1);

      const r2 = await lockout.recordFailedAttempt("user@example.com");
      expect(r2.locked).toBe(false);
      expect(r2.attempts).toBe(2);
    });
    it("should lock after max failures", async () => {
      await lockout.recordFailedAttempt("user@example.com");
      await lockout.recordFailedAttempt("user@example.com");
      const r3 = await lockout.recordFailedAttempt("user@example.com");
      expect(r3.locked).toBe(true);
      expect(r3.attempts).toBe(3);
      expect(r3.unlocksAt).toBeInstanceOf(Date);
    });
    it("should remain locked once locked", async () => {
      await lockout.recordFailedAttempt("user@example.com");
      await lockout.recordFailedAttempt("user@example.com");
      await lockout.recordFailedAttempt("user@example.com");
      const r = await lockout.recordFailedAttempt("user@example.com");
      expect(r.locked).toBe(true);
    });
    it("should use default config when none provided", async () => {
      const lo = new AccountLockout(redis);
      const r = await lo.recordFailedAttempt("a@b.com");
      expect(r.locked).toBe(false);
      expect(r.attempts).toBe(1);
    });
    it("should handle redis errors gracefully", async () => {
      const broken = { get: async () => { throw new Error("fail"); }, pipeline: () => { throw new Error("fail"); } } as any;
      const lo = new AccountLockout(broken);
      const r = await lo.recordFailedAttempt("a@b.com");
      expect(r.locked).toBe(false);
      expect(r.attempts).toBe(0);
    });
    it("should default to 1 attempt when pipeline result is empty", async () => {
      const emptyPipe = { incr: () => emptyPipe, expire: () => emptyPipe, exec: async () => [] as [Error | null, unknown][] } as any;
      const mockRedis: any = {
        get: async () => null,
        pipeline: () => emptyPipe,
        setex: async () => "OK",
      };
      const lo = new AccountLockout(mockRedis, { maxFailures: 3, lockoutSeconds: 60, windowSeconds: 120, prefix: "p:" });
      const r = await lo.recordFailedAttempt("a@b.com");
      expect(r.attempts).toBe(1);
      expect(r.locked).toBe(false);
    });
  });

  describe("clearFailedAttempts", () => {
    it("should clear all lockout data", async () => {
      await lockout.recordFailedAttempt("user@example.com");
      await lockout.recordFailedAttempt("user@example.com");
      await lockout.clearFailedAttempts("user@example.com");
      const r = await lockout.recordFailedAttempt("user@example.com");
      expect(r.attempts).toBe(1);
      expect(r.locked).toBe(false);
    });
    it("should handle redis errors gracefully", async () => {
      const broken = { del: async () => { throw new Error("fail"); } } as any;
      const lo = new AccountLockout(broken);
      await lo.clearFailedAttempts("a@b.com"); // should not throw
    });
  });

  describe("isAccountLocked", () => {
    it("should return false when not locked", async () => {
      const r = await lockout.isAccountLocked("user@example.com");
      expect(r.locked).toBe(false);
    });
    it("should return true when locked", async () => {
      await lockout.recordFailedAttempt("user@example.com");
      await lockout.recordFailedAttempt("user@example.com");
      await lockout.recordFailedAttempt("user@example.com");
      const r = await lockout.isAccountLocked("user@example.com");
      expect(r.locked).toBe(true);
      expect(r.unlocksAt).toBeInstanceOf(Date);
    });
    it("should handle redis errors gracefully", async () => {
      const broken = { get: async () => { throw new Error("fail"); } } as any;
      const lo = new AccountLockout(broken);
      const r = await lo.isAccountLocked("a@b.com");
      expect(r.locked).toBe(false);
    });
  });
});
