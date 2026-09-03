import { describe, it, expect, beforeEach } from "vitest";
import { RefreshLock } from "../src/refresh/refreshLock.js";
import { MockRedis } from "./helpers/mockRedis.js";

describe("RefreshLock", () => {
  let redis: MockRedis;
  let lock: RefreshLock;

  beforeEach(() => {
    redis = new MockRedis();
    lock = new RefreshLock(redis, "test:");
  });

  it("should acquire a lock", async () => {
    expect(await lock.acquire("s1")).toBe(true);
  });
  it("should not acquire twice", async () => {
    expect(await lock.acquire("s1")).toBe(true);
    expect(await lock.acquire("s1")).toBe(false);
  });
  it("should release a lock", async () => {
    await lock.acquire("s1");
    await lock.release("s1");
    expect(await lock.acquire("s1")).toBe(true);
  });
  it("should report isLocked", async () => {
    expect(await lock.isLocked("s1")).toBe(false);
    await lock.acquire("s1");
    expect(await lock.isLocked("s1")).toBe(true);
    await lock.release("s1");
    expect(await lock.isLocked("s1")).toBe(false);
  });
  it("should handle redis errors gracefully", async () => {
    const broken = { setnx: async () => { throw new Error("fail"); }, get: async () => { throw new Error("fail"); }, del: async () => { throw new Error("fail"); } } as any;
    const l = new RefreshLock(broken);
    expect(await l.acquire("s")).toBe(false);
    expect(await l.isLocked("s")).toBe(false);
    await l.release("s"); // should not throw
  });
});
