import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { callInternal, recordLoginFailure } from "../src/bridge.js";

describe("callInternal", () => {
  let fetchSpy: ReturnType<typeof vi.spyOn>;
  const config = { backendUrl: "http://localhost:5000", hmacSecret: "secret" };

  beforeEach(() => {
    fetchSpy = vi.spyOn(globalThis, "fetch");
    process.env.NODE_ENV = "test";
  });

  afterEach(() => {
    fetchSpy.mockRestore();
    delete process.env.NODE_ENV;
  });

  it("should return null in test environment", async () => {
    const result = await callInternal("/audit", { event: "test" }, config);
    expect(result).toBeNull();
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("should call fetch when not in test env", async () => {
    delete process.env.NODE_ENV;
    fetchSpy.mockResolvedValue(new Response(JSON.stringify({ ok: true }), { status: 200 }));
    const result = await callInternal("/audit", { event: "test" }, config);
    expect(fetchSpy).toHaveBeenCalled();
    expect(result).toEqual({ ok: true });
  });

  it("should return null on non-ok response", async () => {
    delete process.env.NODE_ENV;
    fetchSpy.mockResolvedValue(new Response("error", { status: 500 }));
    const result = await callInternal("/audit", { event: "test" }, config);
    expect(result).toBeNull();
  });

  it("should return null on fetch error", async () => {
    delete process.env.NODE_ENV;
    fetchSpy.mockRejectedValue(new Error("network"));
    const result = await callInternal("/audit", { event: "test" }, config);
    expect(result).toBeNull();
  });
});

describe("recordLoginFailure", () => {
  let fetchSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    fetchSpy = vi.spyOn(globalThis, "fetch");
    process.env.NODE_ENV = "test";
  });

  afterEach(() => {
    fetchSpy.mockRestore();
    delete process.env.NODE_ENV;
  });

  it("should return null in test environment", async () => {
    const result = await recordLoginFailure("a@b.com", { backendUrl: "http://localhost:5000", hmacSecret: "secret" });
    expect(result).toBeNull();
  });
});
