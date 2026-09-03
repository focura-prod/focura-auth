import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { silentRefresh } from "../src/refresh.js";

describe("silentRefresh", () => {
  let fetchSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    fetchSpy = vi.spyOn(globalThis, "fetch");
  });

  afterEach(() => {
    fetchSpy.mockRestore();
  });

  it("should return ok:true with tokens on success", async () => {
    const tokens = { accessToken: "a", refreshToken: "r", sseToken: "s", accessTokenExpiry: 1, refreshTokenExpiry: 2 };
    fetchSpy.mockResolvedValue(new Response(JSON.stringify(tokens), { status: 200 }));
    const result = await silentRefresh("session-1", "refresh-token", "http://localhost:5000");
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.tokens.accessToken).toBe("a");
    }
  });

  it("should return ok:false on non-200", async () => {
    fetchSpy.mockResolvedValue(new Response(JSON.stringify({ code: "TOKEN_REVOKED" }), { status: 401 }));
    const result = await silentRefresh("session-2", "refresh-token", "http://localhost:5000");
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.code).toBe("TOKEN_REVOKED");
    }
  });

  it("should return ok:false on network error", async () => {
    fetchSpy.mockRejectedValue(new Error("network"));
    const result = await silentRefresh("session-3", "refresh-token", "http://localhost:5000");
    expect(result.ok).toBe(false);
  });

  it("should deduplicate concurrent refreshes for same session", async () => {
    const tokens = { accessToken: "a", refreshToken: "r", sseToken: "s", accessTokenExpiry: 1, refreshTokenExpiry: 2 };
    fetchSpy.mockResolvedValue(new Response(JSON.stringify(tokens), { status: 200 }));
    const [r1, r2] = await Promise.all([
      silentRefresh("dedup-session", "rt1", "http://localhost:5000"),
      silentRefresh("dedup-session", "rt2", "http://localhost:5000"),
    ]);
    // Only one fetch should have been made
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });

  it("should clear the refresh lock after completion", async () => {
    fetchSpy.mockResolvedValue(new Response("{}", { status: 200 }));
    await silentRefresh("clear-session", "rt", "http://localhost:5000");
    // Wait for the finally timer (100ms) to release the lock
    await new Promise((r) => setTimeout(r, 150));
    await silentRefresh("clear-session", "rt", "http://localhost:5000");
    // A second fetch proves the lock was released
    expect(fetchSpy).toHaveBeenCalledTimes(2);
  });
});
