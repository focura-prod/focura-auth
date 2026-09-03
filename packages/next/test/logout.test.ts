import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { logout } from "../src/logout.js";

describe("logout", () => {
  let fetchSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("ok", { status: 200 }));
  });

  afterEach(() => {
    fetchSpy.mockRestore();
  });

  it("should call logout endpoint", async () => {
    await logout("http://localhost:5000", "token123", false);
    expect(fetchSpy).toHaveBeenCalledWith(
      "http://localhost:5000/api/v1/auth/logout",
      expect.objectContaining({
        method: "POST",
        headers: { "Content-Type": "application/json", "Authorization": "Bearer token123" },
      })
    );
  });

  it("should include logoutAll in body", async () => {
    await logout("http://localhost:5000", "token123", true);
    const body = JSON.parse(fetchSpy.mock.calls[0]![1]!.body as string);
    expect(body.logoutAll).toBe(true);
  });

  it("should handle missing backendToken", async () => {
    await logout("http://localhost:5000", undefined, false);
    const headers = fetchSpy.mock.calls[0]![1]!.headers as Record<string, string>;
    expect(headers.Authorization).toBeUndefined();
  });

  it("should not throw on fetch error", async () => {
    fetchSpy.mockRejectedValue(new Error("network"));
    await expect(logout("http://localhost:5000", "token")).resolves.toBeUndefined();
  });
});
