import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import crypto from "crypto";
import { createExchangeProof, exchangeForTokens } from "../src/exchange.js";

describe("createExchangeProof", () => {
  it("should return timestamp and signature", () => {
    const result = createExchangeProof("u1", "a@b.com", "USER", "s1", "secret");
    expect(typeof result.timestamp).toBe("number");
    expect(typeof result.signature).toBe("string");
    expect(result.signature.length).toBe(64); // sha256 hex
  });

  it("should produce deterministic signature for same inputs", () => {
    const ts = 1234567890;
    // We can't control Date.now(), but we can verify same inputs → same signature
    const a = createExchangeProof("u1", "a@b.com", "USER", "s1", "secret");
    const b = createExchangeProof("u1", "a@b.com", "USER", "s1", "secret");
    // timestamps will differ, but if we compute manually:
    const payload1 = `u1a@b.comUSERs1${a.timestamp}`;
    const expected1 = crypto.createHmac("sha256", "secret").update(payload1).digest("hex");
    expect(a.signature).toBe(expected1);
  });

  it("should produce different signatures with different secrets", () => {
    const a = createExchangeProof("u1", "a@b.com", "USER", "s1", "secret1");
    const b = createExchangeProof("u1", "a@b.com", "USER", "s1", "secret2");
    expect(a.signature).not.toBe(b.signature);
  });
});

describe("exchangeForTokens", () => {
  let fetchSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    fetchSpy = vi.spyOn(globalThis, "fetch");
  });

  afterEach(() => {
    fetchSpy.mockRestore();
  });

  const user = { id: "u1", email: "a@b.com", role: "USER" };
  const config = { backendUrl: "http://localhost:5000", hmacSecret: "secret" };

  it("should exchange for tokens on success", async () => {
    const tokens = { accessToken: "a", refreshToken: "r", sseToken: "s", accessTokenExpiry: 1, refreshTokenExpiry: 2 };
    fetchSpy.mockResolvedValue(new Response(JSON.stringify(tokens), { status: 200 }));
    const result = await exchangeForTokens(user, "s1", config);
    expect(result).toEqual(tokens);
    // Verify the request shape
    const [url, init] = fetchSpy.mock.calls[0]!;
    expect(url).toBe("http://localhost:5000/api/v1/auth/exchange");
    const body = JSON.parse((init as RequestInit).body as string);
    expect(body.userId).toBe("u1");
    expect(body.sessionId).toBe("s1");
    expect(typeof body.timestamp).toBe("number");
    expect(typeof body.signature).toBe("string");
  });

  it("should return null on non-ok response", async () => {
    fetchSpy.mockResolvedValue(new Response(JSON.stringify({ error: "bad" }), { status: 400 }));
    const result = await exchangeForTokens(user, "s1", config);
    expect(result).toBeNull();
  });

  it("should return null when fetch throws", async () => {
    fetchSpy.mockRejectedValue(new Error("network down"));
    const result = await exchangeForTokens(user, "s1", config);
    expect(result).toBeNull();
  });
});
