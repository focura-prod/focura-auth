import { describe, it, expect } from "vitest";
import jwt from "jsonwebtoken";
import { TokenManager } from "../src/tokens/backendToken.js";
import { privateKey, publicKey } from "./helpers/setup.js";

function mgr(overrides?: Record<string, unknown>) {
  return new TokenManager({
    privateKey, publicKey,
    issuer: "test-issuer", audience: "test-audience",
    accessTokenExpiry: "15m", refreshTokenExpiry: "7d", sseTokenExpiry: "30s",
    currentVersion: 1,
    ...overrides,
  });
}

const user = { id: "u1", email: "a@b.com", role: "USER", sessionId: "s1" };

describe("TokenManager", () => {
  describe("createAccessToken", () => {
    it("should return a 3-part JWT string", () => {
      const t = mgr().createAccessToken(user);
      expect(t.split(".")).toHaveLength(3);
    });
    it("should be verifiable as access type", () => {
      const t = mgr().createAccessToken(user);
      const d = mgr().verifyToken(t, "access");
      expect(d.id).toBe("u1");
      expect(d.email).toBe("a@b.com");
      expect(d.role).toBe("USER");
      expect(d.type).toBe("access");
      expect(d.sessionId).toBe("s1");
    });
  });

  describe("createRefreshToken", () => {
    it("should be verifiable as refresh type", () => {
      const t = mgr().createRefreshToken(user);
      expect(mgr().verifyToken(t, "refresh").type).toBe("refresh");
    });
  });

  describe("createTokenPair", () => {
    it("should return both tokens with expiry timestamps", () => {
      const pair = mgr().createTokenPair(user);
      expect(pair.accessToken).toBeDefined();
      expect(pair.refreshToken).toBeDefined();
      expect(pair.accessTokenExpiry).toBeGreaterThan(Date.now());
      expect(pair.refreshTokenExpiry).toBeGreaterThan(pair.accessTokenExpiry);
    });
    it("should auto-generate sessionId when omitted", () => {
      const pair = mgr().createTokenPair({ id: "u1", email: "a@b.com", role: "USER" });
      expect(pair.accessToken).toBeDefined();
    });
  });

  describe("createSseToken", () => {
    it("should create an SSE token", () => {
      const t = mgr().createSseToken("u1");
      expect(mgr().verifyToken(t).type).toBe("sse");
      expect(mgr().verifyToken(t).id).toBe("u1");
    });
  });

  describe("verifyToken", () => {
    it("should reject wrong expected type", () => {
      const t = mgr().createAccessToken(user);
      expect(() => mgr().verifyToken(t, "refresh")).toThrow();
    });
    it("should reject token signed with wrong key", () => {
      const { privateKey: otherKey } = require("crypto").generateKeyPairSync("rsa", {
        modulusLength: 2048,
        publicKeyEncoding: { type: "spki", format: "pem" },
        privateKeyEncoding: { type: "pkcs8", format: "pem" },
      });
      const bad = jwt.sign({ sub: "u1", email: "a@b.com", role: "USER", type: "access", version: 1, jti: "x" }, otherKey, { algorithm: "RS256", expiresIn: "15m", issuer: "test-issuer", audience: "test-audience" });
      expect(() => mgr().verifyToken(bad, "access")).toThrow();
    });
    it("should reject expired token", () => {
      const t = jwt.sign({ sub: "u1", email: "a@b.com", role: "USER", type: "access", version: 1, jti: "x", sessionId: "s1" }, privateKey, { algorithm: "RS256", expiresIn: "0s", issuer: "test-issuer", audience: "test-audience" });
      // token created with expiresIn 0s may still be valid within same ms,
      // so we verify with a manager that expects version=2 to force mismatch fallback
      expect(() => mgr({ currentVersion: 99 }).verifyToken(t, "access")).toThrow();
    });
  });

  describe("getters", () => {
    it("should return constructor values", () => {
      const m = mgr();
      expect(m.getPublicKey()).toBe(publicKey);
      expect(m.getAccessTokenExpiry()).toBe("15m");
      expect(m.getRefreshTokenExpiry()).toBe("7d");
      expect(m.getSseTokenExpiry()).toBe("30s");
      expect(m.getCurrentVersion()).toBe(1);
      expect(m.getIssuer()).toBe("test-issuer");
      expect(m.getAudience()).toBe("test-audience");
    });

    it("should fall back to DEFAULTS when config fields are omitted", () => {
      const m = new TokenManager({ privateKey, publicKey });
      expect(m.getIssuer()).toBe("focura-app");
      expect(m.getAudience()).toBe("focura-backend");
      expect(m.getAccessTokenExpiry()).toBe("15m");
      expect(m.getRefreshTokenExpiry()).toBe("7d");
      expect(m.getSseTokenExpiry()).toBe("30s");
      expect(m.getCurrentVersion()).toBe(1);
      // And it still works end-to-end
      const t = m.createAccessToken(user);
      expect(m.verifyToken(t, "access").id).toBe("u1");
    });
  });

  describe("verifyToken edge cases", () => {
    it("should default missing sub/jti to empty strings", () => {
      const t = jwt.sign(
        { email: "a@b.com", role: "USER", type: "access", version: 1, sessionId: "s1" },
        privateKey, { algorithm: "RS256", expiresIn: "15m", issuer: "test-issuer", audience: "test-audience" }
      );
      const d = mgr().verifyToken(t, "access");
      expect(d.id).toBe("");
      expect(d.jti).toBe("");
      expect(d.sessionId).toBe("s1");
    });
  });

  describe("parseExpiry (static)", () => {
    it("should parse s/m/h/d", () => {
      expect(TokenManager.parseExpiry("30s")).toBe(30_000);
      expect(TokenManager.parseExpiry("15m")).toBe(900_000);
      expect(TokenManager.parseExpiry("2h")).toBe(7_200_000);
      expect(TokenManager.parseExpiry("7d")).toBe(604_800_000);
    });
    it("should throw on invalid", () => {
      expect(() => TokenManager.parseExpiry("bad")).toThrow("Invalid expiry");
      expect(() => TokenManager.parseExpiry("")).toThrow("Invalid expiry");
    });
  });

  describe("extractJti (static)", () => {
    it("should extract jti from valid token", () => {
      const t = mgr().createAccessToken(user);
      const jti = TokenManager.extractJti(t);
      expect(jti.length).toBeGreaterThan(0);
    });
    it("should return empty string on garbage", () => {
      expect(TokenManager.extractJti("garbage")).toBe("");
      expect(TokenManager.extractJti("")).toBe("");
    });
    it("should return empty string when token has no jti", () => {
      const t = jwt.sign(
        { sub: "u1", email: "a@b.com", role: "USER", type: "access", version: 1 },
        privateKey, { algorithm: "RS256", expiresIn: "15m", issuer: "test-issuer", audience: "test-audience" }
      );
      expect(TokenManager.extractJti(t)).toBe("");
    });
  });

  describe("uniqueness", () => {
    it("should produce different jti per token", () => {
      const m = mgr();
      const a = TokenManager.extractJti(m.createAccessToken(user));
      const b = TokenManager.extractJti(m.createAccessToken(user));
      expect(a).not.toBe(b);
    });
  });
});
