import { describe, it, expect, vi, beforeEach } from "vitest";
import { generate, verify as otplibVerify } from "otplib";
import { TotpManager } from "../src/totp/totp.js";

// Wrap otplib verify so we can exercise the boolean-result branch while
// keeping the real implementation as the default behavior.
vi.mock("otplib", async (importOriginal) => {
  const actual = await importOriginal<typeof import("otplib")>();
  return { ...actual, verify: vi.fn(actual.verify) };
});

describe("TotpManager", () => {
  it("should generate a secret", () => {
    const mgr = new TotpManager("TestIssuer");
    const secret = mgr.generateSecret();
    expect(typeof secret).toBe("string");
    expect(secret.length).toBeGreaterThan(10);
  });

  it("should create a URI with issuer and label", () => {
    const mgr = new TotpManager("MyApp");
    const secret = mgr.generateSecret();
    const uri = mgr.createUri(secret, "user@example.com");
    expect(uri).toContain("MyApp");
    expect(uri).toContain("otpauth://totp");
    // otplib percent-encodes the email
    expect(decodeURIComponent(uri)).toContain("user@example.com");
  });

  it("should use default issuer", () => {
    const mgr = new TotpManager();
    const secret = mgr.generateSecret();
    const uri = mgr.createUri(secret, "a@b.com");
    expect(uri).toContain("Auth");
  });

  describe("verify", () => {
    it("should verify a valid token", async () => {
      const mgr = new TotpManager("Test");
      const secret = mgr.generateSecret();
      // Generate a token for the same secret within the current time window
      const token = await generate({ secret });
      const result = await mgr.verify(token, secret);
      expect(result).toBe(true);
    });

    it("should return false for an invalid token", async () => {
      const mgr = new TotpManager("Test");
      const secret = mgr.generateSecret();
      const result = await mgr.verify("000000", secret);
      expect(result).toBe(false);
    });

    it("should handle invalid secrets gracefully", async () => {
      const mgr = new TotpManager("Test");
      // Invalid base32 secret causes otplib to reject; verify must swallow it
      const result = await mgr.verify("123456", "INVALID_SECRET");
      expect(result).toBe(false);
    });

    it("should accept a boolean verify result", async () => {
      // Simulate an older otplib variant that resolves to a plain boolean
      vi.mocked(otplibVerify).mockResolvedValueOnce(true as never);
      const mgr = new TotpManager("Test");
      const result = await mgr.verify("123456", "JBSWY3DPEHPK3PXP");
      expect(result).toBe(true);
    });
  });

  beforeEach(() => {
    vi.mocked(otplibVerify).mockClear();
  });
});
