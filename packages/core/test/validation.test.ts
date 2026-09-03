import { describe, it, expect } from "vitest";
import { exchangeSchema, refreshSchema, logoutSchema } from "../src/validation/auth.validation.js";

describe("exchangeSchema", () => {
  const valid = {
    userId: "550e8400-e29b-41d4-a716-446655440000",
    email: "test@example.com",
    role: "USER",
    sessionId: "550e8400-e29b-41d4-a716-446655440001",
    timestamp: Date.now(),
    signature: "abc123",
  };

  it("should accept valid input", () => {
    expect(exchangeSchema.safeParse(valid).success).toBe(true);
  });

  it("should reject invalid uuid", () => {
    expect(exchangeSchema.safeParse({ ...valid, userId: "bad" }).success).toBe(false);
  });

  it("should reject invalid email", () => {
    expect(exchangeSchema.safeParse({ ...valid, email: "not-an-email" }).success).toBe(false);
  });

  it("should accept timestamp as string", () => {
    expect(exchangeSchema.safeParse({ ...valid, timestamp: "1234567890" }).success).toBe(true);
  });
});

describe("refreshSchema", () => {
  it("should accept valid refreshToken", () => {
    expect(refreshSchema.safeParse({ refreshToken: "abc" }).success).toBe(true);
  });
  it("should reject empty refreshToken", () => {
    expect(refreshSchema.safeParse({ refreshToken: "" }).success).toBe(false);
  });
  it("should reject missing refreshToken", () => {
    expect(refreshSchema.safeParse({}).success).toBe(false);
  });
});

describe("logoutSchema", () => {
  it("should accept with logoutAll", () => {
    expect(logoutSchema.safeParse({ logoutAll: true }).success).toBe(true);
  });
  it("should accept empty (logoutAll is optional)", () => {
    expect(logoutSchema.safeParse({}).success).toBe(true);
  });
  it("should reject non-boolean logoutAll", () => {
    expect(logoutSchema.safeParse({ logoutAll: "yes" }).success).toBe(false);
  });
});
