import { describe, it, expect, vi } from "vitest";
import { handleVerifyEmail } from "../../src/api/verify-email.js";

function mockDataStore() {
  return {
    findUserByEmail: vi.fn(async () => null),
    createUser: vi.fn(async () => ({ id: "u" })),
    createVerificationToken: vi.fn(async () => {}),
    updateUserByEmail: vi.fn(async () => {}),
    findVerificationToken: vi.fn(async () => null),
    deleteVerificationToken: vi.fn(async () => {}),
    createPasswordResetToken: vi.fn(async () => {}),
    findPasswordResetToken: vi.fn(async () => null),
    deletePasswordResetToken: vi.fn(async () => {}),
  };
}

function makeReq(body: unknown): Request {
  return new Request("http://localhost/api/auth/verify-email", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

describe("handleVerifyEmail", () => {
  it("should verify email with valid token", async () => {
    const dataStore = mockDataStore();
    dataStore.findVerificationToken.mockResolvedValue({
      identifier: "test@example.com",
      expires: new Date(Date.now() + 3600_000),
    });
    const req = makeReq({ token: "valid-token" });
    const res = await handleVerifyEmail(req, { dataStore } as any);
    expect(res.status).toBe(200);
    const json = await res.json();
    expect(json.message).toBe("Email verified successfully");
    expect(dataStore.updateUserByEmail).toHaveBeenCalled();
    expect(dataStore.deleteVerificationToken).toHaveBeenCalled();
  });

  it("should reject missing token", async () => {
    const dataStore = mockDataStore();
    const req = makeReq({});
    const res = await handleVerifyEmail(req, { dataStore } as any);
    expect(res.status).toBe(400);
  });

  it("should reject invalid token", async () => {
    const dataStore = mockDataStore();
    const req = makeReq({ token: "invalid" });
    const res = await handleVerifyEmail(req, { dataStore } as any);
    expect(res.status).toBe(400);
    const json = await res.json();
    expect(json.error).toBe("Invalid token");
  });

  it("should reject expired token", async () => {
    const dataStore = mockDataStore();
    dataStore.findVerificationToken.mockResolvedValue({
      identifier: "test@example.com",
      expires: new Date(Date.now() - 1000),
    });
    const req = makeReq({ token: "expired-token" });
    const res = await handleVerifyEmail(req, { dataStore } as any);
    expect(res.status).toBe(400);
    const json = await res.json();
    expect(json.error).toBe("Token expired");
  });

  it("should handle internal errors", async () => {
    const dataStore = mockDataStore();
    dataStore.findVerificationToken.mockRejectedValue(new Error("db error"));
    const req = makeReq({ token: "token" });
    const res = await handleVerifyEmail(req, { dataStore } as any);
    expect(res.status).toBe(500);
  });
});
