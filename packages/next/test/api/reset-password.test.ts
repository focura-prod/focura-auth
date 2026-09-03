import { describe, it, expect, vi } from "vitest";
import { handleResetPassword } from "../../src/api/reset-password.js";

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
  return new Request("http://localhost/api/auth/reset-password", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

describe("handleResetPassword", () => {
  it("should reset password with valid token", async () => {
    const dataStore = mockDataStore();
    dataStore.findPasswordResetToken.mockResolvedValue({ email: "test@example.com", token: "valid-token" });
    const argon2 = { hash: vi.fn(async (pwd: string) => `hashed:${pwd}`) };
    const req = makeReq({ token: "valid-token", password: "newpassword123" });
    const res = await handleResetPassword(req, { dataStore, argon2 });
    expect(res.status).toBe(200);
    const json = await res.json();
    expect(json.message).toBe("Password reset successfully");
    expect(dataStore.updateUserByEmail).toHaveBeenCalled();
    expect(dataStore.deletePasswordResetToken).toHaveBeenCalled();
  });

  it("should reject missing token", async () => {
    const dataStore = mockDataStore();
    const argon2 = { hash: vi.fn() };
    const req = makeReq({ password: "newpassword123" });
    const res = await handleResetPassword(req, { dataStore, argon2 });
    expect(res.status).toBe(400);
  });

  it("should reject missing password", async () => {
    const dataStore = mockDataStore();
    const argon2 = { hash: vi.fn() };
    const req = makeReq({ token: "valid-token" });
    const res = await handleResetPassword(req, { dataStore, argon2 });
    expect(res.status).toBe(400);
  });

  it("should reject short password", async () => {
    const dataStore = mockDataStore();
    const argon2 = { hash: vi.fn() };
    const req = makeReq({ token: "valid-token", password: "short" });
    const res = await handleResetPassword(req, { dataStore, argon2 });
    expect(res.status).toBe(400);
  });

  it("should reject invalid token", async () => {
    const dataStore = mockDataStore();
    const argon2 = { hash: vi.fn() };
    const req = makeReq({ token: "invalid", password: "newpassword123" });
    const res = await handleResetPassword(req, { dataStore, argon2 });
    expect(res.status).toBe(400);
    const json = await res.json();
    expect(json.error).toContain("Invalid or expired");
  });

  it("should handle internal errors", async () => {
    const dataStore = mockDataStore();
    dataStore.findPasswordResetToken.mockRejectedValue(new Error("db error"));
    const argon2 = { hash: vi.fn() };
    const req = makeReq({ token: "valid-token", password: "newpassword123" });
    const res = await handleResetPassword(req, { dataStore, argon2 });
    expect(res.status).toBe(500);
  });
});
