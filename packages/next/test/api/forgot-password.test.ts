import { describe, it, expect, vi } from "vitest";
import { handleForgotPassword } from "../../src/api/forgot-password.js";

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
  return new Request("http://localhost/api/auth/forgot-password", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

describe("handleForgotPassword", () => {
  it("should always return success message (prevent enumeration)", async () => {
    const dataStore = mockDataStore();
    const sendEmail = vi.fn(async () => {});
    const req = makeReq({ email: "test@example.com" });
    const res = await handleForgotPassword(req, { dataStore, sendPasswordResetEmail: sendEmail });
    const json = await res.json();
    expect(json.message).toContain("reset link was sent");
  });

  it("should create reset token and send email when user exists", async () => {
    const dataStore = mockDataStore();
    dataStore.findUserByEmail.mockResolvedValue({ id: "u1", email: "test@example.com" });
    const sendEmail = vi.fn(async () => {});
    const req = makeReq({ email: "test@example.com" });
    await handleForgotPassword(req, { dataStore, sendPasswordResetEmail: sendEmail });
    expect(dataStore.createPasswordResetToken).toHaveBeenCalled();
    expect(sendEmail).toHaveBeenCalled();
  });

  it("should not send email when user does not exist", async () => {
    const dataStore = mockDataStore();
    const sendEmail = vi.fn(async () => {});
    const req = makeReq({ email: "nonexistent@example.com" });
    await handleForgotPassword(req, { dataStore, sendPasswordResetEmail: sendEmail });
    expect(sendEmail).not.toHaveBeenCalled();
  });

  it("should handle missing email", async () => {
    const dataStore = mockDataStore();
    const sendEmail = vi.fn(async () => {});
    const req = makeReq({});
    const res = await handleForgotPassword(req, { dataStore, sendPasswordResetEmail: sendEmail });
    expect(res.status).toBe(200); // same response to prevent enumeration
  });

  it("should handle email send failure", async () => {
    const dataStore = mockDataStore();
    dataStore.findUserByEmail.mockResolvedValue({ id: "u1", email: "test@example.com" });
    const sendEmail = vi.fn(async () => { throw new Error("send failed"); });
    const req = makeReq({ email: "test@example.com" });
    const res = await handleForgotPassword(req, { dataStore, sendPasswordResetEmail: sendEmail });
    expect(res.status).toBe(200); // still returns success
  });

  it("should handle internal errors", async () => {
    const dataStore = mockDataStore();
    dataStore.findUserByEmail.mockRejectedValue(new Error("db error"));
    const sendEmail = vi.fn(async () => {});
    const req = makeReq({ email: "test@example.com" });
    const res = await handleForgotPassword(req, { dataStore, sendPasswordResetEmail: sendEmail });
    expect(res.status).toBe(500);
  });
});
