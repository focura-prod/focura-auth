import { describe, it, expect, vi } from "vitest";
import { handleRegister } from "../../src/api/register.js";

function mockDataStore() {
  return {
    findUserByEmail: vi.fn(async () => null),
    createUser: vi.fn(async () => ({ id: "new-user" })),
    createVerificationToken: vi.fn(async () => {}),
    updateUserByEmail: vi.fn(async () => {}),
    findVerificationToken: vi.fn(async () => null),
    deleteVerificationToken: vi.fn(async () => {}),
    createPasswordResetToken: vi.fn(async () => {}),
    findPasswordResetToken: vi.fn(async () => null),
    deletePasswordResetToken: vi.fn(async () => {}),
  };
}

function mockDeps(overrides?: Record<string, unknown>) {
  const dataStore = mockDataStore();
  return {
    dataStore,
    argon2: { hash: vi.fn(async (pwd: string) => `hashed:${pwd}`) },
    sendVerificationEmail: vi.fn(async () => {}),
    ...overrides,
  };
}

function makeReq(body: unknown): Request {
  return new Request("http://localhost/api/auth/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

describe("handleRegister", () => {
  it("should register a new user successfully", async () => {
    const deps = mockDeps();
    const req = makeReq({ name: "Test User", email: "test@example.com", password: "password123" });
    const res = await handleRegister(req, deps as any);
    expect(res.status).toBe(201);
    const json = await res.json();
    expect(json.message).toBe("Registration successful");
    expect(deps.dataStore.createUser).toHaveBeenCalled();
    expect(deps.dataStore.createVerificationToken).toHaveBeenCalled();
    expect(deps.sendVerificationEmail).toHaveBeenCalled();
  });

  it("should reject short name", async () => {
    const deps = mockDeps();
    const req = makeReq({ name: "ab", email: "test@example.com", password: "password123" });
    const res = await handleRegister(req, deps as any);
    expect(res.status).toBe(400);
  });

  it("should reject invalid email", async () => {
    const deps = mockDeps();
    const req = makeReq({ name: "Test User", email: "not-an-email", password: "password123" });
    const res = await handleRegister(req, deps as any);
    expect(res.status).toBe(400);
  });

  it("should reject short password", async () => {
    const deps = mockDeps();
    const req = makeReq({ name: "Test User", email: "test@example.com", password: "short" });
    const res = await handleRegister(req, deps as any);
    expect(res.status).toBe(400);
  });

  it("should reject duplicate email", async () => {
    const deps = mockDeps();
    deps.dataStore.findUserByEmail.mockResolvedValue({ id: "existing", email: "test@example.com" });
    const req = makeReq({ name: "Test User", email: "test@example.com", password: "password123" });
    const res = await handleRegister(req, deps as any);
    expect(res.status).toBe(409);
    const json = await res.json();
    expect(json.error).toContain("already exists");
  });

  it("should respect rate limiter", async () => {
    const limiter = { check: vi.fn(async () => false) };
    const deps = mockDeps({ limiter, rateLimitKey: "register:1.2.3.4" });
    const req = makeReq({ name: "Test User", email: "test@example.com", password: "password123" });
    const res = await handleRegister(req, deps as any);
    expect(res.status).toBe(429);
  });

  it("should proceed when rate limiter allows", async () => {
    const limiter = { check: vi.fn(async () => true) };
    const deps = mockDeps({ limiter, rateLimitKey: "register:1.2.3.4" });
    const req = makeReq({ name: "Test User", email: "test@example.com", password: "password123" });
    const res = await handleRegister(req, deps as any);
    expect(res.status).toBe(201);
    expect(limiter.check).toHaveBeenCalledWith("register:1.2.3.4");
  });

  it("should proceed when limiter exists but no rate limit key", async () => {
    const limiter = { check: vi.fn(async () => false) };
    const deps = mockDeps({ limiter });
    const req = makeReq({ name: "Test User", email: "test@example.com", password: "password123" });
    const res = await handleRegister(req, deps as any);
    expect(res.status).toBe(201);
    expect(limiter.check).not.toHaveBeenCalled();
  });

  it("should handle internal errors", async () => {
    const deps = mockDeps();
    deps.dataStore.findUserByEmail.mockRejectedValue(new Error("db error"));
    const req = makeReq({ name: "Test User", email: "test@example.com", password: "password123" });
    const res = await handleRegister(req, deps as any);
    expect(res.status).toBe(500);
  });

  it("should still succeed if email sending fails", async () => {
    const deps = mockDeps();
    deps.sendVerificationEmail.mockRejectedValue(new Error("email fail"));
    const req = makeReq({ name: "Test User", email: "test@example.com", password: "password123" });
    const res = await handleRegister(req, deps as any);
    expect(res.status).toBe(201);
  });
});
