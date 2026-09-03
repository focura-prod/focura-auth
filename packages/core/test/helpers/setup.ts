import crypto from "crypto";
import { MockRedis } from "./mockRedis.js";
import type { AuthCoreConfig, User, UserStore, AuditLogger } from "../src/types.js";

// ── RSA key pair (generated once) ──
const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

export { privateKey, publicKey };

// ── Mock user store ──
export function mockUserStore(users: User[] = []): UserStore & { _users: User[] } {
  const store = [...users];
  return {
    _users: store,
    async findById(id: string) {
      return store.find((u) => u.id === id) ?? null;
    },
    async findByEmail(email: string) {
      return store.find((u) => u.email.toLowerCase() === email.toLowerCase()) ?? null;
    },
    async update(id: string, data: Partial<User>) {
      const idx = store.findIndex((u) => u.id === id);
      if (idx >= 0) Object.assign(store[idx]!, data);
    },
    async updateEmailVerified(id: string, verified: Date) {
      const idx = store.findIndex((u) => u.id === id);
      if (idx >= 0) store[idx]!.emailVerified = verified;
    },
  };
}

// ── Mock audit logger ──
export function mockAuditLogger(): AuditLogger & { logs: Array<{ event: string; data: Record<string, unknown> }> } {
  const logs: Array<{ event: string; data: Record<string, unknown> }> = [];
  return {
    logs,
    async log(event: string, data: Record<string, unknown>) {
      logs.push({ event, data });
    },
  };
}

// ── Default test user ──
export const TEST_USER: User = {
  id: "user-1",
  email: "test@example.com",
  name: "Test User",
  role: "USER",
  password: "$argon2id$hashed",
  emailVerified: new Date("2024-01-01"),
  twoFactorEnabled: false,
  twoFactorSecret: null,
  bannedAt: null,
  banReason: null,
  lastLoginAt: null,
  image: null,
};

// ── Default auth config factory ──
export function makeAuthConfig(overrides?: Partial<AuthCoreConfig>): AuthCoreConfig {
  const redis = overrides?.redis ?? new MockRedis();
  const userStore = overrides?.userStore ?? mockUserStore([TEST_USER]);
  return {
    redis,
    userStore,
    hmacSecret: "test-hmac-secret-32chars-long!!",
    jwt: {
      privateKey,
      publicKey,
      issuer: "test-issuer",
      audience: "test-audience",
      accessTokenExpiry: "15m",
      refreshTokenExpiry: "7d",
      sseTokenExpiry: "30s",
      currentVersion: 1,
    },
    ...overrides,
  };
}
