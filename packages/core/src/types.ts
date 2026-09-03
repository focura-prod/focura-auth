// @focura-prod/auth-core — Adapter interfaces and configuration types

export interface RedisAdapter {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, ...args: unknown[]): Promise<"OK" | null>;
  setex(key: string, ttl: number, value: string): Promise<"OK" | null>;
  setnx(key: string, value: string): Promise<number>;
  del(...keys: string[]): Promise<number>;
  exists(key: string): Promise<0 | 1>;
  expire(key: string, seconds: number): Promise<0 | 1>;
  ttl(key: string): Promise<number>;
  sadd(key: string, ...members: string[]): Promise<number>;
  srem(key: string, ...members: string[]): Promise<number>;
  smembers(key: string): Promise<string[]>;
  incr(key: string): Promise<number>;
  scan(cursor: string, ...args: string[]): Promise<[string, string[]]>;
  eval<T = unknown>(script: string, numKeys: number, ...args: string[]): Promise<T>;
  pipeline(): RedisPipeline;
}

export interface RedisPipeline {
  setex(key: string, ttl: number, value: string): this;
  incr(key: string): this;
  expire(key: string, seconds: number): this;
  exec(): Promise<[Error | null, unknown][]>;
}

export interface UserStore {
  findById(id: string): Promise<User | null>;
  findByEmail(email: string): Promise<User | null>;
  update(id: string, data: Partial<User>): Promise<void>;
  updateEmailVerified(id: string, verified: Date): Promise<void>;
}

export interface User {
  id: string;
  email: string;
  name?: string | null;
  role: string;
  password?: string | null;
  emailVerified?: Date | null;
  twoFactorEnabled?: boolean;
  twoFactorSecret?: string | null;
  bannedAt?: Date | null;
  banReason?: string | null;
  lastLoginAt?: Date | null;
  image?: string | null;
}

export interface CacheAdapter {
  get<T>(key: string): Promise<T | null>;
  set(key: string, value: unknown, ttlSeconds?: number): Promise<void>;
  delete(key: string): Promise<void>;
}

export interface AuditLogger {
  log(event: string, data: Record<string, unknown>): Promise<void>;
}

export interface ObservabilitySink {
  setUserContext?(user: { id: string; email?: string }): void;
  addBreadcrumb?(breadcrumb: { message: string; data?: Record<string, unknown> }): void;
  captureException?(error: Error, context?: Record<string, unknown>): void;
}

export interface ErrorFactory {
  UnauthorizedError(message?: string, code?: string): Error;
  TokenExpiredError(): Error;
  InvalidTokenError(code?: string): Error;
  TokenRevokedError(): Error;
  EmailNotVerifiedError(): Error;
  AccountBannedError(reason?: string | null, bannedAt?: Date | null): Error;
  ForbiddenError(message?: string): Error;
  SessionHijackError(reason?: string): Error;
  BadRequestError(message?: string, code?: string): Error;
  ValidationError(message?: string, details?: unknown[], code?: string): Error;
}

export interface SessionLifecycle {
  recordCreation(sessionId: string): Promise<void>;
  invalidate(sessionId: string): Promise<void>;
  isTracked(sessionId: string): Promise<boolean>;
  isInactive(sessionId: string): Promise<boolean>;
}

export type RateLimiterFactory = (
  max: number,
  windowSeconds: number,
  keyFn?: (req: { headers: Record<string, unknown>; ip?: string }) => string | undefined,
  options?: { failOpen?: boolean },
) => (req: unknown, res: unknown, next: () => void) => void;

export interface ZodSchema {
  safeParse(data: unknown): { success: true; data: unknown } | { success: false; error: { issues: Array<{ path: (string | number)[]; message: string }> } };
}

export interface TokenConfig {
  privateKey: string;
  publicKey: string;
  issuer?: string;
  audience?: string;
  accessTokenExpiry?: string;
  refreshTokenExpiry?: string;
  sseTokenExpiry?: string;
  currentVersion?: number;
}

export interface LockoutConfig {
  maxFailures?: number;
  lockoutSeconds?: number;
  windowSeconds?: number;
}

export interface SessionConfig {
  inactivityTimeout?: number;
  absoluteTimeout?: number;
  maxConcurrent?: number;
  metadataTtl?: number;
}

export interface AuthCoreConfig {
  redis: RedisAdapter;
  userStore: UserStore;
  hmacSecret: string;
  jwt: TokenConfig;
  cache?: CacheAdapter;
  auditLogger?: AuditLogger;
  observability?: ObservabilitySink;
  errors?: ErrorFactory;
  keyPrefix?: string;
  lockout?: LockoutConfig;
  session?: SessionConfig;
}

export interface TokenPayload {
  id: string;
  email: string;
  role: string;
  type: "access" | "refresh" | "sse";
  version: number;
  jti: string;
  sessionId?: string;
}

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
  accessTokenExpiry: number;
  refreshTokenExpiry: number;
}

export interface DeviceFingerprint {
  userAgent: string;
  acceptLanguage: string;
  acceptEncoding: string;
  ipAddress: string;
}

export interface SessionMetadata {
  deviceId: string | null;
  ipAddress: string;
  userAgent: string;
  location?: string;
  lastActivity: number;
}

export type AuditEventType =
  | "LOGIN_SUCCESS"
  | "LOGIN_FAILED"
  | "LOGIN_BLOCKED"
  | "LOGOUT"
  | "LOGOUT_ALL_DEVICES"
  | "TOKEN_REFRESHED"
  | "TOKEN_REVOKED"
  | "TOKEN_EXPIRED"
  | "TOKEN_VERSION_MISMATCH"
  | "TOKEN_REPLAY_DETECTED"
  | "EXCHANGE_SUCCESS"
  | "EXCHANGE_FAILED"
  | "SSE_CONNECTED"
  | "SSE_DISCONNECTED"
  | "ACCOUNT_LOCKED"
  | "TOTP_VERIFIED"
  | "TOTP_FAILED"
  | "PERMISSION_DENIED"
  | "EMAIL_NOT_VERIFIED"
  | "SESSION_BOUND"
  | "SESSION_REBOUND"
  | "SESSION_HIJACK_DETECTED"
  | "SESSION_TIMEOUT"
  | "SESSION_REVOKED"
  | "SESSIONS_REVOKED"
  | "MAX_SESSIONS_REACHED"
  | "DEVICE_MISMATCH"
  | "SUSPICIOUS_IP_CHANGE"
  | "CSRF_VALIDATION_FAILED"
  | "UNAUTHORIZED_ACCESS"
  | "RATE_LIMIT_EXCEEDED"
  | "MALWARE_DETECTED"
  | "SUSPICIOUS_ACTIVITY"
  | "DATA_EXPORT"
  | "DATA_DELETION"
  | "SENSITIVE_DATA_ACCESS"
  | "WORKSPACE_CREATED"
  | "WORKSPACE_DELETED"
  | "MEMBER_ADDED"
  | "MEMBER_REMOVED"
  | "ROLE_CHANGED"
  | "SUBSCRIPTION_CREATED"
  | "SUBSCRIPTION_CANCELLED"
  | "PAYMENT_FAILED";

export type AuditSeverity = "info" | "warn" | "critical";
