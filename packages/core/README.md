# @focura-prod/auth-core

Production-ready authentication engine for Node.js backends.

## Features

- **Dual-token RS256 JWT** architecture (15min access / 7d refresh)
- **Token exchange** — HMAC-SHA256 signed proof between services
- **Refresh token rotation** — Atomic Lua script, distributed lock
- **Session binding** — Device fingerprint + IP validation
- **Session management** — Max concurrent sessions, eviction
- **Account lockout** — Configurable failure threshold
- **2FA (TOTP)** — Generate and verify time-based one-time passwords
- **Audit logging** — 50+ event types with severity levels
- **CSRF protection** — Redis-backed tokens
- **Rate limiting** — Sliding window, configurable per-route
- **Cache layer** — Auth result + user profile caching

## Installation

```bash
npm install @focura-prod/auth-core ioredis
```

## Quick Start

```typescript
import { AuthService } from "@focura-prod/auth-core";
import Redis from "ioredis";
import fs from "fs";

const redis = new Redis(process.env.REDIS_URL!);

const auth = new AuthService({
  redis,
  userStore: {
    findById: (id) => prisma.user.findUnique({ where: { id } }),
    findByEmail: (email) => prisma.user.findUnique({ where: { email } }),
    update: (id, data) => prisma.user.update({ where: { id }, data }),
    updateEmailVerified: (id, date) => prisma.user.update({ where: { id }, data: { emailVerified: date } }),
  },
  hmacSecret: process.env.AUTH_SECRET!,
  jwt: {
    privateKey: fs.readFileSync("keys/private.pem", "utf8"),
    publicKey: fs.readFileSync("keys/public.pem", "utf8"),
  },
});
```

## High-Level API

### Token Exchange

Exchange a HMAC-signed proof for JWT tokens:

```typescript
const tokens = await auth.exchange({
  userId: user.id,
  email: user.email,
  role: user.role,
  sessionId: crypto.randomUUID(),
  timestamp: Date.now(),
  signature: hmacSignature,
});

// tokens.accessToken, tokens.refreshToken, tokens.sseToken, tokens.sessionId
```

### Verify Token

Verify an access token and load the user:

```typescript
const { user, payload } = await auth.verifyToken({
  token: accessToken,
  ipAddress: "192.168.1.1",
  userAgent: "Mozilla/5.0...",
});

// payload.id, payload.email, payload.role, payload.jti, payload.sessionId
```

### Refresh Tokens

Rotate refresh tokens atomically:

```typescript
const newTokens = await auth.refresh({
  refreshToken: currentRefreshToken,
});

// newTokens.accessToken, newTokens.refreshToken, newTokens.sseToken
```

### Logout

```typescript
// Single session
await auth.logout({
  userId: user.id,
  sessionId: sessionId,
  accessTokenJti: jti,
  accessToken: token,
});

// All sessions
await auth.logout({
  userId: user.id,
  sessionId: sessionId,
  logoutAll: true,
});
```

### Two-Factor Authentication

```typescript
// Setup — generate secret + URI for QR code
const { secret, uri } = auth.generateTwoFactor();
// Display uri as QR code to user, store secret in database

// Verify TOTP code
const valid = await auth.verifyTwoFactor({ token: "123456", secret });
```

### Session Management

```typescript
// List active sessions
const sessions = await auth.getActiveSessions(userId);

// Revoke a specific session
await auth.revokeSession(userId, sessionId);
```

### Account Lockout

```typescript
// Record failed login attempt
const result = await auth.recordLoginFailure(email);
if (result.locked) {
  console.log(`Account locked until ${result.unlocksAt}`);
}

// Clear failures on successful login
await auth.clearLoginFailures(email);

// Check if account is locked
const status = await auth.isAccountLocked(email);
```

### Audit Logging

```typescript
auth.log("WORKSPACE_CREATED", { userId, workspaceId });
```

## Express Integration

For Express.js applications, use `MiddlewareFactory` for HTTP middleware:

```typescript
import { MiddlewareFactory } from "@focura-prod/auth-core";

const factory = new MiddlewareFactory(config);

// Auth routes
app.post("/api/v1/auth/exchange", factory.createExchangeHandler());
app.post("/api/v1/auth/refresh", factory.createRefreshHandler());
app.post("/api/v1/auth/logout", factory.createLogoutHandler());

// Protected routes
app.get("/api/v1/profile",
  factory.createAuthenticateMiddleware(),
  (req, res) => { res.json({ user: req.user }); }
);

// Role-based access
app.get("/api/v1/admin",
  factory.createAuthenticateMiddleware(),
  factory.createAuthorizeMiddleware("ADMIN"),
  (req, res) => { res.json({ admin: true }); }
);
```

## Adapters

### RedisAdapter

Works with ioredis or any compatible client:

```typescript
import Redis from "ioredis";
const redis = new Redis(process.env.REDIS_URL);

const auth = new AuthService({ redis, ... });
```

### UserStore

Implement this to connect your database:

```typescript
const userStore = {
  findById: async (id) => db.user.findUnique({ where: { id } }),
  findByEmail: async (email) => db.user.findUnique({ where: { email } }),
  update: async (id, data) => db.user.update({ where: { id }, data }),
  updateEmailVerified: async (id, date) => db.user.update({ where: { id }, data: { emailVerified: date } }),
};
```

### CacheAdapter

Optional but recommended for performance:

```typescript
const cache = {
  get: async (key) => { const v = await redis.get(key); return v ? JSON.parse(v) : null; },
  set: async (key, val, ttl) => { await redis.setex(key, ttl!, JSON.stringify(val)); },
  delete: async (key) => { await redis.del(key); },
};
```

## Configuration

```typescript
interface AuthCoreConfig {
  redis: RedisAdapter;           // Required
  userStore: UserStore;          // Required
  hmacSecret: string;            // Required — shared secret for token exchange
  jwt: TokenConfig;              // Required — RSA key pair
  cache?: CacheAdapter;          // Optional — enables auth result caching
  auditLogger?: AuditLogger;     // Optional — persists audit events
  observability?: ObservabilitySink; // Optional — Sentry/Datadog integration
  errors?: ErrorFactory;         // Optional — custom error classes
  keyPrefix?: string;            // Default: "focura:"
  lockout?: LockoutConfig;       // Default: 10 failures / 15min lock / 1hr window
  session?: SessionConfig;       // Default: 7d inactivity / 7d absolute / 5 max concurrent
}
```

## Generated RSA Keys

```bash
openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -in private.pem -pubout -out public.pem
```

## API Hierarchy

### Primary API (Recommended)

```typescript
import { AuthService } from "@focura-prod/auth-core";
```

The `AuthService` class provides high-level, framework-agnostic authentication operations.

### Extension API

Interfaces for integrating your infrastructure:

```typescript
import type { UserStore, RedisAdapter, CacheAdapter, AuditLogger } from "@focura-prod/auth-core";
```

### Advanced API

Low-level classes for custom integrations:

```typescript
import { TokenManager, SessionManager, TotpManager, AccountLockout } from "@focura-prod/auth-core";
```

These are available but not required for normal application development.

---

## Default Configuration

```typescript
import { DEFAULTS } from "@focura-prod/auth-core";

// All default values:
DEFAULTS.keyPrefix;              // "focura:"
DEFAULTS.issuer;                 // "focura-app"
DEFAULTS.audience;               // "focura-backend"
DEFAULTS.accessTokenExpiry;      // "15m"
DEFAULTS.refreshTokenExpiry;     // "7d"
DEFAULTS.sseTokenExpiry;         // "30s"
DEFAULTS.maxConcurrentSessions;  // 5
DEFAULTS.lockoutMaxFailures;     // 10
DEFAULTS.lockoutSeconds;         // 900 (15 minutes)
DEFAULTS.lockoutWindowSeconds;   // 3600 (1 hour)
DEFAULTS.inactivityTimeout;      // 604800 (7 days)
DEFAULTS.absoluteTimeout;        // 604800 (7 days)
```

### resolveConfig

Merges your config with defaults. Useful for advanced customization:

```typescript
import { resolveConfig } from "@focura-prod/auth-core";

const resolved = resolveConfig({
  redis,
  userStore,
  hmacSecret: "...",
  jwt: { privateKey: "...", publicKey: "..." },
  lockout: { maxFailures: 5 },  // override default 10
});

// resolved contains all values with defaults applied
```

---

## Error Handling

All errors include `code` and `statusCode` for API responses:

```typescript
import {
  UnauthorizedError,      // 401, code: UNAUTHORIZED
  TokenExpiredError,      // 401, code: TOKEN_EXPIRED
  InvalidTokenError,      // 401, code: INVALID_TOKEN
  TokenRevokedError,      // 401, code: TOKEN_REVOKED
  SessionHijackError,     // 401, code: SESSION_HIJACK_DETECTED
  EmailNotVerifiedError,  // 403, code: EMAIL_NOT_VERIFIED
  AccountBannedError,     // 403, code: ACCOUNT_BANNED
  ForbiddenError,         // 403, code: FORBIDDEN
  BadRequestError,        // 400, code: BAD_REQUEST
  ValidationError,        // 400, code: VALIDATION_ERROR
} from "@focura-prod/auth-core";
```

### Example: Catching errors

```typescript
try {
  const { user, payload } = await auth.verifyToken({ token, ipAddress, userAgent });
} catch (e) {
  if (e instanceof TokenExpiredError) {
    return res.status(401).json({ error: "Token expired", code: e.code });
  }
  if (e instanceof InvalidTokenError) {
    return res.status(401).json({ error: "Invalid token", code: e.code });
  }
  if (e instanceof SessionHijackError) {
    return res.status(401).json({ error: "Session hijack detected", code: e.code });
  }
  if (e instanceof AccountBannedError) {
    return res.status(403).json({ error: "Account banned", reason: e.message });
  }
  if (e instanceof ValidationError) {
    return res.status(400).json({ error: e.message, details: e.details });
  }
  return res.status(500).json({ error: "Internal server error" });
}
```

### defaultErrors Factory

Use as base for custom error classes:

```typescript
import { defaultErrors } from "@focura-prod/auth-core";

const customErrors = {
  ...defaultErrors,
  UnauthorizedError: (msg) => new MyCustomUnauthorizedError(msg),
};

const auth = new AuthService({ ..., errors: customErrors });
```

---

## Input & Result Types

All types are exported for TypeScript autocompletion:

```typescript
import type {
  // Token exchange
  ExchangeInput,        // { userId, email, role, sessionId, timestamp, signature }
  ExchangeResult,       // { accessToken, refreshToken, sseToken, sessionId }

  // Token verification
  VerifyTokenInput,     // { token, ipAddress?, userAgent? }
  VerifyTokenResult,    // { user, payload }

  // Refresh
  RefreshInput,         // { refreshToken }
  AuthRefreshResult,    // { accessToken, refreshToken, sseToken }

  // Logout
  LogoutInput,          // { userId, sessionId, accessTokenJti?, accessToken?, logoutAll? }

  // 2FA
  TwoFactorSetupResult, // { secret, uri }
  TwoFactorVerifyInput, // { token, secret }

  // Tokens
  TokenPayload,         // { id, email, role, type, version, jti, sessionId? }
  TokenPair,            // { accessToken, refreshToken, accessTokenExpiry, refreshTokenExpiry }

  // Config sub-types
  TokenConfig,          // { privateKey, publicKey, issuer?, audience?, accessTokenExpiry?, ... }
  SessionConfig,        // { inactivityTimeout?, absoluteTimeout?, maxConcurrent?, metadataTtl? }
  LockoutConfig,        // { maxFailures?, lockoutSeconds?, windowSeconds? }

  // Adapters
  RedisAdapter,
  RedisPipeline,
  UserStore,
  User,
  CacheAdapter,
  AuditLogger,
  ObservabilitySink,
  ErrorFactory,
  ZodSchema,

  // Session
  SessionMetadata,      // { deviceId, ipAddress, userAgent, location?, lastActivity }
  SessionLifecycle,     // { recordCreation, invalidate, isTracked, isInactive }
  DeviceFingerprint,    // { userAgent, acceptLanguage, acceptEncoding, ipAddress }
  AuthRequest,          // Extended request with user property
} from "@focura-prod/auth-core";
```

---

## MiddlewareFactory Methods

All HTTP middleware and route handlers:

```typescript
import { MiddlewareFactory } from "@focura-prod/auth-core";

const factory = new MiddlewareFactory(config);

// Route handlers
factory.createExchangeHandler();       // POST /api/v1/auth/exchange
factory.createRefreshHandler();        // POST /api/v1/auth/refresh
factory.createLogoutHandler();         // POST /api/v1/auth/logout

// Auth middleware
factory.createAuthenticateMiddleware();           // Verifies JWT, attaches req.user
factory.createAuthorizeMiddleware("ADMIN", "MOD"); // Role-based access

// Security middleware
factory.createCsrfMiddleware();                   // CSRF token validation
factory.createRateLimitMiddleware();              // Sliding window rate limiting
factory.createSessionTimeoutMiddleware();         // Inactivity + absolute timeout
```

---

## Utility Functions

Low-level helpers available for advanced use:

```typescript
import {
  generateDeviceFingerprint,  // (req) => DeviceFingerprint
  getClientIp,                // (req) => string
  isPrivateIp,                // (ip) => boolean — checks 10.x, 172.16-31.x, 192.168.x, 127.x
  normalizeUserAgent,         // (ua) => string — truncates long user agents
  createSessionMetadata,      // (fingerprint, sessionId) => SessionMetadata
  validateSessionBinding,     // (metadata, fingerprint, options) => { bound, reason? }
  looksLikeServerToServerRequest, // (req) => boolean
  looksLikeServerToServerUA,      // (ua) => boolean
} from "@focura-prod/auth-core";
```

---

## Audit Event Types

50+ event types with severity levels:

```typescript
import { AUDIT_SEVERITY } from "@focura-prod/auth-core";

// AUDIT_SEVERITY maps event types to severity:
// "info"    — LOGIN_SUCCESS, LOGOUT, TOKEN_REFRESHED, SESSION_BOUND, etc.
// "warn"    — LOGIN_FAILED, DEVICE_MISMATCH, RATE_LIMIT_EXCEEDED, etc.
// "critical" — TOKEN_REPLAY_DETECTED, ACCOUNT_LOCKED, MALWARE_DETECTED, etc.
```

```typescript
import type { AuditEventType, AuditSeverity } from "@focura-prod/auth-core";

// AuditEventType — union of all 50+ event strings
// AuditSeverity — "info" | "warn" | "critical"
```

---

## Zod Schemas

Validation schemas used internally (available for external use):

```typescript
import { exchangeSchema, refreshSchema, logoutSchema } from "@focura-prod/auth-core";

// exchangeSchema validates ExchangeInput
// refreshSchema validates RefreshInput
// logoutSchema validates LogoutInput

const result = exchangeSchema.safeParse(data);
if (!result.success) {
  console.log(result.error.issues);
}
```

## License

MIT
