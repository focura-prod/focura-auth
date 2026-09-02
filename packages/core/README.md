# @focura/auth-core

Production-ready authentication core for Express.js backends.

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
npm install @focura/auth-core express ioredis
npm install -D @types/express
```

## Quick Start

```typescript
import { MiddlewareFactory, AccountLockout, SessionManager } from "@focura/auth-core";
import Redis from "ioredis";

const redis = new Redis(process.env.REDIS_URL!);

const auth = new MiddlewareFactory({
  redis,
  userStore: {
    findById: (id) => prisma.user.findUnique({ where: { id } }),
    findByEmail: (email) => prisma.user.findUnique({ where: { email } }),
    update: (id, data) => prisma.user.update({ where: { id }, data }),
    updateEmailVerified: (id, date) => prisma.user.update({ where: { id }, data: { emailVerified: date } }),
  },
  hmacSecret: process.env.NEXTAUTH_SECRET!,
  jwt: {
    privateKey: fs.readFileSync("keys/private.pem", "utf8"),
    publicKey: fs.readFileSync("keys/public.pem", "utf8"),
  },
  cache: {
    get: (key) => redis.get(key).then(JSON.parse),
    set: (key, val, ttl) => redis.setex(key, ttl!, JSON.stringify(val)),
    delete: (key) => redis.del(key),
  },
  auditLogger: {
    log: (event, data) => prisma.auditLog.create({ data: { event, ...data } }),
  },
});

// Auth routes
app.post("/api/v1/auth/exchange", auth.createExchangeHandler());
app.post("/api/v1/auth/refresh", auth.createRefreshHandler());
app.post("/api/v1/auth/logout", auth.createLogoutHandler());

// Protected routes
app.get("/api/v1/profile", auth.createAuthenticateMiddleware(), (req, res) => {
  res.json({ user: req.user });
});

app.get("/api/v1/admin", auth.createAuthenticateMiddleware(), auth.createAuthorizeMiddleware("ADMIN"), (req, res) => {
  res.json({ admin: true });
});
```

## Adapters

### RedisAdapter

Works with ioredis or any compatible client:

```typescript
import Redis from "ioredis";
const redis = new Redis(process.env.REDIS_URL);

// Pass directly — ioredis satisfies the RedisAdapter interface
const auth = new MiddlewareFactory({ redis, ... });
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

## License

MIT
